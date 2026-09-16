//! Persistence: stored credentials, attestation material and PIN state.
//!
//! Test builds keep credentials in `CtapApp::stored_credentials`; PIN state
//! goes through the client's filesystem in every build.

use super::pin::state::{PersistentPinState, PinState};
use super::CtapApp;
use ciborium::{de::from_reader, ser::into_writer};
use p256::ecdsa::{signature::Signer, Signature as P256EcdsaSignature, SigningKey};
use serde::{Deserialize, Serialize};
use trussed::client::{Client as TrussedClient, CryptoClient, FilesystemClient};
use trussed::try_syscall;
use trussed::types::{Location, Message, PathBuf};
use zeroize::Zeroize;

use crate::ctap::constants::*;

#[cfg(not(test))]
const CREDENTIAL_STORE_PATH: &str = "credentials.cbor";
#[cfg(not(test))]
const ATTESTATION_STORE_PATH: &str = "attestation.cbor";
pub(super) const PIN_STATE_STORE_PATH: &str = "pin-state.cbor";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredCredential {
    pub(super) rp_id: String,
    pub(super) user_id: Vec<u8>,
    pub(super) user_name: Option<String>,
    pub(super) user_display_name: Option<String>,
    pub(super) alg: i32,
    pub(super) credential_id: Vec<u8>,
    pub(super) public_key: Vec<u8>,
    pub(super) secret_key: Vec<u8>,
    #[serde(default)]
    pub(super) cred_random_with_uv: Option<Vec<u8>>,
    #[serde(default)]
    pub(super) cred_random_without_uv: Option<Vec<u8>>,
    #[serde(default)]
    pub(super) cred_protect: Option<u8>,
    pub(super) sign_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAttestation {
    private_key: Vec<u8>,
    certificate_chain: Vec<Vec<u8>>,
}

/// On-disk representation of the persistent PIN state.  Kept in sync with
/// `transport-core::state::StoredPinState` so the CLI can read and write the
/// same `pin-state.cbor` file the daemon uses.
///
/// Only the PIN hash and pinRetries are state.  The consecutive-mismatch
/// lockout is volatile (it is what a power cycle clears), so
/// `consecutive_failures` and `pin_auth_blocked` are never read back; they are
/// still written so the CLI's copy of this struct parses, with
/// `pin_auth_blocked` in the meaning the CLI gives it: blocked until reset.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPinState {
    pin_hash: Option<[u8; 16]>,
    pin_retries: u8,
    consecutive_failures: u8,
    pin_auth_blocked: bool,
}

impl StoredPinState {
    fn snapshot(state: &PinState) -> Self {
        let persistent = state.persistent();
        Self {
            pin_hash: persistent.pin_hash,
            pin_retries: persistent.pin_retries,
            consecutive_failures: 0,
            pin_auth_blocked: persistent.pin_retries == 0,
        }
    }
}

impl PinState {
    fn from_stored(stored: StoredPinState) -> Self {
        PinState::from_persistent(PersistentPinState {
            pin_hash: stored.pin_hash,
            pin_retries: stored.pin_retries,
        })
    }
}

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    /// Load the persistent PIN state from `pin-state.cbor` on the internal
    /// filesystem if one exists.  Missing or unreadable files leave the
    /// in-memory state at its defaults.
    pub(super) fn load_persistent_pin_state(&mut self) {
        let path = match PathBuf::try_from(PIN_STATE_STORE_PATH) {
            Ok(p) => p,
            Err(_) => return,
        };
        let reply = match try_syscall!(self.client.read_file(Location::Internal, path)) {
            Ok(reply) => reply,
            Err(_) => return,
        };
        let data = reply.data.as_slice();
        if data.is_empty() {
            return;
        }
        match from_reader::<StoredPinState, _>(data) {
            Ok(stored) => {
                self.pin_state = PinState::from_stored(stored);
            }
            Err(_) => {
                log::warn!("pin-state.cbor is unreadable; starting with defaults");
            }
        }
    }

    /// Persist the current PIN state.  Called after every CTAP handler that
    /// can mutate the PIN/retries/lockout fields so the CLI and the next
    /// daemon attach observe a consistent view.
    pub(super) fn save_persistent_pin_state(&mut self) {
        let path = match PathBuf::try_from(PIN_STATE_STORE_PATH) {
            Ok(p) => p,
            Err(_) => return,
        };
        let stored = StoredPinState::snapshot(&self.pin_state);
        let mut encoded = Vec::new();
        if into_writer(&stored, &mut encoded).is_err() {
            return;
        }
        let message = match Message::from_slice(&encoded) {
            Ok(m) => m,
            Err(_) => return,
        };
        let _ = try_syscall!(self
            .client
            .write_file(Location::Internal, path, message, None));
    }

    #[cfg(not(test))]
    pub(super) fn clear_credentials(&mut self) -> Result<(), u8> {
        let path = Self::store_path()?;
        let _ = try_syscall!(self.client.remove_file(Location::Internal, path));
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn clear_credentials(&mut self) -> Result<(), u8> {
        self.stored_credentials.clear();
        Ok(())
    }

    fn clear_attestation_material(&mut self) {
        if let Some(mut key) = self.attestation_private_key.take() {
            key.zeroize();
        }
        self.attestation_certificate_chain = None;
        self.attestation_material_initialized = false;
    }

    fn ensure_attestation_material(&mut self) {
        if self.attestation_material_initialized {
            return;
        }

        if matches!(
            (
                self.attestation_private_key.as_ref(),
                self.attestation_certificate_chain.as_ref()
            ),
            (Some(_), Some(chain)) if !chain.is_empty()
        ) {
            self.attestation_material_initialized = true;
            return;
        }

        self.attestation_material_initialized = true;

        if self.load_attestation_material().is_err() {
            self.clear_attestation_material();
            self.attestation_material_initialized = true;
        }
    }

    #[cfg(not(test))]
    fn store_path() -> Result<PathBuf, u8> {
        PathBuf::try_from(CREDENTIAL_STORE_PATH).map_err(|_| CTAP2_ERR_PROCESSING)
    }

    #[cfg(not(test))]
    fn attestation_store_path() -> Result<PathBuf, u8> {
        PathBuf::try_from(ATTESTATION_STORE_PATH).map_err(|_| CTAP2_ERR_PROCESSING)
    }

    #[cfg(not(test))]
    fn load_attestation_material(&mut self) -> Result<(), u8> {
        let path = Self::attestation_store_path()?;
        match try_syscall!(self.client.read_file(Location::Internal, path.clone())) {
            Ok(reply) => {
                let data = reply.data.as_slice();
                if data.is_empty() {
                    self.clear_attestation_material();
                    return Ok(());
                }

                let stored: StoredAttestation =
                    from_reader(data).map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
                if stored.private_key.is_empty()
                    || stored.certificate_chain.is_empty()
                    || stored.private_key.len() != 32
                {
                    self.clear_attestation_material();
                    return Err(CTAP2_ERR_INVALID_CBOR);
                }

                self.clear_attestation_material();
                self.attestation_private_key = Some(stored.private_key);
                self.attestation_certificate_chain = Some(stored.certificate_chain);
                Ok(())
            }
            Err(_) => {
                self.clear_attestation_material();
                Ok(())
            }
        }
    }

    #[cfg(test)]
    fn load_attestation_material(&mut self) -> Result<(), u8> {
        Ok(())
    }

    pub(super) fn attestation_signature(
        &mut self,
        auth_data: &[u8],
        client_hash: &[u8],
    ) -> Result<Option<(Vec<u8>, Vec<Vec<u8>>)>, u8> {
        self.ensure_attestation_material();

        let (key_bytes, chain) = match (
            self.attestation_private_key.as_ref(),
            self.attestation_certificate_chain.as_ref(),
        ) {
            (Some(key), Some(chain)) if !chain.is_empty() => (key, chain),
            _ => return Ok(None),
        };

        if key_bytes.len() != 32 {
            return Err(CTAP2_ERR_PROCESSING);
        }

        let signing_key = SigningKey::from_slice(key_bytes).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut message = Vec::with_capacity(auth_data.len() + client_hash.len());
        message.extend_from_slice(auth_data);
        message.extend_from_slice(client_hash);
        let signature: P256EcdsaSignature = signing_key.sign(&message);
        let der = signature.to_der();
        Ok(Some((der.as_bytes().to_vec(), chain.clone())))
    }

    #[cfg(not(test))]
    pub(super) fn load_credentials(&mut self) -> Result<Vec<StoredCredential>, u8> {
        let path = Self::store_path()?;
        match try_syscall!(self.client.read_file(Location::Internal, path.clone())) {
            Ok(reply) => {
                let data = reply.data.as_slice();
                if data.is_empty() {
                    Ok(Vec::new())
                } else {
                    from_reader(data).map_err(|_| CTAP2_ERR_INVALID_CBOR)
                }
            }
            Err(_) => Ok(Vec::new()),
        }
    }

    #[cfg(test)]
    pub(super) fn load_credentials(&mut self) -> Result<Vec<StoredCredential>, u8> {
        Ok(self.stored_credentials.clone())
    }

    #[cfg(not(test))]
    pub(super) fn save_credentials(&mut self, creds: &[StoredCredential]) -> Result<(), u8> {
        let mut encoded = Vec::new();
        into_writer(creds, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let message = Message::from_slice(&encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let path = Self::store_path()?;
        try_syscall!(self
            .client
            .write_file(Location::Internal, path, message, None))
        .map_err(|_| CTAP2_ERR_PROCESSING)?;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn save_credentials(&mut self, creds: &[StoredCredential]) -> Result<(), u8> {
        self.stored_credentials = creds.to_vec();
        Ok(())
    }
}
