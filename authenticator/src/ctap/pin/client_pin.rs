//! The authenticatorClientPIN command and its subcommands.

use super::permissions::{PIN_PERMISSION_CM, PIN_PERMISSION_GA, PIN_PERMISSION_MC};
use super::protocol::{decrypt, verify, PinProtocol, PinProtocolSession};
use super::state::PinState;
use crate::ctap::cbor::{self, canonical_map, canonical_sort};
use crate::ctap::CtapApp;
use crate::PinUvSessionKeys;

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey as P256SecretKey};
use sha2::{Digest, Sha256};
use trussed::client::{Client as TrussedClient, CryptoClient, FilesystemClient};
use trussed::syscall;
use zeroize::Zeroize;

use transport_core::ctap::constants::*;

/// The authenticatorClientPIN subcommands this authenticator implements
/// (CTAP 2.3 §6.5.5).  getPinUvAuthTokenUsingUvWithPermissions (0x06) and
/// getUVRetries (0x07) need a built-in user verification method, which it
/// does not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientPinSubcommand {
    GetPinRetries,
    GetKeyAgreement,
    SetPin,
    ChangePin,
    GetPinToken,
    GetPinUvAuthTokenUsingPinWithPermissions,
}

impl ClientPinSubcommand {
    /// Parse subCommand (0x02).  "If the authenticator implements a command
    /// code having subcommands, but does not implement an invoked subcommand,
    /// it MUST return CTAP2_ERR_INVALID_SUBCOMMAND." (CTAP 2.3 §8.1)
    fn parse(value: Option<&Value>) -> Result<Self, u8> {
        let number = match value {
            Some(Value::Integer(number)) => i128::from(*number),
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        match number {
            0x01 => Ok(Self::GetPinRetries),
            0x02 => Ok(Self::GetKeyAgreement),
            0x03 => Ok(Self::SetPin),
            0x04 => Ok(Self::ChangePin),
            0x05 => Ok(Self::GetPinToken),
            0x09 => Ok(Self::GetPinUvAuthTokenUsingPinWithPermissions),
            _ => Err(CTAP2_ERR_INVALID_SUBCOMMAND),
        }
    }
}

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    fn extract_new_pin(plaintext: &mut [u8]) -> Result<Vec<u8>, u8> {
        if plaintext.len() != 64 {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }
        let mut end = plaintext.len();
        while end > 0 && plaintext[end - 1] == 0 {
            end -= 1;
        }
        let pin = plaintext[..end].to_vec();
        plaintext.zeroize();
        if pin.len() < PinState::MIN_PIN_LENGTH {
            return Err(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        if pin.len() > 63 {
            return Err(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        Ok(pin)
    }

    fn hash_pin(pin: &[u8]) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(pin);
        let digest = hasher.finalize();
        let mut out = [0u8; 16];
        out.copy_from_slice(&digest[..16]);
        out
    }

    /// The PIN check of changePIN (CTAP 2.3 §6.5.5.6), getPinToken
    /// (§6.5.5.7.1) and getPinUvAuthTokenUsingPinWithPermissions (§6.5.5.7.2):
    ///
    /// > The authenticator decrements the pinRetries counter by 1.
    /// >
    /// > The authenticator decrypts pinHashEnc using decrypt and verifies
    /// > against its internally stored CurrentStoredPIN.
    ///
    /// The decremented counter is persisted before pinHashEnc is decrypted, so
    /// cutting power part-way through the check still costs a retry.  A
    /// pinHashEnc that fails to decrypt counts as a mismatch ("If an error
    /// results, or a mismatch is detected").
    fn verify_pin_hash_enc(
        &mut self,
        protocol: PinProtocol,
        keys: &PinUvSessionKeys,
        pin_hash_enc: &[u8],
    ) -> Result<(), u8> {
        let attempt = self.pin_state.begin_pin_attempt()?;
        self.save_persistent_pin_state();
        let candidate = decrypt(protocol, keys, pin_hash_enc);
        let result = self
            .pin_state
            .finish_pin_attempt(attempt, candidate.as_ref().map(|hash| hash.as_slice()));
        self.save_persistent_pin_state();
        result
    }

    fn client_pin_get_key_agreement(&mut self, protocol: PinProtocol) -> Result<Vec<u8>, u8> {
        let secret_key = loop {
            let bytes = syscall!(self.client.random_bytes(32)).bytes;
            if bytes.len() != 32 {
                continue;
            }
            match P256SecretKey::from_slice(bytes.as_slice()) {
                Ok(secret) => break secret,
                Err(_) => continue,
            }
        };
        let public_key = secret_key.public_key().to_encoded_point(false);
        let session = PinProtocolSession {
            protocol,
            public_key,
            secret_key,
        };
        let mut key_map = session.key_agreement_value();
        if let Value::Map(mut entries) = key_map {
            canonical_sort(&mut entries);
            key_map = Value::Map(entries);
        }
        self.pin_protocol_session = Some(session);
        let response = canonical_map(vec![(Value::Integer(Integer::from(1)), key_map)]);
        let mut encoded = Vec::new();
        into_writer(&response, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    fn client_pin_set_pin(
        &mut self,
        protocol: PinProtocol,
        map: &[(Value, Value)],
    ) -> Result<Vec<u8>, u8> {
        if self.pin_state.is_set() {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        let key_agreement = match cbor::map_get(map, Value::Integer(Integer::from(3))) {
            Some(Value::Map(entries)) => entries,
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let new_pin_enc = match cbor::map_get(map, Value::Integer(Integer::from(5))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let pin_auth_param = match cbor::map_get(map, Value::Integer(Integer::from(4))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let session = self.take_session(protocol)?;
        let (keys, transcript_hash) = session.derive_session_keys(key_agreement)?;
        verify(protocol, &keys.auth_key, &new_pin_enc, &pin_auth_param)?;
        let mut plaintext =
            Self::decrypt_pin_block_checked(protocol, &keys, &transcript_hash, &new_pin_enc)?;
        let mut new_pin = Self::extract_new_pin(&mut plaintext)?;
        let hash = Self::hash_pin(&new_pin);
        new_pin.zeroize();
        self.pin_state.set_pin(hash);
        self.save_persistent_pin_state();
        Ok(vec![CTAP2_OK])
    }

    fn client_pin_change_pin(
        &mut self,
        protocol: PinProtocol,
        map: &[(Value, Value)],
    ) -> Result<Vec<u8>, u8> {
        if !self.pin_state.is_set() {
            return Err(CTAP2_ERR_PIN_NOT_SET);
        }
        let key_agreement = match cbor::map_get(map, Value::Integer(Integer::from(3))) {
            Some(Value::Map(entries)) => entries,
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let new_pin_enc = match cbor::map_get(map, Value::Integer(Integer::from(5))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let pin_hash_enc = match cbor::map_get(map, Value::Integer(Integer::from(6))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let pin_auth_param = match cbor::map_get(map, Value::Integer(Integer::from(4))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        self.pin_state.check_pin_attempt_allowed()?;
        let session = self.take_session(protocol)?;
        let (keys, transcript_hash) = session.derive_session_keys(key_agreement)?;
        let mut auth_data = Vec::with_capacity(new_pin_enc.len() + pin_hash_enc.len());
        auth_data.extend_from_slice(&new_pin_enc);
        auth_data.extend_from_slice(&pin_hash_enc);
        verify(protocol, &keys.auth_key, &auth_data, &pin_auth_param)?;
        self.verify_pin_hash_enc(protocol, &keys, &pin_hash_enc)?;

        let mut new_pin_plain =
            Self::decrypt_pin_block_checked(protocol, &keys, &transcript_hash, &new_pin_enc)?;
        let mut new_pin = Self::extract_new_pin(&mut new_pin_plain)?;
        let hash = Self::hash_pin(&new_pin);
        new_pin.zeroize();
        self.pin_state.set_pin(hash);
        self.save_persistent_pin_state();
        Ok(vec![CTAP2_OK])
    }

    fn client_pin_get_token_common(
        &mut self,
        protocol: PinProtocol,
        map: &[(Value, Value)],
        permissions: u8,
        rp_id: Option<String>,
    ) -> Result<Vec<u8>, u8> {
        if !self.pin_state.is_set() {
            return Err(CTAP2_ERR_PIN_NOT_SET);
        }
        let key_agreement = match cbor::map_get(map, Value::Integer(Integer::from(3))) {
            Some(Value::Map(entries)) => entries,
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let pin_hash_enc = match cbor::map_get(map, Value::Integer(Integer::from(6))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        // getPinToken and getPinUvAuthTokenUsingPinWithPermissions take no
        // pinUvAuthParam (CTAP 2.3 §6.5.5.7.1 and §6.5.5.7.2 list keyAgreement
        // and pinHashEnc only): proof of the PIN is pinHashEnc itself, so a
        // pinUvAuthParam sent anyway is ignored rather than verified.

        self.pin_state.check_pin_attempt_allowed()?;
        let session = self.take_session(protocol)?;
        let (keys, _transcript_hash) = session.derive_session_keys(key_agreement)?;
        self.verify_pin_hash_enc(protocol, &keys, &pin_hash_enc)?;

        let random = syscall!(self.client.random_bytes(32)).bytes;
        if random.len() != 32 {
            return Err(CTAP2_ERR_PROCESSING);
        }
        let mut token = [0u8; 32];
        token.copy_from_slice(random.as_slice());
        let encrypted = self.encrypt_for_platform(protocol, &keys, &token)?;
        self.pin_state
            .set_pin_uv_auth_token(token, permissions, rp_id);
        let response = canonical_map(vec![
            (Value::Integer(Integer::from(2)), Value::Bytes(encrypted)),
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(u64::from(self.pin_state.retries()))),
            ),
        ]);
        let mut encoded = Vec::new();
        into_writer(&response, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    fn client_pin_get_token_legacy(
        &mut self,
        protocol: PinProtocol,
        map: &[(Value, Value)],
    ) -> Result<Vec<u8>, u8> {
        if cbor::map_get(map, Value::Integer(Integer::from(9))).is_some()
            || cbor::map_get(map, Value::Integer(Integer::from(10))).is_some()
        {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }
        let permissions = PIN_PERMISSION_MC | PIN_PERMISSION_GA;
        self.client_pin_get_token_common(protocol, map, permissions, None)
    }

    fn client_pin_get_token_with_permissions(
        &mut self,
        protocol: PinProtocol,
        map: &[(Value, Value)],
    ) -> Result<Vec<u8>, u8> {
        let permissions_value = match cbor::map_get(map, Value::Integer(Integer::from(9))) {
            Some(Value::Integer(value)) => {
                let int_value: i128 = value.clone().into();
                if int_value <= 0 || int_value > u8::MAX as i128 {
                    return Err(CTAP1_ERR_INVALID_PARAMETER);
                }
                int_value as u8
            }
            Some(_) => return Err(CTAP1_ERR_INVALID_PARAMETER),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        if permissions_value == 0 {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }

        let rp_id_value = match cbor::map_get(map, Value::Integer(Integer::from(10))) {
            Some(Value::Text(text)) => Some(text.clone()),
            Some(_) => return Err(CTAP2_ERR_INVALID_CBOR),
            None => None,
        };

        if permissions_value & (PIN_PERMISSION_MC | PIN_PERMISSION_GA) != 0 && rp_id_value.is_none()
        {
            return Err(CTAP2_ERR_MISSING_PARAMETER);
        }
        if permissions_value & PIN_PERMISSION_CM != 0 && rp_id_value.is_some() {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }

        let supported_permissions = PIN_PERMISSION_MC | PIN_PERMISSION_GA | PIN_PERMISSION_CM;
        if permissions_value & !supported_permissions != 0 {
            return Err(CTAP2_ERR_UNAUTHORIZED_PERMISSION);
        }

        let assigned_permissions = permissions_value & supported_permissions;
        self.client_pin_get_token_common(protocol, map, assigned_permissions, rp_id_value)
    }

    pub(crate) fn handle_client_pin(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        self.pending_assertion = None;
        let request: Value = from_reader(payload).map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
        let map = match request {
            Value::Map(map) => map,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };
        let subcommand =
            ClientPinSubcommand::parse(cbor::map_get(&map, Value::Integer(Integer::from(2))))?;
        let protocol = self.requested_pin_protocol(&map)?;
        match subcommand {
            ClientPinSubcommand::GetPinRetries => self.client_pin_get_retries(),
            ClientPinSubcommand::GetKeyAgreement => self.client_pin_get_key_agreement(protocol),
            ClientPinSubcommand::SetPin => self.client_pin_set_pin(protocol, &map),
            ClientPinSubcommand::ChangePin => self.client_pin_change_pin(protocol, &map),
            ClientPinSubcommand::GetPinToken => self.client_pin_get_token_legacy(protocol, &map),
            ClientPinSubcommand::GetPinUvAuthTokenUsingPinWithPermissions => {
                self.client_pin_get_token_with_permissions(protocol, &map)
            }
        }
    }

    fn client_pin_get_retries(&mut self) -> Result<Vec<u8>, u8> {
        let mut entries = vec![(
            Value::Integer(Integer::from(0x03)),
            Value::Integer(Integer::from(u64::from(self.pin_state.retries()))),
        )];

        if self.pin_state.needs_power_cycle() {
            entries.push((Value::Integer(Integer::from(0x04)), Value::Bool(true)));
        }

        let response = canonical_map(entries);
        let mut encoded = Vec::new();
        into_writer(&response, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }
}
