mod cbor;
pub mod constants;
mod credential_management;
mod get_assertion;
mod get_info;
mod make_credential;
mod pin;
pub mod presence;
mod reset;
mod storage;
#[cfg(test)]
mod tests;

pub use trussed_core::InterruptFlag;

use self::credential_management::CredentialManagementState;
use self::get_assertion::PendingAssertion;
use self::pin::state::PinState;
use self::presence::{UserPresence, DEFAULT_PRESENCE_TIMEOUT};
#[cfg(test)]
use self::storage::StoredCredential;

use ciborium::{de::from_reader, value::Value};
use core::fmt;
use ctaphid_app::{App, Command, Error};
use log::info;
use rand_core::CryptoRngCore;
use std::time::Duration;
use trussed::client::{Client as TrussedClient, CryptoClient, FilesystemClient};

use self::constants::*;

/// Formats an optional byte for the request log: `0x..` or `n/a`.
#[derive(Copy, Clone)]
struct HexOption(Option<u8>);

impl fmt::Display for HexOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(value) => write!(f, "0x{value:02x}"),
            None => write!(f, "n/a"),
        }
    }
}

pub struct CtapApp<C> {
    client: C,
    aaguid: [u8; 16],
    pin_state: PinState,
    suppress_attestation: bool,
    cred_mgmt_state: CredentialManagementState,
    pending_assertion: Option<PendingAssertion>,
    attestation_private_key: Option<Vec<u8>>,
    attestation_certificate_chain: Option<Vec<Vec<u8>>>,
    attestation_material_initialized: bool,
    rng: Box<dyn CryptoRngCore + Send>,
    presence: Box<dyn UserPresence + Send>,
    presence_timeout: Duration,
    keepalive: Box<dyn FnMut(bool) + Send>,
    interrupt: &'static InterruptFlag,
    #[cfg(test)]
    stored_credentials: Vec<StoredCredential>,
}

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    /// Create the engine.
    ///
    /// `rng` provides every random value the engine chooses: credential IDs,
    /// `CredRandom`, key-agreement keys, pinUvAuthTokens and IVs.  `presence`
    /// is asked whenever an operation needs evidence of user interaction.  `interrupt` is the flag through which the CTAPHID
    /// dispatcher cancels the request being processed; it is also what
    /// [`App::interrupt`] hands to the dispatcher.
    pub fn new(
        client: C,
        rng: impl CryptoRngCore + Send + 'static,
        presence: impl UserPresence + Send + 'static,
        interrupt: &'static InterruptFlag,
        aaguid: [u8; 16],
    ) -> Self {
        let mut app = Self {
            client,
            aaguid,
            pin_state: PinState::new(),
            suppress_attestation: false,
            cred_mgmt_state: CredentialManagementState::new(),
            pending_assertion: None,
            attestation_private_key: None,
            attestation_certificate_chain: None,
            attestation_material_initialized: false,
            rng: Box::new(rng),
            presence: Box::new(presence),
            presence_timeout: DEFAULT_PRESENCE_TIMEOUT,
            keepalive: Box::new(|_| {}),
            interrupt,
            #[cfg(test)]
            stored_credentials: Vec::new(),
        };
        app.load_persistent_pin_state();
        app
    }

    /// Call `callback` with `true` when the engine starts waiting for the
    /// user and with `false` when it stops, so the transport can send the
    /// matching keepalives.
    pub fn set_keepalive_callback(&mut self, callback: impl FnMut(bool) + Send + 'static) {
        self.keepalive = Box::new(callback);
    }

    /// How long presence requests wait for the user.  Defaults to
    /// [`DEFAULT_PRESENCE_TIMEOUT`].
    pub fn set_presence_timeout(&mut self, timeout: Duration) {
        self.presence_timeout = timeout;
    }

    pub fn suppress_attestation(&mut self, suppress: bool) {
        self.suppress_attestation = suppress;
    }

    /// `N` bytes from the injected random number generator.
    fn random_array<const N: usize>(&mut self) -> [u8; N] {
        let mut bytes = [0u8; N];
        self.rng.fill_bytes(&mut bytes);
        bytes
    }

    fn handle_bio_enrollment(&mut self, _payload: &[u8]) -> Result<Vec<u8>, u8> {
        Err(CTAP1_ERR_INVALID_COMMAND)
    }

    fn extract_subcommand_and_pin_protocol_for_logging(payload: &[u8]) -> (Option<u8>, Option<u8>) {
        use std::io::Cursor;

        let mut sub_command = None;
        let mut pin_protocol = None;

        if payload.is_empty() {
            return (sub_command, pin_protocol);
        }

        if let Ok(Value::Map(entries)) = from_reader(Cursor::new(payload)) {
            for (key, value) in entries {
                if let Value::Integer(key_int) = key {
                    let key_val: i128 = key_int.into();
                    match key_val {
                        1 => {
                            if let Value::Integer(sub_int) = value {
                                let value: i128 = sub_int.into();
                                if (0..=u8::MAX as i128).contains(&value) {
                                    sub_command = Some(value as u8);
                                }
                            }
                        }
                        2 => {
                            if let Value::Integer(pin_int) = value {
                                let value: i128 = pin_int.into();
                                if (0..=u8::MAX as i128).contains(&value) {
                                    pin_protocol = Some(value as u8);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        (sub_command, pin_protocol)
    }
}

impl<'interrupt, C, const N: usize> App<'interrupt, N> for CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    fn interrupt(&self) -> Option<&'interrupt InterruptFlag> {
        Some(self.interrupt)
    }

    fn commands(&self) -> &'static [Command] {
        &[Command::Cbor]
    }

    fn call(
        &mut self,
        command: Command,
        request: &[u8],
        response: &mut heapless_bytes::Bytes<N>,
    ) -> Result<(), Error> {
        match command {
            Command::Cbor => {
                if request.is_empty() {
                    return Err(Error::InvalidLength);
                }
                let ctap_cmd = request[0];
                let payload = &request[1..];
                let result = match ctap_cmd {
                    CTAP_CMD_GET_INFO => self.handle_get_info(),
                    CTAP_CMD_MAKE_CREDENTIAL => self.handle_make_credential(payload),
                    CTAP_CMD_GET_ASSERTION => self.handle_get_assertion(payload),
                    CTAP_CMD_GET_NEXT_ASSERTION => self.handle_get_next_assertion(),
                    CTAP_CMD_CLIENT_PIN => self.handle_client_pin(payload),
                    CTAP_CMD_RESET => self.handle_reset(),
                    CTAP_CMD_CREDENTIAL_MANAGEMENT => self.handle_credential_management(payload),
                    CTAP_CMD_BIO_ENROLLMENT => self.handle_bio_enrollment(payload),
                    _ => Err(CTAP1_ERR_INVALID_COMMAND),
                };

                let (message, status) = match result {
                    Ok(bytes) => {
                        let status = bytes.first().copied().unwrap_or(CTAP2_OK);
                        (bytes, status)
                    }
                    Err(status) => (vec![status], status),
                };

                let (sub_command, pin_protocol) = match ctap_cmd {
                    CTAP_CMD_CLIENT_PIN | CTAP_CMD_BIO_ENROLLMENT => {
                        Self::extract_subcommand_and_pin_protocol_for_logging(payload)
                    }
                    _ => (None, None),
                };

                info!(
                    "CTAP2 cmd=0x{ctap_cmd:02x} status=0x{:02x} sub={} pinProtocol={} req_bcnt={} resp_bcnt={} resp_payload_len={}",
                    status,
                    HexOption(sub_command),
                    HexOption(pin_protocol),
                    request.len(),
                    message.len(),
                    message.len(),
                );

                response.clear();
                response
                    .extend_from_slice(&message)
                    .map_err(|_| Error::InvalidLength)
            }
            _ => Err(Error::InvalidCommand),
        }
    }
}
