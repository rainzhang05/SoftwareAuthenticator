//! The CTAP2 authenticator engine.
//!
//! [`CtapApp`] parses CTAP2 commands and answers them.  Everything outside
//! the protocol is injected: persistence through a [`CredentialStore`],
//! randomness through an RNG, and user presence through a [`UserPresence`]
//! implementation.  [`CtapApp::with_file_store`] builds the combination the
//! daemon runs.
//!
//! # Why trait objects
//!
//! The three collaborators are boxed trait objects rather than type
//! parameters.  Each CTAP command makes a handful of calls into them, every
//! one of which does file I/O, key generation or waits for a person, so
//! dynamic dispatch costs nothing measurable.  In exchange the engine is one
//! concrete type: its many `impl` blocks carry no bounds, the daemon and tests
//! name it without spelling out a combination, and a failing test store or a
//! different presence prompt does not produce a new monomorphised copy of the
//! engine.  All three are required to be `Send`, so the engine can later be
//! moved to a worker thread and let the transport handle CTAPHID_CANCEL while
//! a prompt is open.

mod cbor;
pub mod constants;
mod credential_management;
mod get_assertion;
mod get_info;
mod make_credential;
mod pin;
pub mod presence;
mod request;
mod reset;
mod storage;
#[cfg(test)]
mod tests;

pub use self::pin::state::{PersistentPinState, PinAttempt, PinRetryState, MAX_PIN_RETRIES};
pub use self::reset::RESET_WINDOW_AFTER_POWER_UP;
pub use trussed_core::InterruptFlag;

use self::credential_management::CredentialManagementState;
use self::get_assertion::PendingAssertion;
use self::pin::state::PinState;
use self::presence::{UserPresence, DEFAULT_PRESENCE_TIMEOUT};
use crate::store::{CredentialStore, FileStore};

use ciborium::{de::from_reader, value::Value};
use core::fmt;
use ctaphid_app::{App, Command, Error};
use log::info;
use rand_core::{CryptoRngCore, OsRng};
use std::time::Duration;

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

/// The CTAP2 authenticator: a CTAPHID application answering CTAPHID_CBOR.
///
/// `'interrupt` is the lifetime of the interrupt flag the CTAPHID dispatcher
/// uses to cancel a request.
pub struct CtapApp<'interrupt> {
    store: Box<dyn CredentialStore + Send>,
    rng: Box<dyn CryptoRngCore + Send>,
    presence: Box<dyn UserPresence + Send>,
    interrupt: &'interrupt InterruptFlag,
    aaguid: [u8; 16],
    pin_state: PinState,
    /// False while the stored PIN state is unreadable; see
    /// [`storage::load_pin_state`].
    pin_state_writable: bool,
    suppress_attestation: bool,
    cred_mgmt_state: CredentialManagementState,
    pending_assertion: Option<PendingAssertion>,
    presence_timeout: Duration,
    /// How long after power-up authenticatorReset is accepted, if limited.
    reset_window: Option<Duration>,
    keepalive: Box<dyn FnMut(bool) + Send>,
}

impl<'interrupt> CtapApp<'interrupt> {
    /// Create the engine.
    ///
    /// * `store` holds credentials, the PIN state and the attestation key.
    ///   The persistent PIN state is read from it here; construction performs
    ///   no other I/O and never blocks on anything else.
    /// * `rng` provides every random value the engine chooses: credential IDs,
    ///   `CredRandom`, key-agreement keys, pinUvAuthTokens and IVs.  (Credential
    ///   private keys come from [`PrivateKeyMaterial::generate`], which uses
    ///   the operating system's generator.)
    /// * `presence` is asked whenever an operation needs evidence of user
    ///   interaction.
    /// * `interrupt` is the flag through which the CTAPHID dispatcher cancels
    ///   the request being processed; it is what [`App::interrupt`] returns.
    ///
    /// [`PrivateKeyMaterial::generate`]: crate::store::PrivateKeyMaterial::generate
    pub fn new(
        store: impl CredentialStore + Send + 'static,
        rng: impl CryptoRngCore + Send + 'static,
        presence: impl UserPresence + Send + 'static,
        interrupt: &'interrupt InterruptFlag,
        aaguid: [u8; 16],
    ) -> Self {
        let mut rng = rng;
        let (pin_state, pin_state_writable) = storage::load_pin_state(&store, &mut rng);
        Self {
            store: Box::new(store),
            rng: Box::new(rng),
            presence: Box::new(presence),
            interrupt,
            aaguid,
            pin_state,
            pin_state_writable,
            suppress_attestation: false,
            cred_mgmt_state: CredentialManagementState::new(),
            pending_assertion: None,
            presence_timeout: DEFAULT_PRESENCE_TIMEOUT,
            reset_window: Some(RESET_WINDOW_AFTER_POWER_UP),
            keepalive: Box::new(|_| {}),
        }
    }

    /// The engine the daemon runs: `store`, randomness from the operating
    /// system, and `presence` for user presence.
    pub fn with_file_store(
        store: FileStore,
        presence: impl UserPresence + Send + 'static,
        interrupt: &'interrupt InterruptFlag,
        aaguid: [u8; 16],
    ) -> Self {
        Self::new(store, OsRng, presence, interrupt, aaguid)
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

    /// How long after power-up, the construction of this engine,
    /// authenticatorReset is accepted.  Defaults to
    /// [`RESET_WINDOW_AFTER_POWER_UP`], the 10 seconds CTAP 2.3 §6.6 requires
    /// of an authenticator without a display.
    ///
    /// `None` accepts a reset at any time, which does not conform to CTAP.  It
    /// exists for test rigs that reset a long-running authenticator before
    /// every test; user presence is still required.
    pub fn set_reset_window(&mut self, window: Option<Duration>) {
        self.reset_window = window;
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

    /// The log line for one CTAPHID_CBOR exchange: `request` is the command
    /// byte and its parameters, `response` the status byte and its CBOR.
    /// resp_bcnt counts the whole response, resp_payload_len only the CBOR
    /// after the status byte.
    fn request_log_line(request: &[u8], response: &[u8]) -> String {
        let ctap_cmd = request.first().copied().unwrap_or_default();
        let payload = request.get(1..).unwrap_or_default();
        let status = response.first().copied().unwrap_or(CTAP2_OK);
        let (sub_command, pin_protocol) =
            Self::subcommand_and_pin_protocol_for_logging(ctap_cmd, payload);
        format!(
            "CTAP2 cmd=0x{ctap_cmd:02x} status=0x{status:02x} sub={} pinProtocol={} req_bcnt={} resp_bcnt={} resp_payload_len={}",
            HexOption(sub_command),
            HexOption(pin_protocol),
            request.len(),
            response.len(),
            response.len().saturating_sub(1),
        )
    }

    /// The subcommand and pinUvAuthProtocol of a request, for the request
    /// log.  The two parameters sit under different keys per command:
    /// authenticatorClientPIN has pinUvAuthProtocol (0x01) and subCommand
    /// (0x02) (CTAP 2.3 §6.5.5), authenticatorCredentialManagement has
    /// subCommand (0x01) and pinUvAuthProtocol (0x03) (§6.8).  Other commands
    /// log neither.
    fn subcommand_and_pin_protocol_for_logging(
        ctap_cmd: u8,
        payload: &[u8],
    ) -> (Option<u8>, Option<u8>) {
        let (sub_command_key, pin_protocol_key) = match ctap_cmd {
            CTAP_CMD_CLIENT_PIN => (2, 1),
            CTAP_CMD_CREDENTIAL_MANAGEMENT => (1, 3),
            _ => return (None, None),
        };
        let Ok(Value::Map(entries)) = from_reader::<Value, _>(payload) else {
            return (None, None);
        };
        let byte_at = |key: i128| {
            entries
                .iter()
                .find_map(|(entry_key, value)| match (entry_key, value) {
                    (Value::Integer(entry_key), Value::Integer(value))
                        if i128::from(*entry_key) == key =>
                    {
                        u8::try_from(i128::from(*value)).ok()
                    }
                    _ => None,
                })
        };
        (byte_at(sub_command_key), byte_at(pin_protocol_key))
    }
}

impl<'a, 'interrupt: 'a, const N: usize> App<'a, N> for CtapApp<'interrupt> {
    fn interrupt(&self) -> Option<&'a InterruptFlag> {
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
                    // Neither authenticatorBioEnrollment (0x09) nor its
                    // prototype (0x40) is implemented: "If an authenticator
                    // receives a command code it does not implement, it MUST
                    // return CTAP1_ERR_INVALID_COMMAND." (CTAP 2.3 §8.1)
                    // getInfo accordingly has no bioEnroll or
                    // userVerificationMgmtPreview option (§6.4, §6.7.1).
                    _ => Err(CTAP1_ERR_INVALID_COMMAND),
                };

                let message = result.unwrap_or_else(|status| vec![status]);

                info!("{}", Self::request_log_line(request, &message));

                response.clear();
                response
                    .extend_from_slice(&message)
                    .map_err(|_| Error::InvalidLength)
            }
            _ => Err(Error::InvalidCommand),
        }
    }
}
