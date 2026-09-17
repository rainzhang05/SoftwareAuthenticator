//! The authenticatorReset command.

use super::credential_management::CredentialManagementState;
use super::presence::{PresenceOperation, PresenceRequest};
use super::storage::store_status;
use super::CtapApp;

use core::time::Duration;

use crate::ctap::constants::*;

/// "In case of authenticators with no display, request MUST have come to the
/// authenticator within 10 seconds of powering up of the authenticator."
/// (CTAP 2.3 §6.6)
pub const RESET_WINDOW_AFTER_POWER_UP: Duration = Duration::from_secs(10);

impl CtapApp<'_> {
    /// CTAP2 `authenticatorReset` (command 0x07), CTAP 2.3 §6.6.
    ///
    /// This authenticator has no display, so the request must arrive within
    /// [`RESET_WINDOW_AFTER_POWER_UP`] of power-up, which for this software
    /// authenticator is the construction of the [`CtapApp`] ("If the request
    /// comes after 10 seconds of powering up, the authenticator returns
    /// CTAP2_ERR_NOT_ALLOWED."), and "evidence of user interaction is
    /// required": "If user presence is explicitly denied, the authenticator
    /// returns CTAP2_ERR_OPERATION_DENIED. If a user action timeout occurs,
    /// the authenticator returns CTAP2_ERR_USER_ACTION_TIMEOUT."
    ///
    /// [`CredentialStore::clear`](crate::store::CredentialStore::clear)
    /// deletes every credential, writes the default PIN state and, for the
    /// file store, replaces the key protecting both.  If it fails, the
    /// in-memory PIN state is kept, so a PIN still guards whatever is left.
    pub(super) fn handle_reset(&mut self) -> Result<Vec<u8>, u8> {
        // The clock the engine's timers share starts at power-up.
        if let Some(window) = self.reset_window {
            if self.pin_state.now() > window {
                return Err(CTAP2_ERR_NOT_ALLOWED);
            }
        }
        let timeout = self.presence_timeout;
        self.confirm_user_presence(PresenceRequest::new(PresenceOperation::Reset, timeout))?;
        self.cred_mgmt_state = CredentialManagementState::new();
        self.store
            .clear()
            .map_err(|err| store_status("reset the credential store", err))?;
        // The PIN, pinRetries, the pinUvAuthToken and each protocol's key
        // agreement key go back to their initial values, as at power-up
        // (CTAP 2.3 §6.5.5.1).  The store already holds the default PIN state.
        self.pin_state.reset();
        self.pin_state_writable = true;
        Ok(vec![CTAP2_OK])
    }
}
