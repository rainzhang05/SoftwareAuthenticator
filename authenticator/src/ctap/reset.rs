//! The authenticatorReset command.

use super::credential_management::CredentialManagementState;
use super::presence::{PresenceOperation, PresenceRequest};
use super::storage::store_status;
use super::CtapApp;

use crate::ctap::constants::*;

impl CtapApp<'_> {
    /// CTAP2 `authenticatorReset` (command 0x07).  Wipes credentials and
    /// PIN state after collecting user presence.  The standard 10-second
    /// "since power-up" window from the FIDO spec is intentionally not
    /// enforced; a software authenticator on a multi-user desktop already
    /// requires explicit user consent via the presence prompt.
    ///
    /// [`CredentialStore::clear`](crate::store::CredentialStore::clear)
    /// deletes every credential, writes the default PIN state and, for the
    /// file store, replaces the key protecting both.  If it fails, the
    /// in-memory PIN state is kept, so a PIN still guards whatever is left.
    pub(super) fn handle_reset(&mut self) -> Result<Vec<u8>, u8> {
        let timeout = self.presence_timeout;
        self.confirm_user_presence(PresenceRequest::new(PresenceOperation::Reset, timeout))?;
        self.cred_mgmt_state = CredentialManagementState::new();
        self.pending_assertion = None;
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
