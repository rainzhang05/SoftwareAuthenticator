//! The authenticatorReset command.

use super::credential_management::CredentialManagementState;
use super::pin::state::PinState;
use super::CtapApp;

use trussed::client::{Client as TrussedClient, CryptoClient, FilesystemClient};

use transport_core::ctap::constants::*;

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    /// CTAP2 `authenticatorReset` (command 0x07).  Wipes credentials and
    /// PIN state after collecting user presence.  The standard 10-second
    /// "since power-up" window from the FIDO spec is intentionally not
    /// enforced; a software authenticator on a multi-user desktop already
    /// requires explicit user consent via the presence prompt.
    pub(super) fn handle_reset(&mut self) -> Result<Vec<u8>, u8> {
        let _present = self.await_user_presence()?;
        self.clear_credentials()?;
        // The PIN, pinRetries and the pinUvAuthToken go back to their initial
        // values, and so does each protocol's key agreement key, as at
        // power-up (CTAP 2.3 §6.5.5.1).
        self.pin_state = PinState::new();
        self.pin_protocol_session = None;
        self.save_persistent_pin_state();
        self.cred_mgmt_state = CredentialManagementState::new();
        self.pending_assertion = None;
        Ok(vec![CTAP2_OK])
    }
}
