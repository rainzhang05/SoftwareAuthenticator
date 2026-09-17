//! The authenticatorSelection command.

use super::CtapApp;
use super::presence::{PresenceOperation, PresenceRequest};

use crate::ctap::constants::*;

impl CtapApp<'_> {
    /// CTAP2 `authenticatorSelection` (command 0x0B), CTAP 2.3 §6.9: "This
    /// command allows the platform to let a user select a certain
    /// authenticator by asking for user presence. The command has no input
    /// parameters."  Any parameters are ignored.
    ///
    /// "If User Presence is received, the authenticator will return CTAP2_OK.
    /// If User Presence is explicitly denied by the user, the authenticator
    /// will return CTAP2_ERR_OPERATION_DENIED. [...] If a user action timeout
    /// occurs, the authenticator will return CTAP2_ERR_USER_ACTION_TIMEOUT."
    /// A request the platform cancels, as it does on every other
    /// authenticator once one is selected, ends with
    /// CTAP2_ERR_KEEPALIVE_CANCEL.
    pub(super) fn handle_selection(&mut self) -> Result<Vec<u8>, u8> {
        let timeout = self.presence_timeout;
        self.confirm_user_presence(PresenceRequest::new(PresenceOperation::Select, timeout))?;
        Ok(vec![CTAP2_OK])
    }
}
