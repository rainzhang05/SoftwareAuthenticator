//! PIN/UV authentication: the PIN retry state, the PIN/UV auth protocols,
//! pinUvAuthToken permissions and the authenticatorClientPIN command.

mod client_pin;
pub(super) mod permissions;
pub(super) mod protocol;
pub(super) mod state;
