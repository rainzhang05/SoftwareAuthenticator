//! Unit tests for `ctap`, one module per area of the handler code.

// The presence tests reach these through `super::`, as they did when every test
// lived directly in `ctap::tests`.
use super::presence::{take_waiting_log, USER_PRESENCE_MAX_WAIT_MS, USER_PRESENCE_POLL_TIMEOUT_MS};

mod credential_management;
mod get_assertion;
mod get_info;
mod make_credential;
mod pin;
mod presence;
mod support;
