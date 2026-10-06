pub(crate) mod checks;
pub(crate) mod clock;
pub(crate) mod daemon;
pub mod dbus;
pub mod hidraw;
pub mod notification;
pub mod permissions;
pub(crate) mod runtime;
pub(crate) mod setup;
pub mod state;
pub mod uhid;

pub use self::{
    checks::System,
    daemon::UserService,
    dbus::SessionBus as Notifications,
    hidraw::{Hidraw as ClientLink, open_client},
    state::default_state_dir,
    uhid::UhidDevice as Device,
};
pub(crate) use self::{
    clock::BootTimeClock,
    daemon::{PRESENCE_NOTIFY_HELP, RUN_HELP, START_HELP},
    notification::{
        connect_error_message as notification_connect_error,
        failure_message as notification_failure,
    },
    runtime::{current_executable_identity, disable_core_dumps},
};
use std::io;

/// Linux implements the running key.
pub fn ensure_supported() -> io::Result<()> {
    Ok(())
}
/// Prepare the desktop notification backend; connection is per request.
pub fn notifications() -> io::Result<Notifications> {
    Ok(Notifications::new())
}
pub(crate) fn warn_device_access() -> io::Result<()> {
    daemon::warn_device_access();
    Ok(())
}
#[cfg(test)]
pub(crate) mod test_support;
