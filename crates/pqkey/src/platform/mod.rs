//! Operating-system adapters for the daemon and its commands.

pub mod linux;

use crate::transport::HidDeviceDescriptor;
use std::io;

pub use linux::{hidraw::Hidraw as ClientLink, uhid::UhidDevice as Device};

/// Create the selected platform's virtual device. Drop removes it.
pub fn create_device(descriptor: HidDeviceDescriptor) -> io::Result<Device> {
    Device::new(descriptor)
}

pub use linux::hidraw::open_client;

pub use linux::dbus::SessionBus as Notifications;
pub(crate) use linux::notification::{
    connect_error_message as notification_connect_error, failure_message as notification_failure,
};

/// An operation on the installed per-user service.
#[derive(Clone, Copy, Debug)]
pub enum ServiceAction {
    Start,
    Restart,
    Stop,
    Enable,
    ResetFailed,
}

/// Reviewable setup steps prepared by the backend; commands own confirmation.
pub struct SetupSteps {
    pub summary: Vec<String>,
    pub heading: &'static str,
    pub question: &'static str,
    pub instructions: Vec<String>,
    pub artifact: std::path::PathBuf,
}

pub(crate) use linux::daemon::{PRESENCE_NOTIFY_HELP, RUN_HELP, START_HELP, warn_device_access};
pub use linux::{checks::System, daemon::UserService};
