//! The Linux operating-system boundary.
//!
//! Devices and client links exchange reports; services and system preparation
//! expose semantic operations and diagnostics. Presence policy uses a
//! normalized notification server. Runtime helpers select state paths,
//! process protections, executable identity and the suspend-aware clock.

mod linux;

use crate::transport::HidDeviceDescriptor;
use std::io;

#[cfg(test)]
pub(crate) use linux::test_support;
pub(crate) use linux::{
    BootTimeClock, PRESENCE_NOTIFY_HELP, RUN_HELP, START_HELP, current_executable_identity,
    disable_core_dumps, notification_connect_error, notification_failure, warn_device_access,
};
pub use linux::{
    ClientLink, Device, Notifications, System, UserService, default_state_dir, notifications,
    open_client,
};

/// Create the Linux virtual device. Drop removes it.
pub fn create_device(descriptor: HidDeviceDescriptor) -> io::Result<Device> {
    Device::new(descriptor)
}

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
