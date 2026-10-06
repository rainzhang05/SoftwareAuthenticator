//! The operating-system boundary. Only the selected backend is compiled.
//!
//! Devices and client links exchange reports; services and system preparation
//! expose semantic operations and diagnostics. Presence policy uses a
//! normalized notification server. Runtime helpers select state paths,
//! process protections, executable identity and the suspend-aware clock.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
use linux as native;
#[cfg(target_os = "macos")]
use macos as native;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("pqkey supports Linux and macOS builds");

use crate::transport::HidDeviceDescriptor;
use std::io;

#[cfg(test)]
pub(crate) use native::test_support;
pub(crate) use native::{
    BootTimeClock, PRESENCE_NOTIFY_HELP, RUN_HELP, START_HELP, current_executable_identity,
    disable_core_dumps, notification_connect_error, notification_failure, warn_device_access,
};
pub use native::{
    ClientLink, Device, Notifications, System, UserService, default_state_dir, ensure_supported,
    notifications, open_client,
};

/// Create the selected platform's virtual device. Drop removes it.
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
