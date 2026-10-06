//! macOS state paths and explicit stubs for the running key.

use super::{ServiceAction, SetupSteps};
use crate::{
    cli::checks::Problem,
    client::ctaphid::{Report, ReportLink},
    presence::notification::{
        ConnectError, Notification, NotificationEvent, NotificationServer, ServerInfo, Unavailable,
    },
    transport::{CtapHidFrame, HidDevice, HidDeviceDescriptor},
};
use nix::unistd::Pid;
use pqkey_ctap::ctap::Clock;
use std::{
    io,
    os::fd::BorrowedFd,
    path::{Path, PathBuf},
    time::Duration,
};

mod state;
pub use state::default_state_dir;

const UNSUPPORTED: &str = "the key does not run on macOS yet";
fn unsupported() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, UNSUPPORTED)
}

/// Fail before a command reads secrets or changes state.
pub fn ensure_supported() -> io::Result<()> {
    Err(unsupported())
}

/// The virtual-device backend has not been implemented.
pub enum Device {}
impl Device {
    pub fn new(_descriptor: HidDeviceDescriptor) -> io::Result<Self> {
        Err(unsupported())
    }
}
impl HidDevice for Device {
    fn try_read_frame(&self) -> io::Result<Option<CtapHidFrame>> {
        Err(unsupported())
    }
    fn write_frame(&self, _frame: &CtapHidFrame) -> io::Result<()> {
        Err(unsupported())
    }
    fn wait_with(&self, _other: BorrowedFd<'_>, _timeout: Option<Duration>) -> io::Result<bool> {
        Err(unsupported())
    }
}

/// The client-device backend has not been implemented.
pub enum ClientLink {}
impl ReportLink for ClientLink {
    fn send(&mut self, _report: &Report) -> io::Result<()> {
        Err(unsupported())
    }
    fn receive(&mut self, _timeout: Duration) -> io::Result<Option<Report>> {
        Err(unsupported())
    }
}
pub fn open_client(_uniq: &str, _wait: Duration) -> io::Result<(String, ClientLink)> {
    Err(unsupported())
}

/// The per-user service backend has not been implemented.
pub struct UserService;
impl UserService {
    pub const DESCRIPTION: &str = "user service";
    pub const LOG_HINT: &str = UNSUPPORTED;
    pub fn installed() -> io::Result<bool> {
        Err(unsupported())
    }
    pub fn main_pid() -> io::Result<Option<Pid>> {
        Err(unsupported())
    }
    pub fn action(_action: ServiceAction) -> io::Result<()> {
        Err(unsupported())
    }
    pub fn install(_binary: &Path) -> io::Result<bool> {
        Err(unsupported())
    }
    pub fn remove() -> io::Result<Option<PathBuf>> {
        Err(unsupported())
    }
    pub(crate) fn manual_start_problem(_pid: Pid) -> io::Result<Problem> {
        Err(unsupported())
    }
}

/// System preparation has not been implemented.
pub struct System;
impl System {
    pub fn real() -> io::Result<Self> {
        Err(unsupported())
    }
    pub fn check_setup_caller(_state_dir: &Path) -> io::Result<()> {
        Err(unsupported())
    }
    pub fn refresh(&mut self) -> io::Result<()> {
        Err(unsupported())
    }
    pub fn setup_steps(&self) -> io::Result<Option<SetupSteps>> {
        Err(unsupported())
    }
    pub fn apply_setup_steps(&self, _steps: &SetupSteps) -> io::Result<()> {
        Err(unsupported())
    }
    pub fn login_problem(&self) -> io::Result<Option<Problem>> {
        Err(unsupported())
    }
    pub fn start_problems(&self) -> io::Result<Vec<Problem>> {
        Err(unsupported())
    }
    pub fn device_problems(&self, _pid: Pid, _wait: Duration) -> io::Result<Vec<Problem>> {
        Err(unsupported())
    }
    pub fn notification_problem(
        &self,
        _server: &Result<ServerInfo, ConnectError>,
    ) -> io::Result<Option<Problem>> {
        Err(unsupported())
    }
    pub fn uninstall_instructions(_binary: &Path, _state_dir: &Path) -> io::Result<Vec<String>> {
        Err(unsupported())
    }
}

/// No native prompt provider can be constructed yet.
pub enum Notifications {}
pub fn notifications() -> io::Result<Notifications> {
    Err(unsupported())
}
impl NotificationServer for Notifications {
    fn connect(&mut self) -> Result<ServerInfo, ConnectError> {
        Err(ConnectError::Failed(UNSUPPORTED.into()))
    }
    fn notify(&mut self, _notification: &Notification) -> Result<u32, String> {
        Err(UNSUPPORTED.into())
    }
    fn next_event(&mut self, _wait: Duration) -> Result<Option<NotificationEvent>, String> {
        Err(UNSUPPORTED.into())
    }
    fn close(&mut self, _id: u32) -> Result<(), String> {
        Err(UNSUPPORTED.into())
    }
    fn nudge(&mut self) -> Result<u32, String> {
        Err(UNSUPPORTED.into())
    }
    fn disconnect(&mut self) {
        match *self {}
    }
}

pub(crate) fn notification_failure(cause: &Unavailable, _summary: &str) -> String {
    match cause {
        Unavailable::Connect(error) => notification_connect_error(error),
        Unavailable::Failed(message) => message.clone(),
        Unavailable::NoActions | Unavailable::NoBody => UNSUPPORTED.into(),
    }
}
pub(crate) fn notification_connect_error(error: &ConnectError) -> String {
    match error {
        ConnectError::NoSession(message)
        | ConnectError::NoServer(message)
        | ConnectError::Failed(message) => message.clone(),
    }
}
pub(crate) fn warn_device_access() -> io::Result<()> {
    Err(unsupported())
}
pub(crate) fn disable_core_dumps() -> io::Result<()> {
    Err(unsupported())
}
pub(crate) fn current_executable_identity() -> io::Result<(u64, u64)> {
    Err(unsupported())
}

pub(crate) enum BootTimeClock {}
impl BootTimeClock {
    pub(crate) fn new() -> io::Result<Self> {
        Err(unsupported())
    }
}
impl Clock for BootTimeClock {
    fn now(&self) -> Duration {
        match *self {}
    }
}

pub(crate) const START_HELP: &str =
    "Plug the key in: start it, through its user service when that is installed";
pub(crate) const RUN_HELP: &str =
    "Run the key in the foreground until it is stopped (for the user service and test rigs)";
pub(crate) const PRESENCE_NOTIFY_HELP: &str = "Ask with a desktop prompt that has Approve and Deny buttons. If the prompt cannot be shown, every request is denied";

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) use crate::test_support::callback::{Device, Peer, pair};
}
