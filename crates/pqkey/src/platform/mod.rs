//! Operating-system adapters for the daemon and its commands.

pub mod linux;

use crate::transport::HidDeviceDescriptor;
use std::io;

pub use linux::{hidraw::Hidraw as ClientLink, uhid::UhidDevice as Device};

/// Create the selected platform's virtual device. Drop removes it.
pub fn create_device(descriptor: HidDeviceDescriptor) -> io::Result<Device> {
    Device::new(descriptor)
}

pub(crate) use linux::hidraw::device_problems;
pub use linux::hidraw::open_client;
