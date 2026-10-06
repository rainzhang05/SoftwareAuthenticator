//! Reports and the virtual HID device boundary.

use std::{io, os::fd::BorrowedFd, time::Duration};

pub const CTAPHID_FRAME_LEN: usize = 64;

/// The FIDO HID report descriptor shared by platform backends.
pub const CTAPHID_REPORT_DESCRIPTOR: [u8; 34] = [
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (U2F HID Authenticator)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8 bits)
    0x95, 0x40, //   Report Count (64 bytes)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8 bits)
    0x95, 0x40, //   Report Count (64 bytes)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0xC0, // End Collection
];
/// The USB vendor ID the virtual key reports unless `--vendor-id` says
/// otherwise: 0x1209, the vendor ID pid.codes shares out to open source
/// projects.
pub const DEFAULT_VENDOR_ID: u32 = 0x1209;

/// The USB product ID the virtual key reports unless `--product-id` says
/// otherwise: 0x0001, the first of pid.codes' test product IDs (0x0001 to
/// 0x0010 under vendor 0x1209). pid.codes reserves them for private testing,
/// and they are not unique to this project, a test project that is not
/// released and so keeps one of them.
pub const DEFAULT_PRODUCT_ID: u32 = 0x0001;

#[derive(Debug, Clone)]
pub struct HidDeviceDescriptor {
    pub name: String,
    pub vendor_id: u32,
    pub product_id: u32,
    pub version: u32,
    pub country: u32,
    /// The unique identifier used to find this daemon's device.
    pub uniq: String,
}

impl Default for HidDeviceDescriptor {
    fn default() -> Self {
        Self {
            name: "Virtual FIDO Authenticator".to_string(),
            vendor_id: DEFAULT_VENDOR_ID,
            product_id: DEFAULT_PRODUCT_ID,
            version: 0x0001,
            country: 0,
            uniq: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtapHidFrame(pub [u8; CTAPHID_FRAME_LEN]);

impl CtapHidFrame {
    pub fn new(data: [u8; CTAPHID_FRAME_LEN]) -> Self {
        Self(data)
    }

    pub fn as_bytes(&self) -> &[u8; CTAPHID_FRAME_LEN] {
        &self.0
    }
}

/// A virtual HID device, polled by the CTAPHID transport.
///
/// Output reports are received from the host; input reports are sent to it.
/// A callback backend can queue reports and signal a private pipe. The device
/// need not expose a file descriptor, implement `AsFd`, or move to the worker.
pub trait HidDevice {
    /// Take the next complete output report without waiting. `None` means
    /// the queue is empty. Invalid native events are handled by the backend.
    fn try_read_frame(&self) -> io::Result<Option<CtapHidFrame>>;
    /// Send one complete input report to the host.
    fn write_frame(&self, frame: &CtapHidFrame) -> io::Result<()>;
    /// Wait for a queued report, the worker's `other` descriptor, or the
    /// timeout. `None` waits indefinitely. Signals may end the wait early.
    /// Enqueuing a report must wake a concurrent wait; pending reports must
    /// prevent sleep, even when wake bytes have already been drained.
    fn wait_with(&self, other: BorrowedFd<'_>, timeout: Option<Duration>) -> io::Result<bool>;
}
