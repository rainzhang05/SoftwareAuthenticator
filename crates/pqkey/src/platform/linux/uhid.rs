//! The Linux kernel's virtual HID device.
//!
//! Pause between input reports of a multi-packet message.
//!
//! A USB full-speed HID interrupt endpoint delivers at most one report per
//! millisecond, and FIDO clients read at that pace. uhid has no such flow
//! control: each input report goes straight into every hidraw reader's buffer,
//! which holds only 64 reports (`HIDRAW_BUFFER_SIZE`), so a longer burst drops
//! packets. An ML-DSA-87 assertion is 82 packets. Pacing like real hardware
//! keeps even the largest CTAPHID message (129 packets) intact, at a cost of
//! at most about 130 ms.
//! The transport also reads during those pauses: uhid holds only 32 output
//! events, and drops what does not fit.

use crate::transport::{
    CTAPHID_FRAME_LEN, CTAPHID_REPORT_DESCRIPTOR, CtapHidFrame, HidDevice, HidDeviceDescriptor,
};
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll, ppoll};
use nix::sys::time::TimeSpec;
use nix::unistd::{read, write};
use std::cell::Cell;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const DEVICE_PATH: &str = "/dev/uhid";

/// Let each observed event settle before reading it. In drivers/hid/uhid.c,
/// uhid_queue stores `outq[head]` and then head under its queue lock, but
/// uhid_char_poll and uhid_char_read inspect head without that lock. A reader
/// can see head before the event pointer and copy from NULL. Waiting after
/// readiness, once per event, gives the pointer time to become visible on
/// every architecture. This avoids the race but cannot rule it out.
const READ_SETTLING_TIME: Duration = Duration::from_micros(100);

pub(crate) use raw::{UHID_EVENT_SIZE, UHID_EVENT_TYPE_DESTROY};

const BUS_USB: u16 = 0x03;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportType {
    Feature,
    Output,
    Input,
}

impl ReportType {
    fn from_raw(raw: u8) -> Option<Self> {
        match raw {
            raw::UHID_REPORT_TYPE_FEATURE => Some(Self::Feature),
            raw::UHID_REPORT_TYPE_OUTPUT => Some(Self::Output),
            raw::UHID_REPORT_TYPE_INPUT => Some(Self::Input),
            _ => None,
        }
    }
}

fn frame_from_report_slice(slice: &[u8]) -> Option<CtapHidFrame> {
    match slice.len() {
        CTAPHID_FRAME_LEN => {
            let mut data = [0u8; CTAPHID_FRAME_LEN];
            data.copy_from_slice(&slice[..CTAPHID_FRAME_LEN]);
            Some(CtapHidFrame::new(data))
        }
        len if len == CTAPHID_FRAME_LEN + 1 && slice.first().copied() == Some(0) => {
            let mut data = [0u8; CTAPHID_FRAME_LEN];
            data.copy_from_slice(&slice[1..1 + CTAPHID_FRAME_LEN]);
            Some(CtapHidFrame::new(data))
        }
        _ => None,
    }
}

/// The first `size` bytes of the data of an output or set_report event, or
/// `None` when the size the event gives is larger than its data array. The
/// kernel never sends such an event, but the size is not trusted to index with.
fn report_data(data: &[u8; raw::UHID_DATA_MAX], size: u16) -> Option<&[u8]> {
    data.get(..usize::from(size))
}

/// A virtual HID device created through `/dev/uhid`. Dropping it destroys the
/// device.
pub struct UhidDevice {
    inner: UhidInner,
    descriptor: HidDeviceDescriptor,
    /// Set by a UHID_OPEN event, which the kernel sends once something
    /// opens the device. By then udev has long applied its rules to the
    /// hidraw node, so the device then checks the node's mode, once.
    opened: AtomicBool,
    /// Whether that check has run.
    node_checked: AtomicBool,
}

impl UhidDevice {
    pub fn new(descriptor: HidDeviceDescriptor) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(DEVICE_PATH)?;
        let fd = file.as_fd();

        let create2 = descriptor_to_create2(&descriptor)?;
        let mut create_event = raw::uhid_event::new(raw::UHID_EVENT_TYPE_CREATE2);
        create_event.u.create2 = create2;
        write_event_blocking(fd, &mut create_event)?;

        let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(to_io_error)?;
        let mut oflags = OFlag::from_bits_truncate(flags);
        oflags.insert(OFlag::O_NONBLOCK);
        fcntl(fd, FcntlArg::F_SETFL(oflags)).map_err(to_io_error)?;

        Ok(Self {
            inner: UhidInner {
                fd: OwnedFd::from(file),
                readable_since: Cell::new(None),
            },
            descriptor,
            opened: AtomicBool::new(false),
            node_checked: AtomicBool::new(false),
        })
    }

    /// Wrap an already open descriptor that stands in for `/dev/uhid`.
    #[cfg(test)]
    pub(crate) fn from_fd(fd: OwnedFd, descriptor: HidDeviceDescriptor) -> Self {
        Self {
            inner: UhidInner {
                fd,
                readable_since: Cell::new(None),
            },
            descriptor,
            opened: AtomicBool::new(false),
            node_checked: AtomicBool::new(false),
        }
    }

    /// Whether a client opened the device since the last call: by then udev
    /// has long applied its rules to the hidraw node, so its mode is final.
    #[cfg(test)]
    pub fn take_opened(&self) -> bool {
        self.opened.swap(false, Ordering::Relaxed)
    }

    /// Wait for queued fake events to settle, returning the first frame or
    /// `None` once the queue is empty, including after non-frame events.
    #[cfg(test)]
    pub(crate) fn read_settled_frame(&self) -> io::Result<Option<CtapHidFrame>> {
        let (wake, _worker) = std::os::unix::net::UnixStream::pair()?;
        loop {
            if let Some(frame) = self.try_read_frame()? {
                return Ok(Some(frame));
            }
            if self.inner.readable_since.get().is_none() {
                return Ok(None);
            }
            self.wait_with(wake.as_fd(), None)?;
        }
    }
}

impl HidDevice for UhidDevice {
    fn try_read_frame(&self) -> io::Result<Option<CtapHidFrame>> {
        loop {
            match self.inner.try_read_event()? {
                None => {
                    if !self.node_checked.load(Ordering::Relaxed)
                        && self.opened.load(Ordering::Relaxed)
                    {
                        self.node_checked.store(true, Ordering::Relaxed);
                        if let Ok(nodes) =
                            super::permissions::hidraw_nodes_for_descriptor(&self.descriptor)
                        {
                            super::permissions::warn_if_world_accessible(&nodes);
                        }
                    }
                    return Ok(None);
                }
                Some(event) => match event.type_ {
                    raw::UHID_EVENT_TYPE_OUTPUT => {
                        // SAFETY: every union member is plain integers, valid
                        // for any bytes; the type says which one is meant.
                        let output = unsafe { event.u.output };
                        let (size, rtype) = (output.size, output.rtype);
                        // The descriptor declares output reports only.
                        if ReportType::from_raw(rtype) != Some(ReportType::Output) {
                            continue;
                        }
                        let Some(report) = report_data(&output.data, size) else {
                            log::debug!("ignoring an output event with a malformed size of {size}");
                            continue;
                        };
                        if let Some(frame) = frame_from_report_slice(report) {
                            return Ok(Some(frame));
                        }
                    }
                    raw::UHID_EVENT_TYPE_SET_REPORT => {
                        // SAFETY: as for the output event above.
                        let set_report = unsafe { event.u.set_report };
                        let (size, id, rtype) = (set_report.size, set_report.id, set_report.rtype);
                        let report = report_data(&set_report.data, size);
                        if report.is_none() {
                            log::debug!(
                                "rejecting a set_report event with a malformed size of {size}"
                            );
                        }
                        // The kernel holds the writer until a reply comes or
                        // its timeout runs out, so a malformed request, or
                        // one for a feature report the descriptor does not
                        // declare, is answered with an error rather than
                        // ignored.
                        let report = report
                            .filter(|_| ReportType::from_raw(rtype) == Some(ReportType::Output));
                        let status = if report.is_some() {
                            0
                        } else {
                            Errno::EINVAL as u16
                        };
                        self.inner.send_set_report_reply(id, status)?;
                        if let Some(frame) = report.and_then(frame_from_report_slice) {
                            return Ok(Some(frame));
                        }
                    }
                    raw::UHID_EVENT_TYPE_GET_REPORT => {
                        // SAFETY: as for the output event above.
                        let get_report = unsafe { event.u.get_report };
                        // No feature report is declared, and input reports
                        // are only sent, never fetched: refuse every request,
                        // which the kernel reports as EIO, as a USB key
                        // stalls on a request it does not support.
                        let id = get_report.id;
                        self.inner
                            .send_get_report_reply(id, Errno::EINVAL as u16, &[])?;
                    }
                    raw::UHID_EVENT_TYPE_OPEN => self.opened.store(true, Ordering::Relaxed),
                    raw::UHID_EVENT_TYPE_START
                    | raw::UHID_EVENT_TYPE_STOP
                    | raw::UHID_EVENT_TYPE_CLOSE => {}
                    _ => {}
                },
            }
        }
    }

    fn write_frame(&self, frame: &CtapHidFrame) -> io::Result<()> {
        self.inner.send_input_report(frame.as_bytes())
    }

    /// Wait until an event can be read, `other` is readable, or `timeout`
    /// passes. While an observed event settles, wait only for `other`, for
    /// at most the remaining settling time, even with no timeout.
    fn wait_with(&self, other: BorrowedFd<'_>, timeout: Option<Duration>) -> io::Result<bool> {
        self.inner.wait(timeout, other)
    }
}

struct UhidInner {
    fd: OwnedFd,
    /// One readiness observation permits one read after it has settled.
    readable_since: Cell<Option<Instant>>,
}

impl UhidInner {
    fn try_read_event(&self) -> io::Result<Option<raw::uhid_event>> {
        let Some(since) = self.readable_since.get() else {
            let mut fds = [PollFd::new(self.fd.as_fd(), PollFlags::POLLIN)];
            match poll(&mut fds, PollTimeout::ZERO) {
                Ok(ready) if ready > 0 => self.readable_since.set(Some(Instant::now())),
                Ok(_) | Err(Errno::EINTR) => {}
                Err(err) => return Err(to_io_error(err)),
            }
            return Ok(None);
        };
        if since.elapsed() < READ_SETTLING_TIME {
            return Ok(None);
        }
        self.readable_since.set(None);
        match read_event_nonblocking(self.fd.as_fd()) {
            Ok(event) => Ok(Some(event)),
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn wait(&self, timeout: Option<Duration>, other: BorrowedFd<'_>) -> io::Result<bool> {
        let mut fds = [
            PollFd::new(self.fd.as_fd(), PollFlags::POLLIN),
            PollFd::new(other, PollFlags::POLLIN),
        ];
        let settling = self
            .readable_since
            .get()
            .map(|since| READ_SETTLING_TIME.saturating_sub(since.elapsed()));
        if settling == Some(Duration::ZERO) {
            return Ok(true);
        }
        let (fds, timeout) = match settling {
            Some(remaining) => {
                // The device stays readable while the event settles. Polling
                // it would wake immediately instead of waiting for the read.
                (
                    &mut fds[1..],
                    Some(timeout.map_or(remaining, |d| d.min(remaining))),
                )
            }
            None => (&mut fds[..], timeout),
        };
        // ppoll keeps the sub-millisecond settling timeout. Preserve the
        // old poll timeout's cap for waits too long to represent.
        let timeout =
            timeout.map(|d| TimeSpec::from(d.min(Duration::from_millis(i32::MAX as u64))));
        match ppoll(fds, timeout, None) {
            Ok(ready) => Ok(ready > 0
                || self
                    .readable_since
                    .get()
                    .is_some_and(|since| since.elapsed() >= READ_SETTLING_TIME)),
            // Interrupted by a signal: return, so the caller can look at why.
            Err(Errno::EINTR) => Ok(false),
            Err(err) => Err(to_io_error(err)),
        }
    }

    fn send_input_report(&self, data: &[u8; CTAPHID_FRAME_LEN]) -> io::Result<()> {
        let mut event = raw::uhid_event::new(raw::UHID_EVENT_TYPE_INPUT2);
        // SAFETY: every union member is plain integers, valid for any bytes,
        // and the event was created for this member.
        let input = unsafe { &mut event.u.input2 };
        input.size = CTAPHID_FRAME_LEN as u16;
        input.data[..CTAPHID_FRAME_LEN].copy_from_slice(data);
        write_event_blocking(self.fd.as_fd(), &mut event)
    }

    fn send_get_report_reply(&self, id: u32, err: u16, data: &[u8]) -> io::Result<()> {
        if data.len() > raw::UHID_DATA_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "feature report too large",
            ));
        }
        let mut event = raw::uhid_event::new(raw::UHID_EVENT_TYPE_GET_REPORT_REPLY);
        // SAFETY: as for the input report above.
        let reply = unsafe { &mut event.u.get_report_reply };
        reply.id = id;
        reply.err = err;
        reply.size = data.len() as u16;
        reply.data[..data.len()].copy_from_slice(data);
        write_event_blocking(self.fd.as_fd(), &mut event)
    }

    fn send_set_report_reply(&self, id: u32, err: u16) -> io::Result<()> {
        let mut event = raw::uhid_event::new(raw::UHID_EVENT_TYPE_SET_REPORT_REPLY);
        // SAFETY: as for the input report above.
        let reply = unsafe { &mut event.u.set_report_reply };
        reply.id = id;
        reply.err = err;
        write_event_blocking(self.fd.as_fd(), &mut event)
    }
}

impl Drop for UhidInner {
    fn drop(&mut self) {
        // Closing the descriptor would destroy the device as well; saying so
        // explicitly removes it before anything else is torn down.
        let mut event = raw::uhid_event::new(UHID_EVENT_TYPE_DESTROY);
        let _ = write_event_blocking(self.fd.as_fd(), &mut event);
    }
}

fn descriptor_to_create2(descriptor: &HidDeviceDescriptor) -> io::Result<raw::uhid_create2_req> {
    if CTAPHID_REPORT_DESCRIPTOR.len() > raw::HID_MAX_DESCRIPTOR_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "report descriptor too large",
        ));
    }

    let mut req = raw::uhid_create2_req::default();
    copy_str_to_array(&descriptor.name, &mut req.name);
    copy_str_to_array(&descriptor.uniq, &mut req.uniq);
    req.rd_size = CTAPHID_REPORT_DESCRIPTOR.len() as u16;

    log::debug!(
        "create2 rd_size={} (expected={})",
        { req.rd_size },
        CTAPHID_REPORT_DESCRIPTOR.len() as u16
    );
    req.bus = BUS_USB;
    req.vendor = descriptor.vendor_id;
    req.product = descriptor.product_id;
    req.version = descriptor.version;
    req.country = descriptor.country;
    req.rd_data[..CTAPHID_REPORT_DESCRIPTOR.len()].copy_from_slice(&CTAPHID_REPORT_DESCRIPTOR);
    Ok(req)
}

fn copy_str_to_array(value: &str, dest: &mut [u8]) {
    let mut bytes = value.as_bytes();
    if bytes.len() >= dest.len() {
        bytes = &bytes[..dest.len() - 1];
    }
    dest[..bytes.len()].copy_from_slice(bytes);
    dest[bytes.len()] = 0;
}

fn write_event_blocking(fd: BorrowedFd<'_>, event: &mut raw::uhid_event) -> io::Result<()> {
    loop {
        match write(fd, event_as_bytes(event)) {
            Ok(n) if n == UHID_EVENT_SIZE => return Ok(()),
            Ok(_) => return Err(io::Error::other("short write")),
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN) => {
                thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(err) => return Err(to_io_error(err)),
        }
    }
}

fn read_event_nonblocking(fd: BorrowedFd<'_>) -> io::Result<raw::uhid_event> {
    let mut buffer = [0u8; UHID_EVENT_SIZE];
    let mut offset = 0;
    while offset < buffer.len() {
        match read(fd, &mut buffer[offset..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof")),
            Ok(n) => offset += n,
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN) => return Err(io::ErrorKind::WouldBlock.into()),
            Err(err) => return Err(to_io_error(err)),
        }
    }
    Ok(raw::event_from_bytes(&buffer))
}

fn event_as_bytes(event: &raw::uhid_event) -> &[u8] {
    // SAFETY: `uhid_event` is `repr(C, packed)` plain integers with no
    // padding, and every event is built by `uhid_event::new` or
    // `event_from_bytes`, which initialize all of it, so the UHID_EVENT_SIZE
    // bytes behind `event` are initialized. The slice borrows `event`.
    unsafe {
        std::slice::from_raw_parts(
            (event as *const raw::uhid_event) as *const u8,
            UHID_EVENT_SIZE,
        )
    }
}

/// The event the kernel sends when a host writes `frame` to the hidraw node.
#[cfg(test)]
pub(crate) fn output_event(frame: &[u8; CTAPHID_FRAME_LEN]) -> Vec<u8> {
    output_event_with_size(frame, CTAPHID_FRAME_LEN as u16)
}

/// An output event carrying `data`, with `size` taken as given.
#[cfg(test)]
fn output_event_with_size(data: &[u8], size: u16) -> Vec<u8> {
    let mut event = raw::uhid_event::new(raw::UHID_EVENT_TYPE_OUTPUT);
    // SAFETY: as in `UhidInner::send_input_report`.
    let output = unsafe { &mut event.u.output };
    output.data[..data.len()].copy_from_slice(data);
    output.size = size;
    output.rtype = raw::UHID_REPORT_TYPE_OUTPUT;
    event_as_bytes(&event).to_vec()
}

/// A set_report event as the kernel sends it, with `size` taken as given.
#[cfg(test)]
fn set_report_event(id: u32, rtype: u8, data: &[u8], size: u16) -> Vec<u8> {
    let mut event = raw::uhid_event::new(raw::UHID_EVENT_TYPE_SET_REPORT);
    // SAFETY: as in `UhidInner::send_input_report`.
    let set_report = unsafe { &mut event.u.set_report };
    set_report.id = id;
    set_report.rtype = rtype;
    set_report.data[..data.len()].copy_from_slice(data);
    set_report.size = size;
    event_as_bytes(&event).to_vec()
}

/// The report in an input event written by [`UhidDevice::write_frame`], or
/// `None` for any other event.
#[cfg(test)]
pub(crate) fn input_report(event: &[u8]) -> Option<[u8; CTAPHID_FRAME_LEN]> {
    let event = raw::event_from_bytes(event.try_into().ok()?);
    if event.type_ != raw::UHID_EVENT_TYPE_INPUT2 {
        return None;
    }
    // SAFETY: every union member is plain integers, valid for any bytes.
    let input = unsafe { event.u.input2 };
    if input.size as usize != CTAPHID_FRAME_LEN {
        return None;
    }
    input.data[..CTAPHID_FRAME_LEN].try_into().ok()
}

fn to_io_error(err: nix::Error) -> io::Error {
    io::Error::from(err)
}

mod raw {
    pub const UHID_DATA_MAX: usize = 4096;
    pub const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;

    pub const UHID_EVENT_TYPE_DESTROY: u32 = 1;
    pub const UHID_EVENT_TYPE_START: u32 = 2;
    pub const UHID_EVENT_TYPE_STOP: u32 = 3;
    pub const UHID_EVENT_TYPE_OPEN: u32 = 4;
    pub const UHID_EVENT_TYPE_CLOSE: u32 = 5;
    pub const UHID_EVENT_TYPE_OUTPUT: u32 = 6;
    pub const UHID_EVENT_TYPE_GET_REPORT: u32 = 9;
    pub const UHID_EVENT_TYPE_GET_REPORT_REPLY: u32 = 10;
    pub const UHID_EVENT_TYPE_CREATE2: u32 = 11;
    pub const UHID_EVENT_TYPE_INPUT2: u32 = 12;
    pub const UHID_EVENT_TYPE_SET_REPORT: u32 = 13;
    pub const UHID_EVENT_TYPE_SET_REPORT_REPLY: u32 = 14;

    pub const UHID_REPORT_TYPE_FEATURE: u8 = 0;
    pub const UHID_REPORT_TYPE_OUTPUT: u8 = 1;
    pub const UHID_REPORT_TYPE_INPUT: u8 = 2;

    pub const UHID_EVENT_SIZE: usize = size_of::<uhid_event>();

    /// `Default` as all-zero bytes, for the kernel structures below: arrays
    /// longer than 32 elements have no `Default` to derive one from.
    macro_rules! zeroed_default {
        ($($name:ident),+ $(,)?) => {$(
            impl Default for $name {
                fn default() -> Self {
                    // SAFETY: the type is made of integers and integer
                    // arrays only, for which all-zero bytes are a valid value.
                    unsafe { core::mem::zeroed() }
                }
            }
        )+};
    }

    zeroed_default!(
        uhid_create2_req,
        uhid_input2_req,
        uhid_output_req,
        uhid_get_report_req,
        uhid_get_report_reply_req,
        uhid_set_report_req,
        uhid_set_report_reply_req,
        uhid_start_req,
        uhid_event_union,
    );

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_create2_req {
        pub name: [u8; 128],
        pub phys: [u8; 64],
        pub uniq: [u8; 64],
        pub rd_size: u16,
        pub bus: u16,
        pub vendor: u32,
        pub product: u32,
        pub version: u32,
        pub country: u32,
        pub rd_data: [u8; HID_MAX_DESCRIPTOR_SIZE],
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_input2_req {
        pub size: u16,
        pub data: [u8; UHID_DATA_MAX],
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_output_req {
        pub data: [u8; UHID_DATA_MAX],
        pub size: u16,
        pub rtype: u8,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_get_report_req {
        pub id: u32,
        pub rnum: u8,
        pub rtype: u8,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_get_report_reply_req {
        pub id: u32,
        pub err: u16,
        pub size: u16,
        pub data: [u8; UHID_DATA_MAX],
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_set_report_req {
        pub id: u32,
        pub rnum: u8,
        pub rtype: u8,
        pub size: u16,
        pub data: [u8; UHID_DATA_MAX],
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_set_report_reply_req {
        pub id: u32,
        pub err: u16,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_start_req {
        pub dev_flags: u64,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub union uhid_event_union {
        pub create2: uhid_create2_req,
        pub input2: uhid_input2_req,
        pub output: uhid_output_req,
        pub get_report: uhid_get_report_req,
        pub get_report_reply: uhid_get_report_reply_req,
        pub set_report: uhid_set_report_req,
        pub set_report_reply: uhid_set_report_reply_req,
        pub start: uhid_start_req,
    }

    #[repr(C, packed)]
    #[derive(Clone, Copy)]
    pub struct uhid_event {
        pub type_: u32,
        pub u: uhid_event_union,
    }

    // The layout of include/uapi/linux/uhid.h, checked at compile time.
    //
    // On 64-bit systems the kernel's `struct uhid_event` is 4380 bytes: its
    // union is padded to the 8-byte alignment of `struct uhid_start_req`, the
    // one member that is not packed. Every member here is packed, so the event
    // is 4376 bytes, as on 32-bit x86. Nothing lives in the padding, and the
    // kernel takes the shorter event as it is: a read returns min(count, size)
    // bytes of an event, and a write zero-fills whatever it is not given.
    const _: () = {
        use core::mem::offset_of;
        assert!(size_of::<uhid_event>() == 4376);
        assert!(offset_of!(uhid_event, u) == 4);
        assert!(size_of::<uhid_create2_req>() == 4372);
        assert!(offset_of!(uhid_create2_req, rd_size) == 256);
        assert!(offset_of!(uhid_create2_req, vendor) == 260);
        assert!(offset_of!(uhid_create2_req, rd_data) == 276);
        assert!(offset_of!(uhid_input2_req, data) == 2);
        assert!(offset_of!(uhid_output_req, size) == 4096);
        assert!(offset_of!(uhid_output_req, rtype) == 4098);
        assert!(offset_of!(uhid_get_report_req, rtype) == 5);
        assert!(offset_of!(uhid_get_report_reply_req, data) == 8);
        assert!(offset_of!(uhid_set_report_req, size) == 6);
        assert!(offset_of!(uhid_set_report_req, data) == 8);
        assert!(size_of::<uhid_set_report_reply_req>() == 6);
    };

    impl uhid_event {
        /// An all-zero event of type `type_`, whose union fields the caller
        /// fills in. Zeroing the whole union, not only the field in use, keeps
        /// uninitialized bytes out of what is written to the kernel.
        pub fn new(type_: u32) -> Self {
            Self {
                type_,
                u: uhid_event_union::default(),
            }
        }
    }

    pub fn event_from_bytes(bytes: &[u8; UHID_EVENT_SIZE]) -> uhid_event {
        // SAFETY: `bytes` is exactly one `uhid_event` long, the packed type
        // has alignment 1, and any bytes are a valid value of it.
        unsafe { core::ptr::read(bytes.as_ptr() as *const uhid_event) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::ctaphid_host::Command;

    fn init_frame() -> [u8; CTAPHID_FRAME_LEN] {
        let mut frame = [0u8; CTAPHID_FRAME_LEN];
        frame[..4].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
        frame[4] = Command::Init.into_u8() | 0x80;
        frame[5..7].copy_from_slice(&(8u16).to_be_bytes());
        frame[7..15].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        frame
    }

    fn ping_frame() -> [u8; CTAPHID_FRAME_LEN] {
        let mut frame = [0u8; CTAPHID_FRAME_LEN];
        frame[..4].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        frame[4] = Command::Ping.into_u8() | 0x80;
        frame[5..7].copy_from_slice(&(16u16).to_be_bytes());
        for (idx, byte) in frame[7..23].iter_mut().enumerate() {
            *byte = idx as u8;
        }
        frame
    }

    fn with_leading_zero(frame: [u8; CTAPHID_FRAME_LEN]) -> [u8; CTAPHID_FRAME_LEN + 1] {
        let mut out = [0u8; CTAPHID_FRAME_LEN + 1];
        out[1..].copy_from_slice(&frame);
        out
    }

    #[test]
    fn an_event_is_read_only_after_its_readiness_has_settled() {
        use std::io::Write;
        let (device, mut kernel) = crate::platform::test_support::socket_device();
        kernel.write_all(&output_event(&init_frame())).unwrap();
        assert_eq!(device.try_read_frame().unwrap(), None);
        assert!(device.inner.readable_since.get().is_some());

        // Keep the observation young even if the test thread is descheduled.
        device
            .inner
            .readable_since
            .set(Some(Instant::now() + Duration::from_secs(1)));
        assert_eq!(device.try_read_frame().unwrap(), None);
        device
            .inner
            .readable_since
            .set(Some(Instant::now() - READ_SETTLING_TIME));
        assert_eq!(
            device.try_read_frame().unwrap(),
            Some(CtapHidFrame::new(init_frame()))
        );
        assert!(device.inner.readable_since.get().is_none());
        assert_eq!(device.try_read_frame().unwrap(), None);
    }

    #[test]
    fn a_burst_is_read_in_order_one_event_per_settling_period() {
        use std::io::Write;
        let (device, mut kernel) = crate::platform::test_support::socket_device();
        for byte in 0..30 {
            kernel
                .write_all(&output_event(&[byte; CTAPHID_FRAME_LEN]))
                .unwrap();
        }
        let mut last_read = Instant::now();
        for byte in 0..30 {
            assert_eq!(device.try_read_frame().unwrap(), None);
            let observed = device.inner.readable_since.get().unwrap();
            assert_eq!(
                device.read_settled_frame().unwrap(),
                Some(CtapHidFrame::new([byte; CTAPHID_FRAME_LEN]))
            );
            assert!(observed.elapsed() >= READ_SETTLING_TIME);
            assert!(last_read.elapsed() >= READ_SETTLING_TIME);
            assert!(device.inner.readable_since.get().is_none());
            last_read = Instant::now();
        }
        assert_eq!(device.try_read_frame().unwrap(), None);
    }

    #[test]
    fn non_frame_events_each_need_a_new_readiness_observation() {
        use std::io::Write;
        let (device, mut kernel) = crate::platform::test_support::socket_device();
        let types = [
            raw::UHID_EVENT_TYPE_OPEN,
            raw::UHID_EVENT_TYPE_CLOSE,
            raw::UHID_EVENT_TYPE_START,
            raw::UHID_EVENT_TYPE_STOP,
            raw::UHID_EVENT_TYPE_GET_REPORT,
            raw::UHID_EVENT_TYPE_SET_REPORT,
            u32::MAX,
        ];
        for event_type in types {
            kernel
                .write_all(event_as_bytes(&raw::uhid_event::new(event_type)))
                .unwrap();
        }
        kernel.write_all(&output_event(&init_frame())).unwrap();
        assert_eq!(device.try_read_frame().unwrap(), None);
        for _ in types {
            let settled = Instant::now() - READ_SETTLING_TIME;
            device.inner.readable_since.set(Some(settled));
            assert_eq!(device.try_read_frame().unwrap(), None);
            assert!(device.inner.readable_since.get().unwrap() > settled);
        }
        assert!(device.node_checked.load(Ordering::Relaxed));
        assert!(device.take_opened());
        assert!(!device.take_opened());
        device
            .inner
            .readable_since
            .set(Some(Instant::now() - READ_SETTLING_TIME));
        assert_eq!(
            device.try_read_frame().unwrap(),
            Some(CtapHidFrame::new(init_frame()))
        );
        assert_eq!(device.try_read_frame().unwrap(), None);
    }

    #[test]
    fn waiting_for_a_settling_event_sleeps_only_until_it_can_be_read() {
        use std::io::Write;
        let (device, mut kernel) = crate::platform::test_support::socket_device();
        let (wake, _worker) = std::os::unix::net::UnixStream::pair().unwrap();
        kernel.write_all(&output_event(&init_frame())).unwrap();
        assert_eq!(device.try_read_frame().unwrap(), None);
        let observed = Instant::now() - READ_SETTLING_TIME / 2;
        device.inner.readable_since.set(Some(observed));
        let start = Instant::now();
        assert!(
            device
                .wait_with(wake.as_fd(), Some(Duration::from_secs(1)))
                .unwrap()
        );
        // A readable device must not wake this wait before settling. Allow
        // scheduler delay, but not the caller's one-second timeout.
        assert!(observed.elapsed() >= READ_SETTLING_TIME);
        assert!(start.elapsed() < Duration::from_millis(20));
        assert_eq!(
            device.try_read_frame().unwrap(),
            Some(CtapHidFrame::new(init_frame()))
        );
    }

    #[test]
    fn settling_honours_a_shorter_timeout_and_the_worker_wakeup() {
        use std::io::Write;
        let (device, mut kernel) = crate::platform::test_support::socket_device();
        let (wake, mut worker) = std::os::unix::net::UnixStream::pair().unwrap();
        kernel.write_all(&output_event(&init_frame())).unwrap();
        assert_eq!(device.try_read_frame().unwrap(), None);
        // Keep the event settling through both waits, independent of the
        // time taken to schedule the test.
        device
            .inner
            .readable_since
            .set(Some(Instant::now() + Duration::from_secs(1)));
        let timeout = READ_SETTLING_TIME / 4;
        let start = Instant::now();
        assert!(!device.wait_with(wake.as_fd(), Some(timeout)).unwrap());
        assert!(start.elapsed() >= timeout);
        assert!(start.elapsed() < Duration::from_millis(20));
        worker.write_all(&[1]).unwrap();
        assert!(device.wait_with(wake.as_fd(), None).unwrap());
        assert_eq!(device.try_read_frame().unwrap(), None);
        device
            .inner
            .readable_since
            .set(Some(Instant::now() - READ_SETTLING_TIME));
        assert_eq!(
            device.try_read_frame().unwrap(),
            Some(CtapHidFrame::new(init_frame()))
        );
    }

    #[test]
    fn accepts_prefixed_init_report() {
        let frame = init_frame();
        let prefixed = with_leading_zero(frame);

        let parsed = frame_from_report_slice(&prefixed).expect("frame not parsed");
        assert_eq!(parsed.as_bytes(), &init_frame());

        let parsed_without_prefix = frame_from_report_slice(&frame).expect("64-byte frame");
        assert_eq!(parsed_without_prefix.as_bytes(), &init_frame());
    }

    #[test]
    fn accepts_prefixed_ping_report() {
        let frame = ping_frame();
        let prefixed = with_leading_zero(frame);

        let parsed = frame_from_report_slice(&prefixed).expect("frame not parsed");
        assert_eq!(parsed.as_bytes(), &ping_frame());
    }

    #[test]
    fn rejects_nonzero_report_id_prefix() {
        let mut prefixed = with_leading_zero(init_frame());
        prefixed[0] = 1;

        assert!(frame_from_report_slice(&prefixed).is_none());
    }

    #[test]
    fn descriptor_bytes_are_copied_verbatim() {
        let descriptor = HidDeviceDescriptor::default();
        let req = descriptor_to_create2(&descriptor).expect("descriptor conversion");

        assert_eq!(
            &req.rd_data[..CTAPHID_REPORT_DESCRIPTOR.len()],
            &CTAPHID_REPORT_DESCRIPTOR
        );

        let mut event = raw::uhid_event::new(raw::UHID_EVENT_TYPE_CREATE2);
        event.u.create2 = req;

        let bytes = event_as_bytes(&event);
        // SAFETY: both pointers are into `event`.
        let data_offset = unsafe {
            let base = (&event as *const raw::uhid_event).cast::<u8>();
            let data = event.u.create2.rd_data.as_ptr();
            data.offset_from(base) as usize
        };
        let descriptor_bytes = &bytes[data_offset..data_offset + CTAPHID_REPORT_DESCRIPTOR.len()];
        assert_eq!(descriptor_bytes, &CTAPHID_REPORT_DESCRIPTOR);
    }

    #[test]
    fn write_event_sends_raw_descriptor_bytes() {
        use nix::unistd::{pipe, read};

        let descriptor = HidDeviceDescriptor::default();
        let create2 = descriptor_to_create2(&descriptor).expect("descriptor conversion");
        let mut event = raw::uhid_event::new(raw::UHID_EVENT_TYPE_CREATE2);
        event.u.create2 = create2;

        let (read_fd, write_fd) = pipe().expect("pipe");
        write_event_blocking(write_fd.as_fd(), &mut event).expect("write_event");
        // Closed so the read below sees end of file instead of blocking.
        drop(write_fd);

        let mut buffer = [0u8; UHID_EVENT_SIZE];
        let mut offset = 0;
        while offset < buffer.len() {
            let read_bytes = read(&read_fd, &mut buffer[offset..]).expect("read");
            if read_bytes == 0 {
                break;
            }
            offset += read_bytes;
        }
        drop(read_fd);
        assert_eq!(offset, UHID_EVENT_SIZE);

        // SAFETY: both pointers are into `event`.
        let data_offset = unsafe {
            let base = (&event as *const raw::uhid_event).cast::<u8>();
            let data = event.u.create2.rd_data.as_ptr();
            data.offset_from(base) as usize
        };
        let descriptor_bytes = &buffer[data_offset..data_offset + CTAPHID_REPORT_DESCRIPTOR.len()];
        assert_eq!(descriptor_bytes, &CTAPHID_REPORT_DESCRIPTOR);
    }

    /// Every size above the data array, up to the largest a `u16` can say.
    const OVERSIZE: [u16; 3] = [raw::UHID_DATA_MAX as u16 + 1, 0x8000, u16::MAX];

    /// The id and status of the set_report reply `stream` holds next.
    fn read_set_report_reply(stream: &mut std::os::unix::net::UnixStream) -> (u32, u16) {
        use std::io::Read;
        let mut bytes = [0u8; UHID_EVENT_SIZE];
        stream.read_exact(&mut bytes).unwrap();
        let event = raw::event_from_bytes(&bytes);
        assert_eq!({ event.type_ }, raw::UHID_EVENT_TYPE_SET_REPORT_REPLY);
        // SAFETY: every union member is plain integers, valid for any bytes.
        let reply = unsafe { event.u.set_report_reply };
        (reply.id, reply.err)
    }

    #[test]
    fn report_data_rejects_sizes_beyond_the_array() {
        let data = [0u8; raw::UHID_DATA_MAX];
        assert_eq!(report_data(&data, 0).map(<[u8]>::len), Some(0));
        let max = raw::UHID_DATA_MAX as u16;
        assert_eq!(
            report_data(&data, max).map(<[u8]>::len),
            Some(raw::UHID_DATA_MAX)
        );
        for size in OVERSIZE {
            assert!(report_data(&data, size).is_none(), "size {size}");
        }
    }

    #[test]
    fn ignores_output_events_with_an_oversize_size() {
        use std::io::Write;
        let (device, mut kernel) = crate::platform::test_support::socket_device();
        let frame = ping_frame();
        for size in OVERSIZE {
            kernel
                .write_all(&output_event_with_size(&frame, size))
                .unwrap();
        }
        assert_eq!(device.read_settled_frame().unwrap(), None);

        // The device still reads the next well-formed event.
        kernel.write_all(&output_event(&frame)).unwrap();
        assert_eq!(
            device.read_settled_frame().unwrap(),
            Some(CtapHidFrame::new(frame))
        );
    }

    #[test]
    fn answers_set_report_events_with_an_oversize_size_with_einval() {
        use std::io::Write;
        let (device, mut kernel) = crate::platform::test_support::socket_device();
        let frame = init_frame();
        for (id, size) in (1..).zip(OVERSIZE) {
            let event = set_report_event(id, raw::UHID_REPORT_TYPE_OUTPUT, &frame, size);
            kernel.write_all(&event).unwrap();
            assert_eq!(device.read_settled_frame().unwrap(), None);
            assert_eq!(
                read_set_report_reply(&mut kernel),
                (id, Errno::EINVAL as u16)
            );
        }

        let event = set_report_event(9, raw::UHID_REPORT_TYPE_OUTPUT, &frame, 64);
        kernel.write_all(&event).unwrap();
        assert_eq!(
            device.read_settled_frame().unwrap(),
            Some(CtapHidFrame::new(frame))
        );
        assert_eq!(read_set_report_reply(&mut kernel), (9, 0));
    }

    /// The report descriptor declares 64-byte input and output reports and no
    /// feature report, so a feature report is no CTAPHID packet: a SET_REPORT
    /// or GET_REPORT of one is refused (the kernel turns the error into EIO,
    /// as a USB key stalls), and an output event of that type is ignored.
    #[test]
    fn feature_reports_are_refused() {
        use std::io::{Read, Write};
        let (device, mut kernel) = crate::platform::test_support::socket_device();
        let frame = init_frame();
        let event = set_report_event(3, raw::UHID_REPORT_TYPE_FEATURE, &frame, 64);
        kernel.write_all(&event).unwrap();
        assert_eq!(device.read_settled_frame().unwrap(), None);
        assert_eq!(
            read_set_report_reply(&mut kernel),
            (3, Errno::EINVAL as u16)
        );

        let mut event = raw::uhid_event::new(raw::UHID_EVENT_TYPE_GET_REPORT);
        // SAFETY: every union member is plain integers, valid for any bytes.
        let get_report = unsafe { &mut event.u.get_report };
        get_report.id = 4;
        get_report.rtype = raw::UHID_REPORT_TYPE_FEATURE;
        kernel.write_all(event_as_bytes(&event)).unwrap();
        assert_eq!(device.read_settled_frame().unwrap(), None);
        let mut bytes = [0u8; UHID_EVENT_SIZE];
        kernel.read_exact(&mut bytes).unwrap();
        let reply = raw::event_from_bytes(&bytes);
        assert_eq!({ reply.type_ }, raw::UHID_EVENT_TYPE_GET_REPORT_REPLY);
        // SAFETY: as above.
        let reply = unsafe { reply.u.get_report_reply };
        assert_eq!(
            (reply.id, reply.err, reply.size),
            (4, Errno::EINVAL as u16, 0)
        );

        let mut output = output_event(&frame);
        // The rtype byte of uhid_output_req follows its data and size.
        let rtype_offset = 4 + raw::UHID_DATA_MAX + 2;
        output[rtype_offset] = raw::UHID_REPORT_TYPE_FEATURE;
        kernel.write_all(&output).unwrap();
        assert_eq!(device.read_settled_frame().unwrap(), None);
    }

    /// UHID_OPEN, which the kernel sends once a client opens the device, is
    /// reported once through `take_opened`.
    #[test]
    fn an_open_event_is_reported_once() {
        use std::io::Write;
        let (device, mut kernel) = crate::platform::test_support::socket_device();
        assert!(!device.take_opened());
        assert!(!device.node_checked.load(Ordering::Relaxed));
        let open = raw::uhid_event::new(raw::UHID_EVENT_TYPE_OPEN);
        kernel.write_all(event_as_bytes(&open)).unwrap();
        kernel.write_all(&output_event(&init_frame())).unwrap();
        assert_eq!(
            device.read_settled_frame().unwrap(),
            Some(CtapHidFrame::new(init_frame()))
        );
        assert!(device.node_checked.load(Ordering::Relaxed));
        assert!(device.take_opened());
        assert!(!device.take_opened());
    }

    // NOTE: previous versions of this file contained tests for an in-place
    // descriptor rewriter (`force_ctaphid_report_descriptor`).  That helper
    // was never wired into the production write path, so the tests asserted
    // behaviour the code never performed.  They are intentionally removed
    // here; `descriptor_bytes_are_copied_verbatim` and
    // `write_event_sends_raw_descriptor_bytes` above cover the actual
    // serialization contract.
}
