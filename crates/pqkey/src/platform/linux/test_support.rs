//! The kernel's side of a socket-backed Linux device.
pub(crate) use super::Device;
pub(crate) use super::uhid;
use crate::{test_support::callback::Event, transport::HidDeviceDescriptor};
use std::{
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::net::UnixStream,
    },
    time::Duration,
};

/// A uhid device whose descriptor is one end of a socket pair; the other
/// end is returned so the test can play the kernel.
pub(crate) fn socket_device() -> (Device, UnixStream) {
    let (device_end, test_end) = UnixStream::pair().unwrap();
    // /dev/uhid reads and writes whole events. A stream socket with its
    // small default buffers can deliver part of one, and the device drops
    // a partly read event, losing packets. Buffers this large hold every
    // event whole while the other side reads along.
    for socket in [&device_end, &test_end] {
        for option in [nix::libc::SO_SNDBUF, nix::libc::SO_RCVBUF] {
            let size: nix::libc::c_int = 1 << 20;
            // SAFETY: a valid socket, and an int option of the right size.
            let status = unsafe {
                nix::libc::setsockopt(
                    socket.as_raw_fd(),
                    nix::libc::SOL_SOCKET,
                    option,
                    (&size as *const nix::libc::c_int).cast(),
                    size_of::<nix::libc::c_int>() as nix::libc::socklen_t,
                )
            };
            assert_eq!(status, 0, "{}", io::Error::last_os_error());
        }
    }
    device_end.set_nonblocking(true).unwrap();
    let device = Device::from_fd(OwnedFd::from(device_end), HidDeviceDescriptor::default());
    (device, test_end)
}

pub(crate) struct Peer(UnixStream);
pub(crate) fn pair() -> (Device, Peer) {
    let (device, stream) = socket_device();
    (device, Peer(stream))
}
impl Peer {
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        self.0.try_clone().map(Self)
    }
    pub(crate) fn send(&self, frame: &[u8; 64]) -> io::Result<()> {
        (&self.0).write_all(&uhid::output_event(frame))
    }
    pub(crate) fn read_event(&mut self) -> io::Result<Event> {
        let mut event = vec![0u8; uhid::UHID_EVENT_SIZE];
        self.0.read_exact(&mut event)?;
        Ok(match uhid::input_report(&event) {
            Some(frame) => Event::Report(crate::transport::CtapHidFrame::new(frame)),
            None => {
                let event_type = u32::from_ne_bytes(event[..4].try_into().unwrap());
                assert_eq!(event_type, uhid::UHID_EVENT_TYPE_DESTROY);
                Event::Destroyed
            }
        })
    }
    pub(crate) fn receive(&mut self, timeout: Duration) -> io::Result<Option<[u8; 64]>> {
        self.0.set_read_timeout(Some(timeout))?;
        loop {
            match self.read_event() {
                Ok(Event::Report(frame)) => return Ok(Some(frame.0)),
                Ok(Event::Destroyed) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(err) => return Err(err),
            }
        }
    }
}
