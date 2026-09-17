pub mod cli;
pub mod permissions;
pub mod pin_input;
pub mod service;
pub mod shutdown;
pub mod state;
pub mod state_lock;
pub mod transport;
pub mod uhid;

#[cfg(test)]
mod test_support;

use std::{
    io, thread,
    time::{Duration, Instant},
};

use ctaphid_dispatch::{self, Channel, DEFAULT_MESSAGE_SIZE};
use shutdown::ShutdownSignal;
use transport::ctaphid_host::{CtaphidHost, Version};
use transport_core::{Apps, Platform, Runner, Transport};
use trussed::backend::Dispatch;
use uhid::{HidDeviceDescriptor, UhidDevice, CTAPHID_FRAME_LEN};

// CTAPHID capability flags (CTAP spec section 11.2.9.1.3)
pub const CAPABILITY_CBOR: u8 = 0x04; // Implements CTAPHID_CBOR
pub const CAPABILITY_NMSG: u8 = 0x08; // Does NOT implement CTAPHID_MSG

/// Pause between input reports of a multi-packet message.
///
/// A USB full-speed HID interrupt endpoint delivers at most one report per
/// millisecond, and FIDO clients read at that pace. uhid has no such flow
/// control: each input report goes straight into every hidraw reader's buffer,
/// which holds only 64 reports (`HIDRAW_BUFFER_SIZE`), so a longer burst drops
/// packets. An ML-DSA-87 assertion is 82 packets. Pacing like real hardware
/// keeps even the largest CTAPHID message (129 packets) intact, at a cost of
/// at most about 130 ms.
const INPUT_REPORT_INTERVAL: Duration = Duration::from_millis(1);

pub struct UhidTransport<'pipe, 'interrupt> {
    device: UhidDevice,
    host: CtaphidHost<'pipe, { DEFAULT_MESSAGE_SIZE }>,
    dispatch: ctaphid_dispatch::Dispatch<'pipe, 'interrupt, { DEFAULT_MESSAGE_SIZE }>,
    epoch: Instant,
    shutdown: ShutdownSignal,
}

impl<'pipe, 'interrupt> UhidTransport<'pipe, 'interrupt> {
    pub fn new(
        device: UhidDevice,
        host: CtaphidHost<'pipe, { DEFAULT_MESSAGE_SIZE }>,
        dispatch: ctaphid_dispatch::Dispatch<'pipe, 'interrupt, { DEFAULT_MESSAGE_SIZE }>,
        shutdown: ShutdownSignal,
    ) -> Self {
        Self {
            device,
            host,
            dispatch,
            epoch: Instant::now(),
            shutdown,
        }
    }

    fn flush_pending(&mut self) -> io::Result<bool> {
        let mut wrote = false;
        while let Some(frame) = self.host.next_outgoing_frame() {
            if wrote {
                thread::sleep(INPUT_REPORT_INTERVAL);
            }
            self.device.write_frame(&frame)?;
            wrote = true;
        }
        Ok(wrote)
    }
}

impl<'interrupt, D> Transport<'interrupt, D> for UhidTransport<'_, 'interrupt>
where
    D: Dispatch,
{
    fn poll<A: Apps<'interrupt, D>>(&mut self, apps: &mut A) -> io::Result<bool> {
        // Runner::exec only returns when the transport fails, so this is how
        // a requested shutdown gets out of its loop.
        self.shutdown.check()?;
        let mut did_work = false;
        loop {
            match self.device.try_read_frame()? {
                Some(frame) => {
                    let elapsed = self.epoch.elapsed().as_millis() as u64;
                    self.host.handle_frame(&frame, elapsed);
                    did_work = true;
                }
                None => break,
            }
        }

        did_work |=
            apps.with_ctaphid_apps(|apps| self.host.poll_dispatch(&mut self.dispatch, apps));

        if self.host.take_started_processing() {
            did_work = true;
        }

        if self.host.has_pending_frames() {
            did_work |= self.flush_pending()?;
        }

        Ok(did_work)
    }

    fn send(&mut self, waiting_for_user: bool) -> io::Result<bool> {
        let elapsed = self.epoch.elapsed().as_millis() as u64;
        self.host.handle_timeout(elapsed);
        let mut did_work = false;
        if self.host.send_keepalive(waiting_for_user) {
            did_work |= self.flush_pending()?;
        }
        if self.host.has_pending_frames() {
            did_work |= self.flush_pending()?;
        }
        Ok(did_work)
    }

    fn wait(&mut self) -> io::Result<()> {
        self.shutdown.check()?;
        let _ = self.device.wait(Some(Duration::from_millis(10)))?;
        Ok(())
    }
}

/// Create the uhid device and serve CTAPHID on it until the device fails or
/// `shutdown` is requested; the latter ends with [`shutdown::shutdown_error`].
/// `on_ready` runs once the device exists, just before requests are served.
pub fn exec<'interrupt, D, A>(
    runner: Runner<D, A>,
    descriptor: HidDeviceDescriptor,
    platform: Platform,
    data: A::Data,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()>
where
    D: Dispatch,
    D::BackendId: Send + Sync,
    D::Context: Send + Sync,
    A: Apps<'interrupt, D>,
{
    let descriptor_clone = descriptor.clone();
    let device = UhidDevice::new(descriptor)?;
    if let Ok(nodes) = permissions::hidraw_nodes_for_descriptor(&descriptor_clone) {
        for node in nodes {
            let mode = node.mode & 0o777;
            if mode & 0o007 != 0 {
                log::warn!(
                    "{} is world-accessible (mode {:o}); install the bundled udev rule or tighten permissions",
                    node.path.display(),
                    mode
                );
            }
        }
    }
    let channel: Channel<{ DEFAULT_MESSAGE_SIZE }> = Channel::new();
    let (requester, responder) = channel
        .split()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "failed to split CTAPHID channel"))?;
    let mut host = CtaphidHost::new(requester);
    host.set_version(Version {
        major: 2,
        minor: 1,
        build: 0,
    });
    // Setting both capability bits prevents hosts from probing CTAPHID_MSG and enables proper CTAP2 detection
    host.set_capabilities(CAPABILITY_CBOR | CAPABILITY_NMSG);
    let dispatch = ctaphid_dispatch::Dispatch::new(responder);
    let transport = UhidTransport::new(device, host, dispatch, shutdown);
    on_ready()?;
    runner.exec(platform, data, transport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shutdown::is_shutdown;
    use std::{
        io::Read,
        os::{fd::OwnedFd, unix::net::UnixStream},
    };
    use trussed::{
        backend::{CoreOnly, NoId},
        pipe::ServiceEndpoint,
        service::Service,
        types::NoData,
    };

    /// No CTAPHID apps; the transport tests below never reach them.
    struct NoApps;

    impl<'a> Apps<'a, CoreOnly> for NoApps {
        type Data = ();

        fn new(
            _: &mut Service<Platform, CoreOnly>,
            _: &mut Vec<ServiceEndpoint<'static, NoId, NoData>>,
            _: transport_core::Syscall,
            _: (),
        ) -> Self {
            unreachable!("the transport tests construct NoApps directly")
        }

        fn with_ctaphid_apps<T, const N: usize>(
            &mut self,
            f: impl FnOnce(&mut [&mut dyn ctaphid_dispatch::app::App<'a, N>]) -> T,
        ) -> T {
            f(&mut [])
        }
    }

    /// A transport whose "uhid" descriptor is one end of a socket pair; the
    /// other end is returned so the test can see what the device receives.
    fn socket_transport(shutdown: ShutdownSignal) -> (UhidTransport<'static, 'static>, UnixStream) {
        let (device_end, test_end) = UnixStream::pair().unwrap();
        device_end.set_nonblocking(true).unwrap();
        let device = UhidDevice::from_fd(OwnedFd::from(device_end), HidDeviceDescriptor::default());
        let channel = Box::leak(Box::new(Channel::<{ DEFAULT_MESSAGE_SIZE }>::new()));
        let (requester, responder) = channel.split().unwrap();
        let transport = UhidTransport::new(
            device,
            CtaphidHost::new(requester),
            ctaphid_dispatch::Dispatch::new(responder),
            shutdown,
        );
        (transport, test_end)
    }

    #[test]
    fn transport_stops_the_runner_loop_once_shutdown_is_requested() {
        let shutdown = ShutdownSignal::new();
        let (mut transport, _device_side) = socket_transport(shutdown.clone());
        let mut apps = NoApps;

        // Idle: nothing to read, nothing to do, and waiting times out.
        assert!(!Transport::<CoreOnly>::poll(&mut transport, &mut apps).unwrap());
        assert!(!Transport::<CoreOnly>::send(&mut transport, false).unwrap());
        Transport::<CoreOnly>::wait(&mut transport).unwrap();

        shutdown.request();
        let err = Transport::<CoreOnly>::poll(&mut transport, &mut apps).unwrap_err();
        assert!(is_shutdown(&err), "{err:?}");
        let err = Transport::<CoreOnly>::wait(&mut transport).unwrap_err();
        assert!(is_shutdown(&err), "{err:?}");
    }

    #[test]
    fn dropping_the_transport_destroys_the_uhid_device() {
        let (transport, mut device_side) = socket_transport(ShutdownSignal::new());
        drop(transport);

        let mut event = Vec::new();
        device_side.read_to_end(&mut event).unwrap();
        assert_eq!(event.len(), uhid::UHID_EVENT_SIZE);
        let event_type = u32::from_ne_bytes(event[..4].try_into().unwrap());
        assert_eq!(event_type, uhid::UHID_EVENT_TYPE_DESTROY);
    }
}
