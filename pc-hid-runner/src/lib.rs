pub mod attestation;
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
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use ctaphid_dispatch::{self, app::App, Channel, DEFAULT_MESSAGE_SIZE};
use shutdown::ShutdownSignal;
use transport::ctaphid_host::{CtaphidHost, Version};
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

/// How long an idle pass of the loop waits for the device before it looks at
/// the shutdown flag and the CTAPHID timers again.
const IDLE_WAIT: Duration = Duration::from_millis(10);

/// Whether the CTAP app is waiting for the user. The app sets it through its
/// keepalive callback and the loop reports it in CTAPHID keepalives. Clones
/// share the flag, which may be set from another thread.
#[derive(Clone, Debug, Default)]
pub struct WaitingForUser(Arc<AtomicBool>);

impl WaitingForUser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, waiting: bool) {
        self.0.store(waiting, Ordering::Relaxed);
    }

    pub fn get(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// CTAPHID over a uhid device: output reports go into the [`CtaphidHost`],
/// complete requests go to the apps through the dispatcher, and the host's
/// frames come back out as input reports.
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

    /// Read every pending report, let the apps answer a complete request, and
    /// send the frames that produced. Returns whether anything happened.
    ///
    /// Fails with [`shutdown::shutdown_error`] once shutdown has been
    /// requested, which is how [`serve`] gets out of its loop.
    pub fn poll(
        &mut self,
        apps: &mut [&mut dyn App<'interrupt, { DEFAULT_MESSAGE_SIZE }>],
    ) -> io::Result<bool> {
        self.shutdown.check()?;
        let mut did_work = false;
        while let Some(frame) = self.device.try_read_frame()? {
            let elapsed = self.epoch.elapsed().as_millis() as u64;
            self.host.handle_frame(&frame, elapsed);
            did_work = true;
        }

        did_work |= self.host.poll_dispatch(&mut self.dispatch, apps);

        if self.host.take_started_processing() {
            did_work = true;
        }

        if self.host.has_pending_frames() {
            did_work |= self.flush_pending()?;
        }

        Ok(did_work)
    }

    /// Expire CTAPHID timeouts and send a keepalive if one is due, reporting
    /// `waiting_for_user`. Returns whether anything was sent.
    pub fn send(&mut self, waiting_for_user: bool) -> io::Result<bool> {
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

    /// Wait until the device has something to read, for at most a short
    /// while. Fails with [`shutdown::shutdown_error`] once shutdown has been
    /// requested.
    pub fn wait(&mut self) -> io::Result<()> {
        self.shutdown.check()?;
        let _ = self.device.wait(Some(IDLE_WAIT))?;
        Ok(())
    }
}

/// The daemon's main loop: poll the device and the apps, send keepalives that
/// report `waiting`, and wait for the device whenever a pass did nothing.
///
/// Returns only with an error: [`shutdown::shutdown_error`] once shutdown has
/// been requested, or whatever made the device fail.
pub fn serve<'interrupt>(
    transport: &mut UhidTransport<'_, 'interrupt>,
    apps: &mut [&mut dyn App<'interrupt, { DEFAULT_MESSAGE_SIZE }>],
    waiting: &WaitingForUser,
) -> io::Result<()> {
    loop {
        let mut did_work = transport.poll(apps)?;
        did_work |= transport.send(waiting.get())?;
        if !did_work {
            transport.wait()?;
        }
    }
}

/// Create the uhid device, warning if its hidraw node is accessible to every
/// user.
pub fn create_device(descriptor: HidDeviceDescriptor) -> io::Result<UhidDevice> {
    let device = UhidDevice::new(descriptor.clone())?;
    if let Ok(nodes) = permissions::hidraw_nodes_for_descriptor(&descriptor) {
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
    Ok(device)
}

/// Serve CTAPHID on `device` with `apps` until the device fails or `shutdown`
/// is requested; the latter ends with [`shutdown::shutdown_error`]. `on_ready`
/// runs just before requests are served. The device is destroyed on return.
pub fn exec<'interrupt>(
    device: UhidDevice,
    apps: &mut [&mut dyn App<'interrupt, { DEFAULT_MESSAGE_SIZE }>],
    waiting: &WaitingForUser,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    let channel: Channel<{ DEFAULT_MESSAGE_SIZE }> = Channel::new();
    let (requester, responder) = channel
        .split()
        .ok_or_else(|| io::Error::other("failed to split CTAPHID channel"))?;
    let mut host = CtaphidHost::new(requester);
    host.set_version(Version {
        major: 2,
        minor: 1,
        build: 0,
    });
    // Setting both capability bits prevents hosts from probing CTAPHID_MSG and enables proper CTAP2 detection
    host.set_capabilities(CAPABILITY_CBOR | CAPABILITY_NMSG);
    let dispatch = ctaphid_dispatch::Dispatch::new(responder);
    let mut transport = UhidTransport::new(device, host, dispatch, shutdown);
    on_ready()?;
    serve(&mut transport, apps, waiting)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shutdown::is_shutdown;
    use std::{
        io::Read,
        os::{fd::OwnedFd, unix::net::UnixStream},
    };

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
    fn transport_stops_the_loop_once_shutdown_is_requested() {
        let shutdown = ShutdownSignal::new();
        let (mut transport, _device_side) = socket_transport(shutdown.clone());

        // Idle: nothing to read, nothing to do, and waiting times out.
        assert!(!transport.poll(&mut []).unwrap());
        assert!(!transport.send(false).unwrap());
        transport.wait().unwrap();

        shutdown.request();
        let err = transport.poll(&mut []).unwrap_err();
        assert!(is_shutdown(&err), "{err:?}");
        let err = transport.wait().unwrap_err();
        assert!(is_shutdown(&err), "{err:?}");
        let err = serve(&mut transport, &mut [], &WaitingForUser::new()).unwrap_err();
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

    #[test]
    fn waiting_for_user_is_shared_between_clones() {
        let waiting = WaitingForUser::new();
        let app_side = waiting.clone();
        assert!(!waiting.get());
        thread::spawn(move || app_side.set(true)).join().unwrap();
        assert!(waiting.get());
    }
}
