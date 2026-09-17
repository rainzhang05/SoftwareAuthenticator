pub mod attestation;
pub mod cli;
pub mod permissions;
pub mod pin_input;
pub mod presence;
pub mod service;
pub mod shutdown;
pub mod state;
pub mod state_lock;
pub mod transport;
pub mod uhid;

#[cfg(test)]
mod test_support;

use std::{
    io::{self, Read, Write},
    os::{fd::AsFd, unix::net::UnixStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use ctaphid_app::{App, Command, Error as AppError};
use heapless_bytes::Bytes;
use pqkey_ctap::ctap::InterruptFlag;
use shutdown::ShutdownSignal;
use transport::ctaphid_host::{AppRequest, CtaphidHost, MAX_MESSAGE_SIZE, Version};
use uhid::{CTAPHID_FRAME_LEN, HidDeviceDescriptor, UhidDevice};

// CTAPHID capability flags (CTAP spec section 11.2.9.1.3)
pub const CAPABILITY_CBOR: u8 = 0x04; // Implements CTAPHID_CBOR
pub const CAPABILITY_NMSG: u8 = 0x08; // Does NOT implement CTAPHID_MSG

/// The message size the app is built for: the largest CTAPHID message.
pub const MESSAGE_SIZE: usize = MAX_MESSAGE_SIZE;

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

/// The longest the loop waits for the device before it looks at the shutdown
/// flag, the app and the CTAPHID timers again.
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

/// The app's answer to one request.
type AppResponse = Result<Vec<u8>, AppError>;

/// The transport thread's end of the app worker: requests go out, answers
/// come back, and the worker writes a byte to `wake` after each answer so the
/// loop does not sleep through it.
struct AppWorker<'interrupt> {
    requests: Option<mpsc::Sender<AppRequest>>,
    responses: mpsc::Receiver<AppResponse>,
    wake: UnixStream,
    interrupt: Option<&'interrupt InterruptFlag>,
}

impl AppWorker<'_> {
    /// Hand `request` to the app.
    ///
    /// The interrupt flag is marked as working here rather than on the
    /// worker, so a CANCEL that arrives before the worker picks the request
    /// up is not lost. The worker marks it idle again after the call, before
    /// it answers, and a request is only sent once the previous answer has
    /// arrived, so the two never overlap.
    fn submit(&mut self, request: AppRequest) -> io::Result<()> {
        if let Some(flag) = self.interrupt {
            flag.set_working();
        }
        self.requests
            .as_ref()
            .and_then(|requests| requests.send(request).ok())
            .ok_or_else(app_stopped)
    }

    /// Ask the app to cancel the request it is working on. The flag only
    /// changes while a request is being worked on, so this never affects a
    /// later request.
    fn interrupt(&self) {
        if let Some(flag) = self.interrupt {
            flag.interrupt();
        }
    }

    /// The app's next answer, if one has arrived.
    fn try_response(&self) -> io::Result<Option<AppResponse>> {
        let mut drained = [0u8; 16];
        while matches!((&self.wake).read(&mut drained), Ok(n) if n > 0) {}
        match self.responses.try_recv() {
            Ok(response) => Ok(Some(response)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(app_stopped()),
        }
    }

    /// Cancel the request being worked on, if any, and let the worker finish.
    fn stop(&mut self) {
        self.interrupt();
        self.requests = None;
    }
}

fn app_stopped() -> io::Error {
    io::Error::other("the CTAP app stopped")
}

/// The worker thread: answer requests with `app` until the transport hangs
/// up.
fn run_app<'interrupt, A>(
    app: &mut A,
    requests: mpsc::Receiver<AppRequest>,
    responses: mpsc::Sender<AppResponse>,
    wake: UnixStream,
) where
    A: App<'interrupt> + ?Sized,
{
    let interrupt = app.interrupt();
    let mut buffer = Box::new(Bytes::<MESSAGE_SIZE>::new());
    for request in requests {
        buffer.clear();
        let response = app
            .call(request.command, &request.payload, buffer.as_mut_view())
            .map(|()| buffer.to_vec());
        if let Some(flag) = interrupt {
            flag.set_idle();
        }
        if responses.send(response).is_err() {
            return;
        }
        // Full means a wake-up is pending anyway.
        let _ = (&wake).write(&[0]);
    }
}

/// CTAPHID over a uhid device.
///
/// This runs on the daemon's main thread and owns the device and the CTAPHID
/// state ([`CtaphidHost`]); the app runs on a worker thread. The transport
/// reads packets, answers INIT and PING itself, passes complete requests to
/// the app, sends keepalives while the app works, passes CTAPHID_CANCEL on to
/// the app through its interrupt flag, and sends the app's answers.
pub struct UhidTransport<'interrupt> {
    device: UhidDevice,
    host: CtaphidHost,
    app: AppWorker<'interrupt>,
    waiting: WaitingForUser,
    epoch: Instant,
    shutdown: ShutdownSignal,
}

impl UhidTransport<'_> {
    fn now(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
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

    /// Read every pending packet, exchange requests and answers with the
    /// app, send keepalives that are due, and write everything that produced.
    /// Returns whether anything happened.
    ///
    /// Fails with [`shutdown::shutdown_error`] once shutdown has been
    /// requested, which is how [`serve`] gets out of its loop.
    pub fn poll(&mut self) -> io::Result<bool> {
        self.shutdown.check()?;
        let mut did_work = false;
        while let Some(frame) = self.device.try_read_frame()? {
            let now = self.now();
            self.host.handle_frame(&frame, now);
            did_work = true;
        }
        // Before anything new goes to the app: an interrupt is only meant for
        // the request the app has now.
        if self.host.take_interrupt() {
            self.app.interrupt();
        }
        while let Some(response) = self.app.try_response()? {
            self.host.app_response(response);
            did_work = true;
        }
        if let Some(request) = self.host.take_app_request() {
            self.app.submit(request)?;
            did_work = true;
        }

        let now = self.now();
        self.host.handle_timeout(now);
        self.host.send_keepalive(self.waiting.get(), now);
        did_work |= self.flush_pending()?;
        Ok(did_work)
    }

    /// Wait until the device or the app has something, the next CTAPHID timer
    /// is due, or 10 ms have passed. Fails with
    /// [`shutdown::shutdown_error`] once shutdown has been requested.
    pub fn wait(&mut self) -> io::Result<()> {
        self.shutdown.check()?;
        let mut timeout = IDLE_WAIT;
        if let Some(deadline) = self.host.next_deadline() {
            let remaining = Duration::from_millis(deadline.saturating_sub(self.now()));
            timeout = timeout.min(remaining);
        }
        if !timeout.is_zero() {
            self.device
                .wait_with(self.app.wake.as_fd(), Some(timeout))?;
        }
        Ok(())
    }
}

/// The daemon's main loop: poll the device and the app, and wait whenever a
/// pass did nothing.
///
/// Returns only with an error: [`shutdown::shutdown_error`] once shutdown has
/// been requested, or whatever made the device or the app fail.
pub fn serve(transport: &mut UhidTransport<'_>) -> io::Result<()> {
    loop {
        if !transport.poll()? {
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

/// Serve CTAPHID on `device` with `app` until the device or the app fails or
/// `shutdown` is requested; the latter ends with [`shutdown::shutdown_error`].
/// `on_ready` runs just before requests are served. `waiting` is what the app
/// reports through its keepalive callback.
///
/// `app` runs on a worker thread of its own, so the device keeps being served
/// while a request waits for the user. On the way out the request the app is
/// working on is cancelled through its interrupt flag, the device is
/// destroyed, and then the worker is joined: a presence prompt must honour
/// cancellation for this to return.
pub fn exec<'interrupt, A>(
    device: UhidDevice,
    app: &mut A,
    waiting: &WaitingForUser,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()>
where
    A: App<'interrupt> + Send + ?Sized,
{
    let interrupt = app.interrupt();
    let app_commands: &'static [Command] = app.commands();
    let (wake, worker_wake) = UnixStream::pair()?;
    wake.set_nonblocking(true)?;
    worker_wake.set_nonblocking(true)?;
    let (request_sender, request_receiver) = mpsc::channel();
    let (response_sender, response_receiver) = mpsc::channel();

    thread::scope(|scope| {
        let worker = thread::Builder::new()
            .name("ctap-app".into())
            .spawn_scoped(scope, move || {
                run_app(app, request_receiver, response_sender, worker_wake)
            })?;

        let mut host = CtaphidHost::new(app_commands);
        host.set_version(Version {
            major: 2,
            minor: 1,
            build: 0,
        });
        // Setting both capability bits prevents hosts from probing CTAPHID_MSG and enables proper CTAP2 detection
        host.set_capabilities(CAPABILITY_CBOR | CAPABILITY_NMSG);
        let mut transport = UhidTransport {
            device,
            host,
            app: AppWorker {
                requests: Some(request_sender),
                responses: response_receiver,
                wake,
                interrupt,
            },
            waiting: waiting.clone(),
            epoch: Instant::now(),
            shutdown,
        };

        let result = on_ready().and_then(|()| serve(&mut transport));

        transport.app.stop();
        drop(transport);
        match worker.join() {
            Ok(()) => result,
            Err(_) => Err(io::Error::other("the CTAP app panicked")),
        }
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::shutdown::is_shutdown;
    use std::os::fd::{AsRawFd, OwnedFd};

    /// A uhid device whose descriptor is one end of a socket pair; the other
    /// end is returned so the test can play the kernel.
    pub(crate) fn socket_device() -> (UhidDevice, UnixStream) {
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
                        std::mem::size_of::<nix::libc::c_int>() as nix::libc::socklen_t,
                    )
                };
                assert_eq!(status, 0, "{}", io::Error::last_os_error());
            }
        }
        device_end.set_nonblocking(true).unwrap();
        let device = UhidDevice::from_fd(OwnedFd::from(device_end), HidDeviceDescriptor::default());
        (device, test_end)
    }

    /// Answers CTAPHID_CBOR by echoing the request, or panics on 0xFF.
    struct EchoApp;

    impl App<'static> for EchoApp {
        fn commands(&self) -> &'static [Command] {
            &[Command::Cbor]
        }

        fn call(
            &mut self,
            _command: Command,
            request: &[u8],
            response: &mut heapless_bytes::BytesView,
        ) -> Result<(), AppError> {
            assert_ne!(request, [0xFF], "the app fails");
            response.extend_from_slice(request).unwrap();
            Ok(())
        }
    }

    fn event_type(event: &[u8]) -> u32 {
        u32::from_ne_bytes(event[..4].try_into().unwrap())
    }

    #[test]
    fn exec_returns_once_shutdown_is_requested_and_destroys_the_device() {
        let (device, mut device_side) = socket_device();
        let shutdown = ShutdownSignal::new();
        shutdown.request();
        let mut ready = false;
        let err = exec(
            device,
            &mut EchoApp,
            &WaitingForUser::new(),
            shutdown,
            || {
                ready = true;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(is_shutdown(&err), "{err:?}");
        assert!(ready);

        let mut event = Vec::new();
        device_side.read_to_end(&mut event).unwrap();
        assert_eq!(event.len(), uhid::UHID_EVENT_SIZE);
        assert_eq!(event_type(&event), uhid::UHID_EVENT_TYPE_DESTROY);
    }

    #[test]
    fn a_failure_before_serving_stops_the_worker_and_destroys_the_device() {
        let (device, mut device_side) = socket_device();
        let err = exec(
            device,
            &mut EchoApp,
            &WaitingForUser::new(),
            ShutdownSignal::new(),
            || Err(io::Error::other("not ready")),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "not ready");

        let mut event = Vec::new();
        device_side.read_to_end(&mut event).unwrap();
        assert_eq!(event_type(&event), uhid::UHID_EVENT_TYPE_DESTROY);
    }

    #[test]
    fn a_panicking_app_ends_the_loop_with_an_error() {
        let (device, mut device_side) = socket_device();
        device_side
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let mut frame = [0u8; CTAPHID_FRAME_LEN];
        frame[..4].copy_from_slice(&0x0102_0304u32.to_be_bytes());
        frame[4] = Command::Cbor.into_u8() | 0x80;
        frame[5..8].copy_from_slice(&[0, 1, 0xFF]);
        device_side.write_all(&uhid::output_event(&frame)).unwrap();

        let err = exec(
            device,
            &mut EchoApp,
            &WaitingForUser::new(),
            ShutdownSignal::new(),
            || Ok(()),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "the CTAP app panicked");

        let mut event = Vec::new();
        device_side.read_to_end(&mut event).unwrap();
        assert_eq!(event_type(&event), uhid::UHID_EVENT_TYPE_DESTROY);
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
