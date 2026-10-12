pub mod ctaphid_host;
mod device;
mod identification;
use identification::IdentificationWorker;
pub use identification::Identifier;
#[cfg(test)]
mod u2f_tests;
pub use device::CTAPHID_REPORT_DESCRIPTOR;
pub use device::{
    CTAPHID_FRAME_LEN, CtapHidFrame, DEFAULT_PRODUCT_ID, DEFAULT_VENDOR_ID, HidDevice,
    HidDeviceDescriptor,
};

use std::{
    io::{self, Read, Write},
    os::{fd::AsFd, unix::net::UnixStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use self::ctaphid_host::{AppRequest, Command, CtaphidHost, MAX_MESSAGE_SIZE, Version};
use crate::shutdown::ShutdownSignal;
use pqkey_ctap::ctap::constants::{
    CTAP_CMD_RESET, CTAP2_ERR_KEY_STORE_FULL, CTAP2_ERR_PROCESSING, CTAP2_OK,
};
use pqkey_ctap::ctap::{CtapApp, InterruptFlag};

// CTAPHID capability flags (CTAP spec section 11.2.9.1.3)
pub const CAPABILITY_WINK: u8 = 0x01; // Implements CTAPHID_WINK
pub const CAPABILITY_CBOR: u8 = 0x04; // Implements CTAPHID_CBOR
pub const CAPABILITY_NMSG: u8 = 0x08; // Does NOT implement CTAPHID_MSG

/// The largest CTAPHID message, and so the longest answer the app can give.
pub const MESSAGE_SIZE: usize = MAX_MESSAGE_SIZE;

/// Pause between input reports, matching a USB full-speed HID endpoint.
const INPUT_REPORT_INTERVAL: Duration = Duration::from_millis(1);

/// The longest the loop waits for the device before it looks at the shutdown
/// flag, the app and the CTAPHID timers again.
const IDLE_WAIT: Duration = Duration::from_millis(10);

/// Whether the CTAP app is waiting for the user. The app sets it through its
/// keepalive callback and the loop reports it in CTAPHID keepalives. Clones
/// share the flag, which may be set from another thread.
#[derive(Clone, Debug, Default)]
pub struct WaitingForUser(Arc<PresenceTiming>);

#[derive(Debug, Default)]
struct PresenceTiming {
    waiting: AtomicBool,
    times: Mutex<(Option<Instant>, Option<Instant>)>,
}

impl WaitingForUser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, waiting: bool) {
        let mut times = self
            .0
            .times
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if waiting {
            *times = (Some(Instant::now()), None);
        } else {
            times.1 = Some(Instant::now());
        }
        self.0.waiting.store(waiting, Ordering::Relaxed);
    }

    pub fn get(&self) -> bool {
        self.0.waiting.load(Ordering::Relaxed)
    }

    fn times(&self) -> (Option<Instant>, Option<Instant>) {
        *self
            .0
            .times
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// What the transport runs on its worker thread: the CTAP app, which answers
/// complete CTAPHID_CBOR requests and CTAPHID_MSG APDUs.
///
/// `'interrupt` is the lifetime of the app's [`InterruptFlag`], apart from any
/// borrow of the app, so the transport can hold on to the flag while the
/// worker thread has the app.
pub trait App<'interrupt> {
    /// The flag through which the transport cancels the request the app is
    /// working on.
    fn interrupt(&self) -> &'interrupt InterruptFlag;

    /// Answer `request`, the payload of a CTAPHID_CBOR message.
    fn call(&mut self, request: &[u8]) -> Vec<u8>;

    /// Answer the command APDU in a CTAPHID_MSG message.
    fn call_u2f(&mut self, request: &[u8]) -> Vec<u8>;

    /// Whether policy allows U2F registration and authentication.
    fn u2f_enabled(&self) -> bool {
        true
    }
}

impl<'interrupt> App<'interrupt> for CtapApp<'interrupt> {
    fn interrupt(&self) -> &'interrupt InterruptFlag {
        CtapApp::interrupt(self)
    }

    fn call(&mut self, request: &[u8]) -> Vec<u8> {
        CtapApp::call(self, request)
    }

    fn call_u2f(&mut self, request: &[u8]) -> Vec<u8> {
        CtapApp::call_u2f(self, request)
    }
    fn u2f_enabled(&self) -> bool {
        CtapApp::u2f_enabled(self)
    }
}

struct AppResponse {
    payload: Vec<u8>,
    presence_finished: Option<Instant>,
    u2f_enabled: bool,
    reset: bool,
}

/// The transport thread's end of the app worker: requests go out, answers
/// come back, and the worker writes a byte to `wake` after each answer so the
/// loop does not sleep through it.
struct AppWorker<'interrupt> {
    requests: Option<mpsc::Sender<AppRequest>>,
    responses: mpsc::Receiver<AppResponse>,
    wake: UnixStream,
    interrupt: &'interrupt InterruptFlag,
    presence_before: Option<Instant>,
}

impl AppWorker<'_> {
    /// Hand `request` to the app.
    ///
    /// The interrupt flag is marked as working here rather than on the
    /// worker, so a CANCEL that arrives before the worker picks the request
    /// up is not lost. The worker marks it idle again after the call, before
    /// it answers, and a request is only sent once the previous answer has
    /// arrived, so the two never overlap.
    fn submit(&mut self, request: AppRequest, waiting: &WaitingForUser) -> io::Result<()> {
        self.presence_before = waiting.times().0;
        self.interrupt.set_working();
        self.requests
            .as_ref()
            .and_then(|requests| requests.send(request).ok())
            .ok_or_else(app_stopped)
    }

    /// Ask the app to cancel the request it is working on. The flag only
    /// changes while a request is being worked on, so this never affects a
    /// later request.
    fn interrupt(&self) {
        self.interrupt.interrupt();
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
    waiting: &WaitingForUser,
) where
    A: App<'interrupt> + ?Sized,
{
    let interrupt = app.interrupt();
    for request in requests {
        let before = waiting.times().0;
        let payload = if request.command == Command::Msg {
            app.call_u2f(&request.payload)
        } else {
            app.call(&request.payload)
        };
        let times = waiting.times();
        // A failed store reset may already have invalidated credentials.
        // Presence refusal, timeout and cancellation do not reset them.
        let reset = request.command == Command::Cbor
            && request.payload.first() == Some(&CTAP_CMD_RESET)
            && matches!(
                payload.first().copied(),
                Some(CTAP2_OK | CTAP2_ERR_PROCESSING | CTAP2_ERR_KEY_STORE_FULL)
            );
        let response = AppResponse {
            payload,
            presence_finished: if times.0 != before { times.1 } else { None },
            u2f_enabled: app.u2f_enabled(),
            reset,
        };
        interrupt.set_idle();
        if responses.send(response).is_err() {
            return;
        }
        // Full means a wake-up is pending anyway.
        let _ = (&wake).write(&[0]);
    }
}

/// CTAPHID over a platform device.
///
/// This runs on the daemon's main thread and owns the device and the CTAPHID
/// state ([`CtaphidHost`]); the app runs on a worker thread. The transport
/// reads packets, answers INIT and PING itself, passes complete requests to
/// the app, sends keepalives while the app works, passes CTAPHID_CANCEL on to
/// the app through its interrupt flag, and sends the app's answers.
pub struct Transport<'interrupt, D: HidDevice> {
    device: D,
    host: CtaphidHost,
    app: AppWorker<'interrupt>,
    identification: Option<IdentificationWorker>,
    waiting: WaitingForUser,
    epoch: Instant,
    shutdown: ShutdownSignal,
}

impl<D: HidDevice> Transport<'_, D> {
    fn now(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Hand every packet that has arrived to the CTAPHID state machine.
    /// Returns whether there was any.
    fn read_frames(&mut self) -> io::Result<bool> {
        let mut read = false;
        while let Some(frame) = self.device.try_read_frame()? {
            self.shutdown.check()?;
            self.collect_responses()?;
            let now = self.now();
            self.observe_presence();
            self.host.handle_timeout(now);
            self.host.handle_frame(&frame, now);
            read = true;
        }
        Ok(read)
    }

    fn collect_responses(&mut self) -> io::Result<bool> {
        let mut received = false;
        while let Some(response) = self.app.try_response()? {
            if response.reset {
                self.host.reset_u2f();
            }
            self.host.set_u2f_enabled(response.u2f_enabled);
            let finished = response
                .presence_finished
                .map(|at| at.saturating_duration_since(self.epoch).as_millis() as u64);
            self.host
                .app_response(response.payload, self.now(), finished);
            received = true;
        }
        if let Some(worker) = &self.identification {
            while let Some((token, delivered)) = worker.response() {
                self.host
                    .identification_response(token, delivered, self.now());
                received = true;
            }
        }
        Ok(received)
    }

    fn observe_presence(&mut self) {
        let times = self.waiting.times();
        if times.0.is_some() && times.0 != self.app.presence_before {
            self.host.app_presence(true);
            if let Some(finished) = times.1 {
                self.host.app_presence_finished(
                    finished.saturating_duration_since(self.epoch).as_millis() as u64,
                );
            }
        }
    }

    /// Write queued packets, [`INPUT_REPORT_INTERVAL`] apart. Read output
    /// reports during the pauses so a long answer cannot starve the host.
    fn flush_pending(&mut self) -> io::Result<bool> {
        let mut wrote = false;
        while let Some(frame) = self.host.next_outgoing_frame() {
            if wrote {
                let resume = Instant::now() + INPUT_REPORT_INTERVAL;
                self.read_frames()?;
                if self.host.take_interrupt() {
                    self.app.interrupt();
                }
                thread::sleep(resume.saturating_duration_since(Instant::now()));
            }
            self.shutdown.check()?;
            self.host.handle_timeout(self.now());
            if !self.host.is_outgoing_current(&frame) {
                continue;
            }
            self.device.write_frame(frame.frame())?;
            assert!(self.host.outgoing_frame_written(&frame));
            wrote = true;
        }
        Ok(wrote)
    }

    /// Read every pending packet, exchange requests and answers with the
    /// app, send keepalives that are due, and write everything that produced.
    /// Returns whether anything happened.
    ///
    /// Fails with [`crate::shutdown::shutdown_error`] once shutdown has been
    /// requested, which is how [`serve`] gets out of its loop.
    /// Any error ends this session: callers must stop and drop the transport.
    /// Failed writes are not acknowledged and do not complete transactions.
    pub fn poll(&mut self) -> io::Result<bool> {
        self.shutdown.check()?;
        let mut did_work = self.read_frames()?;
        // Before anything new goes to the app: an interrupt is only meant for
        // the request the app has now.
        if self.host.take_interrupt() {
            self.app.interrupt();
        }
        did_work |= self.collect_responses()?;
        if let Some(request) = self.host.take_app_request() {
            self.app.submit(request, &self.waiting)?;
            did_work = true;
        }

        if let Some(request) = self.host.take_identification_request() {
            if !self
                .identification
                .as_ref()
                .is_some_and(|worker| worker.submit(request, self.epoch))
            {
                self.host
                    .identification_response(request.token, false, self.now());
            }
            did_work = true;
        }
        let now = self.now();
        self.observe_presence();
        self.host.handle_timeout(now);
        self.host.send_keepalive(self.waiting.get(), now);
        did_work |= self.flush_pending()?;
        Ok(did_work)
    }

    /// Wait until the device or the app has something, the next CTAPHID timer
    /// is due, or 10 ms have passed. Fails with
    /// [`crate::shutdown::shutdown_error`] once shutdown has been requested.
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
/// Returns only with an error: [`crate::shutdown::shutdown_error`] once
/// shutdown has
/// been requested, or whatever made the device or the app fail.
pub fn serve(transport: &mut Transport<'_, impl HidDevice>) -> io::Result<()> {
    loop {
        if !transport.poll()? {
            transport.wait()?;
        }
    }
}

/// Serve CTAPHID on `device` with `app` until the device or the app fails or
/// `shutdown` is requested; the latter ends with
/// [`crate::shutdown::shutdown_error`].
/// `on_ready` runs just before requests are served. `waiting` is what the app
/// reports through its keepalive callback.
///
/// `app` runs on a worker thread of its own, so the device keeps being served
/// while a request waits for the user. On the way out the request the app is
/// working on is cancelled through its interrupt flag, the device is
/// destroyed, and then the worker is joined: a presence prompt must honour
/// cancellation for this to return.
pub fn exec<'interrupt, A, D>(
    device: D,
    app: &mut A,
    waiting: &WaitingForUser,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
) -> io::Result<()>
where
    A: App<'interrupt> + Send + ?Sized,
    D: HidDevice,
{
    exec_with_identifier(device, app, waiting, shutdown, on_ready, |_| {
        Err(io::Error::other("device identification is unavailable"))
    })
}

/// Serve with a bounded platform identifier independent of the CTAP app.
pub fn exec_with_identifier<'interrupt, A, D>(
    device: D,
    app: &mut A,
    waiting: &WaitingForUser,
    shutdown: ShutdownSignal,
    on_ready: impl FnOnce() -> io::Result<()>,
    identifier: impl Identifier,
) -> io::Result<()>
where
    A: App<'interrupt> + Send + ?Sized,
    D: HidDevice,
{
    let interrupt = app.interrupt();
    let (wake, worker_wake) = UnixStream::pair()?;
    wake.set_nonblocking(true)?;
    worker_wake.set_nonblocking(true)?;
    let (request_sender, request_receiver) = mpsc::channel();
    let (response_sender, response_receiver) = mpsc::channel();

    let worker_wake_clone = worker_wake.try_clone()?;
    thread::scope(|scope| {
        let worker = thread::Builder::new()
            .name("ctap-app".into())
            .spawn_scoped(scope, move || {
                run_app(app, request_receiver, response_sender, worker_wake, waiting)
            })?;

        let (identification, identification_thread) =
            IdentificationWorker::spawn(scope, identifier, worker_wake_clone)?;
        let mut host = CtaphidHost::new();
        host.set_version(Version {
            major: 2,
            minor: 1,
            build: 0,
        });
        host.set_capabilities(CAPABILITY_CBOR | CAPABILITY_WINK);
        let mut transport = Transport {
            device,
            host,
            app: AppWorker {
                requests: Some(request_sender),
                responses: response_receiver,
                wake,
                interrupt,
                presence_before: None,
            },
            identification: Some(identification),
            waiting: waiting.clone(),
            epoch: Instant::now(),
            shutdown,
        };

        let result = on_ready().and_then(|()| serve(&mut transport));

        transport.app.stop();
        transport.identification.as_mut().unwrap().stop();
        drop(transport);
        let identification_result = identification_thread.join();
        if identification_result.is_err() {
            log::error!("the identification worker panicked");
        }
        match worker.join() {
            Ok(()) => result,
            Err(_) => Err(io::Error::other("the CTAP app panicked")),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::test_support::uhid;
    use crate::shutdown::is_shutdown;
    use crate::transport::ctaphid_host::Command;

    use crate::platform::test_support::socket_device;

    /// Answers CTAPHID_CBOR by echoing the request, or panics on 0xFF.
    struct EchoApp<'interrupt> {
        interrupt: &'interrupt InterruptFlag,
    }

    impl<'interrupt> App<'interrupt> for EchoApp<'interrupt> {
        fn interrupt(&self) -> &'interrupt InterruptFlag {
            self.interrupt
        }

        fn call(&mut self, request: &[u8]) -> Vec<u8> {
            assert_ne!(request, [0xFF], "the app fails");
            request.to_vec()
        }

        fn call_u2f(&mut self, request: &[u8]) -> Vec<u8> {
            self.call(request)
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
            &mut EchoApp {
                interrupt: &InterruptFlag::new(),
            },
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
            &mut EchoApp {
                interrupt: &InterruptFlag::new(),
            },
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
            &mut EchoApp {
                interrupt: &InterruptFlag::new(),
            },
            &WaitingForUser::new(),
            ShutdownSignal::new(),
            || Ok(()),
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "the CTAP app panicked");

        // Keepalives may go out while the app works on the request: a panic
        // that prints a backtrace can take longer than KEEPALIVE_INTERVAL_MS.
        // Then the device is destroyed.
        let mut events = Vec::new();
        device_side.read_to_end(&mut events).unwrap();
        assert_eq!(events.len() % uhid::UHID_EVENT_SIZE, 0);
        let events: Vec<&[u8]> = events.chunks(uhid::UHID_EVENT_SIZE).collect();
        let (last, keepalives) = events.split_last().unwrap();
        assert_eq!(event_type(last), uhid::UHID_EVENT_TYPE_DESTROY);
        for event in keepalives {
            let report = uhid::input_report(event).expect("an input report");
            assert_eq!(report[..4], 0x0102_0304u32.to_be_bytes());
            assert_eq!(report[4], Command::KeepAlive.into_u8() | 0x80);
        }
    }

    #[test]
    fn waiting_for_user_is_shared_between_clones() {
        let waiting = WaitingForUser::new();
        let app_side = waiting.clone();
        assert!(!waiting.get());
        thread::spawn(move || app_side.set(true)).join().unwrap();
        assert!(waiting.get());
    }

    /// The CTAPHID packets of a message on `channel`.
    fn message_frames(
        channel: u32,
        command: Command,
        payload: &[u8],
    ) -> Vec<[u8; CTAPHID_FRAME_LEN]> {
        let mut frames = Vec::new();
        let mut frame = [0u8; CTAPHID_FRAME_LEN];
        frame[..4].copy_from_slice(&channel.to_be_bytes());
        frame[4] = command.into_u8() | 0x80;
        frame[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let first = payload.len().min(CTAPHID_FRAME_LEN - 7);
        frame[7..7 + first].copy_from_slice(&payload[..first]);
        frames.push(frame);
        for (seq, chunk) in payload[first..].chunks(CTAPHID_FRAME_LEN - 5).enumerate() {
            let mut frame = [0u8; CTAPHID_FRAME_LEN];
            frame[..4].copy_from_slice(&channel.to_be_bytes());
            frame[4] = seq as u8;
            frame[5..5 + chunk.len()].copy_from_slice(chunk);
            frames.push(frame);
        }
        frames
    }

    /// While a long answer is paced out, one input report a millisecond,
    /// the transport keeps reading what the host writes, so the kernel's
    /// small output queue does not fill up behind it: a request that arrives
    /// during the answer is read and rejected as busy without truncating it.
    #[test]
    fn packets_arriving_while_an_answer_is_paced_out_are_read() {
        let (device, mut kernel) = socket_device();
        kernel
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        // Long enough that pacing it out takes tens of milliseconds, so the
        // second ping arrives while it goes out however slowly the host
        // thread is scheduled.
        let payload: Vec<u8> = (0..3000u32).map(|byte| byte as u8).collect();
        let frames = message_frames(0x0102_0304, Command::Ping, &payload);
        let echo = frames.len();
        for frame in &frames {
            kernel.write_all(&uhid::output_event(frame)).unwrap();
        }

        let interrupt = InterruptFlag::new();
        let (requests, _app_requests) = mpsc::channel();
        let (_app_responses, responses) = mpsc::channel();
        let (wake, _worker_wake) = UnixStream::pair().unwrap();
        wake.set_nonblocking(true).unwrap();
        let mut transport = Transport {
            device,
            host: CtaphidHost::new(),
            app: AppWorker {
                requests: Some(requests),
                responses,
                wake,
                interrupt: &interrupt,
                presence_before: None,
            },
            identification: None,
            waiting: WaitingForUser::new(),
            epoch: Instant::now(),
            shutdown: ShutdownSignal::new(),
        };

        // Settle the initial request before the single poll below flushes
        // its answer. A later poll must not hide a failure to read the second
        // ping during that flush.
        for expected in &frames {
            let frame = transport.device.read_settled_frame().unwrap().unwrap();
            assert_eq!(frame.as_bytes(), expected);
            let now = transport.now();
            transport.host.handle_frame(&frame, now);
        }

        let host = thread::spawn(move || {
            let mut reports = Vec::new();
            let mut event = vec![0u8; uhid::UHID_EVENT_SIZE];
            while reports.len() < echo + 1 {
                kernel.read_exact(&mut event).unwrap();
                if let Some(report) = uhid::input_report(&event) {
                    if reports.is_empty() {
                        // A second client pings while the answer goes out.
                        let ping = message_frames(0x0A0B_0C0D, Command::Ping, b"second");
                        kernel.write_all(&uhid::output_event(&ping[0])).unwrap();
                    }
                    reports.push(report);
                }
            }
            // Handed back so the device's end stays open until the checks
            // below are done; closed, it would read as end of file.
            (reports, kernel)
        });
        assert!(transport.poll().unwrap());
        let (reports, _kernel) = host.join().unwrap();
        assert_eq!(
            transport.device.read_settled_frame().unwrap(),
            None,
            "the ping was left unread"
        );
        // The echo stays intact; the request read during it is busy.
        assert!(
            reports[..echo]
                .iter()
                .all(|report| report[..4] == 0x0102_0304u32.to_be_bytes())
        );
        assert_eq!(reports[echo][..4], 0x0A0B_0C0Du32.to_be_bytes());
        assert_eq!(reports[echo][4], Command::Error.into_u8() | 0x80);
        assert_eq!(reports[echo][7], ctaphid_host::ErrorCode::ChannelBusy as u8);
        assert!(transport.host.next_outgoing_frame().is_none());
        transport.host.handle_frame(
            &CtapHidFrame::new(message_frames(0x0A0B_0C0D, Command::Ping, b"second")[0]),
            transport.now(),
        );
        assert_eq!(
            &transport.host.next_outgoing_frame().unwrap().frame().0[7..13],
            b"second"
        );
    }
}

#[cfg(test)]
mod transmission_tests {
    use super::*;
    use ctaphid_host::ErrorCode;
    use std::{cell::RefCell, collections::VecDeque, os::fd::BorrowedFd};

    struct Device {
        written: RefCell<Vec<CtapHidFrame>>,
        incoming: RefCell<VecDeque<CtapHidFrame>>,
        after: usize,
        fail_write: Option<usize>,
        fail_read: bool,
        stop: Option<ShutdownSignal>,
        _responses: mpsc::Sender<AppResponse>,
        destroyed: Arc<AtomicBool>,
    }

    impl Drop for Device {
        fn drop(&mut self) {
            self.destroyed.store(true, Ordering::SeqCst);
        }
    }

    impl HidDevice for Device {
        fn try_read_frame(&self) -> io::Result<Option<CtapHidFrame>> {
            if self.written.borrow().len() < self.after {
                return Ok(None);
            }
            if let Some(stop) = &self.stop {
                stop.request();
            }
            if self.fail_read {
                return Err(io::Error::other("scripted read failure"));
            }
            Ok(self.incoming.borrow_mut().pop_front())
        }

        fn write_frame(&self, frame: &CtapHidFrame) -> io::Result<()> {
            let mut written = self.written.borrow_mut();
            if self.fail_write == Some(written.len()) {
                return Err(io::Error::other("scripted write failure"));
            }
            written.push(*frame);
            Ok(())
        }

        fn wait_with(&self, _: BorrowedFd<'_>, _: Option<Duration>) -> io::Result<bool> {
            unreachable!()
        }
    }

    fn packet(channel: u32, command: Command, payload: &[u8]) -> CtapHidFrame {
        let mut bytes = [0; CTAPHID_FRAME_LEN];
        bytes[..4].copy_from_slice(&channel.to_be_bytes());
        bytes[4] = command as u8 | 0x80;
        bytes[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes[7..7 + payload.len()].copy_from_slice(payload);
        CtapHidFrame::new(bytes)
    }

    fn transport(interrupt: &InterruptFlag, length: usize) -> Transport<'_, Device> {
        let (requests, _) = mpsc::channel();
        let (responses, receiver) = mpsc::channel();
        let (wake, _peer) = UnixStream::pair().unwrap();
        wake.set_nonblocking(true).unwrap();
        let mut host = CtaphidHost::new();
        host.handle_frame(&packet(1, Command::Cbor, &[4]), 0);
        host.take_app_request().unwrap();
        host.app_response(vec![0x42; length], 1, None);
        Transport {
            device: Device {
                written: RefCell::new(Vec::new()),
                incoming: RefCell::new(VecDeque::new()),
                after: 1,
                fail_write: None,
                fail_read: false,
                stop: None,
                _responses: responses,
                destroyed: Arc::new(AtomicBool::new(false)),
            },
            host,
            app: AppWorker {
                requests: Some(requests),
                responses: receiver,
                wake,
                interrupt,
                presence_before: None,
            },
            identification: None,
            waiting: WaitingForUser::new(),
            epoch: Instant::now(),
            shutdown: ShutdownSignal::new(),
        }
    }

    #[test]
    fn init_read_between_selection_and_write_invalidates_the_local_frame() {
        for length in [58, MAX_MESSAGE_SIZE] {
            let interrupt = InterruptFlag::new();
            let mut transport = transport(&interrupt, length);
            transport
                .device
                .incoming
                .borrow_mut()
                .push_back(packet(1, Command::Init, &[9; 8]));
            assert!(transport.flush_pending().unwrap());
            let written = transport.device.written.borrow();
            assert_eq!(written.len(), 2, "no locally held continuation escaped");
            assert_eq!(written[0].0[4], Command::Cbor as u8 | 0x80);
            assert_eq!(written[1].0[4], Command::Init as u8 | 0x80);
            assert_eq!(&written[1].0[7..15], &[9; 8]);
            assert!(transport.device.incoming.borrow().is_empty());
        }
    }

    #[test]
    fn a_competitor_before_the_selected_last_frame_is_busy() {
        let interrupt = InterruptFlag::new();
        let mut transport = transport(&interrupt, 58);
        transport
            .device
            .incoming
            .borrow_mut()
            .push_back(packet(2, Command::Cbor, &[4]));
        assert!(transport.flush_pending().unwrap());
        assert!(transport.host.take_app_request().is_none());
        let written = transport.device.written.borrow();
        assert_eq!(written.len(), 3);
        assert_eq!(written[1].0[4], 0, "last continuation preserved");
        assert_eq!(
            written[2],
            packet(2, Command::Error, &[ErrorCode::ChannelBusy as u8])
        );
    }

    #[test]
    fn init_cancels_the_worker_and_discards_selected_keepalives() {
        let interrupt = InterruptFlag::new();
        let mut transport = transport(&interrupt, 1);
        transport.host = CtaphidHost::new();
        transport
            .host
            .handle_frame(&packet(1, Command::Cbor, &[4]), 0);
        transport.host.take_app_request().unwrap();
        interrupt.set_working();
        assert!(transport.host.send_keepalive(false, 50));
        assert!(transport.host.send_keepalive(true, 51));
        transport
            .device
            .incoming
            .borrow_mut()
            .push_back(packet(1, Command::Init, &[9; 8]));
        transport.flush_pending().unwrap();
        assert!(
            interrupt.is_interrupted(),
            "INIT is serviced during output pacing"
        );
        let written = transport.device.written.borrow();
        assert_eq!(written.len(), 2);
        assert_eq!(written[0].0[4], Command::KeepAlive as u8 | 0x80);
        assert_eq!(written[1].0[4], Command::Init as u8 | 0x80);
        drop(written);
        transport.host.app_response(vec![0x42; 200], 52, None);
        assert!(
            transport.host.next_outgoing_frame().is_none(),
            "late worker reply suppressed"
        );
        transport
            .host
            .handle_frame(&packet(2, Command::Cbor, &[5]), 53);
        assert_eq!(transport.host.take_app_request().unwrap().payload, [5]);
    }

    #[test]
    fn a_device_write_error_ends_exec_and_destroys_the_device() {
        struct NoCalls<'a>(&'a InterruptFlag);
        impl<'a> App<'a> for NoCalls<'a> {
            fn interrupt(&self) -> &'a InterruptFlag {
                self.0
            }
            fn call(&mut self, _: &[u8]) -> Vec<u8> {
                panic!("PING must not reach the worker")
            }
            fn call_u2f(&mut self, _: &[u8]) -> Vec<u8> {
                panic!("no MSG request")
            }
        }
        let interrupt = InterruptFlag::new();
        let mut transport = transport(&interrupt, 1);
        transport.device.after = 0;
        transport.device.fail_write = Some(0);
        transport
            .device
            .incoming
            .borrow_mut()
            .push_back(packet(1, Command::Ping, &[4]));
        let destroyed = Arc::clone(&transport.device.destroyed);
        let error = exec(
            transport.device,
            &mut NoCalls(&interrupt),
            &WaitingForUser::new(),
            ShutdownSignal::new(),
            || Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "scripted write failure");
        assert!(!crate::shutdown::is_shutdown(&error));
        assert!(destroyed.load(Ordering::SeqCst));
    }

    #[test]
    fn failed_writes_never_retire_the_selected_frame() {
        for (length, failure) in [(1, 0), (58, 0), (58, 1), (MAX_MESSAGE_SIZE, 128)] {
            let interrupt = InterruptFlag::new();
            let mut transport = transport(&interrupt, length);
            transport.device.fail_write = Some(failure);
            assert!(
                transport
                    .flush_pending()
                    .unwrap_err()
                    .to_string()
                    .contains("write failure")
            );
            assert_eq!(transport.device.written.borrow().len(), failure);
            let selected = transport.host.next_outgoing_frame().unwrap();
            assert!(transport.host.is_outgoing_current(&selected));
            transport
                .host
                .handle_frame(&packet(2, Command::Cbor, &[4]), 2);
            assert!(
                transport.host.take_app_request().is_none(),
                "failed final write still owns the CID"
            );
            assert!(transport.host.is_outgoing_current(&selected));
        }
    }

    #[test]
    fn shutdown_or_read_error_during_pacing_does_not_write_the_selected_frame() {
        for shutdown in [false, true] {
            let interrupt = InterruptFlag::new();
            let mut transport = transport(&interrupt, 58);
            if shutdown {
                transport.device.stop = Some(transport.shutdown.clone());
            } else {
                transport.device.fail_read = true;
            }
            let error = transport.flush_pending().unwrap_err();
            assert_eq!(crate::shutdown::is_shutdown(&error), shutdown);
            assert_eq!(transport.device.written.borrow().len(), 1);
            assert_eq!(
                transport.host.next_outgoing_frame().unwrap().frame().0[4],
                0
            );
        }
        let interrupt = InterruptFlag::new();
        let mut transport = transport(&interrupt, 1);
        transport.shutdown.request();
        assert!(crate::shutdown::is_shutdown(
            &transport.flush_pending().unwrap_err()
        ));
        assert!(transport.device.written.borrow().is_empty());
    }
}

#[cfg(test)]
mod callback_tests {
    use super::*;
    use crate::test_support::callback::{self, Event};

    #[test]
    fn callbacks_wake_a_wait_and_queued_reports_do_not_need_more_wake_bytes() {
        let (device, peer) = callback::pair();
        let (other, _writer) = UnixStream::pair().unwrap();
        thread::scope(|scope| {
            let sender = scope.spawn(|| {
                thread::sleep(Duration::from_millis(20));
                peer.send(&[1; 64]).unwrap();
                peer.send(&[2; 64]).unwrap();
            });
            assert!(
                device
                    .wait_with(other.as_fd(), Some(Duration::from_secs(5)))
                    .unwrap()
            );
            sender.join().unwrap();
        });
        assert_eq!(device.try_read_frame().unwrap().unwrap().0, [1; 64]);
        assert!(
            device
                .wait_with(other.as_fd(), Some(Duration::ZERO))
                .unwrap()
        );
        assert_eq!(device.try_read_frame().unwrap().unwrap().0, [2; 64]);
        assert!(device.try_read_frame().unwrap().is_none());
        drop(device);
        let mut reader = peer.try_clone().unwrap();
        assert!(matches!(reader.read_event().unwrap(), Event::Destroyed));
    }

    #[test]
    fn a_callback_device_waits_for_the_worker_and_honours_timeouts() {
        let (device, _peer) = callback::pair();
        let (other, mut writer) = UnixStream::pair().unwrap();
        let start = Instant::now();
        assert!(
            !device
                .wait_with(other.as_fd(), Some(Duration::from_millis(20)))
                .unwrap()
        );
        assert!(start.elapsed() >= Duration::from_millis(20));
        writer.write_all(&[0]).unwrap();
        assert!(
            device
                .wait_with(other.as_fd(), Some(Duration::from_secs(5)))
                .unwrap()
        );
    }

    struct Echo<'a>(&'a InterruptFlag);
    impl<'a> App<'a> for Echo<'a> {
        fn interrupt(&self) -> &'a InterruptFlag {
            self.0
        }
        fn call(&mut self, request: &[u8]) -> Vec<u8> {
            request.to_vec()
        }

        fn call_u2f(&mut self, request: &[u8]) -> Vec<u8> {
            self.call(request)
        }
    }

    #[test]
    fn the_transport_serves_callbacks_and_destroys_the_device_on_shutdown() {
        let (device, mut peer) = callback::pair();
        let shutdown = ShutdownSignal::new();
        let stop = shutdown.clone();
        let (sender, ready) = mpsc::channel();
        let worker = thread::spawn(move || {
            let flag = InterruptFlag::new();
            exec(
                device,
                &mut Echo(&flag),
                &WaitingForUser::new(),
                shutdown,
                || {
                    sender.send(()).unwrap();
                    Ok(())
                },
            )
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        let mut init = [0; 64];
        init[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        init[4] = 0x86;
        init[6] = 8;
        init[7..15].copy_from_slice(&[1; 8]);
        peer.send(&init).unwrap();
        let answer = peer.receive(Duration::from_secs(5)).unwrap().unwrap();
        assert_eq!(&answer[7..15], &[1; 8]);
        let mut request = [0; 64];
        request[..4].copy_from_slice(&answer[15..19]);
        request[4] = 0x90;
        request[6] = 1;
        request[7] = 0x42;
        peer.send(&request).unwrap();
        let answer = peer.receive(Duration::from_secs(5)).unwrap().unwrap();
        assert_eq!(&answer[..8], &request[..8]);
        stop.request();
        assert!(crate::shutdown::is_shutdown(
            &worker.join().unwrap().unwrap_err()
        ));
        assert!(matches!(peer.read_event().unwrap(), Event::Destroyed));
    }
}
