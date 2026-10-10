//! Polling through the real worker and a blocking engine presence provider.

use super::*;
use nix::poll::{PollFd, PollFlags, poll};
use pqkey_ctap::ctap::presence::{Cancellation, PresenceOutcome, PresenceRequest, UserPresence};
use pqkey_ctap::store::{MemoryStore, PrivateKeyMaterial};
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicU8, AtomicUsize};

struct Device {
    input: mpsc::Receiver<CtapHidFrame>,
    output: mpsc::Sender<CtapHidFrame>,
    wake: UnixStream,
    destroyed: Arc<AtomicBool>,
}

#[test]
fn a_presence_prompt_that_finishes_between_polls_does_not_wait_for_key_generation() {
    let (input, requests) = mpsc::channel();
    let (answers, output) = mpsc::channel();
    let (wake, peer_wake) = UnixStream::pair().unwrap();
    wake.set_nonblocking(true).unwrap();
    let device = Device {
        input: requests,
        output: answers,
        wake,
        destroyed: Arc::new(AtomicBool::new(false)),
    };
    let shutdown = ShutdownSignal::new();
    let stop = shutdown.clone();
    let worker = thread::spawn(move || {
        let interrupt = InterruptFlag::new();
        let waiting = WaitingForUser::new();
        let mut app = CtapApp::new(
            MemoryStore::new(),
            rand_core::UnwrapErr(getrandom::SysRng),
            pqkey_ctap::ctap::presence::AutoApprove,
            &interrupt,
            [0; 16],
        );
        app.set_key_generator(|alg| {
            thread::sleep(Duration::from_millis(800));
            PrivateKeyMaterial::try_generate(alg)
        });
        let signal = waiting.clone();
        app.set_keepalive_callback(move |value| signal.set(value));
        exec(device, &mut app, &waiting, shutdown, || Ok(()))
    });
    let request = [vec![0, 1, 0, 0, 0, 0, 64], vec![0x42; 64]].concat();
    send(&input, &peer_wake, 1, Command::Msg, &request);
    assert_eq!(receive(&output), (1, Command::Msg as u8, vec![0x69, 0x85]));
    stop.request();
    assert!(crate::shutdown::is_shutdown(
        &worker.join().unwrap().unwrap_err()
    ));
}

impl HidDevice for Device {
    fn try_read_frame(&self) -> io::Result<Option<CtapHidFrame>> {
        let mut bytes = [0; 16];
        while matches!((&self.wake).read(&mut bytes), Ok(n) if n > 0) {}
        Ok(self.input.try_recv().ok())
    }
    fn write_frame(&self, frame: &CtapHidFrame) -> io::Result<()> {
        self.output
            .send(*frame)
            .map_err(|_| io::Error::other("test peer stopped"))
    }
    fn wait_with(&self, other: BorrowedFd<'_>, timeout: Option<Duration>) -> io::Result<bool> {
        let mut descriptors = [
            PollFd::new(self.wake.as_fd(), PollFlags::POLLIN),
            PollFd::new(other, PollFlags::POLLIN),
        ];
        let timeout =
            nix::poll::PollTimeout::try_from(timeout.unwrap_or(Duration::from_millis(10)))
                .map_err(io::Error::other)?;
        poll(&mut descriptors, timeout)
            .map(|n| n > 0)
            .map_err(io::Error::other)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        self.destroyed.store(true, Ordering::SeqCst);
    }
}

struct Presence {
    decision: Arc<AtomicU8>,
    prompts: Arc<AtomicUsize>,
}

impl UserPresence for Presence {
    fn confirm(
        &mut self,
        _: &PresenceRequest<'_>,
        cancellation: Cancellation<'_>,
    ) -> PresenceOutcome {
        self.prompts.fetch_add(1, Ordering::SeqCst);
        loop {
            if cancellation.is_cancelled() {
                return PresenceOutcome::Cancelled;
            }
            match self.decision.load(Ordering::SeqCst) {
                1 => return PresenceOutcome::Approved,
                2 => return PresenceOutcome::Denied,
                _ => thread::sleep(Duration::from_millis(1)),
            }
        }
    }
}

fn send(
    input: &mpsc::Sender<CtapHidFrame>,
    wake: &UnixStream,
    channel: u32,
    command: Command,
    payload: &[u8],
) {
    let mut first = [0; 64];
    first[..4].copy_from_slice(&channel.to_be_bytes());
    first[4] = command as u8 | 0x80;
    first[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let head = payload.len().min(57);
    first[7..7 + head].copy_from_slice(&payload[..head]);
    input.send(CtapHidFrame::new(first)).unwrap();
    for (sequence, chunk) in payload[head..].chunks(59).enumerate() {
        let mut frame = [0; 64];
        frame[..4].copy_from_slice(&channel.to_be_bytes());
        frame[4] = sequence as u8;
        frame[5..5 + chunk.len()].copy_from_slice(chunk);
        input.send(CtapHidFrame::new(frame)).unwrap();
    }
    (&*wake).write_all(&[1]).unwrap();
}

fn receive(output: &mpsc::Receiver<CtapHidFrame>) -> (u32, u8, Vec<u8>) {
    loop {
        let first = output.recv_timeout(Duration::from_secs(5)).unwrap().0;
        let command = first[4] & 0x7f;
        if command == Command::KeepAlive as u8 {
            continue;
        }
        let channel = u32::from_be_bytes(first[..4].try_into().unwrap());
        let length = usize::from(u16::from_be_bytes([first[5], first[6]]));
        let mut payload = first[7..7 + length.min(57)].to_vec();
        let mut sequence = 0;
        while payload.len() < length {
            let frame = output.recv_timeout(Duration::from_secs(5)).unwrap().0;
            assert_eq!(&frame[..4], &first[..4]);
            assert_eq!(frame[4], sequence);
            sequence += 1;
            payload.extend_from_slice(&frame[5..5 + (length - payload.len()).min(59)]);
        }
        return (channel, command, payload);
    }
}

#[test]
fn the_worker_keeps_one_prompt_and_shutdown_cancels_it_before_joining() {
    let (input, requests) = mpsc::channel();
    let (answers, output) = mpsc::channel();
    let (wake, peer_wake) = UnixStream::pair().unwrap();
    wake.set_nonblocking(true).unwrap();
    let destroyed = Arc::new(AtomicBool::new(false));
    let device = Device {
        input: requests,
        output: answers,
        wake,
        destroyed: destroyed.clone(),
    };
    let decision = Arc::new(AtomicU8::new(0));
    let prompts = Arc::new(AtomicUsize::new(0));
    let presence = Presence {
        decision: decision.clone(),
        prompts: prompts.clone(),
    };
    let shutdown = ShutdownSignal::new();
    let stop = shutdown.clone();
    let worker = thread::spawn(move || {
        let interrupt = InterruptFlag::new();
        let waiting = WaitingForUser::new();
        let mut app = CtapApp::new(
            MemoryStore::new(),
            rand_core::UnwrapErr(getrandom::SysRng),
            presence,
            &interrupt,
            [0; 16],
        );
        let signal = waiting.clone();
        app.set_keepalive_callback(move |value| signal.set(value));
        exec(device, &mut app, &waiting, shutdown, || Ok(()))
    });
    let request = [vec![0, 1, 0, 0, 0, 0, 64], vec![0x42; 64]].concat();
    for _ in 0..3 {
        send(&input, &peer_wake, 1, Command::Msg, &request);
        assert_eq!(receive(&output), (1, Command::Msg as u8, vec![0x69, 0x85]));
    }
    assert_eq!(prompts.load(Ordering::SeqCst), 1);
    send(&input, &peer_wake, 2, Command::Cbor, &[4]);
    assert_eq!(receive(&output), (2, Command::Error as u8, vec![6]));
    decision.store(1, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(5);
    let registration = loop {
        send(&input, &peer_wake, 1, Command::Msg, &request);
        let (channel, command, reply) = receive(&output);
        assert_eq!((channel, command), (1, Command::Msg as u8));
        if reply.ends_with(&[0x90, 0]) {
            assert_eq!(reply[66], 107);
            break reply;
        }
        assert_eq!(reply, [0x69, 0x85]);
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(prompts.load(Ordering::SeqCst), 1);
    let authentication = [
        vec![0, 2, 3, 0, 0, 0, 172],
        vec![0x42; 64],
        vec![107],
        registration[67..174].to_vec(),
    ]
    .concat();
    decision.store(2, Ordering::SeqCst);
    send(&input, &peer_wake, 1, Command::Msg, &authentication);
    assert_eq!(receive(&output), (1, Command::Msg as u8, vec![0x69, 0x85]));
    assert_eq!(prompts.load(Ordering::SeqCst), 2);
    decision.store(1, Ordering::SeqCst);
    send(&input, &peer_wake, 1, Command::Cbor, &[7]);
    assert_eq!(receive(&output), (1, Command::Cbor as u8, vec![0]));
    send(&input, &peer_wake, 1, Command::Msg, &authentication);
    assert_eq!(receive(&output), (1, Command::Msg as u8, vec![0x6a, 0x80]));
    assert_eq!(prompts.load(Ordering::SeqCst), 3);
    decision.store(0, Ordering::SeqCst);
    send(&input, &peer_wake, 1, Command::Msg, &request);
    assert_eq!(receive(&output), (1, Command::Msg as u8, vec![0x69, 0x85]));
    stop.request();
    assert!(crate::shutdown::is_shutdown(
        &worker.join().unwrap().unwrap_err()
    ));
    assert!(destroyed.load(Ordering::SeqCst));
    assert_eq!(prompts.load(Ordering::SeqCst), 4);
}
