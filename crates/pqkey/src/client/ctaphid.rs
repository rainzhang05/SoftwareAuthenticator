//! A CTAPHID client (CTAP 2.3 §11.2): what a platform does to talk to a key
//! over HID, one transaction at a time, at the pace of the protocol.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use crate::transport::ctaphid_host::{BROADCAST_CID, Command};
use crate::uhid::CTAPHID_FRAME_LEN;

/// A 64-byte HID report.
pub type Report = [u8; CTAPHID_FRAME_LEN];

/// How reports reach the key and come back: a hidraw node, or in tests the
/// kernel's side of a uhid device.
pub trait ReportLink {
    /// Send one output report.
    fn send(&mut self, report: &Report) -> io::Result<()>;
    /// The next input report, or `None` if none arrives within `timeout`.
    fn receive(&mut self, timeout: Duration) -> io::Result<Option<Report>>;
}

/// The payload of an initialization packet: 64 − 7 bytes (§11.2.4).
const INIT_DATA: usize = CTAPHID_FRAME_LEN - 7;
/// The payload of a continuation packet: 64 − 5 bytes.
const CONT_DATA: usize = CTAPHID_FRAME_LEN - 5;
/// ERR_CHANNEL_BUSY, CTAPHID_ERROR's code while another channel's
/// transaction runs (§11.2.9.1.7).
const ERR_CHANNEL_BUSY: u8 = 0x06;
/// The KEEPALIVE status that asks for the user (§11.2.9.1.5).
pub const STATUS_UPNEEDED: u8 = 0x02;

/// How long without any packet, not even a keepalive, before the key counts
/// as gone: it sends a keepalive every 100 ms at most while it works.
const IDLE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long to keep retrying while another client's transaction keeps the
/// key busy: "the client SHOULD retry the request" (§11.2.9.1.6, in the
/// spirit of ERR_CHANNEL_BUSY).
const BUSY_RETRY_FOR: Duration = Duration::from_secs(10);
const BUSY_RETRY_INTERVAL: Duration = Duration::from_millis(100);

/// What went wrong talking CTAPHID.
#[derive(Debug)]
pub enum HidError {
    /// The link failed.
    Io(io::Error),
    /// The key answered CTAPHID_ERROR with this code.
    Ctaphid(u8),
    /// No packet arrived for 3 seconds, not even a keepalive.
    Silent,
    /// The key answered something that is not CTAPHID.
    Malformed(&'static str),
    /// Another client's transaction kept the key busy.
    Busy,
}

impl From<io::Error> for HidError {
    fn from(err: io::Error) -> Self {
        HidError::Io(err)
    }
}

impl std::fmt::Display for HidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HidError::Io(err) => write!(f, "cannot talk to the key: {err}"),
            HidError::Ctaphid(code) => write!(f, "the key answered CTAPHID error {code:#04x}"),
            HidError::Silent => f.write_str("the key stopped answering"),
            HidError::Malformed(what) => write!(f, "the key's answer is malformed: {what}"),
            HidError::Busy => f.write_str(
                "the key is busy with another program's request, such as a browser waiting for \
                 your approval; finish or cancel that first",
            ),
        }
    }
}

/// A CTAPHID channel to the key.
pub struct CtapHid<L> {
    link: L,
    channel: u32,
    /// Once set, a request that waits for the user is cancelled.
    cancel: Arc<AtomicBool>,
}

impl<L: ReportLink> CtapHid<L> {
    /// Allocate a channel with CTAPHID_INIT on the broadcast channel
    /// (§11.2.9.1.3), retrying while the key is busy with another client.
    pub fn open(link: L) -> Result<Self, HidError> {
        Self::open_within(link, BUSY_RETRY_FOR)
    }

    /// [`open`](Self::open), retrying for at most `patience` while the key
    /// is busy.
    pub fn open_within(mut link: L, patience: Duration) -> Result<Self, HidError> {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(|err| HidError::Io(io::Error::other(err)))?;
        let deadline = Instant::now() + patience;
        loop {
            send_message(&mut link, BROADCAST_CID, Command::Init, &nonce)?;
            match receive_message(
                &mut link,
                BROADCAST_CID,
                &AtomicBool::new(false),
                &mut |_| {},
                |payload| payload.starts_with(&nonce),
            ) {
                Ok(payload) => {
                    let channel = payload
                        .get(8..12)
                        .map(|cid| u32::from_be_bytes(cid.try_into().expect("4 bytes")))
                        .ok_or(HidError::Malformed("a short INIT response"))?;
                    return Ok(Self {
                        link,
                        channel,
                        cancel: Arc::default(),
                    });
                }
                Err(HidError::Ctaphid(ERR_CHANNEL_BUSY)) if Instant::now() < deadline => {
                    thread::sleep(BUSY_RETRY_INTERVAL);
                }
                Err(HidError::Ctaphid(ERR_CHANNEL_BUSY)) => return Err(HidError::Busy),
                Err(err) => return Err(err),
            }
        }
    }

    /// Cancel a request that waits for the user once `flag` is set, for
    /// example by a SIGINT handler.
    pub fn with_cancel_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.cancel = flag;
        self
    }

    /// Send a CTAPHID_CBOR request and return the response, status byte
    /// included.  `keepalive` sees each KEEPALIVE status, so the caller can
    /// tell the user to approve; the cancel flag
    /// ([`with_cancel_flag`](Self::with_cancel_flag)) sends CTAPHID_CANCEL.
    pub fn cbor(
        &mut self,
        request: &[u8],
        keepalive: &mut dyn FnMut(u8),
    ) -> Result<Vec<u8>, HidError> {
        let deadline = Instant::now() + BUSY_RETRY_FOR;
        loop {
            send_message(&mut self.link, self.channel, Command::Cbor, request)?;
            match receive_message(
                &mut self.link,
                self.channel,
                &self.cancel,
                keepalive,
                |_| true,
            ) {
                Err(HidError::Ctaphid(ERR_CHANNEL_BUSY)) if Instant::now() < deadline => {
                    thread::sleep(BUSY_RETRY_INTERVAL);
                }
                Err(HidError::Ctaphid(ERR_CHANNEL_BUSY)) => return Err(HidError::Busy),
                other => return other,
            }
        }
    }
}

/// Send `payload` as `command` on `channel`: an initialization packet, then
/// continuation packets with sequence numbers from 0 (§11.2.4).
fn send_message<L: ReportLink>(
    link: &mut L,
    channel: u32,
    command: Command,
    payload: &[u8],
) -> Result<(), HidError> {
    let length =
        u16::try_from(payload.len()).map_err(|_| HidError::Malformed("a request too long"))?;
    let (first, rest) = payload.split_at(payload.len().min(INIT_DATA));
    let mut report = [0u8; CTAPHID_FRAME_LEN];
    report[..4].copy_from_slice(&channel.to_be_bytes());
    report[4] = command.into_u8() | 0x80;
    report[5..7].copy_from_slice(&length.to_be_bytes());
    report[7..7 + first.len()].copy_from_slice(first);
    link.send(&report)?;
    for (sequence, chunk) in rest.chunks(CONT_DATA).enumerate() {
        let mut report = [0u8; CTAPHID_FRAME_LEN];
        report[..4].copy_from_slice(&channel.to_be_bytes());
        report[4] =
            u8::try_from(sequence).map_err(|_| HidError::Malformed("a request too long"))?;
        report[5..5 + chunk.len()].copy_from_slice(chunk);
        link.send(&report)?;
    }
    Ok(())
}

/// The next message on `channel` that `accept` takes: KEEPALIVE statuses go
/// to `keepalive`, CTAPHID_ERROR is an error, packets of other channels
/// (every reader of a hidraw node sees every report) are skipped.  Once
/// `cancel` is set, the request is cancelled with CTAPHID_CANCEL
/// (§11.2.9.1.5), once, and its answer awaited.
fn receive_message<L: ReportLink>(
    link: &mut L,
    channel: u32,
    cancel: &AtomicBool,
    keepalive: &mut dyn FnMut(u8),
    accept: impl Fn(&[u8]) -> bool,
) -> Result<Vec<u8>, HidError> {
    let mut cancelled = false;
    loop {
        let report = link.receive(IDLE_TIMEOUT)?.ok_or(HidError::Silent)?;
        if u32::from_be_bytes(report[..4].try_into().expect("4 bytes")) != channel
            || report[4] & 0x80 == 0
        {
            continue;
        }
        let command = report[4] & 0x7F;
        let length = usize::from(u16::from_be_bytes([report[5], report[6]]));
        let mut payload = report[7..7 + length.min(INIT_DATA)].to_vec();
        let mut sequence = 0u8;
        while payload.len() < length {
            let next = link.receive(IDLE_TIMEOUT)?.ok_or(HidError::Silent)?;
            if u32::from_be_bytes(next[..4].try_into().expect("4 bytes")) != channel {
                continue;
            }
            if next[4] != sequence {
                return Err(HidError::Malformed("a continuation packet out of sequence"));
            }
            let missing = length - payload.len();
            payload.extend_from_slice(&next[5..5 + missing.min(CONT_DATA)]);
            sequence = sequence.wrapping_add(1);
        }
        match Command::try_from(command) {
            Ok(Command::KeepAlive) => {
                keepalive(payload.first().copied().unwrap_or(0));
                if !cancelled && cancel.load(Ordering::Relaxed) {
                    cancelled = true;
                    send_message(link, channel, Command::Cancel, &[])?;
                }
            }
            Ok(Command::Error) => {
                return Err(HidError::Ctaphid(payload.first().copied().unwrap_or(0)));
            }
            Ok(_) if accept(&payload) => return Ok(payload),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key that answers every request with CTAPHID_ERROR ERR_CHANNEL_BUSY,
    /// as one does while another client's transaction runs.
    struct BusyKey {
        answer: Option<Report>,
    }

    impl ReportLink for BusyKey {
        fn send(&mut self, report: &Report) -> io::Result<()> {
            let mut answer = [0u8; CTAPHID_FRAME_LEN];
            answer[..4].copy_from_slice(&report[..4]);
            answer[4] = Command::Error.into_u8() | 0x80;
            answer[6] = 1;
            answer[7] = ERR_CHANNEL_BUSY;
            self.answer = Some(answer);
            Ok(())
        }

        fn receive(&mut self, _timeout: Duration) -> io::Result<Option<Report>> {
            Ok(self.answer.take())
        }
    }

    #[test]
    fn a_busy_key_is_given_up_on_after_the_patience_asked_for() {
        let started = Instant::now();
        let result = CtapHid::open_within(BusyKey { answer: None }, Duration::from_millis(300));
        assert!(matches!(result, Err(HidError::Busy)));
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(300), "{waited:?}");
        assert!(waited < Duration::from_secs(2), "{waited:?}");
        assert!(
            HidError::Busy
                .to_string()
                .contains("finish or cancel that first")
        );
    }
}
