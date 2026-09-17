//! CTAPHID framing (CTAP 2.3 §11.2): packets in, requests out to the app,
//! responses and keepalives back as packets.
//!
//! [`CtaphidHost`] is a state machine without I/O, threads or clocks. The
//! transport ([`crate::UhidTransport`]) feeds it the packets the host sent
//! and the current time, passes the requests it hands out to the app,
//! reports the app's answers back, and sends the packets it queues.
//!
//! # Transactions
//!
//! One transaction is served at a time (§11.2.5.1). It starts with the
//! initialization packet of a request and is in one of two states:
//!
//! * **Receiving**: continuation packets are still expected. Each one must
//!   arrive within [`CONTINUATION_TIMEOUT_MS`] of the previous packet.
//! * **Processing**: the request is complete and the app is working on it
//!   (or will as soon as it is free). While a CTAPHID_CBOR request is
//!   processed, keepalives go out every [`KEEPALIVE_INTERVAL_MS`] and
//!   whenever their status changes.
//!
//! INIT and PING never reach the app; they are answered as soon as they are
//! complete. While a transaction is under way:
//!
//! * a request on any other channel fails with ERR_CHANNEL_BUSY;
//! * CTAPHID_INIT on the transaction's channel aborts it (resynchronisation);
//! * CTAPHID_CANCEL on the transaction's channel asks the app to cancel a
//!   CBOR request it is processing. The transaction goes on: the app's answer,
//!   CTAP2_ERR_KEEPALIVE_CANCEL or whatever it had already decided, is the
//!   response. CANCEL is never answered itself;
//! * any other request on the transaction's channel fails with
//!   ERR_INVALID_SEQ while receiving (and ends the transaction) and with
//!   ERR_CHANNEL_BUSY while processing (and does not).
//!
//! # The app outlives aborted transactions
//!
//! The app cannot be stopped, only asked to cancel. When a transaction is
//! aborted while the app works on it, the host asks the app to cancel, forgets
//! the transaction and discards the app's answer when it comes. A request
//! that completes in the meantime is held (keepalives report PROCESSING)
//! until the app is free.

use std::{collections::VecDeque, convert::TryInto};

use ctaphid_app::{Command, Error as AppError};
use getrandom::SysRng;
use log::debug;
use rand_core::{CryptoRng, UnwrapErr};

/// The operating system RNG; panics if it fails, as rand 0.8's `OsRng` did.
type OsRng = UnwrapErr<SysRng>;

use crate::uhid::{CTAPHID_FRAME_LEN, CtapHidFrame};

const PACKET_SIZE: usize = CTAPHID_FRAME_LEN;
const INIT_DATA: usize = PACKET_SIZE - 7;
const CONT_DATA: usize = PACKET_SIZE - 5;

/// The largest message: "a packet size of 64 bytes ... means that the maximum
/// message payload length is 64 - 7 + 128 * (64 - 5) = 7609 bytes" (CTAP 2.3
/// §11.2.4).
pub const MAX_MESSAGE_SIZE: usize = INIT_DATA + 128 * CONT_DATA;

/// The broadcast channel, "reserved for broadcast commands, i.e. at the time
/// of channel allocation" (CTAP 2.3 §11.2.3).
pub const BROADCAST_CID: u32 = 0xffff_ffff;

/// How long a message being received may wait for its next packet.
///
/// CTAP 2.3 §11.2.5.2 requires a timeout but sets no value: "A transaction
/// has to be completed within a specified period of time to prevent a
/// stalling application to cause the device to be completely locked out".
/// It is measured between packets rather than over the whole message, so a
/// slow host can still send the largest message (129 packets).
pub const CONTINUATION_TIMEOUT_MS: u64 = 550;

/// How often keepalives are sent while a CTAPHID_CBOR request is processed.
///
/// CTAP 2.3 §11.2.9.1.7: "It SHOULD be sent at least every 100ms and
/// whenever the status changes." Half of that leaves room for scheduling
/// delays.
pub const KEEPALIVE_INTERVAL_MS: u64 = 50;

/// CTAP2_ERR_KEEPALIVE_CANCEL, the CTAP status of a cancelled request.
pub const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2D;

/// How many channels CTAPHID_INIT keeps allocated. Every client that opens
/// the device allocates one and none is ever released, so the least recently
/// used channel is forgotten once this many exist.
pub const MAX_CHANNELS: usize = 256;

const CHANNEL_GENERATION_RETRY_LIMIT: usize = 64;
const LOG_PREVIEW: usize = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub build: u8,
}

/// CTAPHID_ERROR codes (CTAP 2.3 §11.2.9.1.6).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ErrorCode {
    InvalidCommand = 0x01,
    InvalidLength = 0x03,
    InvalidSeq = 0x04,
    Timeout = 0x05,
    ChannelBusy = 0x06,
    InvalidChannel = 0x0B,
    Other = 0x7F,
}

/// CTAPHID_KEEPALIVE status codes (CTAP 2.3 §11.2.9.1.7).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum KeepaliveStatus {
    Processing = 1,
    UpNeeded = 2,
}

/// A complete request for the app.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppRequest {
    pub command: Command,
    pub payload: Vec<u8>,
}

/// The channels allocated by CTAPHID_INIT, least recently used first.
///
/// CTAP 2.3 §11.2.3 leaves the allocation algorithm to the vendor: "The
/// actual algorithm for generation of channel identifiers is vendor specific
/// and not defined by this specification."
#[derive(Debug, Default)]
struct Channels {
    ids: VecDeque<u32>,
}

impl Channels {
    fn contains(&self, id: u32) -> bool {
        self.ids.contains(&id)
    }

    /// Mark `id` as just used, if it is allocated.
    fn touch(&mut self, id: u32) {
        if let Some(index) = self.ids.iter().position(|&known| known == id) {
            self.ids.remove(index);
            self.ids.push_back(id);
        }
    }

    /// Allocate `id`, forgetting the least recently used channel if the
    /// table is full. Returns false if `id` is already allocated.
    fn insert(&mut self, id: u32) -> bool {
        if self.contains(id) {
            return false;
        }
        if self.ids.len() == MAX_CHANNELS {
            self.ids.pop_front();
        }
        self.ids.push_back(id);
        true
    }

    fn len(&self) -> usize {
        self.ids.len()
    }
}

/// A complete request being processed by the app.
#[derive(Debug)]
struct Processing {
    channel: u32,
    command: Command,
    /// The payload, until the request is handed to the app.
    request: Option<Vec<u8>>,
    /// When the last keepalive was sent, or the request completed.
    keepalive_at: u64,
    /// The status of the last keepalive; PROCESSING before the first.
    keepalive_status: KeepaliveStatus,
}

#[derive(Debug)]
enum State {
    Idle,
    Receiving {
        channel: u32,
        command: Command,
        length: usize,
        next_sequence: u8,
        last_packet_at: u64,
    },
    Processing(Processing),
}

pub struct CtaphidHost<R = OsRng> {
    state: State,
    /// The message being received.
    message: Vec<u8>,
    pending: VecDeque<CtapHidFrame>,
    channels: Channels,
    rng: R,
    capabilities: u8,
    version: Version,
    /// The commands the app answers.
    app_commands: &'static [Command],
    /// Whether the app is working on a request, possibly for a transaction
    /// that has since been aborted.
    app_busy: bool,
    /// Whether the app should be asked to cancel what it is working on.
    interrupt_app: bool,
}

impl CtaphidHost<OsRng> {
    pub fn new(app_commands: &'static [Command]) -> Self {
        Self::with_rng(app_commands, UnwrapErr(SysRng))
    }
}

impl<R: CryptoRng> CtaphidHost<R> {
    pub fn with_rng(app_commands: &'static [Command], rng: R) -> Self {
        Self {
            state: State::Idle,
            message: Vec::with_capacity(MAX_MESSAGE_SIZE),
            pending: VecDeque::new(),
            channels: Channels::default(),
            rng,
            capabilities: 0,
            version: Version::default(),
            app_commands,
            app_busy: false,
            interrupt_app: false,
        }
    }

    pub fn set_version(&mut self, version: Version) {
        self.version = version;
    }

    pub fn set_capabilities(&mut self, capabilities: u8) {
        self.capabilities = capabilities;
    }

    /// Handle one packet from the host, received at `now` (milliseconds).
    pub fn handle_frame(&mut self, frame: &CtapHidFrame, now: u64) {
        let packet = frame.as_bytes();
        let channel = u32::from_be_bytes(packet[..4].try_into().unwrap());
        if packet[4] & 0x80 == 0 {
            self.handle_continuation(channel, packet[4], &packet[5..], now);
            return;
        }

        let command_byte = packet[4] & 0x7f;
        let length = u16::from_be_bytes([packet[5], packet[6]]) as usize;
        let data = &packet[7..];
        debug!(
            "RX init cid={channel:08x} cmd=0x{command_byte:02x} len={length} preview={:02x?}",
            &data[..length.min(LOG_PREVIEW)]
        );
        self.channels.touch(channel);
        match Command::try_from(command_byte) {
            Ok(Command::Cancel) => self.handle_cancel(channel),
            Ok(Command::Init) => self.handle_init(channel, length, data),
            command => self.handle_request(channel, command.ok(), length, data, now),
        }
    }

    /// Expire a message whose next packet is overdue.
    pub fn handle_timeout(&mut self, now: u64) {
        if let State::Receiving {
            channel,
            last_packet_at,
            ..
        } = self.state
            && now >= last_packet_at + CONTINUATION_TIMEOUT_MS
        {
            debug!("message timeout cid={channel:08x}");
            self.state = State::Idle;
            self.enqueue_error(channel, ErrorCode::Timeout);
        }
    }

    /// Queue a keepalive if one is due for the CBOR request being processed:
    /// [`KEEPALIVE_INTERVAL_MS`] after the last one, or at once when the
    /// status changes. `waiting_for_user` is what the app reports. Returns
    /// whether one was queued.
    pub fn send_keepalive(&mut self, waiting_for_user: bool, now: u64) -> bool {
        let State::Processing(processing) = &mut self.state else {
            return false;
        };
        if processing.command != Command::Cbor {
            return false;
        }
        // A held request is not being worked on, whatever the app reports
        // about the one it is finishing.
        let status = if waiting_for_user && processing.request.is_none() {
            KeepaliveStatus::UpNeeded
        } else {
            KeepaliveStatus::Processing
        };
        if status == processing.keepalive_status
            && now < processing.keepalive_at + KEEPALIVE_INTERVAL_MS
        {
            return false;
        }
        processing.keepalive_at = now;
        processing.keepalive_status = status;
        let channel = processing.channel;
        let mut frame = [0u8; PACKET_SIZE];
        frame[..4].copy_from_slice(&channel.to_be_bytes());
        frame[4] = Command::KeepAlive.into_u8() | 0x80;
        frame[5..7].copy_from_slice(&1u16.to_be_bytes());
        frame[7] = status as u8;
        debug!("TX keepalive cid={channel:08x} status={status:?}");
        self.pending.push_back(CtapHidFrame::new(frame));
        true
    }

    /// When [`handle_timeout`](Self::handle_timeout) or
    /// [`send_keepalive`](Self::send_keepalive) next has something to do,
    /// if anything.
    pub fn next_deadline(&self) -> Option<u64> {
        match &self.state {
            State::Idle => None,
            State::Receiving { last_packet_at, .. } => {
                Some(last_packet_at + CONTINUATION_TIMEOUT_MS)
            }
            State::Processing(processing) if processing.command == Command::Cbor => {
                Some(processing.keepalive_at + KEEPALIVE_INTERVAL_MS)
            }
            State::Processing(_) => None,
        }
    }

    /// The request the app should work on next, if the app is free and one
    /// is ready. The app must answer it through
    /// [`app_response`](Self::app_response).
    pub fn take_app_request(&mut self) -> Option<AppRequest> {
        if self.app_busy {
            return None;
        }
        let State::Processing(processing) = &mut self.state else {
            return None;
        };
        let payload = processing.request.take()?;
        self.app_busy = true;
        Some(AppRequest {
            command: processing.command,
            payload,
        })
    }

    /// Whether the app should be asked to cancel the request it is working
    /// on. Reading this clears it.
    pub fn take_interrupt(&mut self) -> bool {
        std::mem::take(&mut self.interrupt_app)
    }

    /// Whether the app is working on a request.
    pub fn app_busy(&self) -> bool {
        self.app_busy
    }

    /// The app's answer to the request last taken with
    /// [`take_app_request`](Self::take_app_request).
    pub fn app_response(&mut self, response: Result<Vec<u8>, AppError>) {
        self.app_busy = false;
        let State::Processing(processing) = &self.state else {
            debug!("discarding the app's response to an aborted transaction");
            return;
        };
        if processing.request.is_some() {
            // The transaction the app answered was aborted, and this one is
            // still waiting for the app.
            debug!("discarding the app's response to an aborted transaction");
            return;
        }
        let (channel, command) = (processing.channel, processing.command);
        self.state = State::Idle;
        match response {
            Ok(payload) => self.enqueue_message(channel, command, &payload),
            Err(error) => {
                let code = match error {
                    AppError::InvalidCommand => ErrorCode::InvalidCommand,
                    AppError::InvalidLength => ErrorCode::InvalidLength,
                    AppError::NoResponse => ErrorCode::Other,
                };
                self.enqueue_error(channel, code);
            }
        }
    }

    pub fn has_pending_frames(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn next_outgoing_frame(&mut self) -> Option<CtapHidFrame> {
        self.pending.pop_front()
    }

    /// The channel of the transaction under way, if any.
    fn busy_channel(&self) -> Option<u32> {
        match &self.state {
            State::Idle => None,
            State::Receiving { channel, .. } => Some(*channel),
            State::Processing(processing) => Some(processing.channel),
        }
    }

    /// CTAP 2.3 §11.2.9.1.5: "If there is an outstanding request that can be
    /// cancelled, the authenticator MUST cancel it and that cancelled request
    /// will reply with the error CTAP2_ERR_KEEPALIVE_CANCEL." ... "the
    /// authenticator MUST NOT reply to the CTAPHID_CANCEL message itself" ...
    /// "A CTAPHID_CANCEL received while no CTAPHID_CBOR request is being
    /// processed, or on a non-active CID SHALL be ignored by the
    /// authenticator."
    fn handle_cancel(&mut self, channel: u32) {
        let State::Processing(processing) = &self.state else {
            return;
        };
        if processing.channel != channel || processing.command != Command::Cbor {
            return;
        }
        if processing.request.is_some() {
            // The app has not started on it: it is cancelled here.
            debug!("cancelled cid={channel:08x} before the app started");
            self.state = State::Idle;
            self.enqueue_message(channel, Command::Cbor, &[CTAP2_ERR_KEEPALIVE_CANCEL]);
        } else {
            // The app answers, with CTAP2_ERR_KEEPALIVE_CANCEL if it could
            // still cancel.
            debug!("cancelling cid={channel:08x}");
            self.interrupt_app = true;
        }
    }

    /// CTAP 2.3 §11.2.9.1.3. On an allocated channel INIT "synchronizes a
    /// channel, discarding the current transaction, buffers and state as
    /// quickly as possible"; on the broadcast channel it allocates one.
    fn handle_init(&mut self, channel: u32, length: usize, data: &[u8]) {
        match self.busy_channel() {
            Some(busy) if busy != channel => {
                self.enqueue_error(channel, ErrorCode::ChannelBusy);
                return;
            }
            _ => {}
        }
        if length != 8 {
            self.enqueue_error(channel, ErrorCode::InvalidLength);
            return;
        }
        // §11.2.5.3: "If the device detects an INIT command during a
        // transaction that has the same channel id as the active transaction,
        // the transaction is aborted (if possible) and all buffered data
        // flushed (if any)."
        if let State::Processing(processing) = &self.state
            && processing.request.is_none()
        {
            self.interrupt_app = true;
        }
        let aborted = !matches!(self.state, State::Idle);
        if aborted {
            debug!("INIT aborts the transaction on cid={channel:08x}");
            self.state = State::Idle;
        }

        let assigned = if channel == BROADCAST_CID {
            match self.allocate_channel() {
                Some(assigned) => assigned,
                None => {
                    self.enqueue_error(channel, ErrorCode::ChannelBusy);
                    return;
                }
            }
        } else if aborted || self.channels.contains(channel) {
            // A channel that had a transaction is in use, even if it has
            // dropped out of the table.
            channel
        } else {
            self.enqueue_error(channel, ErrorCode::InvalidChannel);
            return;
        };

        let mut response = [0u8; 17];
        response[..8].copy_from_slice(&data[..8]);
        response[8..12].copy_from_slice(&assigned.to_be_bytes());
        response[12] = 2; // CTAPHID protocol version
        response[13] = self.version.major;
        response[14] = self.version.minor;
        response[15] = self.version.build;
        response[16] = self.capabilities;
        self.enqueue_message(channel, Command::Init, &response);
    }

    /// The initialization packet of any request but INIT and CANCEL.
    /// `command` is `None` for an undefined command code.
    fn handle_request(
        &mut self,
        channel: u32,
        command: Option<Command>,
        length: usize,
        data: &[u8],
        now: u64,
    ) {
        if let Some(busy) = self.busy_channel() {
            // §11.2.5.1: "If an application tries to access the device from a
            // different channel while the device is busy with a transaction,
            // that request will immediately fail with a busy-error message
            // sent to the requesting channel."
            if busy != channel || matches!(self.state, State::Processing(_)) {
                self.enqueue_error(channel, ErrorCode::ChannelBusy);
                return;
            }
            // A new message on a channel that has not finished sending the
            // last one: §11.2.9.1.6 "ERR_INVALID_SEQ: The sequence does not
            // match expected value". The half-received message is dropped.
            self.state = State::Idle;
            self.enqueue_error(channel, ErrorCode::InvalidSeq);
            return;
        }

        if channel == 0 || channel == BROADCAST_CID {
            self.enqueue_error(channel, ErrorCode::InvalidChannel);
            return;
        }
        let command = match command {
            Some(command @ Command::Ping) => command,
            Some(command) if self.app_commands.contains(&command) => command,
            _ => {
                self.enqueue_error(channel, ErrorCode::InvalidCommand);
                return;
            }
        };
        if length > MAX_MESSAGE_SIZE {
            self.enqueue_error(channel, ErrorCode::InvalidLength);
            return;
        }

        self.message.clear();
        self.message
            .extend_from_slice(&data[..length.min(INIT_DATA)]);
        if length <= INIT_DATA {
            self.complete_message(channel, command, now);
        } else {
            self.state = State::Receiving {
                channel,
                command,
                length,
                next_sequence: 0,
                last_packet_at: now,
            };
        }
    }

    /// CTAP 2.3 §11.2.5.4: "The device keeps track of packets arriving in
    /// correct and ascending order and that no expected packets are missing.
    /// ... Spurious continuation packets appearing without a prior
    /// initialization packet will be ignored."
    fn handle_continuation(&mut self, channel: u32, sequence: u8, data: &[u8], now: u64) {
        let State::Receiving {
            channel: receiving,
            command,
            length,
            next_sequence,
            last_packet_at,
        } = &mut self.state
        else {
            return;
        };
        if *receiving != channel {
            return;
        }
        if sequence != *next_sequence {
            debug!("RX cont cid={channel:08x} seq={sequence}, expected {next_sequence}");
            self.state = State::Idle;
            self.enqueue_error(channel, ErrorCode::InvalidSeq);
            return;
        }
        *next_sequence += 1;
        *last_packet_at = now;
        let (command, length) = (*command, *length);
        let missing = length - self.message.len();
        self.message
            .extend_from_slice(&data[..missing.min(CONT_DATA)]);
        if self.message.len() == length {
            self.complete_message(channel, command, now);
        }
    }

    fn complete_message(&mut self, channel: u32, command: Command, now: u64) {
        if command == Command::Ping {
            // §11.2.9.1.4: the device "immediately echoes the same data back".
            self.state = State::Idle;
            let message = std::mem::take(&mut self.message);
            self.enqueue_message(channel, command, &message);
            self.message = message;
            return;
        }
        if command == Command::Cbor {
            debug!(
                "request cid={channel:08x} ctap=0x{:02x} len={}",
                self.message.first().copied().unwrap_or_default(),
                self.message.len()
            );
        }
        self.state = State::Processing(Processing {
            channel,
            command,
            request: Some(self.message.clone()),
            keepalive_at: now,
            keepalive_status: KeepaliveStatus::Processing,
        });
    }

    /// Queue the packets of a message.
    ///
    /// A message holds at most [`MAX_MESSAGE_SIZE`] bytes: its length must
    /// fit the two-byte BCNT of the initialization packet, and its
    /// continuation packets the sequence numbers 0 to 0x7f, "the sequence
    /// number of each continuation packet [...] incremented for each
    /// continuation packet" with the high bit reserved for initialization
    /// packets (CTAP 2.3 §11.2.4).  A longer payload, which only the app can
    /// produce, is not sent: the channel gets ERR_OTHER instead.
    fn enqueue_message(&mut self, channel: u32, command: Command, payload: &[u8]) {
        debug!(
            "TX cid={channel:08x} cmd=0x{:02x} len={} preview={:02x?}",
            command.into_u8(),
            payload.len(),
            &payload[..payload.len().min(LOG_PREVIEW)]
        );
        let Some(length) = u16::try_from(payload.len())
            .ok()
            .filter(|_| payload.len() <= MAX_MESSAGE_SIZE)
        else {
            log::error!(
                "a {}-byte response to cid={channel:08x} exceeds the {MAX_MESSAGE_SIZE} bytes a message can hold",
                payload.len()
            );
            self.enqueue_error(channel, ErrorCode::Other);
            return;
        };
        let mut frame = [0u8; PACKET_SIZE];
        frame[..4].copy_from_slice(&channel.to_be_bytes());
        frame[4] = command.into_u8() | 0x80;
        frame[5..7].copy_from_slice(&length.to_be_bytes());
        let (head, rest) = payload.split_at(payload.len().min(INIT_DATA));
        frame[7..7 + head.len()].copy_from_slice(head);
        self.pending.push_back(CtapHidFrame::new(frame));

        for (sequence, chunk) in (0..=0x7f_u8).zip(rest.chunks(CONT_DATA)) {
            let mut frame = [0u8; PACKET_SIZE];
            frame[..4].copy_from_slice(&channel.to_be_bytes());
            frame[4] = sequence;
            frame[5..5 + chunk.len()].copy_from_slice(chunk);
            self.pending.push_back(CtapHidFrame::new(frame));
        }
    }

    fn enqueue_error(&mut self, channel: u32, code: ErrorCode) {
        self.enqueue_message(channel, Command::Error, &[code as u8]);
    }

    fn allocate_channel(&mut self) -> Option<u32> {
        for _ in 0..CHANNEL_GENERATION_RETRY_LIMIT {
            let candidate = self.rng.next_u32();
            if candidate == 0 || candidate == BROADCAST_CID {
                continue;
            }
            if self.channels.insert(candidate) {
                debug!(
                    "allocated cid={candidate:08x} ({} channels)",
                    self.channels.len()
                );
                return Some(candidate);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CAPABILITY_CBOR, CAPABILITY_NMSG};
    use rand_core::{Infallible, TryCryptoRng, TryRng};

    const APP_COMMANDS: &[Command] = &[Command::Cbor];
    const FIRST: u32 = 0x0A0A_0A0A;
    const SECOND: u32 = 0x0B0B_0B0B;

    #[derive(Clone)]
    struct TestRng {
        values: Vec<u32>,
        index: usize,
    }

    impl TestRng {
        fn new(values: &[u32]) -> Self {
            Self {
                values: values.to_vec(),
                index: 0,
            }
        }
    }

    impl TryRng for TestRng {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            let value = *self.values.get(self.index).expect("test RNG exhausted");
            self.index += 1;
            Ok(value)
        }

        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            unimplemented!()
        }

        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Infallible> {
            unimplemented!()
        }
    }

    impl TryCryptoRng for TestRng {}

    fn host() -> CtaphidHost<TestRng> {
        host_with_channels(&[])
    }

    fn host_with_channels(ids: &[u32]) -> CtaphidHost<TestRng> {
        let mut host = CtaphidHost::with_rng(APP_COMMANDS, TestRng::new(ids));
        host.set_capabilities(CAPABILITY_CBOR | CAPABILITY_NMSG);
        host
    }

    /// A CTAPHID message split into its initialization and continuation
    /// packets, as a host sends it.
    fn message_packets(channel: u32, command: u8, payload: &[u8]) -> Vec<CtapHidFrame> {
        let mut first = [0u8; PACKET_SIZE];
        first[..4].copy_from_slice(&channel.to_be_bytes());
        first[4] = command | 0x80;
        first[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let (head, rest) = payload.split_at(payload.len().min(INIT_DATA));
        first[7..7 + head.len()].copy_from_slice(head);
        let mut packets = vec![CtapHidFrame::new(first)];
        for (sequence, chunk) in rest.chunks(CONT_DATA).enumerate() {
            let mut packet = [0u8; PACKET_SIZE];
            packet[..4].copy_from_slice(&channel.to_be_bytes());
            packet[4] = sequence as u8;
            packet[5..5 + chunk.len()].copy_from_slice(chunk);
            packets.push(CtapHidFrame::new(packet));
        }
        packets
    }

    fn send<R: CryptoRng>(
        host: &mut CtaphidHost<R>,
        channel: u32,
        command: Command,
        payload: &[u8],
        now: u64,
    ) {
        for packet in message_packets(channel, command.into_u8(), payload) {
            host.handle_frame(&packet, now);
        }
    }

    /// A message the host sent back, reassembled.
    #[derive(Debug, PartialEq, Eq)]
    struct Message {
        channel: u32,
        command: u8,
        payload: Vec<u8>,
    }

    fn message(channel: u32, command: Command, payload: &[u8]) -> Message {
        Message {
            channel,
            command: command.into_u8(),
            payload: payload.to_vec(),
        }
    }

    fn error(channel: u32, code: ErrorCode) -> Message {
        message(channel, Command::Error, &[code as u8])
    }

    fn keepalive(channel: u32, status: KeepaliveStatus) -> Message {
        message(channel, Command::KeepAlive, &[status as u8])
    }

    /// Every message queued so far, checking the packets' framing.
    fn sent<R: CryptoRng>(host: &mut CtaphidHost<R>) -> Vec<Message> {
        let mut messages = Vec::new();
        while let Some(frame) = host.next_outgoing_frame() {
            let packet = frame.as_bytes();
            assert_ne!(packet[4] & 0x80, 0, "continuation packet out of place");
            let channel = u32::from_be_bytes(packet[..4].try_into().unwrap());
            let length = u16::from_be_bytes([packet[5], packet[6]]) as usize;
            let mut payload = packet[7..7 + length.min(INIT_DATA)].to_vec();
            let mut sequence = 0;
            while payload.len() < length {
                let frame = host.next_outgoing_frame().expect("a continuation packet");
                let packet = frame.as_bytes();
                assert_eq!(packet[..4], channel.to_be_bytes());
                assert_eq!(packet[4], sequence);
                let missing = length - payload.len();
                payload.extend_from_slice(&packet[5..5 + missing.min(CONT_DATA)]);
                sequence += 1;
            }
            messages.push(Message {
                channel,
                command: packet[4] & 0x7f,
                payload,
            });
        }
        messages
    }

    /// Complete a CBOR request on `channel` and hand it to the app.
    fn start_cbor<R: CryptoRng>(host: &mut CtaphidHost<R>, channel: u32, payload: &[u8], now: u64) {
        send(host, channel, Command::Cbor, payload, now);
        let request = host.take_app_request().expect("a request for the app");
        assert_eq!(request.command, Command::Cbor);
        assert_eq!(request.payload, payload);
    }

    #[test]
    fn handles_init() {
        let mut host = host_with_channels(&[0x1234_5678]);
        host.set_version(Version {
            major: 2,
            minor: 1,
            build: 7,
        });
        send(
            &mut host,
            BROADCAST_CID,
            Command::Init,
            &[1, 2, 3, 4, 5, 6, 7, 8],
            0,
        );
        let mut expected = vec![1, 2, 3, 4, 5, 6, 7, 8, 0x12, 0x34, 0x56, 0x78, 2, 2, 1, 7];
        expected.push(CAPABILITY_CBOR | CAPABILITY_NMSG);
        assert_eq!(
            sent(&mut host),
            [message(BROADCAST_CID, Command::Init, &expected)]
        );
    }

    #[test]
    fn broadcast_init_skips_reserved_ids() {
        let mut host = host_with_channels(&[0, BROADCAST_CID, 0x1234_5678]);
        send(&mut host, BROADCAST_CID, Command::Init, &[0xAA; 8], 0);
        assert_eq!(sent(&mut host)[0].payload[8..12], [0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn broadcast_init_retries_on_collision() {
        let mut host = host_with_channels(&[0x0102_0304, 0x0102_0304, 0x0BAD_F00D]);
        send(&mut host, BROADCAST_CID, Command::Init, &[1; 8], 0);
        assert_eq!(
            sent(&mut host)[0].payload[8..12],
            0x0102_0304u32.to_be_bytes()
        );
        send(&mut host, BROADCAST_CID, Command::Init, &[2; 8], 1);
        assert_eq!(
            sent(&mut host)[0].payload[8..12],
            0x0BAD_F00Du32.to_be_bytes()
        );
    }

    #[test]
    fn reinit_existing_channel_reuses_cid() {
        let mut host = host_with_channels(&[0xA1A2_A3A4]);
        send(&mut host, BROADCAST_CID, Command::Init, &[1; 8], 0);
        assert_eq!(
            sent(&mut host)[0].payload[8..12],
            0xA1A2_A3A4u32.to_be_bytes()
        );
        send(&mut host, 0xA1A2_A3A4, Command::Init, &[2; 8], 1);
        let response = sent(&mut host);
        assert_eq!(response[0].channel, 0xA1A2_A3A4);
        assert_eq!(
            response[0].payload[..12],
            [2, 2, 2, 2, 2, 2, 2, 2, 0xA1, 0xA2, 0xA3, 0xA4]
        );

        send(&mut host, 0x5555_5555, Command::Init, &[3; 8], 2);
        assert_eq!(
            sent(&mut host),
            [error(0x5555_5555, ErrorCode::InvalidChannel)]
        );
    }

    /// Send CTAPHID_INIT on `channel` and return the response.
    fn init_on(host: &mut CtaphidHost<TestRng>, channel: u32) -> Message {
        send(host, channel, Command::Init, &[0x5A; 8], 0);
        let mut messages = sent(host);
        assert_eq!(messages.len(), 1);
        messages.remove(0)
    }

    /// Broadcast INITs never release a channel, so the table of allocated
    /// channels is bounded and forgets the least recently used one.
    #[test]
    fn allocated_channels_are_bounded_and_the_least_recently_used_is_forgotten() {
        let ids: Vec<u32> = (1..=MAX_CHANNELS as u32 + 1).collect();
        let mut host = host_with_channels(&ids);
        let init = Command::Init.into_u8();

        for &id in &ids[..MAX_CHANNELS] {
            assert_eq!(
                init_on(&mut host, BROADCAST_CID).payload[8..12],
                id.to_be_bytes()
            );
        }
        // Channel 1 is used again, so channel 2 is now the least recently used.
        assert_eq!(init_on(&mut host, 1).command, init);

        let response = init_on(&mut host, BROADCAST_CID);
        assert_eq!(
            response.payload[8..12],
            (MAX_CHANNELS as u32 + 1).to_be_bytes()
        );
        assert_eq!(host.channels.len(), MAX_CHANNELS);
        assert_eq!(init_on(&mut host, 2), error(2, ErrorCode::InvalidChannel));
        assert_eq!(init_on(&mut host, 1).command, init);
        assert_eq!(init_on(&mut host, 3).command, init);
    }

    #[test]
    fn ping_echoes_a_multi_packet_payload() {
        let mut host = host();
        let payload: Vec<u8> = (0..=255).cycle().take(MAX_MESSAGE_SIZE).collect();
        send(&mut host, FIRST, Command::Ping, &payload, 0);
        assert_eq!(sent(&mut host), [message(FIRST, Command::Ping, &payload)]);
        assert!(host.take_app_request().is_none());
    }

    #[test]
    fn cbor_requests_go_to_the_app_and_its_response_back() {
        let mut host = host();
        let request = [0x42u8; 300];
        start_cbor(&mut host, FIRST, &request, 0);
        assert!(sent(&mut host).is_empty());
        assert!(host.app_busy());

        let response = vec![0x00; 1000];
        host.app_response(Ok(response.clone()));
        assert!(!host.app_busy());
        assert_eq!(sent(&mut host), [message(FIRST, Command::Cbor, &response)]);
        assert!(!host.send_keepalive(true, 1_000), "no transaction");
    }

    #[test]
    fn app_errors_are_ctaphid_errors() {
        let mut host = host();
        for (error_from_app, code) in [
            (AppError::InvalidCommand, ErrorCode::InvalidCommand),
            (AppError::InvalidLength, ErrorCode::InvalidLength),
            // ERR_OTHER is 0x7F (§11.2.9.1.6); it used to be sent as 0x0C.
            (AppError::NoResponse, ErrorCode::Other),
        ] {
            start_cbor(&mut host, FIRST, &[0x04], 0);
            host.app_response(Err(error_from_app));
            assert_eq!(sent(&mut host), [error(FIRST, code)]);
        }
    }

    /// The largest response goes out in 129 packets; a longer one would need
    /// a BCNT or sequence numbers CTAPHID does not have (CTAP 2.3 §11.2.4),
    /// and fails with ERR_OTHER instead of being sent malformed.
    #[test]
    fn responses_longer_than_a_message_are_errors() {
        let mut host = host();
        let largest: Vec<u8> = (0..=255).cycle().take(MAX_MESSAGE_SIZE).collect();
        start_cbor(&mut host, FIRST, &[0x04], 0);
        host.app_response(Ok(largest.clone()));
        assert_eq!(host.pending.len(), 129);
        assert_eq!(sent(&mut host), [message(FIRST, Command::Cbor, &largest)]);

        for length in [MAX_MESSAGE_SIZE + 1, usize::from(u16::MAX) + 1] {
            start_cbor(&mut host, FIRST, &[0x04], 0);
            host.app_response(Ok(vec![0; length]));
            assert_eq!(
                sent(&mut host),
                [error(FIRST, ErrorCode::Other)],
                "{length} bytes"
            );
        }
        // The channel is free again.
        send(&mut host, FIRST, Command::Ping, &[1], 0);
        assert_eq!(sent(&mut host), [message(FIRST, Command::Ping, &[1])]);
    }

    #[test]
    fn requests_the_app_does_not_answer_are_invalid_commands() {
        let mut host = host();
        // CTAPHID_MSG (CAPABILITY_NMSG), WINK and LOCK (not advertised), and
        // an undefined command code.
        for command in [0x03, 0x08, 0x04, 0x02] {
            host.handle_frame(&message_packets(FIRST, command, &[0; 70])[0], 0);
            assert_eq!(sent(&mut host), [error(FIRST, ErrorCode::InvalidCommand)]);
        }
        // Nothing is left half received.
        send(&mut host, SECOND, Command::Ping, &[1], 0);
        assert_eq!(sent(&mut host), [message(SECOND, Command::Ping, &[1])]);
    }

    #[test]
    fn reserved_channels_and_oversized_messages_are_rejected() {
        let mut host = host();
        send(&mut host, 0, Command::Ping, &[1], 0);
        send(&mut host, BROADCAST_CID, Command::Cbor, &[4], 0);
        send(&mut host, 0, Command::Init, &[0; 8], 0);
        send(&mut host, FIRST, Command::Init, &[0; 7], 0);
        let mut oversized = message_packets(FIRST, Command::Ping.into_u8(), &[])[0];
        oversized.0[5..7].copy_from_slice(&(MAX_MESSAGE_SIZE as u16 + 1).to_be_bytes());
        host.handle_frame(&oversized, 0);
        assert_eq!(
            sent(&mut host),
            [
                error(0, ErrorCode::InvalidChannel),
                error(BROADCAST_CID, ErrorCode::InvalidChannel),
                error(0, ErrorCode::InvalidChannel),
                error(FIRST, ErrorCode::InvalidLength),
                error(FIRST, ErrorCode::InvalidLength),
            ]
        );
    }

    /// CTAP 2.3 §11.2.5.1: a request from another channel while a request is
    /// being received fails with ERR_CHANNEL_BUSY. That error must leave the
    /// request being received alone; it used to be written into the first
    /// byte of the message buffer, turning makeCredential (0x01) into
    /// clientPIN (0x06).
    #[test]
    fn an_error_for_another_channel_leaves_a_request_being_received_intact() {
        let mut host = host();
        let request: Vec<u8> = (0..100u8).map(|i| if i == 0 { 0x01 } else { i }).collect();
        let packets = message_packets(FIRST, Command::Cbor.into_u8(), &request);
        assert_eq!(packets.len(), 2);

        host.handle_frame(&packets[0], 0);
        send(&mut host, SECOND, Command::Cbor, &[0x04], 1);
        assert_eq!(sent(&mut host), [error(SECOND, ErrorCode::ChannelBusy)]);

        host.handle_frame(&packets[1], 2);
        assert_eq!(host.take_app_request().unwrap().payload, request);
    }

    /// CTAP 2.3 §11.2.9.1.5: "A CTAPHID_CANCEL received while no
    /// CTAPHID_CBOR request is being processed, or on a non-active CID SHALL
    /// be ignored by the authenticator."
    #[test]
    fn cancel_while_idle_receiving_or_on_another_channel_is_ignored() {
        let mut host = host();
        send(&mut host, FIRST, Command::Cancel, &[], 0);
        assert!(sent(&mut host).is_empty(), "CANCEL while idle");

        let request = [0x04u8; 100];
        let packets = message_packets(FIRST, Command::Cbor.into_u8(), &request);
        host.handle_frame(&packets[0], 1);
        send(&mut host, SECOND, Command::Cancel, &[], 2);
        send(&mut host, FIRST, Command::Cancel, &[], 2);
        assert!(sent(&mut host).is_empty(), "CANCEL while receiving");
        host.handle_frame(&packets[1], 3);
        assert_eq!(host.take_app_request().unwrap().payload, request);

        send(&mut host, SECOND, Command::Cancel, &[], 4);
        assert!(sent(&mut host).is_empty(), "CANCEL on another channel");
        assert!(!host.take_interrupt());
    }

    /// CTAP 2.3 §11.2.9.1.5: "The CTAP2_ERR_KEEPALIVE_CANCEL response MUST be
    /// the response to that request, not an error response in the HID
    /// transport." It used to be sent as CTAPHID_ERROR 0x2D, which is not a
    /// CTAPHID error code.
    #[test]
    fn cancel_asks_the_app_and_its_answer_is_the_cbor_response() {
        let mut host = host();
        start_cbor(&mut host, FIRST, &[0x01, 0xA0], 0);
        send(&mut host, FIRST, Command::Cancel, &[], 10);
        assert!(host.take_interrupt());
        assert!(!host.take_interrupt(), "reading clears it");
        assert!(sent(&mut host).is_empty(), "CANCEL is not answered");

        // Still processing: other channels are busy and keepalives go on.
        send(&mut host, SECOND, Command::Ping, &[1], 20);
        assert!(host.send_keepalive(false, 60));
        assert_eq!(
            sent(&mut host),
            [
                error(SECOND, ErrorCode::ChannelBusy),
                keepalive(FIRST, KeepaliveStatus::Processing)
            ]
        );

        host.app_response(Ok(vec![CTAP2_ERR_KEEPALIVE_CANCEL]));
        assert_eq!(
            sent(&mut host),
            [message(FIRST, Command::Cbor, &[CTAP2_ERR_KEEPALIVE_CANCEL])]
        );
    }

    /// A request that is complete but waits for the app to finish an aborted
    /// one has not started, so CANCEL answers it at once.
    #[test]
    fn cancel_of_a_request_the_app_has_not_started_answers_it() {
        let mut host = host();
        start_cbor(&mut host, FIRST, &[0x02], 0);
        send(&mut host, FIRST, Command::Init, &[0; 8], 1);
        send(&mut host, FIRST, Command::Cbor, &[0x04], 2);
        assert!(host.take_app_request().is_none(), "the app is busy");
        sent(&mut host);

        send(&mut host, FIRST, Command::Cancel, &[], 3);
        assert_eq!(
            sent(&mut host),
            [message(FIRST, Command::Cbor, &[CTAP2_ERR_KEEPALIVE_CANCEL])]
        );
        host.app_response(Ok(vec![0x00]));
        assert!(sent(&mut host).is_empty());
        assert!(host.take_app_request().is_none());
    }

    /// CTAP 2.3 §11.2.9.1.7: a keepalive "SHOULD be sent at least every 100ms
    /// and whenever the status changes", and not on every pass of the loop.
    #[test]
    fn keepalives_follow_the_interval_and_status_changes() {
        let mut host = host();
        assert_eq!(host.next_deadline(), None);
        start_cbor(&mut host, FIRST, &[0x01], 1_000);
        assert_eq!(host.next_deadline(), Some(1_000 + KEEPALIVE_INTERVAL_MS));

        let mut sent_at = Vec::new();
        for now in 1_000..1_400 {
            if host.send_keepalive(false, now) {
                sent_at.push(now);
            }
        }
        assert_eq!(sent_at, [1_050, 1_100, 1_150, 1_200, 1_250, 1_300, 1_350]);
        assert_eq!(host.next_deadline(), Some(1_400));
        sent(&mut host);

        assert!(host.send_keepalive(true, 1_360), "status change");
        assert!(!host.send_keepalive(true, 1_361));
        assert!(host.send_keepalive(false, 1_362), "status change");
        assert!(host.send_keepalive(true, 1_363), "status change");
        assert!(!host.send_keepalive(true, 1_412));
        assert!(host.send_keepalive(true, 1_413));
        assert_eq!(
            sent(&mut host),
            [
                keepalive(FIRST, KeepaliveStatus::UpNeeded),
                keepalive(FIRST, KeepaliveStatus::Processing),
                keepalive(FIRST, KeepaliveStatus::UpNeeded),
                keepalive(FIRST, KeepaliveStatus::UpNeeded),
            ]
        );

        host.app_response(Ok(vec![0x00]));
        assert!(
            !host.send_keepalive(true, 2_000),
            "no keepalive after the response"
        );
    }

    /// There is no limit on how long the app may take: a presence prompt can
    /// last 30 s and the engine's own timeout governs it. Requests used to be
    /// abandoned with an error after 2 s.
    #[test]
    fn the_app_may_take_as_long_as_it_needs() {
        let mut host = host();
        start_cbor(&mut host, FIRST, &[0x01], 0);
        for now in (0..=60_000).step_by(10) {
            host.handle_timeout(now);
            host.send_keepalive(true, now);
        }
        let messages = sent(&mut host);
        assert!(
            messages
                .iter()
                .all(|m| *m == keepalive(FIRST, KeepaliveStatus::UpNeeded))
        );
        assert!(!host.take_interrupt());
        host.app_response(Ok(vec![0x00, 0xA0]));
        assert_eq!(
            sent(&mut host),
            [message(FIRST, Command::Cbor, &[0x00, 0xA0])]
        );
    }

    /// Only CTAPHID_CBOR is cancellable and gets keepalives.
    #[test]
    fn requests_other_than_cbor_get_no_keepalives() {
        const VENDOR: &[Command] = &[Command::Cbor, Command::Wink];
        let mut host = CtaphidHost::with_rng(VENDOR, TestRng::new(&[]));
        send(&mut host, FIRST, Command::Wink, &[], 0);
        assert_eq!(host.take_app_request().unwrap().command, Command::Wink);
        assert_eq!(host.next_deadline(), None);
        assert!(!host.send_keepalive(true, 1_000));
        send(&mut host, FIRST, Command::Cancel, &[], 1_000);
        assert!(!host.take_interrupt());
        host.app_response(Ok(vec![]));
        assert_eq!(sent(&mut host), [message(FIRST, Command::Wink, &[])]);
    }

    /// CTAP 2.3 §11.2.5.2 and §11.2.5.4: a message must be completed in time,
    /// packet by packet. The timeout used to run from the initialization
    /// packet, so a slow host could not send a long message at all.
    #[test]
    fn the_receive_timeout_runs_from_the_last_packet() {
        let mut host = host();
        let payload = [0x77u8; 300];
        let packets = message_packets(FIRST, Command::Ping.into_u8(), &payload);
        assert_eq!(packets.len(), 6);
        let mut now = 0;
        for packet in &packets {
            host.handle_timeout(now);
            host.handle_frame(packet, now);
            assert_eq!(
                host.next_deadline(),
                (packet != packets.last().unwrap()).then_some(now + CONTINUATION_TIMEOUT_MS)
            );
            now += CONTINUATION_TIMEOUT_MS - 1;
        }
        assert_eq!(sent(&mut host), [message(FIRST, Command::Ping, &payload)]);

        host.handle_frame(&packets[0], 10_000);
        host.handle_frame(&packets[1], 10_100);
        host.handle_timeout(10_100 + CONTINUATION_TIMEOUT_MS - 1);
        assert!(sent(&mut host).is_empty());
        host.handle_timeout(10_100 + CONTINUATION_TIMEOUT_MS);
        assert_eq!(sent(&mut host), [error(FIRST, ErrorCode::Timeout)]);
        // The rest of the message is ignored, and the device is free.
        host.handle_frame(&packets[2], 10_700);
        send(&mut host, SECOND, Command::Ping, &[1], 10_700);
        assert_eq!(sent(&mut host), [message(SECOND, Command::Ping, &[1])]);
    }

    #[test]
    fn packets_out_of_sequence_end_the_message() {
        let mut host = host();
        let packets = message_packets(FIRST, Command::Ping.into_u8(), &[1u8; 200]);
        host.handle_frame(&packets[0], 0);
        host.handle_frame(&packets[2], 1);
        assert_eq!(sent(&mut host), [error(FIRST, ErrorCode::InvalidSeq)]);
        host.handle_frame(&packets[1], 2);
        assert!(sent(&mut host).is_empty(), "spurious continuation packet");
        send(&mut host, SECOND, Command::Ping, &[1], 3);
        assert_eq!(sent(&mut host), [message(SECOND, Command::Ping, &[1])]);
    }

    /// CTAP 2.3 §11.2.5.3: "If the device detects an INIT command during a
    /// transaction that has the same channel id as the active transaction,
    /// the transaction is aborted (if possible) and all buffered data flushed
    /// (if any)." INIT used to be answered with ERR_INVALID_SEQ and the
    /// transaction kept going.
    #[test]
    fn init_on_the_channel_being_received_resynchronises_it() {
        let mut host = host_with_channels(&[FIRST]);
        init_on(&mut host, BROADCAST_CID);
        let packets = message_packets(FIRST, Command::Cbor.into_u8(), &[0x01; 100]);
        host.handle_frame(&packets[0], 0);

        send(&mut host, FIRST, Command::Init, &[9; 8], 1);
        let response = sent(&mut host);
        assert_eq!(response.len(), 1);
        assert_eq!(response[0].command, Command::Init.into_u8());
        assert_eq!(
            response[0].payload[..12],
            [9, 9, 9, 9, 9, 9, 9, 9, 0x0A, 0x0A, 0x0A, 0x0A]
        );

        host.handle_frame(&packets[1], 2);
        assert!(host.take_app_request().is_none(), "the old message is gone");
        host.handle_timeout(10_000);
        start_cbor(&mut host, FIRST, &[0x04], 10_000);
    }

    #[test]
    fn init_on_the_channel_being_processed_aborts_it_and_the_late_answer_is_discarded() {
        let mut host = host_with_channels(&[FIRST]);
        init_on(&mut host, BROADCAST_CID);
        start_cbor(&mut host, FIRST, &[0x01], 0);

        send(&mut host, FIRST, Command::Init, &[9; 8], 1);
        assert!(host.take_interrupt(), "the app is asked to cancel");
        assert_eq!(sent(&mut host)[0].command, Command::Init.into_u8());

        // The next request waits for the app, reporting PROCESSING even though
        // the app still waits for the user on the aborted one.
        send(&mut host, FIRST, Command::Cbor, &[0x04], 2);
        assert!(host.take_app_request().is_none());
        assert!(host.send_keepalive(true, 2 + KEEPALIVE_INTERVAL_MS));
        assert_eq!(
            sent(&mut host),
            [keepalive(FIRST, KeepaliveStatus::Processing)]
        );

        host.app_response(Ok(vec![CTAP2_ERR_KEEPALIVE_CANCEL]));
        assert!(sent(&mut host).is_empty(), "the late answer is discarded");
        assert_eq!(host.take_app_request().unwrap().payload, [0x04]);
        host.app_response(Ok(vec![0x00]));
        assert_eq!(sent(&mut host), [message(FIRST, Command::Cbor, &[0x00])]);
    }

    #[test]
    fn a_new_request_on_a_busy_channel_is_rejected_without_ending_the_transaction() {
        let mut host = host();
        start_cbor(&mut host, FIRST, &[0x01], 0);
        send(&mut host, FIRST, Command::Cbor, &[0x04], 1);
        send(&mut host, FIRST, Command::Ping, &[1], 1);
        send(&mut host, SECOND, Command::Init, &[0; 8], 1);
        send(&mut host, BROADCAST_CID, Command::Init, &[0; 8], 1);
        assert_eq!(
            sent(&mut host),
            [
                error(FIRST, ErrorCode::ChannelBusy),
                error(FIRST, ErrorCode::ChannelBusy),
                error(SECOND, ErrorCode::ChannelBusy),
                error(BROADCAST_CID, ErrorCode::ChannelBusy),
            ]
        );
        assert!(host.take_app_request().is_none());
        host.app_response(Ok(vec![0x00]));
        assert_eq!(sent(&mut host), [message(FIRST, Command::Cbor, &[0x00])]);

        // While receiving, a new message on the same channel replaces nothing.
        let packets = message_packets(FIRST, Command::Ping.into_u8(), &[1; 100]);
        host.handle_frame(&packets[0], 2);
        send(&mut host, FIRST, Command::Ping, &[2], 3);
        host.handle_frame(&packets[1], 4);
        assert_eq!(sent(&mut host), [error(FIRST, ErrorCode::InvalidSeq)]);
    }
}
