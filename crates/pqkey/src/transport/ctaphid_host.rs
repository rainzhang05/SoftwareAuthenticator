//! CTAPHID framing (CTAP 2.3 §11.2): packets in, requests out to the app,
//! responses and keepalives back as packets.
//!
//! [`CtaphidHost`] is a state machine without I/O, threads or clocks. The
//! transport ([`crate::Transport`]) feeds it the packets the host sent
//! and the current time, passes the requests it hands out to the app,
//! reports the app's answers back, and sends the packets it queues.
//!
//! # Transactions
//!
//! One transaction is served at a time (§11.2.5.1). It starts with the
//! initialization packet of a request and is in one of three states:
//!
//! * **Receiving**: continuation packets are still expected. Each one must
//!   arrive within [`CONTINUATION_TIMEOUT_MS`] of the previous packet.
//! * **Processing**: the request is complete and the app is working on it
//!   (or will as soon as it is free). While a CTAPHID_CBOR request is
//!   processed, keepalives go out every [`KEEPALIVE_INTERVAL_MS`] and
//!   whenever their status changes.
//! * **Transmitting**: the response is queued or being written. The CID
//!   remains owned until the transport reports the final successful device
//!   write through [`CtaphidHost::outgoing_frame_written`]. Selecting that
//!   report does not complete the transaction. Auxiliary errors and
//!   keepalives do not release ownership.
//!
//! The app answers CTAPHID_CBOR and CTAPHID_MSG. INIT and PING are
//! answered as soon as they are complete, and every other command with
//! ERR_INVALID_CMD. U2F presence polling retains a worker operation across
//! completed MSG transactions; identical repeats collect its answer once.
//! While a transaction or a U2F prompt is under way:
//!
//! * a request on any other channel fails with ERR_CHANNEL_BUSY;
//! * CTAPHID_INIT on the transaction's channel aborts it (resynchronisation);
//! * CTAPHID_CANCEL on the transaction's channel asks the app to cancel a
//!   CBOR request it is processing. The transaction goes on: the app's answer,
//!   CTAP2_ERR_KEEPALIVE_CANCEL or whatever it had already decided, is the
//!   response. CANCEL is never answered itself;
//! * any other request on the transaction's channel fails with
//!   ERR_INVALID_SEQ while receiving (and ends the transaction) and with
//!   ERR_CHANNEL_BUSY while processing or transmitting (and does not).
//!
//! A valid same-CID INIT discards received data and all unsent output on
//! that CID. It invalidates selected reports too: the transport rechecks
//! their tokens after processing input and before writing them. Already
//! successful writes cannot be recalled. INIT's reply owns the replacement
//! transaction until it is written.
//!
//! # The app outlives aborted transactions
//!
//! The app cannot be stopped, only asked to cancel. When a transaction is
//! aborted while the app works on it, the host asks the app to cancel, forgets
//! the transaction and discards the app's answer when it comes. A request
//! that completes in the meantime is held (keepalives report PROCESSING)
//! until the app is free.

use std::{collections::VecDeque, convert::TryInto};

use getrandom::SysRng;
use log::debug;
use rand_core::{CryptoRng, UnwrapErr};

/// The operating system RNG; panics if it fails, as rand 0.8's `OsRng` did.
type OsRng = UnwrapErr<SysRng>;

use crate::transport::{CTAPHID_FRAME_LEN, CtapHidFrame};
use pqkey_ctap::ctap::u2f::{SW_CONDITIONS_NOT_SATISFIED, requests_presence};

/// Initial presence requests receive a polling response within this time.
pub const U2F_RESPONSE_WAIT_MS: u64 = 100;
/// A client that stops polling relinquishes its pending prompt.
pub const U2F_POLL_TIMEOUT_MS: u64 = 3_000;
/// An approved response may be collected once during this interval.
pub const U2F_APPROVAL_MS: u64 = 10_000;

/// A complete application request, with its HID response command.
#[derive(Debug)]
pub struct AppRequest {
    /// CBOR or MSG.
    pub command: Command,
    /// The complete CTAP2 message or U2F APDU.
    pub payload: Vec<u8>,
}

struct U2fPoll {
    channel: u32,
    request: Vec<u8>,
    last_poll: u64,
    started: u64,
    presence_started: bool,
    presence_finished: Option<u64>,
    answer: Option<(Vec<u8>, u64)>,
}

impl U2fPoll {
    fn deadline(&self) -> u64 {
        match &self.answer {
            Some((_, expires)) => expires.saturating_add(1),
            None => self.presence_finished.map_or_else(
                || self.last_poll.saturating_add(U2F_POLL_TIMEOUT_MS + 1),
                |at| at.saturating_add(U2F_APPROVAL_MS + 1),
            ),
        }
    }
}

struct DeniedPoll {
    channel: u32,
    request: Vec<u8>,
    last_poll: u64,
}

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

/// Total identification budget, including queueing and platform delivery.
pub const IDENTIFICATION_TIMEOUT_MS: u64 = 500;

/// A daemon identification operation, never a CTAP application request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentificationRequest {
    pub token: u64,
    pub deadline: u64,
}

/// CTAP2_ERR_KEEPALIVE_CANCEL, the CTAP status of a cancelled request.
pub const CTAP2_ERR_KEEPALIVE_CANCEL: u8 = 0x2D;

/// How many channels CTAPHID_INIT keeps allocated. Every client that opens
/// the device allocates one and none is ever released, so the least recently
/// used channel is forgotten once this many exist. Requests on a forgotten
/// channel are still served, so a long-lived client is not cut off by others
/// coming and going; only CTAPHID_INIT there, to resynchronise it, is
/// refused.
pub const MAX_CHANNELS: usize = 256;

const CHANNEL_GENERATION_RETRY_LIMIT: usize = 64;
const LOG_PREVIEW: usize = 8;

/// The CTAPHID commands this transport handles (CTAP 2.3 §11.2.9), with the
/// code they carry in an initialization packet, high bit cleared. Every other
/// code is answered with ERR_INVALID_CMD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Ping = 0x01,
    Msg = 0x03,
    Lock = 0x04,
    Init = 0x06,
    Wink = 0x08,
    Cbor = 0x10,
    Cancel = 0x11,
    KeepAlive = 0x3B,
    Error = 0x3F,
}

impl Command {
    pub fn into_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for Command {
    type Error = u8;

    /// The command with `code`, or `code` back if this transport does not
    /// handle it.
    fn try_from(code: u8) -> Result<Self, u8> {
        Ok(match code {
            0x01 => Command::Ping,
            0x03 => Command::Msg,
            0x04 => Command::Lock,
            0x06 => Command::Init,
            0x08 => Command::Wink,
            0x10 => Command::Cbor,
            0x11 => Command::Cancel,
            0x3B => Command::KeepAlive,
            0x3F => Command::Error,
            _ => return Err(code),
        })
    }
}

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
    InvalidParameter = 0x02,
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

/// A complete CBOR or MSG request being processed by the app.
#[derive(Debug)]
struct Processing {
    channel: u32,
    command: Command,
    started: u64,
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
    Identifying {
        channel: u32,
        request: IdentificationRequest,
        submitted: bool,
    },
    Transmitting {
        channel: u32,
        final_frame: u64,
    },
}

/// A selected report, still owned by the host until its successful write.
///
/// Selection does not remove it. After processing incoming packets, check
/// [`CtaphidHost::is_outgoing_current`] before writing: INIT can invalidate
/// this token. Only a successful device write may be reported through
/// [`CtaphidHost::outgoing_frame_written`].
#[derive(Clone, Copy, Debug)]
pub struct OutgoingFrame {
    frame: CtapHidFrame,
    token: u64,
}

impl OutgoingFrame {
    pub fn frame(&self) -> &CtapHidFrame {
        &self.frame
    }
}

pub struct CtaphidHost<R = OsRng> {
    state: State,
    /// An exclusive channel lease, independent of transaction ownership.
    lease: Option<(u32, u64)>,
    /// The message being received.
    message: Vec<u8>,
    pending: VecDeque<OutgoingFrame>,
    next_token: u64,
    next_identification: u64,
    channels: Channels,
    rng: R,
    capabilities: u8,
    version: Version,
    /// Whether the app is working on a request, possibly for a transaction
    /// that has since been aborted.
    app_busy: bool,
    /// Whether the app should be asked to cancel what it is working on.
    interrupt_app: bool,
    app_command: Option<Command>,
    u2f: Option<U2fPoll>,
    denied_polls: Vec<DeniedPoll>,
}

impl CtaphidHost<OsRng> {
    pub fn new() -> Self {
        Self::with_rng(UnwrapErr(SysRng))
    }
}

impl Default for CtaphidHost<OsRng> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: CryptoRng> CtaphidHost<R> {
    pub fn with_rng(rng: R) -> Self {
        Self {
            state: State::Idle,
            lease: None,
            message: Vec::with_capacity(MAX_MESSAGE_SIZE),
            pending: VecDeque::new(),
            next_token: 0,
            next_identification: 0,
            channels: Channels::default(),
            rng,
            capabilities: 0,
            version: Version::default(),
            app_busy: false,
            interrupt_app: false,
            app_command: None,
            u2f: None,
            denied_polls: Vec::new(),
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
        self.expire_lease(now);
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
        self.expire_lease(now);
        if let State::Identifying {
            channel, request, ..
        } = self.state
            && now >= request.deadline
        {
            self.finish_error(channel, ErrorCode::Other);
        }
        self.denied_polls
            .retain(|poll| now.saturating_sub(poll.last_poll) <= U2F_POLL_TIMEOUT_MS);
        if let Some(poll) = &self.u2f
            && now >= poll.deadline()
        {
            if poll.answer.is_none() {
                self.interrupt_app = true;
            }
            self.u2f = None;
        }
        if let State::Processing(processing) = &self.state
            && processing.command == Command::Msg
            && processing.request.is_none()
            && let Some(poll) = &self.u2f
            && poll.presence_started
            && now.saturating_sub(poll.started) >= U2F_RESPONSE_WAIT_MS
        {
            let channel = processing.channel;
            self.state = State::Idle;
            self.enqueue_message(
                channel,
                Command::Msg,
                &SW_CONDITIONS_NOT_SATISFIED.to_be_bytes(),
            );
        }
        if let State::Receiving {
            channel,
            last_packet_at,
            ..
        } = self.state
            && now >= last_packet_at + CONTINUATION_TIMEOUT_MS
        {
            debug!("message timeout cid={channel:08x}");
            self.finish_error(channel, ErrorCode::Timeout);
        }
    }

    /// Observe presence while the current MSG operation waits. The worker's
    /// completed reply separately carries the exact presence-finish time.
    pub fn app_presence(&mut self, waiting: bool) {
        if waiting
            && self.app_command == Some(Command::Msg)
            && let Some(poll) = &mut self.u2f
        {
            poll.presence_started = true;
        }
    }

    /// Retain the ten-second collection window while the worker finishes a
    /// response after presence, even if it has not produced that reply yet.
    pub fn app_presence_finished(&mut self, at: u64) {
        if self.app_command == Some(Command::Msg)
            && let Some(poll) = &mut self.u2f
        {
            poll.presence_finished = Some(at);
        }
    }

    /// A policy change must not expose a previously approved U2F answer.
    pub fn set_u2f_enabled(&mut self, enabled: bool) {
        if !enabled {
            self.reset_u2f();
        }
    }

    /// Forget U2F state when credential storage has been reset. A suppressed
    /// handle must be checked against the new store rather than replayed.
    pub fn reset_u2f(&mut self) {
        self.u2f = None;
        self.denied_polls.clear();
    }

    /// Queue a keepalive if one is due for the request being processed:
    /// [`KEEPALIVE_INTERVAL_MS`] after the last one, or at once when the
    /// status changes. `waiting_for_user` is what the app reports. Returns
    /// whether one was queued.
    pub fn send_keepalive(&mut self, waiting_for_user: bool, now: u64) -> bool {
        let State::Processing(processing) = &mut self.state else {
            return false;
        };
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
        self.queue_frame(CtapHidFrame::new(frame));
        true
    }

    /// When [`handle_timeout`](Self::handle_timeout) or
    /// [`send_keepalive`](Self::send_keepalive) next has something to do,
    /// if anything.
    pub fn next_deadline(&self) -> Option<u64> {
        let transaction = match &self.state {
            State::Idle | State::Transmitting { .. } => None,
            State::Receiving { last_packet_at, .. } => {
                Some(last_packet_at + CONTINUATION_TIMEOUT_MS)
            }
            State::Processing(processing) => Some(processing.keepalive_at + KEEPALIVE_INTERVAL_MS),
            State::Identifying { request, .. } => Some(request.deadline),
        };
        let polling = self.u2f.as_ref().map(|poll| {
            if poll.answer.is_none() && poll.presence_started
                && matches!(&self.state, State::Processing(p) if p.command == Command::Msg && p.request.is_none()) {
                poll.started.saturating_add(U2F_RESPONSE_WAIT_MS).min(poll.deadline())
            } else { poll.deadline() }
        });
        transaction
            .into_iter()
            .chain(polling)
            .chain(self.lease.map(|(_, expires)| expires))
            .min()
    }

    fn expire_lease(&mut self, now: u64) {
        if self.lease.is_some_and(|(_, expires)| now >= expires) {
            self.lease = None;
        }
    }

    fn lease_conflicts(&self, channel: u32) -> bool {
        self.lease.is_some_and(|(owner, _)| owner != channel)
    }

    /// Submit identification once. Its result must carry this token back.
    pub fn take_identification_request(&mut self) -> Option<IdentificationRequest> {
        let State::Identifying {
            request, submitted, ..
        } = &mut self.state
        else {
            return None;
        };
        if *submitted {
            return None;
        }
        *submitted = true;
        Some(*request)
    }

    /// Complete only the current identification, within its original budget.
    pub fn identification_response(&mut self, token: u64, delivered: bool, now: u64) {
        let State::Identifying {
            channel, request, ..
        } = self.state
        else {
            return;
        };
        if request.token != token {
            return;
        }
        if delivered && now < request.deadline {
            self.enqueue_message(channel, Command::Wink, &[]);
        } else {
            self.finish_error(channel, ErrorCode::Other);
        }
    }

    /// The CBOR or MSG request the app should work on next,
    /// if the app is free and one is ready. The app must answer it through
    /// [`app_response`](Self::app_response).
    pub fn take_app_request(&mut self) -> Option<AppRequest> {
        if self.app_busy {
            return None;
        }
        let State::Processing(processing) = &mut self.state else {
            return None;
        };
        let payload = processing.request.take()?;
        let command = processing.command;
        if command == Command::Msg && requests_presence(&payload) {
            self.u2f = Some(U2fPoll {
                channel: processing.channel,
                request: payload.clone(),
                last_poll: processing.started,
                started: processing.started,
                presence_started: false,
                presence_finished: None,
                answer: None,
            });
        }
        self.app_busy = true;
        self.app_command = Some(command);
        Some(AppRequest { command, payload })
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
    pub fn app_response(&mut self, response: Vec<u8>, now: u64, presence_finished: Option<u64>) {
        self.app_busy = false;
        let command = self.app_command.take();
        if command == Some(Command::Msg)
            && let Some(mut poll) = self.u2f.take()
        {
            let status = response.get(response.len().saturating_sub(2)..);
            let direct = matches!(&self.state, State::Processing(p) if p.command == Command::Msg && p.request.is_none());
            let late = direct
                && presence_finished.is_some()
                && now.saturating_sub(poll.started) > U2F_RESPONSE_WAIT_MS;
            if status == Some(SW_CONDITIONS_NOT_SATISFIED.to_be_bytes().as_slice()) {
                self.denied_polls.push(DeniedPoll {
                    channel: poll.channel,
                    request: poll.request,
                    last_poll: poll.last_poll,
                });
            } else if (!direct || late)
                && presence_finished.is_some()
                && now
                    <= presence_finished
                        .unwrap_or(now)
                        .saturating_add(U2F_APPROVAL_MS)
            {
                if late {
                    self.state = State::Idle;
                    self.enqueue_message(
                        poll.channel,
                        Command::Msg,
                        &SW_CONDITIONS_NOT_SATISFIED.to_be_bytes(),
                    );
                }
                poll.answer = Some((
                    response,
                    presence_finished
                        .unwrap_or(now)
                        .saturating_add(U2F_APPROVAL_MS),
                ));
                self.u2f = Some(poll);
                return;
            } else if !direct || late {
                if late {
                    self.state = State::Idle;
                    self.enqueue_message(
                        poll.channel,
                        Command::Msg,
                        &SW_CONDITIONS_NOT_SATISFIED.to_be_bytes(),
                    );
                }
                return;
            }
        }
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
        let channel = processing.channel;
        let command = processing.command;
        self.state = State::Idle;
        self.enqueue_message(channel, command, &response);
    }

    /// Select the next report without retiring it or releasing its CID.
    pub fn next_outgoing_frame(&self) -> Option<OutgoingFrame> {
        self.pending.front().copied()
    }

    /// Whether a selected report remains the queue head after incoming I/O.
    pub fn is_outgoing_current(&self, frame: &OutgoingFrame) -> bool {
        self.pending
            .front()
            .is_some_and(|head| head.token == frame.token)
    }

    /// Retire a report after `HidDevice::write_frame` returned `Ok(())`.
    ///
    /// Returns false for an invalidated or already retired token, changing
    /// nothing. Only the successful write of the owned response's final
    /// report completes its transaction. Auxiliary errors and keepalives
    /// cannot complete another transaction.
    pub fn outgoing_frame_written(&mut self, frame: &OutgoingFrame) -> bool {
        if !self.is_outgoing_current(frame) {
            return false;
        }
        self.pending.pop_front();
        if matches!(self.state, State::Transmitting { final_frame, .. } if final_frame == frame.token)
        {
            self.state = State::Idle;
        }
        true
    }

    /// The channel of the transaction under way, if any.
    fn busy_channel(&self) -> Option<u32> {
        match &self.state {
            State::Idle => self
                .u2f
                .as_ref()
                .filter(|poll| poll.answer.is_none())
                .map(|poll| poll.channel),
            State::Receiving { channel, .. } => Some(*channel),
            State::Processing(processing) => Some(processing.channel),
            State::Identifying { channel, .. } => Some(*channel),
            State::Transmitting { channel, .. } => Some(*channel),
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
        if self.lease_conflicts(channel) {
            self.enqueue_error(channel, ErrorCode::ChannelBusy);
            return;
        }
        match self.busy_channel() {
            Some(busy) if busy != channel => {
                self.enqueue_error(channel, ErrorCode::ChannelBusy);
                return;
            }
            _ => {}
        }
        if length != 8 {
            if self.busy_channel().is_some() {
                self.enqueue_error(channel, ErrorCode::InvalidLength);
            } else {
                self.finish_error(channel, ErrorCode::InvalidLength);
            }
            return;
        }
        let aborted = !matches!(self.state, State::Idle);
        let assigned = if channel == BROADCAST_CID {
            match self.allocate_channel() {
                Some(assigned) => assigned,
                None => {
                    if aborted {
                        self.enqueue_error(channel, ErrorCode::ChannelBusy);
                    } else {
                        self.finish_error(channel, ErrorCode::ChannelBusy);
                    }
                    return;
                }
            }
        } else if channel != 0 && (aborted || self.channels.contains(channel)) {
            // An active channel remains valid even after LRU eviction.
            channel
        } else {
            if aborted {
                self.enqueue_error(channel, ErrorCode::InvalidChannel);
            } else {
                self.finish_error(channel, ErrorCode::InvalidChannel);
            }
            return;
        };

        // Validation succeeded. Invalidate even a selected report by keeping
        // it in this queue until its write is acknowledged. Other channels'
        // auxiliary replies retain their FIFO order and never own this CID.
        self.pending
            .retain(|frame| frame.frame.0[..4] != channel.to_be_bytes());
        self.message.clear();
        if self
            .u2f
            .as_ref()
            .is_some_and(|poll| poll.channel == channel)
        {
            if self.u2f.as_ref().is_some_and(|poll| poll.answer.is_none()) {
                self.interrupt_app = true;
            }
            self.u2f = None;
        }
        self.denied_polls.retain(|poll| poll.channel != channel);
        // §11.2.5.3: "If the device detects an INIT command during a
        // transaction that has the same channel id as the active transaction,
        // the transaction is aborted (if possible) and all buffered data
        // flushed (if any)."
        if let State::Processing(processing) = &self.state
            && processing.request.is_none()
        {
            self.interrupt_app = true;
        }
        if aborted {
            debug!("INIT aborts the transaction on cid={channel:08x}");
            self.state = State::Idle;
        }

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
        if self.lease_conflicts(channel) {
            self.enqueue_error(channel, ErrorCode::ChannelBusy);
            return;
        }
        if let Some(busy) = self.busy_channel() {
            // §11.2.5.1: "If an application tries to access the device from a
            // different channel while the device is busy with a transaction,
            // that request will immediately fail with a busy-error message
            // sent to the requesting channel."
            if busy != channel
                || matches!(
                    self.state,
                    State::Processing(_) | State::Identifying { .. } | State::Transmitting { .. }
                )
                || (matches!(self.state, State::Idle) && command != Some(Command::Msg))
            {
                self.enqueue_error(channel, ErrorCode::ChannelBusy);
                return;
            }
            // A new message on a channel that has not finished sending the
            // last one: §11.2.9.1.6 "ERR_INVALID_SEQ: The sequence does not
            // match expected value". The half-received message is dropped.
            if matches!(self.state, State::Receiving { .. }) {
                self.finish_error(channel, ErrorCode::InvalidSeq);
                return;
            }
        }

        // Any other channel is served, allocated or not (see MAX_CHANNELS).
        if channel == 0 || channel == BROADCAST_CID {
            self.finish_error(channel, ErrorCode::InvalidChannel);
            return;
        }
        let command = match command {
            Some(
                command @ (Command::Ping
                | Command::Cbor
                | Command::Msg
                | Command::Lock
                | Command::Wink),
            ) => command,
            _ => {
                self.finish_error(channel, ErrorCode::InvalidCommand);
                return;
            }
        };
        // A CTAPHID_CBOR request carries at least the CTAP command byte
        // (§11.2.9.1.2: "BCNT 1..(n + 1)").
        if length > MAX_MESSAGE_SIZE
            || (matches!(command, Command::Cbor | Command::Msg) && length == 0)
            || (command == Command::Lock && length != 1)
            || (command == Command::Wink && length != 0)
        {
            self.finish_error(channel, ErrorCode::InvalidLength);
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
            self.finish_error(channel, ErrorCode::InvalidSeq);
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
        if command == Command::Wink {
            let token = self.next_identification;
            self.next_identification = token
                .checked_add(1)
                .expect("identification token exhausted");
            self.state = State::Identifying {
                channel,
                request: IdentificationRequest {
                    token,
                    deadline: now.saturating_add(IDENTIFICATION_TIMEOUT_MS),
                },
                submitted: false,
            };
            return;
        }
        if command == Command::Lock {
            let seconds = self.message[0];
            if seconds > 10 {
                self.finish_error(channel, ErrorCode::InvalidParameter);
            } else {
                self.lease = (seconds != 0)
                    .then_some((channel, now.saturating_add(u64::from(seconds) * 1_000)));
                self.enqueue_message(channel, command, &[]);
            }
            return;
        }
        if command == Command::Msg {
            if let Some(poll) = &mut self.u2f {
                if poll.channel == channel && poll.request == self.message {
                    poll.last_poll = now;
                    let response = if let Some((_, expires)) = &poll.answer {
                        if now > *expires {
                            None
                        } else {
                            self.u2f
                                .take()
                                .and_then(|poll| poll.answer.map(|(reply, _)| reply))
                        }
                    } else {
                        Some(SW_CONDITIONS_NOT_SATISFIED.to_be_bytes().to_vec())
                    };
                    if let Some(response) = response {
                        self.state = State::Idle;
                        self.enqueue_message(channel, command, &response);
                        return;
                    }
                } else if poll.answer.is_none() {
                    self.finish_error(channel, ErrorCode::ChannelBusy);
                    return;
                }
            }
            if let Some(poll) = self
                .denied_polls
                .iter_mut()
                .find(|poll| poll.channel == channel && poll.request == self.message)
                && now.saturating_sub(poll.last_poll) <= U2F_POLL_TIMEOUT_MS
            {
                poll.last_poll = now;
                self.state = State::Idle;
                self.enqueue_message(channel, command, &SW_CONDITIONS_NOT_SATISFIED.to_be_bytes());
                return;
            }
            self.denied_polls
                .retain(|poll| now.saturating_sub(poll.last_poll) <= U2F_POLL_TIMEOUT_MS);
            if requests_presence(&self.message) && self.denied_polls.len() >= MAX_CHANNELS {
                self.finish_error(channel, ErrorCode::ChannelBusy);
                return;
            }
        }
        if command == Command::Ping {
            // §11.2.9.1.4: the device "immediately echoes the same data back".
            self.state = State::Idle;
            let message = std::mem::take(&mut self.message);
            self.enqueue_message(channel, command, &message);
            self.message = message;
            return;
        }
        self.u2f = None;
        debug!(
            "request cid={channel:08x} ctap=0x{:02x} len={}",
            self.message.first().copied().unwrap_or_default(),
            self.message.len()
        );
        self.state = State::Processing(Processing {
            channel,
            command,
            started: now,
            request: Some(self.message.clone()),
            keepalive_at: now,
            keepalive_status: KeepaliveStatus::Processing,
        });
    }

    /// Queue the packets of a message.
    ///
    /// A message holds at most [`MAX_MESSAGE_SIZE`] bytes: its length must
    /// fit the two-byte BCNT of the initialization packet, and its
    /// continuation packets the sequence numbers 0 to 0x7f: "A larger message
    /// is then divided into one or more continuation packets, starting with
    /// sequence number 0, which then increments by one to a maximum of 127."
    /// (CTAP 2.3 §11.2.4)  A longer payload, which only the app can
    /// produce, is not sent: the channel gets ERR_OTHER instead.
    fn enqueue_message(&mut self, channel: u32, command: Command, payload: &[u8]) {
        let final_frame = self.queue_message(channel, command, payload);
        self.state = State::Transmitting {
            channel,
            final_frame,
        };
    }

    fn queue_frame(&mut self, frame: CtapHidFrame) -> u64 {
        let token = self.next_token;
        // Never reuse a token, including after INIT. Exhaustion requires
        // more reports than a device could write in its lifetime.
        self.next_token = token
            .checked_add(1)
            .expect("CTAPHID report token exhausted");
        self.pending.push_back(OutgoingFrame { frame, token });
        token
    }

    /// Append a whole message without changing transaction ownership.
    fn queue_message(&mut self, channel: u32, command: Command, payload: &[u8]) -> u64 {
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
            return self.queue_message(channel, Command::Error, &[ErrorCode::Other as u8]);
        };
        let mut frame = [0u8; PACKET_SIZE];
        frame[..4].copy_from_slice(&channel.to_be_bytes());
        frame[4] = command.into_u8() | 0x80;
        frame[5..7].copy_from_slice(&length.to_be_bytes());
        let (head, rest) = payload.split_at(payload.len().min(INIT_DATA));
        frame[7..7 + head.len()].copy_from_slice(head);
        let mut final_frame = self.queue_frame(CtapHidFrame::new(frame));

        for (sequence, chunk) in (0..=0x7f_u8).zip(rest.chunks(CONT_DATA)) {
            let mut frame = [0u8; PACKET_SIZE];
            frame[..4].copy_from_slice(&channel.to_be_bytes());
            frame[4] = sequence;
            frame[5..5 + chunk.len()].copy_from_slice(chunk);
            final_frame = self.queue_frame(CtapHidFrame::new(frame));
        }
        final_frame
    }

    /// An auxiliary rejection, never the owned transaction's response.
    fn enqueue_error(&mut self, channel: u32, code: ErrorCode) {
        self.queue_message(channel, Command::Error, &[code as u8]);
    }

    fn finish_error(&mut self, channel: u32, code: ErrorCode) {
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
    #[test]
    fn wink_validation_delivery_deadline_and_late_results() {
        let mut host = host();
        for length in [1, 57, 58, MAX_MESSAGE_SIZE, MAX_MESSAGE_SIZE + 1] {
            host.handle_frame(&message_packets(FIRST, 8, &vec![0; length])[0], 0);
            assert_eq!(sent(&mut host), [error(FIRST, ErrorCode::InvalidLength)]);
            assert!(host.take_identification_request().is_none());
        }
        for (delivered, now, expected) in [
            (true, 499, message(FIRST, Command::Wink, &[])),
            (true, 500, error(FIRST, ErrorCode::Other)),
            (false, 1, error(FIRST, ErrorCode::Other)),
        ] {
            send(&mut host, FIRST, Command::Wink, &[], 0);
            let request = host.take_identification_request().unwrap();
            assert!(host.take_app_request().is_none());
            assert!(host.take_identification_request().is_none());
            assert!(!host.send_keepalive(true, 100));
            send(&mut host, FIRST, Command::Cancel, &[], 1);
            assert!(!host.take_interrupt());
            host.identification_response(request.token, delivered, now);
            assert_eq!(sent(&mut host), [expected]);
            host.identification_response(request.token, true, now);
            assert!(sent(&mut host).is_empty());
        }
        send(&mut host, FIRST, Command::Wink, &[], 1_000);
        let old = host.take_identification_request().unwrap();
        host.handle_timeout(1_500);
        assert_eq!(sent(&mut host), [error(FIRST, ErrorCode::Other)]);
        send(&mut host, FIRST, Command::Wink, &[], 1_501);
        let new = host.take_identification_request().unwrap();
        host.identification_response(old.token, true, 1_502);
        assert!(host.next_outgoing_frame().is_none());
        host.identification_response(new.token, true, 1_503);
        assert_eq!(sent(&mut host), [message(FIRST, Command::Wink, &[])]);
    }

    #[test]
    fn init_invalidates_identification_and_its_selected_result_but_not_a_lease() {
        let mut host = host_with_channels(&[FIRST]);
        init_on(&mut host, BROADCAST_CID);
        send(&mut host, FIRST, Command::Lock, &[10], 0);
        sent(&mut host);
        for completed in [false, true] {
            send(&mut host, FIRST, Command::Wink, &[], 1);
            let request = host.take_identification_request().unwrap();
            send(&mut host, SECOND, Command::Ping, &[], 2);
            if completed {
                host.identification_response(request.token, true, 3);
            }
            send(&mut host, FIRST, Command::Init, &[0; 8], 4);
            host.identification_response(request.token, true, 5);
            let output = sent(&mut host);
            assert_eq!(output.len(), 2);
            assert_eq!(output[0], error(SECOND, ErrorCode::ChannelBusy));
            assert_eq!(output[1].command, Command::Init as u8);
            assert_eq!(host.lease, Some((FIRST, 10_000)));
        }
        send(&mut host, FIRST, Command::Wink, &[], 10);
        let request = host.take_identification_request().unwrap();
        host.identification_response(request.token, true, 11);
        let selected = host.next_outgoing_frame().unwrap();
        send(&mut host, FIRST, Command::Init, &[0; 8], 12);
        assert!(!host.is_outgoing_current(&selected));
        assert!(!host.outgoing_frame_written(&selected));
    }

    #[test]
    fn lock_validation_renewal_and_exact_expiry() {
        let mut host = host();
        for payload in [&[][..], &[1, 2][..], &[0; 70][..]] {
            send(&mut host, FIRST, Command::Lock, payload, 0);
            assert_eq!(sent(&mut host), [error(FIRST, ErrorCode::InvalidLength)]);
        }
        send(&mut host, FIRST, Command::Lock, &[10], 100);
        assert_eq!(sent(&mut host), [message(FIRST, Command::Lock, &[])]);
        for value in [11, 255] {
            send(&mut host, FIRST, Command::Lock, &[value], 200);
            assert_eq!(sent(&mut host), [error(FIRST, ErrorCode::InvalidParameter)]);
            assert_eq!(host.lease, Some((FIRST, 10_100)));
        }
        send(&mut host, SECOND, Command::Lock, &[0], 300);
        assert_eq!(sent(&mut host), [error(SECOND, ErrorCode::ChannelBusy)]);
        send(&mut host, FIRST, Command::Lock, &[1], 500);
        sent(&mut host);
        assert_eq!(host.next_deadline(), Some(1_500));
        for now in [1_499, 1_500] {
            send(&mut host, SECOND, Command::Ping, &[], now);
            let expected = if now == 1_499 {
                error(SECOND, ErrorCode::ChannelBusy)
            } else {
                message(SECOND, Command::Ping, &[])
            };
            assert_eq!(sent(&mut host), [expected]);
        }
        assert!(host.lease.is_none());
    }

    #[test]
    fn unlock_and_expiry_do_not_complete_selected_responses() {
        for unlock in [false, true] {
            let mut host = host();
            send(&mut host, FIRST, Command::Lock, &[1], 0);
            sent(&mut host);
            if unlock {
                send(&mut host, FIRST, Command::Lock, &[0], 10);
            } else {
                send(&mut host, FIRST, Command::Ping, &[42; MAX_MESSAGE_SIZE], 10);
                host.handle_timeout(1_000);
            }
            assert!(host.lease.is_none());
            let selected = host.next_outgoing_frame().unwrap();
            send(&mut host, SECOND, Command::Ping, &[], 1_001);
            assert!(host.is_outgoing_current(&selected));
            assert_eq!(host.busy_channel(), Some(FIRST));
            let replies = sent(&mut host);
            assert_eq!(replies.last(), Some(&error(SECOND, ErrorCode::ChannelBusy)));
            assert!(host.busy_channel().is_none());
            send(&mut host, SECOND, Command::Ping, &[], 1_002);
            assert_eq!(sent(&mut host), [message(SECOND, Command::Ping, &[])]);
        }
    }

    #[test]
    fn lock_init_cancel_reserved_channels_and_reset_are_independent() {
        let mut host = host_with_channels(&[FIRST]);
        assert_eq!(init_on(&mut host, BROADCAST_CID).channel, BROADCAST_CID);
        send(&mut host, FIRST, Command::Lock, &[10], 0);
        let selected = host.next_outgoing_frame().unwrap();
        for cid in [SECOND, 0, BROADCAST_CID] {
            send(&mut host, cid, Command::Init, &[0; 8], 1);
        }
        send(&mut host, SECOND, Command::Cancel, &[], 2);
        send(&mut host, FIRST, Command::Init, &[0; 8], 3);
        assert!(!host.is_outgoing_current(&selected));
        assert!(!host.outgoing_frame_written(&selected));
        assert_eq!(host.lease, Some((FIRST, 10_000)));
        assert_eq!(sent(&mut host).len(), 4);
        host.reset_u2f();
        assert_eq!(host.lease, Some((FIRST, 10_000)));
        send(&mut host, FIRST, Command::Lock, &[0], 4);
        let selected = host.next_outgoing_frame().unwrap();
        send(&mut host, FIRST, Command::Init, &[0; 8], 5);
        assert!(!host.is_outgoing_current(&selected));
        assert!(host.lease.is_none());
    }

    #[test]
    fn lease_expiry_preserves_receiving_processing_and_partial_transmission() {
        for phase in 0..3 {
            let mut host = host();
            send(&mut host, FIRST, Command::Lock, &[1], 0);
            sent(&mut host);
            if phase == 0 {
                host.handle_frame(&message_packets(FIRST, 1, &[7; 100])[0], 900);
            } else {
                start_cbor(&mut host, FIRST, &[4], 900);
                if phase == 2 {
                    host.app_response(vec![8; MAX_MESSAGE_SIZE], 901, None);
                    let first = host.next_outgoing_frame().unwrap();
                    assert!(host.outgoing_frame_written(&first));
                }
            }
            host.handle_timeout(1_000);
            assert!(host.lease.is_none());
            assert_eq!(host.busy_channel(), Some(FIRST));
            send(&mut host, SECOND, Command::Ping, &[], 1_000);
            assert_eq!(host.busy_channel(), Some(FIRST));
        }
    }

    #[test]
    fn failed_init_allocation_does_not_replace_an_unwritten_reply() {
        let mut host = host_with_channels(&[0; 128]);
        send(&mut host, BROADCAST_CID, Command::Init, &[0; 8], 0);
        let selected = host.next_outgoing_frame().unwrap();
        send(&mut host, BROADCAST_CID, Command::Init, &[1; 8], 1);
        assert!(host.is_outgoing_current(&selected));
        assert!(host.outgoing_frame_written(&selected));
        assert_eq!(host.busy_channel(), None);
        start_cbor(&mut host, FIRST, &[4], 2);
        assert_eq!(
            sent(&mut host),
            [error(BROADCAST_CID, ErrorCode::ChannelBusy)]
        );
        assert_eq!(host.busy_channel(), Some(FIRST));
    }

    #[test]
    fn every_response_frame_keeps_ownership_until_its_successful_write() {
        for command in [Command::Ping, Command::Cbor, Command::Msg] {
            for length in [
                0,
                1,
                INIT_DATA,
                INIT_DATA + 1,
                INIT_DATA + CONT_DATA + 1,
                MAX_MESSAGE_SIZE,
            ] {
                let mut host = host();
                let payload: Vec<u8> = (0..length).map(|n| n as u8).collect();
                if command == Command::Ping {
                    send(&mut host, FIRST, command, &payload, 0);
                } else {
                    send(&mut host, FIRST, command, &[4], 0);
                    assert_eq!(host.take_app_request().unwrap().command, command);
                    host.app_response(payload.clone(), 1, None);
                }
                let packets = message_packets(FIRST, command as u8, &payload);
                for (index, expected) in packets.iter().enumerate() {
                    let selected = host.next_outgoing_frame().unwrap();
                    assert_eq!(selected.frame(), expected);
                    assert_eq!(host.busy_channel(), Some(FIRST));
                    // In particular, selection of the last frame is not completion.
                    send(&mut host, SECOND, Command::Cbor, &[4], 2);
                    send(&mut host, FIRST, Command::Ping, &[1], 2);
                    send(&mut host, BROADCAST_CID, Command::Init, &[0; 8], 2);
                    assert!(host.take_app_request().is_none());
                    assert!(host.is_outgoing_current(&selected));
                    assert!(host.outgoing_frame_written(&selected));
                    assert!(
                        !host.outgoing_frame_written(&selected),
                        "duplicate completion"
                    );
                    assert_eq!(
                        host.busy_channel(),
                        if index + 1 == packets.len() {
                            None
                        } else {
                            Some(FIRST)
                        }
                    );
                }
                // Already queued busy replies cannot release this new request.
                start_cbor(&mut host, SECOND, &[4], 3);
                while let Some(frame) = host.next_outgoing_frame() {
                    assert_eq!(frame.frame().0[4], Command::Error as u8 | 0x80);
                    assert_eq!(frame.frame().0[7], ErrorCode::ChannelBusy as u8);
                    assert!(host.outgoing_frame_written(&frame));
                    assert_eq!(host.busy_channel(), Some(SECOND));
                }
                host.app_response(vec![0], 4, None);
                assert_eq!(sent(&mut host), [message(SECOND, Command::Cbor, &[0])]);
                assert_eq!(host.busy_channel(), None);
            }
        }
    }

    #[test]
    fn init_invalidates_every_selected_response_boundary() {
        for length in [1, INIT_DATA + 1, MAX_MESSAGE_SIZE] {
            let packets = message_packets(FIRST, Command::Ping as u8, &vec![0x42; length]);
            for boundary in 0..packets.len() {
                let mut host = host();
                send(&mut host, FIRST, Command::Ping, &vec![0x42; length], 0);
                for expected in &packets[..boundary] {
                    let selected = host.next_outgoing_frame().unwrap();
                    assert_eq!(selected.frame(), expected);
                    assert!(host.outgoing_frame_written(&selected));
                }
                let stale = host.next_outgoing_frame().unwrap();
                send(&mut host, SECOND, Command::Ping, &[1], 1);
                send(&mut host, FIRST, Command::Init, &[9; 8], 2);
                assert!(host.message.is_empty());
                assert!(!host.is_outgoing_current(&stale));
                assert!(!host.outgoing_frame_written(&stale));
                assert_eq!(host.busy_channel(), Some(FIRST));
                let replies = sent(&mut host);
                assert_eq!(replies.len(), 2);
                assert_eq!(replies[0], error(SECOND, ErrorCode::ChannelBusy));
                assert_eq!(replies[1].command, Command::Init as u8);
                assert_eq!(&replies[1].payload[..8], &[9; 8]);
                start_cbor(&mut host, FIRST, &[4], 3);
            }
        }
    }

    #[test]
    fn invalid_init_and_cancel_do_not_truncate_a_transmitting_response() {
        let mut host = host();
        let payload = vec![0x42; 200];
        send(&mut host, FIRST, Command::Ping, &payload, 0);
        let selected = host.next_outgoing_frame().unwrap();
        send(&mut host, FIRST, Command::Init, &[0; 7], 1);
        send(&mut host, FIRST, Command::Cancel, &[], 1);
        send(&mut host, SECOND, Command::Cancel, &[], 1);
        assert!(!host.take_interrupt());
        assert!(host.is_outgoing_current(&selected));
        assert_eq!(
            sent(&mut host),
            [
                message(FIRST, Command::Ping, &payload),
                error(FIRST, ErrorCode::InvalidLength)
            ]
        );
    }

    #[test]
    fn repeated_init_invalidates_its_own_unwritten_reply() {
        let mut host = host();
        start_cbor(&mut host, FIRST, &[4], 0);
        assert!(host.send_keepalive(true, 50));
        let keepalive = host.next_outgoing_frame().unwrap();
        send(&mut host, FIRST, Command::Init, &[1; 8], 51);
        assert!(host.take_interrupt());
        let old_init = host.next_outgoing_frame().unwrap();
        send(&mut host, FIRST, Command::Init, &[2; 8], 52);
        assert!(!host.outgoing_frame_written(&keepalive));
        assert!(!host.outgoing_frame_written(&old_init));
        host.app_response(vec![0x42; 200], 53, None);
        let replies = sent(&mut host);
        assert_eq!(replies.len(), 1);
        assert_eq!(&replies[0].payload[..8], &[2; 8]);
        start_cbor(&mut host, SECOND, &[4], 54);
    }

    #[test]
    fn terminal_transport_errors_and_held_cancellation_are_owned() {
        let mut host = host();
        host.handle_frame(&message_packets(FIRST, 0x02, &[])[0], 0);
        assert_eq!(host.busy_channel(), Some(FIRST));
        send(&mut host, SECOND, Command::Ping, &[], 1);
        assert_eq!(
            sent(&mut host),
            [
                error(FIRST, ErrorCode::InvalidCommand),
                error(SECOND, ErrorCode::ChannelBusy)
            ]
        );
        start_cbor(&mut host, FIRST, &[4], 2);
        send(&mut host, FIRST, Command::Init, &[0; 8], 3);
        sent(&mut host);
        send(&mut host, SECOND, Command::Cbor, &[4], 4);
        send(&mut host, SECOND, Command::Cancel, &[], 5);
        let selected = host.next_outgoing_frame().unwrap();
        assert_eq!(host.busy_channel(), Some(SECOND));
        host.app_response(vec![0x42; 100], 6, None);
        assert!(
            host.is_outgoing_current(&selected),
            "late old worker response is ignored"
        );
        assert_eq!(
            sent(&mut host),
            [message(
                SECOND,
                Command::Cbor,
                &[CTAP2_ERR_KEEPALIVE_CANCEL]
            )]
        );
        start_cbor(&mut host, SECOND, &[4], 7);
    }

    #[test]
    fn u2f_pending_and_cached_replies_are_owned_separately_from_the_worker() {
        for approved in [true, false] {
            let mut host = host();
            let request = start_u2f(&mut host, 0);
            host.app_presence(true);
            host.handle_timeout(100);
            let pending = host.next_outgoing_frame().unwrap();
            let answer = if approved {
                vec![0x42; 200].into_iter().chain([0x90, 0]).collect()
            } else {
                vec![0x69, 0x85]
            };
            host.app_response(answer.clone(), 101, Some(101));
            assert!(host.is_outgoing_current(&pending));
            send(&mut host, SECOND, Command::Ping, &[], 102);
            send(&mut host, FIRST, Command::Msg, &request, 102);
            assert_eq!(
                sent(&mut host),
                [
                    message(FIRST, Command::Msg, &[0x69, 0x85]),
                    error(SECOND, ErrorCode::ChannelBusy),
                    error(FIRST, ErrorCode::ChannelBusy)
                ]
            );
            send(&mut host, FIRST, Command::Msg, &request, 103);
            let cached = host.next_outgoing_frame().unwrap();
            assert_eq!(host.busy_channel(), Some(FIRST));
            send(&mut host, SECOND, Command::Cbor, &[4], 104);
            assert!(host.take_app_request().is_none());
            assert!(host.is_outgoing_current(&cached));
            assert_eq!(
                sent(&mut host),
                [
                    message(FIRST, Command::Msg, &answer),
                    error(SECOND, ErrorCode::ChannelBusy)
                ]
            );
            send(&mut host, FIRST, Command::Msg, &request, 105);
            if approved {
                assert!(host.take_app_request().is_some(), "approval consumed once");
            } else {
                assert!(host.take_app_request().is_none(), "denial is suppressed");
                assert_eq!(
                    sent(&mut host),
                    [message(FIRST, Command::Msg, &[0x69, 0x85])]
                );
            }
        }
    }

    #[test]
    fn queued_replies_keep_other_channels_busy() {
        for length in [1, INIT_DATA, INIT_DATA + 1, MAX_MESSAGE_SIZE] {
            let mut host = host();
            start_cbor(&mut host, FIRST, &[4], 0);
            let response = vec![0x42; length];
            host.app_response(response.clone(), 1, None);
            send(&mut host, SECOND, Command::Cbor, &[4], 2);
            assert!(
                host.take_app_request().is_none(),
                "queued {length}-byte response still owns the CID"
            );
            assert_eq!(
                sent(&mut host),
                [
                    message(FIRST, Command::Cbor, &response),
                    error(SECOND, ErrorCode::ChannelBusy)
                ]
            );
        }
    }

    #[test]
    fn init_discards_queued_keepalives_and_response_fragments() {
        let mut host = host();
        start_cbor(&mut host, FIRST, &[4], 0);
        assert!(host.send_keepalive(true, 50));
        host.app_response(vec![0x42; 200], 51, None);
        send(&mut host, FIRST, Command::Init, &[9; 8], 52);
        let replies = sent(&mut host);
        assert_eq!(
            replies.len(),
            1,
            "only the resynchronization reply survives"
        );
        assert_eq!(replies[0].command, Command::Init as u8);
        assert_eq!(&replies[0].payload[..8], &[9; 8]);
    }

    #[test]
    fn reset_discards_suppression_so_invalidated_handles_reach_the_engine() {
        let mut host = host();
        let request = start_u2f(&mut host, 0);
        host.app_response(vec![0x69, 0x85], 1, Some(1));
        sent(&mut host);
        assert_eq!(host.denied_polls.len(), 1);
        host.reset_u2f();
        send(&mut host, FIRST, Command::Msg, &request, 2);
        assert_eq!(host.take_app_request().unwrap().payload, request);
        host.app_response(vec![0x6a, 0x80], 3, None);
        assert_eq!(
            sent(&mut host),
            [message(FIRST, Command::Msg, &[0x6a, 0x80])]
        );
    }
    #[test]
    fn an_unobserved_presence_wait_still_defers_a_late_answer() {
        let mut host = host();
        let request = start_u2f(&mut host, 0);
        host.app_response(vec![5, 0x90, 0], 200, Some(150));
        assert_eq!(
            sent(&mut host),
            [message(FIRST, Command::Msg, &[0x69, 0x85])]
        );
        send(&mut host, FIRST, Command::Msg, &request, 201);
        assert_eq!(
            sent(&mut host),
            [message(FIRST, Command::Msg, &[5, 0x90, 0])]
        );
    }

    #[test]
    fn presence_completion_preserves_approval_while_the_worker_prepares_the_answer() {
        let mut host = host();
        let request = start_u2f(&mut host, 0);
        host.app_presence(true);
        host.app_presence_finished(1);
        host.handle_timeout(100);
        sent(&mut host);
        host.handle_timeout(3_001);
        assert!(!host.take_interrupt(), "presence has already finished");
        host.app_response(vec![5, 0x90, 0], 5_000, Some(1));
        send(&mut host, FIRST, Command::Msg, &request, 5_001);
        assert_eq!(
            sent(&mut host),
            [message(FIRST, Command::Msg, &[5, 0x90, 0])]
        );
    }
    fn u2f_register() -> Vec<u8> {
        [vec![0, 1, 0, 0, 0, 0, 64], vec![0x42; 64]].concat()
    }

    fn start_u2f<R: CryptoRng>(host: &mut CtaphidHost<R>, now: u64) -> Vec<u8> {
        let request = u2f_register();
        send(host, FIRST, Command::Msg, &request, now);
        let submitted = host.take_app_request().unwrap();
        assert_eq!(submitted.command, Command::Msg);
        assert_eq!(submitted.payload, request);
        request
    }

    #[test]
    fn msg_replies_preserve_the_command_and_direct_status_words() {
        let mut host = host();
        for (request, response) in [
            (vec![0, 3, 0, 0], b"U2F_V2\x90\0".to_vec()),
            (vec![0], vec![0x67, 0]),
            (vec![0, 2, 7, 0], vec![0x69, 0x85]),
            (vec![0, 2, 3, 0], vec![0x6a, 0x80]),
        ] {
            send(&mut host, FIRST, Command::Msg, &request, 0);
            assert_eq!(host.take_app_request().unwrap().payload, request);
            host.app_response(response.clone(), 1, None);
            assert_eq!(sent(&mut host), [message(FIRST, Command::Msg, &response)]);
            assert!(host.u2f.is_none());
            assert!(host.denied_polls.is_empty());
        }
    }

    #[test]
    fn pending_u2f_repeats_do_not_resubmit_and_approval_is_delivered_once() {
        let mut host = host();
        let request = start_u2f(&mut host, 0);
        host.app_presence(true);
        host.handle_timeout(99);
        assert!(sent(&mut host).is_empty());
        host.handle_timeout(100);
        assert_eq!(
            sent(&mut host),
            [message(FIRST, Command::Msg, &[0x69, 0x85])]
        );
        for now in [200, 300, 400] {
            send(&mut host, FIRST, Command::Msg, &request, now);
            assert_eq!(
                sent(&mut host),
                [message(FIRST, Command::Msg, &[0x69, 0x85])]
            );
            assert!(host.take_app_request().is_none());
        }
        host.app_response(vec![5, 0x90, 0], 500, Some(450));
        assert!(sent(&mut host).is_empty(), "no unsolicited response");
        send(&mut host, FIRST, Command::Msg, &request, 600);
        assert_eq!(
            sent(&mut host),
            [message(FIRST, Command::Msg, &[5, 0x90, 0])]
        );
        send(&mut host, FIRST, Command::Msg, &request, 700);
        assert_eq!(host.take_app_request().unwrap().payload, request);
        assert!(sent(&mut host).is_empty(), "approval has been consumed");
    }

    #[test]
    fn immediate_approval_answers_the_first_request() {
        let mut host = host();
        start_u2f(&mut host, 0);
        host.app_response(vec![5, 0x90, 0], 1, Some(0));
        assert_eq!(
            sent(&mut host),
            [message(FIRST, Command::Msg, &[5, 0x90, 0])]
        );
        assert!(host.u2f.is_none());
    }

    #[test]
    fn denied_or_timed_out_polls_stay_denied_until_the_client_is_quiet() {
        for finished in [1, 30_000] {
            let mut host = host();
            let request = start_u2f(&mut host, 0);
            host.app_presence(true);
            host.handle_timeout(100);
            sent(&mut host);
            // Poll until the configured presence timeout.
            for now in (200..finished).step_by(100) {
                send(&mut host, FIRST, Command::Msg, &request, now);
                sent(&mut host);
            }
            host.app_response(vec![0x69, 0x85], finished, Some(finished));
            for now in [finished + 100, finished + 3_000, finished + 5_000] {
                send(&mut host, FIRST, Command::Msg, &request, now);
                assert_eq!(
                    sent(&mut host),
                    [message(FIRST, Command::Msg, &[0x69, 0x85])]
                );
                assert!(host.take_app_request().is_none());
            }
            host.handle_timeout(finished + 8_001);
            send(&mut host, FIRST, Command::Msg, &request, finished + 8_001);
            assert_eq!(host.take_app_request().unwrap().payload, request);
        }
    }

    #[test]
    fn an_abandoned_prompt_is_cancelled_and_its_late_reply_is_discarded() {
        let mut host = host();
        start_u2f(&mut host, 0);
        host.app_presence(true);
        host.handle_timeout(100);
        sent(&mut host);
        host.handle_timeout(3_000);
        assert!(!host.take_interrupt());
        host.handle_timeout(3_001);
        assert!(host.take_interrupt());
        assert!(host.u2f.is_none());
        host.app_response(vec![5, 0x90, 0], 3_100, Some(3_050));
        assert!(sent(&mut host).is_empty());
        start_u2f(&mut host, 3_200);
    }

    #[test]
    fn changed_bytes_other_channels_and_other_commands_are_busy_during_u2f() {
        let mut host = host();
        let request = start_u2f(&mut host, 0);
        host.app_presence(true);
        host.handle_timeout(100);
        sent(&mut host);
        let mut changed = request.clone();
        changed[7] ^= 1;
        send(&mut host, FIRST, Command::Msg, &changed, 200);
        send(&mut host, SECOND, Command::Msg, &request, 200);
        send(&mut host, FIRST, Command::Cbor, &[4], 200);
        send(&mut host, FIRST, Command::Ping, &[], 200);
        assert_eq!(
            sent(&mut host),
            [
                error(FIRST, ErrorCode::ChannelBusy),
                error(SECOND, ErrorCode::ChannelBusy),
                error(FIRST, ErrorCode::ChannelBusy),
                error(FIRST, ErrorCode::ChannelBusy)
            ]
        );
        assert_eq!(host.u2f.as_ref().unwrap().last_poll, 0);
    }

    #[test]
    fn approval_expiry_is_measured_from_presence_and_other_engine_calls_clear_it() {
        for now in [10_450, 10_451] {
            let mut host = host();
            let request = start_u2f(&mut host, 0);
            host.app_presence(true);
            host.handle_timeout(100);
            sent(&mut host);
            host.app_response(vec![5, 0x90, 0], 700, Some(450));
            host.handle_timeout(now);
            send(&mut host, FIRST, Command::Msg, &request, now);
            if now == 10_450 {
                assert_eq!(
                    sent(&mut host),
                    [message(FIRST, Command::Msg, &[5, 0x90, 0])]
                );
            } else {
                assert_eq!(host.take_app_request().unwrap().payload, request);
            }
        }
        let mut host = host();
        start_u2f(&mut host, 0);
        host.app_presence(true);
        host.handle_timeout(100);
        sent(&mut host);
        host.app_response(vec![5, 0x90, 0], 200, Some(150));
        start_cbor(&mut host, SECOND, &[4], 300);
        assert!(host.u2f.is_none());
    }

    #[test]
    fn init_cancels_u2f_but_cancel_is_ignored() {
        let mut host = host_with_channels(&[FIRST]);
        send(&mut host, BROADCAST_CID, Command::Init, &[0; 8], 0);
        sent(&mut host);
        start_u2f(&mut host, 0);
        send(&mut host, FIRST, Command::Cancel, &[], 50);
        assert!(!host.take_interrupt());
        assert!(sent(&mut host).is_empty());
        host.app_presence(true);
        host.handle_timeout(100);
        sent(&mut host);
        send(&mut host, FIRST, Command::Cancel, &[], 200);
        assert!(!host.take_interrupt());
        send(&mut host, FIRST, Command::Init, &[0; 8], 200);
        assert!(host.take_interrupt());
        assert!(host.u2f.is_none());
        assert_eq!(sent(&mut host)[0].command, Command::Init as u8);
        host.app_response(vec![5, 0x90, 0], 250, Some(220));
        assert!(sent(&mut host).is_empty());
    }

    #[test]
    fn policy_changes_clear_cached_approval_and_denial() {
        let mut host = host();
        start_u2f(&mut host, 0);
        host.app_response(vec![0x69, 0x85], 1, Some(1));
        sent(&mut host);
        assert_eq!(host.denied_polls.len(), 1);
        host.set_u2f_enabled(false);
        assert!(host.denied_polls.is_empty());
        start_u2f(&mut host, 10);
        host.app_presence(true);
        host.handle_timeout(110);
        sent(&mut host);
        host.app_response(vec![5, 0x90, 0], 200, Some(150));
        host.set_u2f_enabled(false);
        assert!(host.u2f.is_none());
    }

    #[test]
    fn suppression_is_bounded_without_evicting_live_denials() {
        let mut host = host();
        for index in 0..MAX_CHANNELS {
            let mut request = u2f_register();
            request[7..15].copy_from_slice(&(index as u64).to_be_bytes());
            send(&mut host, FIRST, Command::Msg, &request, 0);
            assert!(host.take_app_request().is_some());
            host.app_response(vec![0x69, 0x85], 1, Some(1));
            sent(&mut host);
        }
        let mut request = u2f_register();
        request[7] = 255;
        send(&mut host, FIRST, Command::Msg, &request, 2);
        assert_eq!(sent(&mut host), [error(FIRST, ErrorCode::ChannelBusy)]);
        assert_eq!(host.denied_polls.len(), MAX_CHANNELS);
    }
    use super::*;
    use crate::{CAPABILITY_CBOR, CAPABILITY_NMSG};
    use rand_core::{Infallible, TryCryptoRng, TryRng};

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
        let mut host = CtaphidHost::with_rng(TestRng::new(ids));
        host.set_capabilities(CAPABILITY_CBOR);
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
            let packet = frame.frame().as_bytes();
            assert_ne!(packet[4] & 0x80, 0, "continuation packet out of place");
            let channel = u32::from_be_bytes(packet[..4].try_into().unwrap());
            let length = u16::from_be_bytes([packet[5], packet[6]]) as usize;
            let mut payload = packet[7..7 + length.min(INIT_DATA)].to_vec();
            assert!(host.outgoing_frame_written(&frame));
            let mut sequence = 0;
            while payload.len() < length {
                let frame = host.next_outgoing_frame().expect("a continuation packet");
                let packet = frame.frame().as_bytes();
                assert_eq!(packet[..4], channel.to_be_bytes());
                assert_eq!(packet[4], sequence);
                let missing = length - payload.len();
                payload.extend_from_slice(&packet[5..5 + missing.min(CONT_DATA)]);
                sequence += 1;
                assert!(host.outgoing_frame_written(&frame));
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
        expected.push(CAPABILITY_CBOR);
        let actual = sent(&mut host);
        assert_eq!(actual[0].payload[16] & CAPABILITY_NMSG, 0);
        assert_eq!(actual, [message(BROADCAST_CID, Command::Init, &expected)]);
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
        // Only INIT is refused there: its requests are still served.
        send(&mut host, 2, Command::Ping, &[7], 0);
        assert_eq!(sent(&mut host), [message(2, Command::Ping, &[7])]);
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
        host.app_response(response.clone(), 0, None);
        assert!(!host.app_busy());
        assert_eq!(sent(&mut host), [message(FIRST, Command::Cbor, &response)]);
        assert!(!host.send_keepalive(true, 1_000), "no transaction");
    }

    /// A CTAPHID_CBOR request carries at least the CTAP command byte (CTAP 2.3
    /// §11.2.9.1.2), so an empty one never reaches the app.
    #[test]
    fn empty_application_messages_have_an_invalid_hid_length() {
        let mut host = host();
        for command in [Command::Cbor, Command::Msg] {
            send(&mut host, FIRST, command, &[], 0);
            assert_eq!(sent(&mut host), [error(FIRST, ErrorCode::InvalidLength)]);
            assert!(host.take_app_request().is_none());
        }
        // The channel is free again.
        start_cbor(&mut host, FIRST, &[0x04], 1);
    }

    /// The largest response goes out in 129 packets; a longer one would need
    /// a BCNT or sequence numbers CTAPHID does not have (CTAP 2.3 §11.2.4),
    /// and fails with ERR_OTHER instead of being sent malformed.
    #[test]
    fn responses_longer_than_a_message_are_errors() {
        let mut host = host();
        let largest: Vec<u8> = (0..=255).cycle().take(MAX_MESSAGE_SIZE).collect();
        start_cbor(&mut host, FIRST, &[0x04], 0);
        host.app_response(largest.clone(), 0, None);
        assert_eq!(host.pending.len(), 129);
        assert_eq!(sent(&mut host), [message(FIRST, Command::Cbor, &largest)]);

        for length in [MAX_MESSAGE_SIZE + 1, usize::from(u16::MAX) + 1] {
            start_cbor(&mut host, FIRST, &[0x04], 0);
            host.app_response(vec![0; length], 0, None);
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
        host.handle_frame(&message_packets(FIRST, 0x02, &[0; 70])[0], 0);
        assert_eq!(sent(&mut host), [error(FIRST, ErrorCode::InvalidCommand)]);
        // Nothing is left half received.
        send(&mut host, SECOND, Command::Ping, &[1], 0);
        assert_eq!(sent(&mut host), [message(SECOND, Command::Ping, &[1])]);
    }

    #[test]
    fn reserved_channels_and_oversized_messages_are_rejected() {
        let mut host = host();
        send(&mut host, 0, Command::Ping, &[1], 0);
        assert_eq!(sent(&mut host), [error(0, ErrorCode::InvalidChannel)]);
        send(&mut host, BROADCAST_CID, Command::Cbor, &[4], 0);
        assert_eq!(
            sent(&mut host),
            [error(BROADCAST_CID, ErrorCode::InvalidChannel)]
        );
        send(&mut host, 0, Command::Init, &[0; 8], 0);
        assert_eq!(sent(&mut host), [error(0, ErrorCode::InvalidChannel)]);
        send(&mut host, FIRST, Command::Init, &[0; 7], 0);
        assert_eq!(sent(&mut host), [error(FIRST, ErrorCode::InvalidLength)]);
        let mut oversized = message_packets(FIRST, Command::Ping.into_u8(), &[])[0];
        oversized.0[5..7].copy_from_slice(&(MAX_MESSAGE_SIZE as u16 + 1).to_be_bytes());
        host.handle_frame(&oversized, 0);
        assert_eq!(sent(&mut host), [error(FIRST, ErrorCode::InvalidLength)]);
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

        host.app_response(vec![CTAP2_ERR_KEEPALIVE_CANCEL], 0, None);
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
        sent(&mut host);
        send(&mut host, FIRST, Command::Cbor, &[0x04], 2);
        assert!(host.take_app_request().is_none(), "the app is busy");
        sent(&mut host);

        send(&mut host, FIRST, Command::Cancel, &[], 3);
        assert_eq!(
            sent(&mut host),
            [message(FIRST, Command::Cbor, &[CTAP2_ERR_KEEPALIVE_CANCEL])]
        );
        host.app_response(vec![0x00], 0, None);
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

        host.app_response(vec![0x00], 0, None);
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
        host.app_response(vec![0x00, 0xA0], 0, None);
        assert_eq!(
            sent(&mut host),
            [message(FIRST, Command::Cbor, &[0x00, 0xA0])]
        );
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

        host.app_response(vec![CTAP2_ERR_KEEPALIVE_CANCEL], 0, None);
        assert!(sent(&mut host).is_empty(), "the late answer is discarded");
        assert_eq!(host.take_app_request().unwrap().payload, [0x04]);
        host.app_response(vec![0x00], 0, None);
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
        host.app_response(vec![0x00], 0, None);
        assert_eq!(sent(&mut host), [message(FIRST, Command::Cbor, &[0x00])]);

        // While receiving, a new message on the same channel replaces nothing.
        let packets = message_packets(FIRST, Command::Ping.into_u8(), &[1; 100]);
        host.handle_frame(&packets[0], 2);
        send(&mut host, FIRST, Command::Ping, &[2], 3);
        host.handle_frame(&packets[1], 4);
        assert_eq!(sent(&mut host), [error(FIRST, ErrorCode::InvalidSeq)]);
    }
}
