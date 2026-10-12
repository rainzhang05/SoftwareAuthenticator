//! CTAPHID framing: arbitrary packets, time and app answers into
//! `CtaphidHost`, checking every packet it sends back.
//!
//! Invariants:
//! * no panic;
//! * every outgoing message is well formed: an initialization packet with a
//!   length of at most 7,609 bytes followed by exactly the continuation
//!   packets it needs, on the same channel, numbered from 0, zero padded, and
//!   never interleaved with another message;
//! * only INIT, PING, CBOR, MSG, KEEPALIVE and ERROR go out, never CANCEL; errors
//!   carry one defined CTAPHID error code and keepalives one defined status;
//! * messages only go to channels that sent an initialization packet, and
//!   channels allocated by INIT are neither 0 nor the broadcast channel;
//! * a CBOR response carries exactly what the app answered, or
//!   CTAP2_ERR_KEEPALIVE_CANCEL; an answer longer than a message goes out as
//!   ERR_OTHER instead;
//! * at most one message is queued per packet, answer or timer (no unbounded
//!   growth), requests for the app are never empty, never handed out while it
//!   is busy and never exceed 7,609 bytes, and timers are never further away
//!   than the longest timeout.
//! * an independent request/worker model predicts response bytes and order;
//!   CID ownership lasts through the final successful write, including when
//!   that report has already been selected;
//! * selection and failed writes do not consume reports; valid INIT may
//!   explicitly truncate its CID's output, and session teardown may discard
//!   pending output. Every other truncation or stale continuation fails.

use std::collections::HashSet;

use crate::rng::NarrowRng;
use arbitrary::{Arbitrary, Unstructured};
use pqkey::transport::ctaphid_host::{
    CONTINUATION_TIMEOUT_MS, CTAP2_ERR_KEEPALIVE_CANCEL, Command, CtaphidHost,
    KEEPALIVE_INTERVAL_MS, MAX_MESSAGE_SIZE, OutgoingFrame,
};
use pqkey::transport::{CTAPHID_FRAME_LEN, CtapHidFrame};

mod model;

pub const INIT_DATA: usize = CTAPHID_FRAME_LEN - 7;
pub const CONT_DATA: usize = CTAPHID_FRAME_LEN - 5;
const BROADCAST: u32 = 0xffff_ffff;

const ERROR_CODES: &[u8] = &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0B, 0x7F];

#[derive(Arbitrary, Debug)]
pub enum Channel {
    /// One the host allocated, by index.
    Allocated(u8),
    Broadcast,
    Zero,
    Raw(u32),
}

#[derive(Arbitrary, Debug)]
pub enum Mangle {
    None,
    Drop(u8),
    Duplicate(u8),
    Swap(u8, u8),
}

#[derive(Arbitrary, Debug)]
pub enum Action {
    /// Any 64 bytes.
    Packet(Box<[u8; CTAPHID_FRAME_LEN]>),
    /// An initialization packet with a chosen channel, command and length.
    Init {
        channel: Channel,
        command: u8,
        length: u16,
        data: Box<[u8; INIT_DATA]>,
    },
    /// A continuation packet.
    Continuation {
        channel: Channel,
        sequence: u8,
        data: Box<[u8; CONT_DATA]>,
    },
    /// A whole message, split into packets as a host sends it, possibly
    /// with one packet dropped, repeated or out of order.
    Message {
        channel: Channel,
        command: u8,
        length: u16,
        fill: u8,
        mangle: Mangle,
        gap_ms: u16,
    },
    Advance(u16),
    Timeout,
    Keepalive(bool),
    /// The transport hands the next request to the app.
    TakeRequest,
    /// The app answers the request it is working on.
    Respond {
        length: u16,
        fill: u8,
    },
    /// The transport reads the interrupt flag.
    TakeInterrupt,
    /// A real U2F APDU rather than a patterned message payload.
    Apdu {
        channel: Channel,
        payload: Vec<u8>,
    },
    /// A U2F result after presence, with the presence completion timestamp.
    U2fRespond {
        approved: bool,
    },
    /// Select without writing, including the last response report.
    SelectOutput,
    /// Write a selected report successfully, unless INIT invalidated it.
    WriteOutput,
    /// A failed device write: retain the selected report without completion.
    FailOutput,
    /// Successfully transmit at most this many reports.
    Transmit(u8),
    /// Explicit same-channel abort and resynchronization.
    Abort(Channel),
    /// End the session, allowing pending output to be discarded on teardown.
    Shutdown,
    /// Hand identification to the independent daemon worker.
    TakeIdentification,
    /// Complete the latest or previous identification attempt.
    IdentificationResult {
        previous: bool,
        delivered: bool,
    },
}

struct Harness {
    host: CtaphidHost<NarrowRng>,
    now: u64,
    /// Channels allocated by INIT, as the host announced them.
    allocated: Vec<u32>,
    /// Channels that sent an initialization packet.
    senders: HashSet<u32>,
    app_busy: bool,
    model: model::Model,
    selected: Option<OutgoingFrame>,
    assembly: Option<Assembly>,
    stopped: bool,
    identification: Option<u64>,
    previous_identification: Option<u64>,
}

struct Assembly {
    channel: u32,
    command: u8,
    length: usize,
    payload: Vec<u8>,
    sequence: u8,
}

impl Harness {
    fn channel(&self, channel: &Channel) -> u32 {
        match channel {
            Channel::Allocated(index) if !self.allocated.is_empty() => {
                self.allocated[usize::from(*index) % self.allocated.len()]
            }
            Channel::Allocated(index) => u32::from(*index),
            Channel::Broadcast => BROADCAST,
            Channel::Zero => 0,
            Channel::Raw(raw) => *raw,
        }
    }

    fn packet(&mut self, packet: [u8; CTAPHID_FRAME_LEN]) {
        if packet[4] & 0x80 != 0 {
            self.senders
                .insert(u32::from_be_bytes(packet[..4].try_into().unwrap()));
        }
        let abort = self.model.packet(&packet, self.now);
        self.host.handle_frame(&CtapHidFrame::new(packet), self.now);
        if abort.is_some_and(|cid| {
            self.assembly
                .as_ref()
                .is_some_and(|message| message.channel == cid)
        }) {
            self.assembly = None;
        }
    }

    fn message_packets(channel: u32, command: u8, payload: &[u8], length: u16) -> Vec<[u8; 64]> {
        let mut first = [0u8; CTAPHID_FRAME_LEN];
        first[..4].copy_from_slice(&channel.to_be_bytes());
        first[4] = command | 0x80;
        first[5..7].copy_from_slice(&length.to_be_bytes());
        let (head, rest) = payload.split_at(payload.len().min(INIT_DATA));
        first[7..7 + head.len()].copy_from_slice(head);
        let mut packets = vec![first];
        for (sequence, chunk) in rest.chunks(CONT_DATA).enumerate() {
            let mut packet = [0u8; CTAPHID_FRAME_LEN];
            packet[..4].copy_from_slice(&channel.to_be_bytes());
            packet[4] = sequence as u8;
            packet[5..5 + chunk.len()].copy_from_slice(chunk);
            packets.push(packet);
        }
        packets
    }

    fn write_selected(&mut self) {
        let Some(selected) = self.selected.take() else {
            return;
        };
        if !self.host.is_outgoing_current(&selected) {
            assert!(
                !self.host.outgoing_frame_written(&selected),
                "stale completion accepted"
            );
            return;
        }
        let packet = selected.frame().as_bytes();
        let channel = u32::from_be_bytes(packet[..4].try_into().unwrap());
        if packet[4] & 0x80 != 0 {
            assert!(
                self.assembly.is_none(),
                "unexplained truncation or interleaved message"
            );
            let length = usize::from(u16::from_be_bytes([packet[5], packet[6]]));
            assert!(length <= MAX_MESSAGE_SIZE);
            let head = length.min(INIT_DATA);
            assert!(packet[7 + head..].iter().all(|&byte| byte == 0), "padding");
            self.assembly = Some(Assembly {
                channel,
                command: packet[4] & 0x7f,
                length,
                payload: packet[7..7 + head].to_vec(),
                sequence: 0,
            });
        } else {
            let message = self
                .assembly
                .as_mut()
                .expect("stale continuation without an initialization report");
            assert_eq!(channel, message.channel, "interleaved channel");
            assert_eq!(packet[4], message.sequence, "continuation sequence");
            message.sequence += 1;
            let count = (message.length - message.payload.len()).min(CONT_DATA);
            message.payload.extend_from_slice(&packet[5..5 + count]);
            assert!(packet[5 + count..].iter().all(|&byte| byte == 0), "padding");
        }
        // No input can intervene between this simulated successful write and
        // its completion callback, just as in the real transport thread.
        assert!(self.host.outgoing_frame_written(&selected));
        assert!(
            !self.host.outgoing_frame_written(&selected),
            "duplicate completion"
        );
        if self
            .assembly
            .as_ref()
            .is_some_and(|message| message.payload.len() == message.length)
        {
            let message = self.assembly.take().unwrap();
            self.model
                .output(message.channel, message.command, &message.payload);
            self.check_message(message.channel, message.command, &message.payload);
        }
    }

    fn transmit(&mut self, count: usize) {
        for _ in 0..count {
            self.selected = self.host.next_outgoing_frame();
            if self.selected.is_none() {
                break;
            }
            self.write_selected();
        }
    }

    fn drain(&mut self) {
        while self.host.next_outgoing_frame().is_some() {
            self.transmit(1);
        }
        assert!(self.assembly.is_none(), "unexplained response truncation");
        self.model.drained();
    }

    fn check_message(&mut self, channel: u32, command: u8, payload: &[u8]) {
        assert!(
            self.senders.contains(&channel),
            "a message for channel {channel:08x}, which sent nothing"
        );
        let command = Command::try_from(command).expect("a defined command");
        match command {
            Command::Error => {
                assert_eq!(payload.len(), 1);
                assert!(
                    ERROR_CODES.contains(&payload[0]),
                    "error 0x{:02x}",
                    payload[0]
                );
            }
            Command::KeepAlive => {
                assert_eq!(payload.len(), 1);
                assert!(matches!(payload[0], 1 | 2), "keepalive status");
                assert_ne!(channel, BROADCAST);
            }
            Command::Init => {
                assert_eq!(payload.len(), 17);
                assert_eq!(payload[12], 2, "CTAPHID protocol version");
                let assigned = u32::from_be_bytes(payload[8..12].try_into().unwrap());
                if channel == BROADCAST {
                    assert!(assigned != 0 && assigned != BROADCAST, "reserved channel");
                    if !self.allocated.contains(&assigned) {
                        self.allocated.push(assigned);
                    }
                } else {
                    assert_eq!(assigned, channel, "INIT on a channel keeps it");
                }
            }
            Command::Lock | Command::Wink => {
                assert!(payload.is_empty());
                assert_ne!(channel, BROADCAST);
            }
            Command::Ping => assert_ne!(channel, BROADCAST),
            Command::Cbor | Command::Msg => assert_ne!(channel, BROADCAST),
            Command::Cancel => panic!("CTAPHID_CANCEL is never sent"),
        }
    }

    fn check_timers(&self) {
        if let Some(deadline) = self.host.next_deadline() {
            assert!(
                deadline
                    <= self.now
                        + CONTINUATION_TIMEOUT_MS
                            .max(KEEPALIVE_INTERVAL_MS)
                            .max(pqkey::transport::ctaphid_host::U2F_APPROVAL_MS + 1),
                "a timer further away than any timeout"
            );
        }
        assert_eq!(self.host.app_busy(), self.app_busy);
    }

    fn act(&mut self, action: Action) {
        match action {
            Action::Apdu { channel, payload } => {
                let length = payload.len().min(MAX_MESSAGE_SIZE);
                let channel = self.channel(&channel);
                for packet in Self::message_packets(
                    channel,
                    Command::Msg as u8,
                    &payload[..length],
                    length as u16,
                ) {
                    self.packet(packet);
                }
            }
            Action::U2fRespond { approved } => {
                if self.app_busy {
                    self.app_busy = false;
                    let response = if approved {
                        vec![5, 0x90, 0]
                    } else {
                        vec![0x69, 0x85]
                    };
                    self.model
                        .respond(response.clone(), self.now, Some(self.now));
                    self.host.app_response(response, self.now, Some(self.now));
                }
            }
            Action::Packet(packet) => self.packet(*packet),
            Action::Init {
                channel,
                command,
                length,
                data,
            } => {
                let mut packet = [0u8; CTAPHID_FRAME_LEN];
                packet[..4].copy_from_slice(&self.channel(&channel).to_be_bytes());
                packet[4] = command | 0x80;
                packet[5..7].copy_from_slice(&length.to_be_bytes());
                packet[7..].copy_from_slice(&*data);
                self.packet(packet);
            }
            Action::Continuation {
                channel,
                sequence,
                data,
            } => {
                let mut packet = [0u8; CTAPHID_FRAME_LEN];
                packet[..4].copy_from_slice(&self.channel(&channel).to_be_bytes());
                packet[4] = sequence & 0x7f;
                packet[5..].copy_from_slice(&*data);
                self.packet(packet);
            }
            Action::Message {
                channel,
                command,
                length,
                fill,
                mangle,
                gap_ms,
            } => {
                let channel = self.channel(&channel);
                let length = length % (MAX_MESSAGE_SIZE as u16 + 64);
                let payload: Vec<u8> = (0..length).map(|i| fill.wrapping_add(i as u8)).collect();
                let mut packets = Self::message_packets(channel, command, &payload, length);
                let pick = |index: u8| usize::from(index) % packets.len();
                match mangle {
                    Mangle::None => {}
                    Mangle::Drop(index) => {
                        let index = pick(index);
                        packets.remove(index);
                    }
                    Mangle::Duplicate(index) => {
                        let index = pick(index);
                        packets.insert(index, packets[index]);
                    }
                    Mangle::Swap(a, b) => {
                        let (a, b) = (pick(a), pick(b));
                        packets.swap(a, b);
                    }
                }
                for packet in packets {
                    self.packet(packet);
                    self.now += u64::from(gap_ms % 700);
                }
            }
            Action::Advance(ms) => self.now += u64::from(ms),
            Action::Timeout => {
                self.model.timeout(self.now);
                self.host.handle_timeout(self.now);
            }
            Action::Keepalive(waiting) => {
                self.host.app_presence(waiting);
                let sent = self.host.send_keepalive(waiting, self.now);
                assert_eq!(sent, self.model.keepalive(waiting, self.now));
            }
            Action::TakeRequest => {
                let request = self.host.take_app_request();
                assert_eq!(
                    request.is_some(),
                    self.model.wants_request(),
                    "worker admission"
                );
                if let Some(request) = request {
                    self.model.take_request(&request);
                    assert!(!self.app_busy, "a request for a busy app");
                    assert!(!request.payload.is_empty(), "an empty CBOR request");
                    assert!(request.payload.len() <= MAX_MESSAGE_SIZE);
                    self.app_busy = true;
                }
            }
            Action::Respond { length, fill } => {
                if !self.app_busy {
                    return;
                }
                self.app_busy = false;
                // Up to a little more than a message holds: a longer answer
                // goes out as ERR_OTHER.
                let length = usize::from(length) % (MAX_MESSAGE_SIZE + 64);
                let response: Vec<u8> = (0..length).map(|i| fill.wrapping_add(i as u8)).collect();
                self.model.respond(response.clone(), self.now, None);
                self.host.app_response(response, self.now, None);
            }
            Action::TakeInterrupt => {
                self.host.take_interrupt();
            }
            Action::SelectOutput => self.selected = self.host.next_outgoing_frame(),
            Action::WriteOutput => self.write_selected(),
            Action::FailOutput => {
                if self.selected.is_none() {
                    self.selected = self.host.next_outgoing_frame();
                }
                // No successful write, hence no completion callback.
                if let Some(selected) = &self.selected
                    && self.host.is_outgoing_current(selected)
                {
                    assert!(self.host.next_outgoing_frame().is_some());
                }
            }
            Action::Transmit(count) => self.transmit(usize::from(count)),
            Action::Abort(channel) => {
                let channel = self.channel(&channel);
                self.packet(Self::message_packets(channel, Command::Init as u8, &[0xA5; 8], 8)[0]);
            }
            Action::Shutdown => self.stopped = true,
            Action::TakeIdentification => {
                let request = self.host.take_identification_request();
                assert_eq!(request.is_some(), self.model.wants_identification());
                if let Some(request) = request {
                    self.model
                        .take_identification(request.token, request.deadline);
                    self.previous_identification = self.identification;
                    self.identification = Some(request.token);
                }
            }
            Action::IdentificationResult {
                previous,
                delivered,
            } => {
                let token = if previous {
                    self.previous_identification
                } else {
                    self.identification
                };
                if let Some(token) = token {
                    self.model.identification_result(token, delivered, self.now);
                    self.host
                        .identification_response(token, delivered, self.now);
                }
            }
        }
        self.check_timers();
    }
}

/// Run one fuzz input.
pub fn run(data: &[u8]) {
    let mut u = Unstructured::new(data);
    let Ok((seed, range)) = u.arbitrary::<(u64, u16)>() else {
        return;
    };
    let mut harness = Harness {
        host: CtaphidHost::with_rng(NarrowRng::new(seed, u32::from(range) + 1)),
        now: 0,
        allocated: Vec::new(),
        senders: HashSet::new(),
        app_busy: false,
        model: model::Model::new(seed, u32::from(range) + 1),
        selected: None,
        assembly: None,
        stopped: false,
        identification: None,
        previous_identification: None,
    };
    harness.host.set_capabilities(0x05);
    while let Ok(action) = u.arbitrary::<Action>() {
        harness.act(action);
        if u.is_empty() || harness.stopped {
            break;
        }
    }
    if !harness.stopped {
        harness.drain();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn committed_transmission_boundary_seeds_replay() {
        let directory =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds/ctaphid_packets");
        let mut count = 0;
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            super::run(&std::fs::read(&path).unwrap());
            count += 1;
        }
        assert!(count > 0, "transmission boundary seeds are missing");
    }
}
