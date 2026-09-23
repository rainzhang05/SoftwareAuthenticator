//! CTAPHID framing: arbitrary packets, time and app answers into
//! `CtaphidHost`, checking every packet it sends back.
//!
//! Invariants:
//! * no panic;
//! * every outgoing message is well formed: an initialization packet with a
//!   length of at most 7,609 bytes followed by exactly the continuation
//!   packets it needs, on the same channel, numbered from 0, zero padded, and
//!   never interleaved with another message;
//! * only defined commands go out; errors carry one defined CTAPHID error
//!   code and keepalives one defined status;
//! * messages only go to channels that sent an initialization packet, and
//!   channels allocated by INIT are neither 0 nor the broadcast channel;
//! * a CBOR response carries exactly what the app answered, or
//!   CTAP2_ERR_KEEPALIVE_CANCEL;
//! * at most one message is queued per packet, answer or timer (no unbounded
//!   growth), requests for the app are never handed out while it is busy and
//!   never exceed 7,609 bytes, and timers are never further away than the
//!   longest timeout.

use std::collections::HashSet;

use crate::rng::NarrowRng;
use arbitrary::{Arbitrary, Unstructured};
use pqkey::transport::ctaphid_host::{
    CONTINUATION_TIMEOUT_MS, CTAP2_ERR_KEEPALIVE_CANCEL, Command, CtaphidHost,
    KEEPALIVE_INTERVAL_MS, MAX_MESSAGE_SIZE,
};
use pqkey::uhid::{CTAPHID_FRAME_LEN, CtapHidFrame};

pub const INIT_DATA: usize = CTAPHID_FRAME_LEN - 7;
pub const CONT_DATA: usize = CTAPHID_FRAME_LEN - 5;
const BROADCAST: u32 = 0xffff_ffff;

const ERROR_CODES: &[u8] = &[0x01, 0x03, 0x04, 0x05, 0x06, 0x0B, 0x7F];

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
}

struct Harness {
    host: CtaphidHost<NarrowRng>,
    now: u64,
    /// Channels allocated by INIT, as the host announced them.
    allocated: Vec<u32>,
    /// Channels that sent an initialization packet.
    senders: HashSet<u32>,
    app_busy: bool,
    /// What the app answered in this step, if it did.
    app_answer: Option<Vec<u8>>,
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
        self.host.handle_frame(&CtapHidFrame::new(packet), self.now);
        assert!(self.drain() <= 1, "more than one message for one packet");
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

    /// Take every queued packet, check it and return how many messages
    /// there were.
    fn drain(&mut self) -> usize {
        let mut messages = 0;
        while let Some(frame) = self.host.next_outgoing_frame() {
            let packet = *frame.as_bytes();
            assert_ne!(packet[4] & 0x80, 0, "a continuation packet out of place");
            let channel = u32::from_be_bytes(packet[..4].try_into().unwrap());
            let command = packet[4] & 0x7f;
            let length = usize::from(u16::from_be_bytes([packet[5], packet[6]]));
            assert!(length <= MAX_MESSAGE_SIZE, "a {length}-byte message");
            let head = length.min(INIT_DATA);
            let mut payload = packet[7..7 + head].to_vec();
            assert!(packet[7 + head..].iter().all(|&b| b == 0), "padding");
            let mut sequence = 0u8;
            while payload.len() < length {
                let frame = self
                    .host
                    .next_outgoing_frame()
                    .expect("the rest of the message is queued with it");
                let packet = frame.as_bytes();
                assert_eq!(packet[..4], channel.to_be_bytes(), "interleaved channel");
                assert_eq!(packet[4], sequence, "continuation sequence");
                let chunk = (length - payload.len()).min(CONT_DATA);
                payload.extend_from_slice(&packet[5..5 + chunk]);
                assert!(packet[5 + chunk..].iter().all(|&b| b == 0), "padding");
                sequence += 1;
            }
            self.check_message(channel, command, &payload);
            messages += 1;
        }
        messages
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
            Command::Ping => assert_ne!(channel, BROADCAST),
            Command::Cbor => {
                assert_ne!(channel, BROADCAST);
                let answered = self.app_answer.take();
                assert!(
                    answered.as_deref() == Some(payload) || payload == [CTAP2_ERR_KEEPALIVE_CANCEL],
                    "a CBOR response the app did not give"
                );
            }
            Command::Cancel => panic!("CTAPHID_CANCEL is never sent"),
        }
    }

    fn check_timers(&self) {
        if let Some(deadline) = self.host.next_deadline() {
            assert!(
                deadline <= self.now + CONTINUATION_TIMEOUT_MS.max(KEEPALIVE_INTERVAL_MS),
                "a timer further away than any timeout"
            );
        }
        assert_eq!(self.host.app_busy(), self.app_busy);
    }

    fn act(&mut self, action: Action) {
        match action {
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
                self.host.handle_timeout(self.now);
                assert!(self.drain() <= 1);
            }
            Action::Keepalive(waiting) => {
                let sent = self.host.send_keepalive(waiting, self.now);
                assert_eq!(self.drain(), usize::from(sent));
            }
            Action::TakeRequest => {
                if let Some(request) = self.host.take_app_request() {
                    assert!(!self.app_busy, "a request for a busy app");
                    assert!(!request.is_empty(), "an empty CBOR request");
                    assert!(request.len() <= MAX_MESSAGE_SIZE);
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
                self.app_answer = Some(response.clone());
                self.host.app_response(response);
                assert!(self.drain() <= 1);
            }
            Action::TakeInterrupt => {
                self.host.take_interrupt();
            }
        }
        self.app_answer = None;
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
        app_answer: None,
    };
    harness.host.set_capabilities(0x0C);
    while let Ok(action) = u.arbitrary::<Action>() {
        harness.act(action);
        if u.is_empty() {
            break;
        }
    }
}
