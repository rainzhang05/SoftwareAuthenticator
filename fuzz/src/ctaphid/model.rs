//! An I/O-independent oracle: requests and worker events predict messages;
//! only complete successful transmissions release their transaction owner.

use super::*;
use pqkey::transport::ctaphid_host::{
    MAX_CHANNELS, U2F_APPROVAL_MS, U2F_POLL_TIMEOUT_MS, U2F_RESPONSE_WAIT_MS,
};
use pqkey_ctap::ctap::u2f::requests_presence;
use rand_core::Rng;
use std::collections::VecDeque;

struct Owner {
    id: u64,
    channel: u32,
    command: u8,
    length: usize,
    request: Vec<u8>,
    sequence: u8,
    at: u64,
    started: u64,
    submitted: bool,
    responding: bool,
    keepalive_at: u64,
    status: u8,
    identification: Option<(u64, u64)>,
}

struct Worker {
    id: u64,
    command: u8,
}

struct Poll {
    id: u64,
    channel: u32,
    request: Vec<u8>,
    started: u64,
    last: u64,
    presence: bool,
    answer: Option<(Vec<u8>, u64)>,
}

struct Reply {
    channel: u32,
    command: u8,
    payload: Vec<u8>,
    completes: Option<u64>,
}

pub(super) struct Model {
    rng: NarrowRng,
    channels: VecDeque<u32>,
    owner: Option<Owner>,
    worker: Option<Worker>,
    poll: Option<Poll>,
    denied: Vec<(u32, Vec<u8>, u64)>,
    replies: VecDeque<Reply>,
    next_id: u64,
    lease: Option<(u32, u64)>,
    next_identification: u64,
}

impl Model {
    pub fn new(seed: u64, range: u32) -> Self {
        Self {
            rng: NarrowRng::new(seed, range),
            channels: VecDeque::new(),
            owner: None,
            worker: None,
            poll: None,
            denied: Vec::new(),
            replies: VecDeque::new(),
            next_id: 0,
            lease: None,
            next_identification: 0,
        }
    }

    fn begin(&mut self, channel: u32, command: u8, length: usize, data: &[u8], now: u64) {
        let id = self.next_id;
        self.next_id += 1;
        self.owner = Some(Owner {
            id,
            channel,
            command,
            length,
            request: data[..length.min(data.len())].to_vec(),
            sequence: 0,
            at: now,
            started: now,
            submitted: false,
            responding: false,
            keepalive_at: now,
            status: 1,
            identification: None,
        });
    }

    fn reply(&mut self, channel: u32, command: u8, payload: Vec<u8>, terminal: bool) {
        let completes = if terminal {
            let owner = self.owner.as_mut().expect("a response needs an owner");
            assert_eq!(owner.channel, channel);
            assert!(!owner.responding, "a second response to one request");
            owner.responding = true;
            Some(owner.id)
        } else {
            None
        };
        let (command, payload) = if payload.len() > MAX_MESSAGE_SIZE {
            (Command::Error as u8, vec![0x7f])
        } else {
            (command, payload)
        };
        self.replies.push_back(Reply {
            channel,
            command,
            payload,
            completes,
        });
    }

    fn error(&mut self, channel: u32, code: u8, terminal: bool) {
        self.reply(channel, Command::Error as u8, vec![code], terminal);
    }

    fn busy_channel(&self) -> Option<u32> {
        self.owner.as_ref().map(|o| o.channel).or_else(|| {
            self.poll
                .as_ref()
                .filter(|p| p.answer.is_none())
                .map(|p| p.channel)
        })
    }

    /// Return the channel whose unsent output was explicitly aborted.
    pub fn packet(&mut self, packet: &[u8; 64], now: u64) -> Option<u32> {
        if self.lease.is_some_and(|(_, expires)| now >= expires) {
            self.lease = None;
        }
        let channel = u32::from_be_bytes(packet[..4].try_into().unwrap());
        if packet[4] & 0x80 == 0 {
            if let Some(owner) = &mut self.owner
                && owner.channel == channel
                && !owner.responding
                && owner.request.len() < owner.length
            {
                if packet[4] != owner.sequence {
                    self.error(channel, 4, true);
                } else {
                    owner.sequence += 1;
                    owner.at = now;
                    let count = (owner.length - owner.request.len()).min(CONT_DATA);
                    owner.request.extend_from_slice(&packet[5..5 + count]);
                    if owner.request.len() == owner.length {
                        self.complete(now);
                    }
                }
            }
            return None;
        }
        if let Some(index) = self.channels.iter().position(|cid| *cid == channel) {
            self.channels.remove(index);
            self.channels.push_back(channel);
        }
        let command = packet[4] & 0x7f;
        let length = usize::from(u16::from_be_bytes([packet[5], packet[6]]));
        if command == Command::Cancel as u8 {
            if let Some(owner) = &self.owner
                && owner.channel == channel
                && owner.command == Command::Cbor as u8
                && !owner.responding
                && owner.request.len() == owner.length
                && !owner.submitted
            {
                self.reply(
                    channel,
                    Command::Cbor as u8,
                    vec![CTAP2_ERR_KEEPALIVE_CANCEL],
                    true,
                );
            }
            return None;
        }
        if self.lease.is_some_and(|(owner, _)| channel != owner) {
            self.error(channel, 6, false);
            return None;
        }
        if command == Command::Init as u8 {
            if self.busy_channel().is_some_and(|busy| busy != channel) {
                self.error(channel, 6, false);
                return None;
            }
            if length != 8 {
                let terminal = self.busy_channel().is_none();
                if terminal {
                    self.begin(channel, command, length, &packet[7..], now);
                }
                self.error(channel, 3, terminal);
                return None;
            }
            let active = self.owner.is_some();
            let assigned = if channel == BROADCAST {
                let mut assigned = None;
                for _ in 0..64 {
                    let candidate = self.rng.next_u32();
                    if candidate != 0
                        && candidate != BROADCAST
                        && !self.channels.contains(&candidate)
                    {
                        if self.channels.len() == MAX_CHANNELS {
                            self.channels.pop_front();
                        }
                        self.channels.push_back(candidate);
                        assigned = Some(candidate);
                        break;
                    }
                }
                if assigned.is_none() {
                    // An allocation failure has no resynchronization result.
                    if active {
                        self.error(channel, 6, false);
                    } else {
                        self.begin(channel, command, length, &packet[7..], now);
                        self.error(channel, 6, true);
                    }
                    return None;
                }
                assigned.unwrap()
            } else if channel != 0 && (active || self.channels.contains(&channel)) {
                channel
            } else {
                if !active {
                    self.begin(channel, command, length, &packet[7..], now);
                }
                self.error(channel, 0x0b, !active);
                return None;
            };
            self.replies.retain(|reply| reply.channel != channel);
            if self
                .poll
                .as_ref()
                .is_some_and(|poll| poll.channel == channel)
            {
                self.poll = None;
            }
            self.denied.retain(|(cid, _, _)| *cid != channel);
            self.begin(channel, command, length, &packet[7..], now);
            let mut payload = packet[7..15].to_vec();
            payload.extend_from_slice(&assigned.to_be_bytes());
            payload.extend_from_slice(&[2, 0, 0, 0, 5]);
            self.reply(channel, command, payload, true);
            return Some(channel);
        }
        if let Some(busy) = self.busy_channel() {
            let receiving = self
                .owner
                .as_ref()
                .is_some_and(|o| !o.responding && o.request.len() < o.length);
            if busy != channel
                || self.owner.is_some() && !receiving
                || self.owner.is_none() && command != Command::Msg as u8
            {
                self.error(channel, 6, false);
                return None;
            }
            if receiving {
                self.error(channel, 4, true);
                return None;
            }
        }
        self.begin(channel, command, length, &packet[7..], now);
        if channel == 0 || channel == BROADCAST {
            self.error(channel, 0x0b, true);
        } else if !matches!(command, 1 | 3 | 4 | 8 | 0x10) {
            self.error(channel, 1, true);
        } else if length > MAX_MESSAGE_SIZE
            || matches!(command, 3 | 0x10) && length == 0
            || command == 4 && length != 1
            || command == 8 && length != 0
        {
            self.error(channel, 3, true);
        } else if length <= INIT_DATA {
            self.complete(now);
        }
        None
    }

    fn complete(&mut self, now: u64) {
        let owner = self.owner.as_mut().unwrap();
        owner.started = now;
        owner.keepalive_at = now;
        let owner = self.owner.as_ref().unwrap();
        let (channel, command, request) = (owner.channel, owner.command, owner.request.clone());
        if command == 4 {
            let seconds = request[0];
            if seconds > 10 {
                self.error(channel, 2, true);
            } else {
                self.lease = (seconds != 0).then_some((channel, now + u64::from(seconds) * 1_000));
                self.reply(channel, command, vec![], true);
            }
            return;
        }
        if command == 8 {
            let token = self.next_identification;
            self.next_identification += 1;
            self.owner.as_mut().unwrap().identification = Some((token, now + 500));
            return;
        }
        if command == Command::Ping as u8 {
            self.reply(channel, command, request, true);
            return;
        }
        if command == Command::Msg as u8 {
            if let Some(poll) = &mut self.poll {
                if poll.channel == channel && poll.request == request {
                    poll.last = now;
                    let response = match &poll.answer {
                        Some((answer, expires)) if now <= *expires => Some(answer.clone()),
                        Some(_) => None,
                        None => Some(vec![0x69, 0x85]),
                    };
                    if let Some(response) = response {
                        if poll.answer.is_some() {
                            self.poll = None;
                        }
                        self.reply(channel, command, response, true);
                        return;
                    }
                } else if poll.answer.is_none() {
                    self.error(channel, 6, true);
                    return;
                }
            }
            if let Some((_, _, last)) = self.denied.iter_mut().find(|(cid, body, last)| {
                *cid == channel
                    && *body == request
                    && now.saturating_sub(*last) <= U2F_POLL_TIMEOUT_MS
            }) {
                *last = now;
                self.reply(channel, command, vec![0x69, 0x85], true);
                return;
            }
            self.denied
                .retain(|(_, _, last)| now.saturating_sub(*last) <= U2F_POLL_TIMEOUT_MS);
            if requests_presence(&request) && self.denied.len() >= MAX_CHANNELS {
                self.error(channel, 6, true);
                return;
            }
        }
        self.poll = None;
    }

    pub fn timeout(&mut self, now: u64) {
        if self.lease.is_some_and(|(_, expires)| now >= expires) {
            self.lease = None;
        }
        if let Some(owner) = &self.owner
            && !owner.responding
            && owner
                .identification
                .is_some_and(|(_, deadline)| now >= deadline)
        {
            self.error(owner.channel, 0x7f, true);
        }
        self.denied
            .retain(|(_, _, last)| now.saturating_sub(*last) <= U2F_POLL_TIMEOUT_MS);
        if self.poll.as_ref().is_some_and(|poll| {
            now > poll
                .answer
                .as_ref()
                .map_or(poll.last + U2F_POLL_TIMEOUT_MS, |(_, expiry)| *expiry)
        }) {
            self.poll = None;
        }
        if let Some(owner) = &self.owner
            && !owner.responding
        {
            if owner.request.len() < owner.length && now >= owner.at + CONTINUATION_TIMEOUT_MS {
                self.error(owner.channel, 5, true);
            } else if owner.command == Command::Msg as u8
                && owner.submitted
                && self.poll.as_ref().is_some_and(|poll| {
                    poll.presence && now.saturating_sub(poll.started) >= U2F_RESPONSE_WAIT_MS
                })
            {
                self.reply(owner.channel, Command::Msg as u8, vec![0x69, 0x85], true);
            }
        }
    }

    pub fn keepalive(&mut self, waiting: bool, now: u64) -> bool {
        if waiting
            && self
                .worker
                .as_ref()
                .is_some_and(|worker| worker.command == Command::Msg as u8)
            && let Some(poll) = &mut self.poll
        {
            poll.presence = true;
        }
        let Some(owner) = &mut self.owner else {
            return false;
        };
        if owner.responding
            || owner.request.len() != owner.length
            || !matches!(owner.command, 3 | 0x10)
        {
            return false;
        }
        let status = if waiting && owner.submitted { 2 } else { 1 };
        if status == owner.status && now < owner.keepalive_at + KEEPALIVE_INTERVAL_MS {
            return false;
        }
        owner.status = status;
        owner.keepalive_at = now;
        let channel = owner.channel;
        self.reply(channel, Command::KeepAlive as u8, vec![status], false);
        true
    }

    pub fn wants_identification(&self) -> bool {
        self.owner.as_ref().is_some_and(|owner| {
            owner.identification.is_some() && !owner.submitted && !owner.responding
        })
    }

    pub fn take_identification(&mut self, token: u64, deadline: u64) {
        assert!(self.wants_identification());
        let owner = self.owner.as_mut().unwrap();
        assert_eq!(owner.identification, Some((token, deadline)));
        owner.submitted = true;
    }

    pub fn identification_result(&mut self, token: u64, delivered: bool, now: u64) {
        if let Some(owner) = &self.owner
            && !owner.responding
            && let Some((expected, deadline)) = owner.identification
            && token == expected
        {
            if delivered && now < deadline {
                self.reply(owner.channel, 8, vec![], true);
            } else {
                self.error(owner.channel, 0x7f, true);
            }
        }
    }

    pub fn wants_request(&self) -> bool {
        self.worker.is_none()
            && self.owner.as_ref().is_some_and(|owner| {
                !owner.responding
                    && !owner.submitted
                    && owner.request.len() == owner.length
                    && matches!(owner.command, 3 | 0x10)
            })
    }

    pub fn take_request(&mut self, request: &pqkey::transport::ctaphid_host::AppRequest) {
        assert!(
            self.wants_request(),
            "another CID or aborted request reached the worker"
        );
        let owner = self.owner.as_mut().unwrap();
        assert_eq!(request.command as u8, owner.command);
        assert_eq!(request.payload, owner.request);
        owner.submitted = true;
        self.worker = Some(Worker {
            id: owner.id,
            command: owner.command,
        });
        if owner.command == Command::Msg as u8 && requests_presence(&owner.request) {
            self.poll = Some(Poll {
                id: owner.id,
                channel: owner.channel,
                request: owner.request.clone(),
                started: owner.started,
                last: owner.started,
                presence: false,
                answer: None,
            });
        }
    }

    pub fn respond(&mut self, response: Vec<u8>, now: u64, presence_finished: Option<u64>) {
        let worker = self.worker.take().unwrap();
        let direct = self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.id == worker.id && owner.submitted && !owner.responding);
        if worker.command == Command::Msg as u8
            && let Some(mut poll) = self.poll.take()
        {
            assert_eq!(poll.id, worker.id);
            let late = direct
                && presence_finished.is_some()
                && now.saturating_sub(poll.started) > U2F_RESPONSE_WAIT_MS;
            if response.ends_with(&[0x69, 0x85]) {
                self.denied.push((poll.channel, poll.request, poll.last));
            } else if (!direct || late) && presence_finished.is_some() {
                if late {
                    self.reply(poll.channel, Command::Msg as u8, vec![0x69, 0x85], true);
                }
                let expiry = presence_finished.unwrap() + U2F_APPROVAL_MS;
                if now <= expiry {
                    poll.answer = Some((response, expiry));
                    self.poll = Some(poll);
                }
                return;
            } else if !direct || late {
                return;
            }
        }
        if direct {
            self.reply(
                self.owner.as_ref().unwrap().channel,
                worker.command,
                response,
                true,
            );
        }
    }

    pub fn output(&mut self, channel: u32, command: u8, payload: &[u8]) {
        let expected = self
            .replies
            .pop_front()
            .expect("unsolicited or stale output");
        assert_eq!(
            (channel, command, payload),
            (
                expected.channel,
                expected.command,
                expected.payload.as_slice()
            ),
            "response order, bytes, or ownership"
        );
        if let Some(id) = expected.completes {
            assert_eq!(
                self.owner.as_ref().unwrap().id,
                id,
                "an auxiliary response released another transaction"
            );
            self.owner = None;
        }
    }

    pub fn drained(&self) {
        assert!(self.replies.is_empty(), "unexplained response truncation");
    }
}
