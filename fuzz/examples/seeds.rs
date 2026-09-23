//! Writes the seed corpora in `fuzz/seeds/`.
//!
//! ```text
//! cargo run --release --manifest-path fuzz/Cargo.toml --example seeds
//! ```
//!
//! * `ctap_request`: real CTAP2 requests, one per file, as a platform sends
//!   them.
//! * `ctaphid_packets`: CTAPHID exchanges (INIT, PING, CBOR with keepalives,
//!   CANCEL, timeouts, busy channels, the largest message, an empty request
//!   and an answer too long for a message), encoded in the target's input
//!   format and checked by decoding them back.
//! * `ctap_request_structured` and `ctap_sequence`: inputs picked from a
//!   deterministic random search, each kept because it reached a command and
//!   status no earlier one did (for the sequence target: PIN set, tokens,
//!   credentials made, asserted and managed).
//! * `credential_key`: valid and invalid key material for every algorithm.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use arbitrary::{Arbitrary, Unstructured};
use ciborium::value::Value;
use p256::elliptic_curve::sec1::ToSec1Point;
use pqkey_fuzz::cbor::{bytes, int, text};
use pqkey_fuzz::ctaphid::{Action, CONT_DATA, Channel, INIT_DATA, Mangle};
use pqkey_fuzz::requests::command;
use pqkey_fuzz::rng::SplitMix;
use pqkey_fuzz::{sequence, structured};
use rand_core::Rng;
use sha2::{Digest, Sha256};

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds");
    ctap_request(&root.join("ctap_request"));
    ctaphid_packets(&root.join("ctaphid_packets"));
    searched(
        &root.join("ctap_request_structured"),
        4_000,
        512,
        16,
        structured::run_traced,
    );
    searched(
        &root.join("ctap_sequence"),
        3_000,
        1_536,
        24,
        sequence::run_traced,
    );
    credential_key(&root.join("credential_key"));
}

/// Replace the seeds in `dir` with `seeds`, named by content like libFuzzer
/// names corpus entries.
fn write_all(dir: &Path, seeds: &[Vec<u8>]) {
    if dir.exists() {
        fs::remove_dir_all(dir).expect("remove old seeds");
    }
    fs::create_dir_all(dir).expect("create the seed directory");
    for seed in seeds {
        let name: String = Sha256::digest(seed)[..10]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        fs::write(dir.join(name), seed).expect("write a seed");
    }
    println!("{}: {} seeds", dir.display(), seeds.len());
}

fn map(entries: Vec<(Value, Value)>) -> Value {
    Value::Map(entries)
}

/// A valid P-256 COSE key, as a platform sends for keyAgreement.
fn platform_key() -> Value {
    let secret = p256::SecretKey::from_slice(&[0x11; 32]).expect("a valid scalar");
    let point = secret.public_key().to_sec1_point(false);
    map(vec![
        (int(1), int(2)),
        (int(3), int(-25)),
        (int(-1), int(1)),
        (int(-2), bytes(point.x().expect("x").as_ref())),
        (int(-3), bytes(point.y().expect("y").as_ref())),
    ])
}

fn descriptor(id: &[u8]) -> Value {
    map(vec![
        (text("id"), bytes(id)),
        (text("type"), text("public-key")),
    ])
}

fn ctap_request(dir: &Path) {
    let hash = [0x68; 32];
    let credential_id = [[0x01].as_slice(), &[0x42; 32]].concat();
    let rp = map(vec![
        (text("id"), text("example.com")),
        (text("name"), text("Example")),
    ]);
    let user = map(vec![
        (text("id"), bytes(b"user-1")),
        (text("name"), text("alice")),
        (text("displayName"), text("Alice")),
    ]);
    let params = |alg: i64| {
        Value::Array(vec![map(vec![
            (text("alg"), int(alg)),
            (text("type"), text("public-key")),
        ])])
    };
    let mut seeds = vec![
        vec![0x04],
        vec![0x07],
        vec![0x08],
        vec![0x09],
        vec![0x0B],
        vec![0x04, 0xA0],
    ];
    for alg in [-7, -48, -49, -50] {
        seeds.push(command(
            0x01,
            &map(vec![
                (int(1), bytes(&hash)),
                (int(2), rp.clone()),
                (int(3), user.clone()),
                (int(4), params(alg)),
                (int(7), map(vec![(text("rk"), Value::Bool(true))])),
            ]),
        ));
    }
    seeds.push(command(
        0x01,
        &map(vec![
            (int(1), bytes(&hash)),
            (int(2), rp.clone()),
            (int(3), user.clone()),
            (
                int(4),
                Value::Array(vec![
                    map(vec![
                        (text("alg"), int(-257)),
                        (text("type"), text("public-key")),
                    ]),
                    map(vec![
                        (text("alg"), int(-50)),
                        (text("type"), text("public-key")),
                    ]),
                    map(vec![
                        (text("alg"), int(-7)),
                        (text("type"), text("public-key")),
                    ]),
                ]),
            ),
            (int(5), Value::Array(vec![descriptor(&credential_id)])),
            (
                int(6),
                map(vec![
                    (text("credProtect"), int(2)),
                    (text("hmac-secret"), Value::Bool(true)),
                ]),
            ),
            (int(8), bytes(&[0x33; 32])),
            (int(9), int(2)),
            (int(11), Value::Array(vec![text("none")])),
        ]),
    ));
    seeds.push(command(
        0x02,
        &map(vec![
            (int(1), text("example.com")),
            (int(2), bytes(&hash)),
            (int(3), Value::Array(vec![descriptor(&credential_id)])),
            (int(5), map(vec![(text("up"), Value::Bool(false))])),
        ]),
    ));
    seeds.push(command(
        0x02,
        &map(vec![
            (int(1), text("example.com")),
            (int(2), bytes(&hash)),
            (
                int(4),
                map(vec![(
                    text("hmac-secret"),
                    map(vec![
                        (int(1), platform_key()),
                        (int(2), bytes(&[0x21; 48])),
                        (int(3), bytes(&[0x22; 32])),
                        (int(4), int(2)),
                    ]),
                )]),
            ),
            (int(6), bytes(&[0x33; 16])),
            (int(7), int(1)),
        ]),
    ));
    seeds.push(command(
        0x02,
        &map(vec![
            (int(1), text("example.com")),
            (int(2), bytes(&hash)),
            (int(6), bytes(&[])),
            (int(7), int(2)),
        ]),
    ));
    seeds.push(command(0x06, &map(vec![(int(2), int(1))])));
    for protocol in [1, 2] {
        let iv_len = if protocol == 2 { 16 } else { 0 };
        seeds.push(command(
            0x06,
            &map(vec![(int(1), int(protocol)), (int(2), int(2))]),
        ));
        seeds.push(command(
            0x06,
            &map(vec![
                (int(1), int(protocol)),
                (int(2), int(3)),
                (int(3), platform_key()),
                (
                    int(4),
                    bytes(&vec![0x44; if protocol == 2 { 32 } else { 16 }]),
                ),
                (int(5), bytes(&vec![0x55; 64 + iv_len])),
            ]),
        ));
        seeds.push(command(
            0x06,
            &map(vec![
                (int(1), int(protocol)),
                (int(2), int(4)),
                (int(3), platform_key()),
                (int(4), bytes(&[0x44; 32])),
                (int(5), bytes(&vec![0x55; 64 + iv_len])),
                (int(6), bytes(&vec![0x66; 16 + iv_len])),
            ]),
        ));
        seeds.push(command(
            0x06,
            &map(vec![
                (int(1), int(protocol)),
                (int(2), int(5)),
                (int(3), platform_key()),
                (int(6), bytes(&vec![0x66; 16 + iv_len])),
            ]),
        ));
        seeds.push(command(
            0x06,
            &map(vec![
                (int(1), int(protocol)),
                (int(2), int(9)),
                (int(3), platform_key()),
                (int(6), bytes(&vec![0x66; 16 + iv_len])),
                (int(9), int(0x07)),
                (int(10), text("example.com")),
            ]),
        ));
    }
    let rp_id_hash = Sha256::digest(b"example.com").to_vec();
    let credential_management = |subcommand: i64, params: Option<Value>| {
        let mut entries = vec![(int(1), int(subcommand))];
        if let Some(params) = params {
            entries.push((int(2), params));
        }
        if !matches!(subcommand, 3 | 5) {
            entries.push((int(3), int(2)));
            entries.push((int(4), bytes(&[0x77; 32])));
        }
        command(0x0A, &map(entries))
    };
    seeds.push(credential_management(1, None));
    seeds.push(credential_management(2, None));
    seeds.push(credential_management(3, None));
    seeds.push(credential_management(
        4,
        Some(map(vec![(int(1), bytes(&rp_id_hash))])),
    ));
    seeds.push(credential_management(5, None));
    seeds.push(credential_management(
        6,
        Some(map(vec![(int(2), descriptor(&credential_id))])),
    ));
    seeds.push(credential_management(
        7,
        Some(map(vec![
            (int(2), descriptor(&credential_id)),
            (
                int(3),
                map(vec![
                    (text("id"), bytes(b"user-1")),
                    (text("name"), text("bob")),
                ]),
            ),
        ])),
    ));
    // A non-canonical encoding of subCommandParams (a two-byte length for a
    // one-entry map), which credential management authenticates as received.
    let mut non_canonical = vec![0x0A, 0xA4, 0x01, 0x04, 0x02, 0xB8, 0x01, 0x01, 0x58, 0x20];
    non_canonical.extend_from_slice(&rp_id_hash);
    non_canonical.extend_from_slice(&[0x03, 0x02, 0x04, 0x58, 0x20]);
    non_canonical.extend_from_slice(&[0x77; 32]);
    seeds.push(non_canonical);
    write_all(dir, &seeds);
}

/// Encodes values in the input format `arbitrary` 1.x decodes.
#[derive(Default)]
struct Encoder(Vec<u8>);

impl Encoder {
    fn variant(&mut self, index: u32, count: u32) -> &mut Self {
        let value = ((u64::from(index) << 32).div_ceil(u64::from(count))) as u32;
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }

    fn raw(&mut self, raw: &[u8]) -> &mut Self {
        self.0.extend_from_slice(raw);
        self
    }

    fn channel(&mut self, channel: &Channel) -> &mut Self {
        match channel {
            Channel::Allocated(index) => self.variant(0, 4).raw(&[*index]),
            Channel::Broadcast => self.variant(1, 4),
            Channel::Zero => self.variant(2, 4),
            Channel::Raw(raw) => self.variant(3, 4).raw(&raw.to_le_bytes()),
        }
    }

    fn action(&mut self, action: &Action) -> &mut Self {
        match action {
            Action::Packet(packet) => self.variant(0, 10).raw(&packet[..]),
            Action::Init {
                channel,
                command,
                length,
                data,
            } => self
                .variant(1, 10)
                .channel(channel)
                .raw(&[*command])
                .raw(&length.to_le_bytes())
                .raw(&data[..]),
            Action::Continuation {
                channel,
                sequence,
                data,
            } => self
                .variant(2, 10)
                .channel(channel)
                .raw(&[*sequence])
                .raw(&data[..]),
            Action::Message {
                channel,
                command,
                length,
                fill,
                mangle,
                gap_ms,
            } => {
                self.variant(3, 10)
                    .channel(channel)
                    .raw(&[*command])
                    .raw(&length.to_le_bytes())
                    .raw(&[*fill]);
                match mangle {
                    Mangle::None => self.variant(0, 4),
                    Mangle::Drop(index) => self.variant(1, 4).raw(&[*index]),
                    Mangle::Duplicate(index) => self.variant(2, 4).raw(&[*index]),
                    Mangle::Swap(a, b) => self.variant(3, 4).raw(&[*a, *b]),
                };
                self.raw(&gap_ms.to_le_bytes())
            }
            Action::Advance(ms) => self.variant(4, 10).raw(&ms.to_le_bytes()),
            Action::Timeout => self.variant(5, 10),
            Action::Keepalive(waiting) => self.variant(6, 10).raw(&[u8::from(*waiting)]),
            Action::TakeRequest => self.variant(7, 10),
            Action::Respond { length, fill } => {
                self.variant(8, 10).raw(&length.to_le_bytes()).raw(&[*fill])
            }
            Action::TakeInterrupt => self.variant(9, 10),
        }
    }
}

fn message(channel: Channel, command: u8, length: u16, fill: u8) -> Action {
    Action::Message {
        channel,
        command,
        length,
        fill,
        mangle: Mangle::None,
        gap_ms: 1,
    }
}

fn respond(length: u16, fill: u8) -> Action {
    Action::Respond { length, fill }
}

/// An exchange: `(seed, channel range)` and its actions, encoded and checked
/// to decode back to the same actions.
fn exchange(actions: &[Action]) -> Vec<u8> {
    let mut encoder = Encoder::default();
    encoder
        .raw(&0x5EED_u64.to_le_bytes())
        .raw(&u16::MAX.to_le_bytes());
    for action in actions {
        encoder.action(action);
    }
    let encoded = encoder.0;

    let mut u = Unstructured::new(&encoded);
    let (seed, range) = u.arbitrary::<(u64, u16)>().expect("config");
    assert_eq!((seed, range), (0x5EED, u16::MAX));
    for action in actions {
        let decoded = Action::arbitrary(&mut u).expect("an action");
        assert_eq!(
            format!("{decoded:?}"),
            format!("{action:?}"),
            "encoding round trip"
        );
    }
    assert!(u.is_empty());
    pqkey_fuzz::ctaphid::run(&encoded);
    encoded
}

fn ctaphid_packets(dir: &Path) {
    const INIT: u8 = 0x06;
    const PING: u8 = 0x01;
    const CBOR: u8 = 0x10;
    const CANCEL: u8 = 0x11;
    const WINK: u8 = 0x08;
    let first = || Channel::Allocated(0);
    let second = || Channel::Allocated(1);
    let init = || message(Channel::Broadcast, INIT, 8, 0xA0);

    let seeds = vec![
        // Allocate a channel, ping, and a CBOR request answered after
        // keepalives.
        exchange(&[
            init(),
            message(first(), PING, 200, 1),
            message(first(), CBOR, 1, 0x04),
            Action::TakeRequest,
            Action::Keepalive(false),
            Action::Advance(60),
            Action::Keepalive(true),
            Action::Advance(60),
            Action::Keepalive(true),
            respond(300, 0),
        ]),
        // CANCEL of a request the app works on.
        exchange(&[
            init(),
            message(first(), CBOR, 100, 0x01),
            Action::TakeRequest,
            message(first(), CANCEL, 0, 0),
            Action::TakeInterrupt,
            respond(1, 0x2D),
        ]),
        // A message whose continuation packets stop coming.
        exchange(&[
            init(),
            Action::Init {
                channel: first(),
                command: CBOR,
                length: 300,
                data: Box::new([0x01; INIT_DATA]),
            },
            Action::Advance(600),
            Action::Timeout,
            Action::Continuation {
                channel: first(),
                sequence: 0,
                data: Box::new([0x02; CONT_DATA]),
            },
        ]),
        // Two channels: the second is busy while the first is served, and
        // INIT on the first aborts its transaction.
        exchange(&[
            init(),
            init(),
            message(first(), CBOR, 10, 0x02),
            Action::TakeRequest,
            message(second(), PING, 4, 9),
            message(first(), INIT, 8, 0xB0),
            Action::TakeInterrupt,
            message(first(), CBOR, 1, 0x04),
            respond(1, 0x2D),
            Action::TakeRequest,
            respond(64, 0),
        ]),
        // The largest message in both directions, and an answer too long for
        // one, which goes out as ERR_OTHER.
        exchange(&[
            init(),
            message(first(), PING, 7609, 3),
            message(first(), CBOR, 7609, 0x02),
            Action::TakeRequest,
            respond(7609, 7),
            message(first(), CBOR, 1, 0x04),
            Action::TakeRequest,
            respond(7610, 7),
        ]),
        // Packets out of order, missing and repeated.
        exchange(&[
            init(),
            Action::Message {
                channel: first(),
                command: PING,
                length: 300,
                fill: 0,
                mangle: Mangle::Swap(1, 2),
                gap_ms: 5,
            },
            Action::Message {
                channel: first(),
                command: PING,
                length: 300,
                fill: 0,
                mangle: Mangle::Drop(1),
                gap_ms: 5,
            },
            Action::Advance(1000),
            Action::Timeout,
            Action::Message {
                channel: first(),
                command: CBOR,
                length: 130,
                fill: 0,
                mangle: Mangle::Duplicate(1),
                gap_ms: 5,
            },
        ]),
        // Reserved channels, an unallocated channel, bad lengths, an empty
        // CBOR request, and a command the transport does not implement.
        exchange(&[
            message(Channel::Zero, PING, 1, 0),
            message(Channel::Broadcast, CBOR, 1, 0),
            message(Channel::Raw(0x1234_5678), INIT, 8, 0),
            message(Channel::Broadcast, INIT, 7, 0),
            init(),
            message(first(), CBOR, 0, 0),
            message(first(), WINK, 0, 0),
            Action::TakeRequest,
            Action::Packet(Box::new([0xFF; 64])),
        ]),
    ];
    write_all(dir, &seeds);
}

const IMPLEMENTED: &[u8] = &[0x01, 0x02, 0x04, 0x06, 0x07, 0x08, 0x0A];

/// Keep inputs from a deterministic random search that reach a command and
/// status pair no earlier input reached, at most `max` of them.
fn searched(
    dir: &Path,
    candidates: usize,
    max_len: usize,
    max: usize,
    run: fn(&[u8]) -> Vec<(u8, u8)>,
) {
    let mut rng = SplitMix(0xC0FFEE);
    let mut seen = BTreeSet::new();
    let mut seeds: Vec<(usize, Vec<u8>)> = Vec::new();
    for _ in 0..candidates {
        let len = 16 + (rng.next_u32() as usize) % max_len;
        let mut input = vec![0u8; len];
        rng.fill_bytes(&mut input);
        // Only the commands the engine implements: any other command byte
        // is a distinct but uninteresting pair.
        let trace: Vec<(u8, u8)> = run(&input)
            .into_iter()
            .filter(|(command, _)| IMPLEMENTED.contains(command))
            .collect();
        let new = trace.iter().filter(|pair| !seen.contains(*pair)).count();
        if new > 0 {
            seen.extend(trace);
            seeds.push((new, input));
        }
    }
    seeds.sort_by_key(|seed| std::cmp::Reverse(seed.0));
    seeds.truncate(max);
    let seeds: Vec<Vec<u8>> = seeds.into_iter().map(|(_, input)| input).collect();
    println!("{}: {} command/status pairs", dir.display(), seen.len());
    write_all(dir, &seeds);
}

fn credential_key(dir: &Path) {
    let layout = |alg: u8, sign_with: u8, key: &[u8]| {
        let auth_data = [0x49u8; 37];
        let mut input = vec![alg, sign_with, auth_data.len() as u8];
        input.extend_from_slice(&[0x68; 32]);
        input.extend_from_slice(&auth_data);
        input.extend_from_slice(key);
        input
    };
    let seeds = vec![
        layout(0, 0, &[0x11; 32]),
        layout(0, 0, &[0xFF; 32]),
        layout(0, 1, &[0x11; 32]),
        layout(1, 1, &[0x22; 32]),
        layout(2, 2, &[0x33; 32]),
        layout(3, 3, &[0x44; 32]),
        layout(3, 0, &[0x44; 32]),
        layout(1, 1, &[0x55; 2560]),
        layout(3, 3, &[0x66; 100]),
    ];
    write_all(dir, &seeds);
}
