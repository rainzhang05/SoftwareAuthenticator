//! The CTAP engine as the fuzz targets drive it, and the checks every
//! response must pass.

use std::sync::{
    Arc,
    atomic::{AtomicU8, AtomicU64, Ordering},
};
use std::time::Duration;

use ciborium::value::Value;
use pqkey_ctap::ctap::constants::*;
use pqkey_ctap::ctap::presence::{Cancellation, PresenceOutcome, PresenceRequest, UserPresence};
use pqkey_ctap::ctap::{Clock, CtapApp, InterruptFlag};
use pqkey_ctap::store::MemoryStore;

use crate::rng::SplitMix;

/// The interrupt flag of every fuzzed engine.  Nothing marks it: the
/// transport, which would, is not part of these targets.
static NEVER_INTERRUPTED: InterruptFlag = InterruptFlag::new();

/// The largest CTAPHID message, and so the longest answer the engine may give
/// (`pqkey::MESSAGE_SIZE`).
pub const MESSAGE_SIZE: usize = pqkey::MESSAGE_SIZE;

/// Every status code CTAP defines (CTAP 2.3 §8.2) that the engine may answer.
pub const STATUS_CODES: &[u8] = &[
    CTAP2_OK,
    CTAP1_ERR_INVALID_COMMAND,
    CTAP1_ERR_INVALID_PARAMETER,
    CTAP1_ERR_INVALID_LENGTH,
    CTAP1_ERR_INVALID_SEQ,
    CTAP1_ERR_TIMEOUT,
    CTAP1_ERR_CHANNEL_BUSY,
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
    CTAP2_ERR_INVALID_CBOR,
    CTAP2_ERR_MISSING_PARAMETER,
    CTAP2_ERR_LIMIT_EXCEEDED,
    CTAP2_ERR_LARGE_BLOB_STORAGE_FULL,
    CTAP2_ERR_CREDENTIAL_EXCLUDED,
    CTAP2_ERR_PROCESSING,
    CTAP2_ERR_INVALID_CREDENTIAL,
    CTAP2_ERR_USER_ACTION_PENDING,
    CTAP2_ERR_UNSUPPORTED_ALGORITHM,
    CTAP2_ERR_OPERATION_DENIED,
    CTAP2_ERR_KEY_STORE_FULL,
    CTAP2_ERR_UNSUPPORTED_OPTION,
    CTAP2_ERR_INVALID_OPTION,
    CTAP2_ERR_KEEPALIVE_CANCEL,
    CTAP2_ERR_NO_CREDENTIALS,
    CTAP2_ERR_USER_ACTION_TIMEOUT,
    CTAP2_ERR_NOT_ALLOWED,
    CTAP2_ERR_PIN_INVALID,
    CTAP2_ERR_PIN_BLOCKED,
    CTAP2_ERR_PIN_AUTH_INVALID,
    CTAP2_ERR_PIN_AUTH_BLOCKED,
    CTAP2_ERR_PIN_NOT_SET,
    CTAP2_ERR_PUAT_REQUIRED,
    CTAP2_ERR_PIN_POLICY_VIOLATION,
    CTAP2_ERR_REQUEST_TOO_LARGE,
    CTAP2_ERR_ACTION_TIMEOUT,
    CTAP2_ERR_UP_REQUIRED,
    CTAP2_ERR_INVALID_SUBCOMMAND,
    CTAP2_ERR_UNAUTHORIZED_PERMISSION,
    CTAP2_ERR_INTEGRITY_FAILURE,
    CTAP1_ERR_OTHER,
];

/// Answers presence requests with whatever outcome the fuzz input selected
/// last, so denial, timeout and cancellation paths are reached too.
#[derive(Clone, Debug, Default)]
pub struct FuzzPresence(Arc<AtomicU8>);

impl FuzzPresence {
    /// Answer the following requests with the outcome `selector` names:
    /// approval unless it is one of the last three byte values.
    pub fn select(&self, selector: u8) {
        self.0.store(selector, Ordering::Relaxed);
    }
}

/// A deterministic clock shared by the engine and the platform model.
#[derive(Clone, Default)]
pub struct FuzzClock(Arc<AtomicU64>);

impl FuzzClock {
    /// Move time forward without making a CTAP request.
    pub fn advance(&self, millis: u64) {
        let mut now = self.0.load(Ordering::Relaxed);
        loop {
            match self.0.compare_exchange_weak(
                now,
                now.saturating_add(millis),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => now = observed,
            }
        }
    }
}

impl Clock for FuzzClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::Relaxed))
    }
}

impl UserPresence for FuzzPresence {
    fn confirm(
        &mut self,
        _request: &PresenceRequest<'_>,
        _cancellation: Cancellation<'_>,
    ) -> PresenceOutcome {
        match self.0.load(Ordering::Relaxed) {
            0xFD => PresenceOutcome::Denied,
            0xFE => PresenceOutcome::TimedOut,
            0xFF => PresenceOutcome::Cancelled,
            _ => PresenceOutcome::Approved,
        }
    }
}

/// A fresh engine over an empty in-memory store, with a seeded RNG.
pub struct Engine {
    app: CtapApp<'static>,
    presence: FuzzPresence,
    clock: FuzzClock,
    /// The command byte and response status of every request so far.
    pub(crate) trace: Vec<(u8, u16)>,
}

impl Engine {
    pub fn new(seed: u64) -> Self {
        Self::with_store(seed, MemoryStore::new())
    }

    /// An engine over `store`, for example one with a small credential limit.
    pub fn with_store(seed: u64, store: MemoryStore) -> Self {
        let presence = FuzzPresence::default();
        let mut app = CtapApp::new(
            store,
            SplitMix(seed),
            presence.clone(),
            &NEVER_INTERRUPTED,
            [0xA5; 16],
        );
        let clock = FuzzClock::default();
        app.set_clock(clock.clone());
        // Repeated registrations exercise storage and signatures with the
        // fixed RSA key, without generating expensive primes in a fuzz loop.
        app.set_key_generator(|alg| match alg.key_kind() {
            pqkey_ctap::KeyKind::RsaPrimes => {
                Ok(pqkey_ctap::store::PrivateKeyMaterial::RsaPrimes {
                    primes: pqkey_ctap::rsa_fixture::PRIMES,
                })
            }
            pqkey_ctap::KeyKind::P256Scalar | pqkey_ctap::KeyKind::Seed => {
                pqkey_ctap::store::PrivateKeyMaterial::try_generate(alg)
            }
        });
        Self {
            app,
            presence,
            clock,
            trace: Vec::new(),
        }
    }

    pub fn presence(&self) -> &FuzzPresence {
        &self.presence
    }

    pub fn clock(&self) -> &FuzzClock {
        &self.clock
    }

    /// The command byte and response status of every request so far.
    pub fn into_trace(self) -> Vec<(u8, u16)> {
        self.trace
    }

    /// Send one CTAPHID_CBOR message, `request` being the command byte and
    /// its parameters, check the response and return it.
    pub fn call(&mut self, request: &[u8]) -> Vec<u8> {
        let response = self.app.call(request);
        if request.is_empty() {
            // The transport answers an empty CTAPHID_CBOR message itself.
            assert_eq!(
                response,
                [CTAP1_ERR_INVALID_LENGTH],
                "an empty CBOR message"
            );
            return Vec::new();
        }
        // An engine answer longer than a CTAPHID message turns into a
        // CTAPHID error instead of a CTAP status: the platform learns nothing.
        assert!(
            response.len() <= MESSAGE_SIZE,
            "the response must fit {MESSAGE_SIZE} bytes"
        );
        check_response(request[0], &response);
        self.trace.push((request[0], u16::from(response[0])));
        response
    }

    /// Send a U2F APDU and retain its full status word in the trace. The high
    /// bit tags U2F instructions so they cannot collide with CTAP2 commands.
    pub fn call_u2f(&mut self, request: &[u8]) -> Vec<u8> {
        use pqkey_ctap::ctap::u2f::*;
        let response = self.app.call_u2f(request);
        assert!((2..=MESSAGE_SIZE).contains(&response.len()));
        let end = response.len() - 2;
        let status = u16::from_be_bytes(response[end..].try_into().unwrap());
        assert!(
            [
                SW_NO_ERROR,
                SW_CONDITIONS_NOT_SATISFIED,
                SW_COMMAND_NOT_ALLOWED,
                SW_WRONG_DATA,
                SW_WRONG_LENGTH,
                SW_CLA_NOT_SUPPORTED,
                SW_INS_NOT_SUPPORTED,
                SW_WRONG_PARAMETERS,
                SW_INTERNAL_ERROR
            ]
            .contains(&status)
        );
        let ins = request.get(1).copied().unwrap_or(0);
        if status != SW_NO_ERROR {
            assert_eq!(end, 0, "error carries data");
        } else {
            match ins {
                3 => assert_eq!(&response[..end], b"U2F_V2"),
                1 => {
                    assert_eq!(response[0], 5);
                    assert_eq!(response[1], 4);
                    assert_eq!(response[66], 107);
                    assert_eq!(response[67], 2);
                    let certificate = &response[174..end];
                    assert_eq!(certificate[0], 0x30);
                    let (prefix, length) = if certificate[1] < 128 {
                        (2, usize::from(certificate[1]))
                    } else {
                        let bytes = usize::from(certificate[1] & 0x7f);
                        assert!((1..=2).contains(&bytes));
                        (
                            2 + bytes,
                            certificate[2..2 + bytes]
                                .iter()
                                .fold(0usize, |n, b| n * 256 + usize::from(*b)),
                        )
                    };
                    let signature = &certificate[prefix + length..];
                    assert!((8..=72).contains(&signature.len()));
                    let data = u2f_data(request).unwrap();
                    let base = [
                        vec![0],
                        data[32..64].to_vec(),
                        data[..32].to_vec(),
                        response[67..174].to_vec(),
                        response[1..66].to_vec(),
                    ]
                    .concat();
                    pqkey_ctap::verify_signature(
                        pqkey_ctap::CoseAlg::ES256,
                        &u2f_public_key(&response[1..66]),
                        &base,
                        signature,
                    )
                    .unwrap();
                }
                2 => {
                    assert!(end >= 13);
                    assert!(response[0] <= 1);
                }
                _ => panic!("successful unsupported U2F instruction"),
            }
        }
        self.trace.push((ins | 0x80, status));
        response
    }
}

/// Data of a successful U2F registration or authentication request, decoded
/// independently of the engine for the fuzz model.
pub fn u2f_data(request: &[u8]) -> Option<&[u8]> {
    let (start, length) = if *request.get(4)? == 0 {
        (
            7,
            usize::from(u16::from_be_bytes([*request.get(5)?, *request.get(6)?])),
        )
    } else {
        (5, usize::from(request[4]))
    };
    request.get(start..start + length)
}

/// COSE encoding of a U2F uncompressed P-256 public key.
pub fn u2f_public_key(public: &[u8]) -> Vec<u8> {
    use crate::cbor::{bytes, encode, int};
    assert_eq!(public.len(), 65);
    assert_eq!(public[0], 4);
    encode(&Value::Map(vec![
        (int(1), int(2)),
        (int(3), int(-7)),
        (int(-1), int(1)),
        (int(-2), bytes(&public[1..33])),
        (int(-3), bytes(&public[33..65])),
    ]))
}

/// The checks every answer to a CTAPHID_CBOR request must pass.
pub fn check_response(command: u8, response: &[u8]) {
    assert!(!response.is_empty(), "a response has a status byte");
    assert!(response.len() <= MAX_RESPONSE_SIZE, "response too long");
    let status = response[0];
    assert!(
        STATUS_CODES.contains(&status),
        "undefined status 0x{status:02x} for command 0x{command:02x}"
    );
    if status != CTAP2_OK {
        assert_eq!(response.len(), 1, "an error carries no parameters");
        return;
    }
    let body = &response[1..];
    if body.is_empty() {
        return;
    }
    // "the response data is a CBOR map" (CTAP 2.3 §8): exactly one well-formed
    // map with nothing after it.
    let mut reader = body;
    let value: Value = ciborium::de::from_reader(&mut reader)
        .unwrap_or_else(|err| panic!("response to 0x{command:02x} is not CBOR: {err}"));
    assert!(
        matches!(value, Value::Map(_)),
        "response to 0x{command:02x} is not a map"
    );
    assert!(reader.is_empty(), "bytes after the response map");
}
