//! The CTAP engine as the fuzz targets drive it, and the checks every
//! response must pass.

use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use ciborium::value::Value;
use pqkey_ctap::ctap::constants::*;
use pqkey_ctap::ctap::presence::{Cancellation, PresenceOutcome, PresenceRequest, UserPresence};
use pqkey_ctap::ctap::{CtapApp, InterruptFlag};
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
    /// The command byte and response status of every request so far.
    pub(crate) trace: Vec<(u8, u8)>,
}

impl Engine {
    pub fn new(seed: u64) -> Self {
        Self::with_store(seed, MemoryStore::new())
    }

    /// An engine over `store`, for example one with a small credential limit.
    pub fn with_store(seed: u64, store: MemoryStore) -> Self {
        let presence = FuzzPresence::default();
        let app = CtapApp::new(
            store,
            SplitMix(seed),
            presence.clone(),
            &NEVER_INTERRUPTED,
            [0xA5; 16],
        );
        Self {
            app,
            presence,
            trace: Vec::new(),
        }
    }

    pub fn presence(&self) -> &FuzzPresence {
        &self.presence
    }

    /// The command byte and response status of every request so far.
    pub fn into_trace(self) -> Vec<(u8, u8)> {
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
        self.trace.push((request[0], response[0]));
        response
    }
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
