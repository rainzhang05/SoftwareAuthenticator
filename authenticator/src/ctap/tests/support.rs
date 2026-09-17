//! Test doubles and PIN/UV auth protocol helpers shared by the test modules.

use crate::ctap::cbor::{canonical_map, canonical_sort};
use crate::ctap::pin::protocol::HmacSha256;
use crate::ctap::presence::{
    Cancellation, PresenceOperation, PresenceOutcome, PresenceRequest, UserPresence,
};
use crate::ctap::{CtapApp, InterruptFlag};
use crate::store::{
    AttestationRecord, Corruption, CredentialRecord, CredentialStore, MemoryStore, PinStateRecord,
    PrivateKeyMaterial, StoreError,
};
use crate::{ClassicPinProtocol, CoseAlg, PinUvSessionKeys};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use hmac::Mac;
use p256::{
    ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint, EncodedPoint,
    PublicKey as P256PublicKey, SecretKey as P256SecretKey,
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::ctap::constants::*;

/// The interrupt flag of every test app that is never cancelled.  The engine
/// only reads the flag, so sharing it between concurrently running tests is
/// safe as long as no test marks it; cancellation tests use their own.
pub(super) static NEVER_INTERRUPTED: InterruptFlag = InterruptFlag::new();

/// A presence request as a [`ScriptedPresence`] saw it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SeenRequest {
    pub(super) operation: PresenceOperation,
    pub(super) rp_id: Option<String>,
    pub(super) user_name: Option<String>,
    pub(super) user_display_name: Option<String>,
    pub(super) timeout: Duration,
}

impl SeenRequest {
    /// The request the engine makes for `operation` on `rp_id` with the
    /// default timeout and no user details.
    pub(super) fn new(operation: PresenceOperation, rp_id: Option<&str>) -> Self {
        Self {
            operation,
            rp_id: rp_id.map(str::to_owned),
            user_name: None,
            user_display_name: None,
            timeout: crate::ctap::presence::DEFAULT_PRESENCE_TIMEOUT,
        }
    }
}

/// What the presence test doubles observed, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum PresenceEvent {
    /// The engine told the transport whether it is waiting for the user.
    Waiting(bool),
    /// The engine asked for user presence.
    Asked(SeenRequest),
}

/// The events of one test app, shared between the app and the test.
#[derive(Clone, Debug, Default)]
pub(super) struct PresenceLog(Arc<Mutex<Vec<PresenceEvent>>>);

impl PresenceLog {
    fn push(&self, event: PresenceEvent) {
        self.0.lock().expect("presence log lock").push(event);
    }

    /// Record a call of the keepalive callback.
    pub(super) fn record_waiting(&self, waiting: bool) {
        self.push(PresenceEvent::Waiting(waiting));
    }

    /// Remove and return every event recorded so far.
    pub(super) fn take(&self) -> Vec<PresenceEvent> {
        std::mem::take(&mut *self.0.lock().expect("presence log lock"))
    }
}

/// Answers presence requests from a script, approving once the script runs
/// out, and records every request it sees.
pub(super) struct ScriptedPresence {
    outcomes: VecDeque<PresenceOutcome>,
    log: PresenceLog,
}

impl UserPresence for ScriptedPresence {
    fn confirm(
        &mut self,
        request: &PresenceRequest<'_>,
        _cancellation: Cancellation<'_>,
    ) -> PresenceOutcome {
        self.log.push(PresenceEvent::Asked(SeenRequest {
            operation: request.operation,
            rp_id: request.rp_id.map(str::to_owned),
            user_name: request.user_name.map(str::to_owned),
            user_display_name: request.user_display_name.map(str::to_owned),
            timeout: request.timeout,
        }));
        self.outcomes
            .pop_front()
            .unwrap_or(PresenceOutcome::Approved)
    }
}

/// The engine as the unit tests build it.
pub(super) type TestApp = CtapApp<'static>;

/// An app over an empty [`TestStore`] whose user approves every presence
/// request.
pub(super) fn test_app(aaguid: [u8; 16]) -> TestApp {
    new_app(TestStore::new(), aaguid)
}

/// An app over `store` whose user approves every presence request.
pub(super) fn new_app(store: TestStore, aaguid: [u8; 16]) -> TestApp {
    app_with_store(store, aaguid, [], &NEVER_INTERRUPTED).0
}

/// An app whose presence requests are answered by `outcomes` in order, then
/// approved, together with the log of presence events.
pub(super) fn scripted_app(
    aaguid: [u8; 16],
    outcomes: impl IntoIterator<Item = PresenceOutcome>,
) -> (TestApp, PresenceLog) {
    scripted_app_with_interrupt(aaguid, outcomes, &NEVER_INTERRUPTED)
}

/// [`scripted_app`] with the given interrupt flag.
pub(super) fn scripted_app_with_interrupt(
    aaguid: [u8; 16],
    outcomes: impl IntoIterator<Item = PresenceOutcome>,
    interrupt: &'static InterruptFlag,
) -> (TestApp, PresenceLog) {
    app_with_store(TestStore::new(), aaguid, outcomes, interrupt)
}

/// An app over `store` drawing randomness from `rng`, whose user approves
/// every presence request.
pub(super) fn app_with_store_and_rng(
    store: TestStore,
    rng: TestRng,
    aaguid: [u8; 16],
) -> (TestApp, PresenceLog) {
    let log = PresenceLog::default();
    let presence = ScriptedPresence {
        outcomes: VecDeque::new(),
        log: log.clone(),
    };
    let app = CtapApp::new(store, rng, presence, &NEVER_INTERRUPTED, aaguid);
    (app, log)
}

/// An app over `store`, with presence answered by `outcomes` then approved.
pub(super) fn app_with_store(
    store: TestStore,
    aaguid: [u8; 16],
    outcomes: impl IntoIterator<Item = PresenceOutcome>,
    interrupt: &'static InterruptFlag,
) -> (TestApp, PresenceLog) {
    let log = PresenceLog::default();
    let presence = ScriptedPresence {
        outcomes: outcomes.into_iter().collect(),
        log: log.clone(),
    };
    let seed = u64::from_le_bytes(aaguid[..8].try_into().expect("8 bytes"));
    let mut app = CtapApp::new(store, TestRng::new(seed), presence, interrupt, aaguid);
    let keepalive_log = log.clone();
    app.set_keepalive_callback(move |waiting| keepalive_log.record_waiting(waiting));
    (app, log)
}

/// A deterministic random number generator, so test runs are reproducible:
/// SplitMix64, or one byte repeated.
///
/// It is not cryptographically secure; the `CryptoRng` marker only lets the
/// engine accept it, and it must never be used outside tests.
pub(super) enum TestRng {
    SplitMix(u64),
    Constant(u8),
}

impl TestRng {
    pub(super) fn new(seed: u64) -> Self {
        TestRng::SplitMix(seed)
    }

    /// Every random byte is `fill`.
    pub(super) fn constant(fill: u8) -> Self {
        TestRng::Constant(fill)
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        match self {
            TestRng::SplitMix(state) => {
                *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = *state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                z ^ (z >> 31)
            }
            TestRng::Constant(fill) => u64::from_le_bytes([*fill; 8]),
        }
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

/// Store operations a [`TestStore`] can be told to fail.
#[derive(Debug, Default)]
pub(super) struct Faults {
    pub(super) get: bool,
    pub(super) put: bool,
    pub(super) list: bool,
    /// `pin_state` reports the record as corrupt.
    pub(super) pin_state: bool,
    pub(super) set_pin_state: bool,
    pub(super) attestation: bool,
    pub(super) clear: bool,
}

#[derive(Default)]
struct TestStoreState {
    store: MemoryStore,
    faults: Faults,
    pin_state_writes: Vec<PinStateRecord>,
}

/// The unit tests' [`CredentialStore`]: a [`MemoryStore`] that records PIN
/// state writes and fails operations on demand.
///
/// Clones share one store, so a test keeps a handle to inspect or fault the
/// store an app owns, or to start a new app on the same storage.
#[derive(Clone, Default)]
pub(super) struct TestStore(Arc<Mutex<TestStoreState>>);

impl TestStore {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// A store holding at most `max` credentials.
    pub(super) fn with_max_credentials(max: usize) -> Self {
        let store = Self::new();
        let mut state = store.lock();
        state.store = MemoryStore::new().with_max_credentials(max);
        drop(state);
        store
    }

    fn lock(&self) -> MutexGuard<'_, TestStoreState> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Change which operations fail.
    pub(super) fn faults(&self, change: impl FnOnce(&mut Faults)) {
        change(&mut self.lock().faults);
    }

    /// Every PIN state written so far, oldest first.
    pub(super) fn pin_state_writes(&self) -> Vec<PinStateRecord> {
        self.lock().pin_state_writes.clone()
    }

    /// Every credential, most recently created first.
    pub(super) fn credentials(&self) -> Vec<CredentialRecord> {
        self.lock().store.list().expect("list credentials")
    }

    /// The credential with `credential_id`.
    pub(super) fn credential(&self, credential_id: &[u8]) -> CredentialRecord {
        self.lock()
            .store
            .get(credential_id)
            .expect("read credential")
            .expect("credential is stored")
    }

    fn fail_if(&self, failing: impl FnOnce(&Faults) -> bool) -> Result<(), StoreError> {
        if failing(&self.lock().faults) {
            Err(StoreError::Io {
                path: "injected".into(),
                source: std::io::Error::other("injected failure"),
            })
        } else {
            Ok(())
        }
    }
}

impl CredentialStore for TestStore {
    fn get(&self, credential_id: &[u8]) -> Result<Option<CredentialRecord>, StoreError> {
        self.fail_if(|faults| faults.get)?;
        self.lock().store.get(credential_id)
    }

    fn put(&mut self, record: &CredentialRecord) -> Result<(), StoreError> {
        self.fail_if(|faults| faults.put)?;
        self.lock().store.put(record)
    }

    fn delete(&mut self, credential_id: &[u8]) -> Result<bool, StoreError> {
        self.lock().store.delete(credential_id)
    }

    fn list(&self) -> Result<Vec<CredentialRecord>, StoreError> {
        self.fail_if(|faults| faults.list)?;
        self.lock().store.list()
    }

    fn count(&self) -> Result<usize, StoreError> {
        self.fail_if(|faults| faults.list)?;
        self.lock().store.count()
    }

    fn max_credentials(&self) -> usize {
        self.lock().store.max_credentials()
    }

    fn clear(&mut self) -> Result<(), StoreError> {
        self.fail_if(|faults| faults.clear)?;
        self.lock().store.clear()
    }

    fn pin_state(&self) -> Result<Option<PinStateRecord>, StoreError> {
        if self.lock().faults.pin_state {
            return Err(StoreError::Corrupt {
                object: "pin-state".into(),
                reason: Corruption::Authentication,
            });
        }
        self.lock().store.pin_state()
    }

    fn set_pin_state(&mut self, state: &PinStateRecord) -> Result<(), StoreError> {
        self.fail_if(|faults| faults.set_pin_state)?;
        let mut locked = self.lock();
        locked.pin_state_writes.push(state.clone());
        locked.store.set_pin_state(state)
    }

    fn attestation(&self) -> Result<Option<AttestationRecord>, StoreError> {
        self.fail_if(|faults| faults.attestation)?;
        self.lock().store.attestation()
    }

    fn set_attestation(&mut self, record: &AttestationRecord) -> Result<(), StoreError> {
        self.lock().store.set_attestation(record)
    }
}

/// Every credential in the app's store, most recently created first.
pub(super) fn stored(app: &TestApp) -> Vec<CredentialRecord> {
    app.store.list().expect("list credentials")
}

/// The credential with `credential_id` in the app's store.
pub(super) fn stored_by_id(app: &TestApp, credential_id: &[u8]) -> CredentialRecord {
    app.store
        .get(credential_id)
        .expect("read credential")
        .expect("credential is stored")
}

/// Put `record` into the app's store, as if the app had created it.
pub(super) fn insert(app: &mut TestApp, record: &CredentialRecord) {
    app.store.put(record).expect("store credential");
}

/// [`insert`], taking the record by value.
pub(super) fn insert_owned(app: &mut TestApp, record: CredentialRecord) {
    insert(app, &record);
}

/// A credential with fresh key material, user ID `user_id` and fixed
/// `CredRandom` values.
pub(super) fn credential(
    rp_id: &str,
    user_id: &[u8],
    credential_id: &[u8],
    alg: CoseAlg,
) -> CredentialRecord {
    CredentialRecord {
        credential_id: credential_id.to_vec(),
        rp_id: rp_id.into(),
        user_id: user_id.to_vec(),
        user_name: None,
        user_display_name: None,
        alg,
        private_key: PrivateKeyMaterial::generate(alg),
        cred_random_with_uv: [0x10; 32],
        cred_random_without_uv: [0x20; 32],
        cred_protect: 1,
        sign_count: 0,
        created_at: 0,
    }
}

pub(super) fn request_classic_key_agreement(
    app: &mut TestApp,
    protocol: ClassicPinProtocol,
) -> Vec<(Value, Value)> {
    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(protocol.identifier())),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x02)),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize key agreement request");
    let response = app
        .handle_client_pin(&payload)
        .expect("classic key agreement succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode key agreement response")
    else {
        panic!("response must be a map");
    };
    match map
        .into_iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(1)))
    {
        Some((_, Value::Map(entries))) => entries,
        _ => panic!("missing key agreement data"),
    }
}

fn extract_coordinate(entries: &[(Value, Value)], label: i32) -> Vec<u8> {
    entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(label)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("coordinate is present")
}

fn authenticator_public_key(entries: &[(Value, Value)]) -> P256PublicKey {
    let x = extract_coordinate(entries, -2);
    let y = extract_coordinate(entries, -3);
    assert_eq!(x.len(), 32);
    assert_eq!(y.len(), 32);
    let mut encoded = [0u8; 65];
    encoded[0] = 0x04;
    encoded[1..33].copy_from_slice(&x);
    encoded[33..65].copy_from_slice(&y);
    P256PublicKey::from_sec1_bytes(&encoded).expect("authenticator public key is valid")
}

fn classic_platform_key_entries(point: &EncodedPoint) -> Vec<(Value, Value)> {
    let x_field = point.x().expect("x coordinate present");
    let x_slice: &[u8] = x_field.as_ref();
    let x = x_slice.to_vec();
    let y_field = point.y().expect("y coordinate present");
    let y_slice: &[u8] = y_field.as_ref();
    let y = y_slice.to_vec();
    let mut entries = vec![
        // kty: EC2
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(2)),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Integer(Integer::from(-25)),
        ),
        (
            Value::Integer(Integer::from(-1)),
            Value::Integer(Integer::from(1)),
        ),
        (Value::Integer(Integer::from(-2)), Value::Bytes(x)),
        (Value::Integer(Integer::from(-3)), Value::Bytes(y)),
    ];
    canonical_sort(&mut entries);
    entries
}

/// Platform-side `encapsulate`: the shared secret and the platform
/// key-agreement key to send.
pub(super) fn derive_classic_session(
    protocol: ClassicPinProtocol,
    auth_entries: &[(Value, Value)],
    platform_secret: &P256SecretKey,
) -> (PinUvSessionKeys, Vec<(Value, Value)>) {
    let auth_public = authenticator_public_key(auth_entries);
    let platform_public = platform_secret.public_key().to_encoded_point(false);
    let shared = diffie_hellman(platform_secret.to_nonzero_scalar(), auth_public.as_affine());
    let shared_bytes = shared.raw_secret_bytes();
    let keys = crate::derive_classic_pin_uv_session_keys(protocol, shared_bytes.as_ref());
    let platform_entries = classic_platform_key_entries(&platform_public);
    (keys, platform_entries)
}

pub(super) fn classic_encrypt(
    protocol: ClassicPinProtocol,
    keys: &PinUvSessionKeys,
    plaintext: &[u8],
    iv: Option<[u8; 16]>,
) -> Vec<u8> {
    match iv {
        Some(iv_bytes) => {
            crate::encrypt_classic_pin_block(protocol, keys, Some(&iv_bytes), plaintext)
                .expect("classic encryption succeeds")
        }
        None => crate::encrypt_classic_pin_block(protocol, keys, None, plaintext)
            .expect("classic encryption succeeds"),
    }
}

/// Platform-side `authenticate(key, message)`, written independently of the
/// authenticator's implementation: protocol one keeps the first 16 bytes of
/// HMAC-SHA-256 (CTAP 2.3 §6.5.6), protocol two keeps all 32 (§6.5.7).
pub(super) fn platform_authenticate(
    protocol: ClassicPinProtocol,
    key: &[u8; 32],
    message: &[u8],
) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("valid MAC key");
    mac.update(message);
    let full = mac.finalize().into_bytes();
    match protocol {
        ClassicPinProtocol::V1 => full[..16].to_vec(),
        ClassicPinProtocol::V2 => full.to_vec(),
    }
}

/// `authenticate(shared secret, message)`: the pinUvAuthParam of setPIN and
/// changePIN, and hmac-secret's saltAuth.
pub(super) fn classic_pin_auth(
    protocol: ClassicPinProtocol,
    keys: &PinUvSessionKeys,
    data: &[u8],
) -> Vec<u8> {
    platform_authenticate(protocol, &keys.auth_key, data)
}

/// `authenticate(pinUvAuthToken, message)`: the pinUvAuthParam of
/// makeCredential, getAssertion and credential management.
pub(super) fn token_pin_auth(
    protocol: ClassicPinProtocol,
    token: &[u8; 32],
    message: &[u8],
) -> Vec<u8> {
    platform_authenticate(protocol, token, message)
}

/// Flip the last bit of a MAC so it has the right length but the wrong value.
pub(super) fn corrupt_mac(mut mac: Vec<u8>) -> Vec<u8> {
    let last = mac.last_mut().expect("MAC is not empty");
    *last ^= 0x01;
    mac
}

pub(super) fn int(value: i64) -> Value {
    Value::Integer(Integer::from(value))
}

pub(super) fn encode(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    into_writer(value, &mut encoded).expect("encode CBOR");
    encoded
}

/// Send an authenticatorClientPIN request built from `entries`.
pub(super) fn client_pin(app: &mut TestApp, entries: Vec<(Value, Value)>) -> Result<Vec<u8>, u8> {
    app.handle_client_pin(&encode(&canonical_map(entries)))
}

/// `newPin` right-padded with 0x00 to the 64-byte paddedPin (CTAP 2.3 §6.5.5.5).
pub(super) fn padded_pin(pin: &[u8]) -> [u8; 64] {
    let mut padded = [0u8; 64];
    padded[..pin.len()].copy_from_slice(pin);
    padded
}

/// `LEFT(SHA-256(pin), 16)`.
pub(super) fn pin_hash(pin: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(pin);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&digest[..16]);
    hash
}

/// The platform's side of one PIN/UV auth protocol exchange: it has called
/// getKeyAgreement and encapsulated against the authenticator's key.
pub(super) struct PlatformPinSession {
    pub(super) protocol: ClassicPinProtocol,
    pub(super) keys: PinUvSessionKeys,
    pub(super) key_agreement: Value,
}

impl PlatformPinSession {
    pub(super) fn establish(
        app: &mut TestApp,
        protocol: ClassicPinProtocol,
        platform_secret: u8,
    ) -> Self {
        let authenticator_key = request_classic_key_agreement(app, protocol);
        let secret = P256SecretKey::from_slice(&[platform_secret; 32]).expect("valid secret key");
        let (keys, platform_key) = derive_classic_session(protocol, &authenticator_key, &secret);
        Self {
            protocol,
            keys,
            key_agreement: canonical_map(platform_key),
        }
    }

    /// `encrypt(shared secret, plaintext)`; protocol two uses a fixed IV.
    pub(super) fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let iv = match self.protocol {
            ClassicPinProtocol::V1 => None,
            ClassicPinProtocol::V2 => Some([0x5A; 16]),
        };
        classic_encrypt(self.protocol, &self.keys, plaintext, iv)
    }

    pub(super) fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
        crate::decrypt_classic_pin_block(self.protocol, &self.keys, ciphertext)
            .expect("ciphertext decrypts")
    }
}

/// setPIN over `protocol`, with `padded_new_pin` as the plaintext of newPinEnc.
pub(super) fn set_pin_padded(
    app: &mut TestApp,
    protocol: ClassicPinProtocol,
    padded_new_pin: &[u8],
) -> Result<Vec<u8>, u8> {
    let session = PlatformPinSession::establish(app, protocol, 0x51);
    let new_pin_enc = session.encrypt(padded_new_pin);
    set_pin_encrypted(app, &session, new_pin_enc)
}

/// setPIN with a newPinEnc exactly as given, authenticated correctly.
pub(super) fn set_pin_encrypted(
    app: &mut TestApp,
    session: &PlatformPinSession,
    new_pin_enc: Vec<u8>,
) -> Result<Vec<u8>, u8> {
    let pin_uv_auth_param = classic_pin_auth(session.protocol, &session.keys, &new_pin_enc);
    client_pin(
        app,
        vec![
            (int(1), int(session.protocol.identifier().into())),
            (int(2), int(0x03)),
            (int(3), session.key_agreement.clone()),
            (int(4), Value::Bytes(pin_uv_auth_param)),
            (int(5), Value::Bytes(new_pin_enc)),
        ],
    )
}

/// getPINRetries: `(pinRetries, powerCycleState)`.
pub(super) fn get_pin_retries(app: &mut TestApp) -> (u8, Option<bool>) {
    let response = client_pin(app, vec![(int(2), int(0x01))]).expect("getPINRetries succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode getPINRetries") else {
        panic!("response must be a map");
    };
    let mut retries = None;
    let mut power_cycle_state = None;
    for (key, value) in map {
        match (key, value) {
            (Value::Integer(key), Value::Integer(value)) if key == Integer::from(3) => {
                retries = Some(u8::try_from(value).expect("pinRetries fits a byte"));
            }
            (Value::Integer(key), Value::Bool(flag)) if key == Integer::from(4) => {
                power_cycle_state = Some(flag);
            }
            _ => {}
        }
    }
    (retries.expect("pinRetries present"), power_cycle_state)
}

/// getPinToken (0x05) with `pin` over `protocol`: the decrypted pinUvAuthToken.
pub(super) fn get_pin_token(
    app: &mut TestApp,
    protocol: ClassicPinProtocol,
    pin: &[u8],
) -> Result<[u8; 32], u8> {
    request_pin_uv_auth_token(app, protocol, pin, 0x05, Vec::new())
}

/// getPinUvAuthTokenUsingPinWithPermissions (0x09) with `pin` over
/// `protocol`: the decrypted pinUvAuthToken.
pub(super) fn get_pin_uv_auth_token(
    app: &mut TestApp,
    protocol: ClassicPinProtocol,
    pin: &[u8],
    permissions: i128,
    rp_id: Option<&str>,
) -> Result<[u8; 32], u8> {
    let mut parameters = vec![(
        int(9),
        Value::Integer(Integer::try_from(permissions).expect("CBOR integer")),
    )];
    if let Some(rp_id) = rp_id {
        parameters.push((int(10), Value::Text(rp_id.into())));
    }
    request_pin_uv_auth_token(app, protocol, pin, 0x09, parameters)
}

fn request_pin_uv_auth_token(
    app: &mut TestApp,
    protocol: ClassicPinProtocol,
    pin: &[u8],
    subcommand: i64,
    parameters: Vec<(Value, Value)>,
) -> Result<[u8; 32], u8> {
    let session = PlatformPinSession::establish(app, protocol, 0x21);
    request_pin_uv_auth_token_with(app, &session, pin, subcommand, parameters)
}

/// getPinToken (0x05) with `pin`, over a key agreement the platform already has.
pub(super) fn get_pin_token_with(
    app: &mut TestApp,
    session: &PlatformPinSession,
    pin: &[u8],
) -> Result<[u8; 32], u8> {
    request_pin_uv_auth_token_with(app, session, pin, 0x05, Vec::new())
}

fn request_pin_uv_auth_token_with(
    app: &mut TestApp,
    session: &PlatformPinSession,
    pin: &[u8],
    subcommand: i64,
    parameters: Vec<(Value, Value)>,
) -> Result<[u8; 32], u8> {
    let protocol = session.protocol;
    let pin_hash_enc = session.encrypt(&pin_hash(pin));
    let mut entries = vec![
        (int(1), int(protocol.identifier().into())),
        (int(2), int(subcommand)),
        (int(3), session.key_agreement.clone()),
        (int(6), Value::Bytes(pin_hash_enc)),
    ];
    entries.extend(parameters);
    let response = client_pin(app, entries)?;
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode getPinToken") else {
        panic!("response must be a map");
    };
    let encrypted = map
        .into_iter()
        .find_map(|(key, value)| match (key, value) {
            (Value::Integer(key), Value::Bytes(bytes)) if key == Integer::from(2) => Some(bytes),
            _ => None,
        })
        .expect("pinUvAuthToken present");
    Ok(session
        .decrypt(&encrypted)
        .try_into()
        .expect("pinUvAuthToken is 32 bytes"))
}

/// An authenticatorMakeCredential request for an ES256 credential, optionally
/// carrying `(pinUvAuthProtocol, pinUvAuthParam)`.
pub(super) fn make_credential_request(
    client_hash: &[u8],
    rp_id: &str,
    pin_uv_auth: Option<(ClassicPinProtocol, Vec<u8>)>,
) -> Vec<u8> {
    let (param, protocol) = pin_uv_auth_values(pin_uv_auth);
    make_credential_request_with(client_hash, rp_id, param, protocol)
}

fn pin_uv_auth_values(
    pin_uv_auth: Option<(ClassicPinProtocol, Vec<u8>)>,
) -> (Option<Value>, Option<Value>) {
    match pin_uv_auth {
        Some((protocol, param)) => (
            Some(Value::Bytes(param)),
            Some(int(protocol.identifier().into())),
        ),
        None => (None, None),
    }
}

/// An authenticatorMakeCredential request with pinUvAuthParam (0x08) and
/// pinUvAuthProtocol (0x09) exactly as given.
pub(super) fn make_credential_request_with(
    client_hash: &[u8],
    rp_id: &str,
    pin_uv_auth_param: Option<Value>,
    pin_uv_auth_protocol: Option<Value>,
) -> Vec<u8> {
    let mut entries = vec![
        (int(1), Value::Bytes(client_hash.to_vec())),
        (
            int(2),
            canonical_map(vec![(Value::Text("id".into()), Value::Text(rp_id.into()))]),
        ),
        (
            int(3),
            canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x01]))]),
        ),
        (
            int(4),
            Value::Array(vec![canonical_map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (Value::Text("alg".into()), int(CoseAlg::ES256 as i64)),
            ])]),
        ),
    ];
    if let Some(param) = pin_uv_auth_param {
        entries.push((int(8), param));
    }
    if let Some(protocol) = pin_uv_auth_protocol {
        entries.push((int(9), protocol));
    }
    encode(&canonical_map(entries))
}

/// An authenticatorGetAssertion request, optionally carrying
/// `(pinUvAuthProtocol, pinUvAuthParam)` and an extensions map.
pub(super) fn get_assertion_request(
    client_hash: &[u8],
    rp_id: &str,
    pin_uv_auth: Option<(ClassicPinProtocol, Vec<u8>)>,
    extensions: Option<Value>,
) -> Vec<u8> {
    let (param, protocol) = pin_uv_auth_values(pin_uv_auth);
    get_assertion_request_with(client_hash, rp_id, param, protocol, extensions)
}

/// An authenticatorGetAssertion request with pinUvAuthParam (0x06) and
/// pinUvAuthProtocol (0x07) exactly as given.
pub(super) fn get_assertion_request_with(
    client_hash: &[u8],
    rp_id: &str,
    pin_uv_auth_param: Option<Value>,
    pin_uv_auth_protocol: Option<Value>,
    extensions: Option<Value>,
) -> Vec<u8> {
    let mut entries = vec![
        (int(1), Value::Text(rp_id.into())),
        (int(2), Value::Bytes(client_hash.to_vec())),
    ];
    if let Some(extensions) = extensions {
        entries.push((int(4), extensions));
    }
    if let Some(param) = pin_uv_auth_param {
        entries.push((int(6), param));
    }
    if let Some(protocol) = pin_uv_auth_protocol {
        entries.push((int(7), protocol));
    }
    encode(&canonical_map(entries))
}

/// A discoverable ES256 credential bound to `rp_id`.
pub(super) fn es256_credential(rp_id: &str, credential_id: &[u8]) -> CredentialRecord {
    credential(rp_id, &[0x01], credential_id, CoseAlg::ES256)
}

/// The authenticator data of a makeCredential or getAssertion response.
pub(super) fn response_auth_data(response: &[u8]) -> Vec<u8> {
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(entries) = from_reader(&response[1..]).expect("decode response") else {
        panic!("response must be a map");
    };
    entries
        .into_iter()
        .find(|(k, _)| *k == int(2))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        })
        .expect("authData present")
}

/// The user verified (UV) bit of the authenticator data flags.
pub(super) const FLAG_UV: u8 = 0x04;

/// Give `app` an in-use pinUvAuthToken, as a successful
/// getPinUvAuthTokenUsingPinWithPermissions over `protocol` would.  Only a PIN
/// issues tokens, so a PIN is set first if there is none: without one the
/// authenticator is not "protected by some form of user verification" and
/// makeCredential and getAssertion ignore a pinUvAuthParam (CTAP 2.3 §6.1.2
/// step 11, §6.2.2 step 6).
pub(super) fn install_pin_uv_auth_token(
    app: &mut TestApp,
    protocol: ClassicPinProtocol,
    token: [u8; 32],
    permissions: u8,
    rp_id: Option<&str>,
) {
    if !app.pin_state.is_set() {
        app.pin_state.set_pin(pin_hash(b"1234"));
    }
    app.pin_state
        .issue_pin_uv_auth_token(protocol, token, permissions, rp_id.map(str::to_string));
}
