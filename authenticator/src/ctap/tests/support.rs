//! Test doubles and PIN/UV auth protocol helpers shared by the test modules.

use crate::ctap::cbor::{canonical_map, canonical_sort};
use crate::ctap::pin::protocol::HmacSha256;
use crate::ctap::storage::StoredCredential;
use crate::ctap::CtapApp;
use crate::{ClassicPinProtocol, CoseAlg, PinUvSessionKeys};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use core::task::Poll;
use hmac::Mac;
use p256::{
    ecdh::diffie_hellman, elliptic_curve::sec1::ToEncodedPoint, EncodedPoint,
    PublicKey as P256PublicKey, SecretKey as P256SecretKey,
};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use trussed::api::{reply, Reply, Request, RequestVariant};
use trussed::client::{
    AttestationClient, CertificateClient, Client as TrussedClient, ClientResult, CounterClient,
    CryptoClient, FilesystemClient, FutureResult, ManagementClient, PollClient, UiClient,
};
use trussed::error::Error as TrussedError;
use trussed::types::{consent, Message};

use transport_core::ctap::constants::*;

#[derive(Default)]
pub(super) struct TestClient {
    pending: Option<Result<Reply, TrussedError>>,
    random_counter: u8,
    random_fill: Option<u8>,
    files: HashMap<Vec<u8>, Vec<u8>>,
    writes: Vec<(Vec<u8>, Vec<u8>)>,
    presence_responses: VecDeque<consent::Result>,
}

impl TestClient {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Make every random byte `fill` instead of a counter.
    pub(super) fn set_random_fill(&mut self, fill: u8) {
        self.random_fill = Some(fill);
    }

    /// Put `data` at `path`, as if an earlier run had written it.
    pub(super) fn insert_file(&mut self, path: &str, data: Vec<u8>) {
        self.files.insert(path.as_bytes().to_vec(), data);
    }

    /// Every write to `path`, oldest first.
    pub(super) fn writes_to(&self, path: &str) -> Vec<Vec<u8>> {
        self.writes
            .iter()
            .filter(|(written, _)| written.as_slice() == path.as_bytes())
            .map(|(_, data)| data.clone())
            .collect()
    }

    pub(super) fn set_presence_responses<I>(&mut self, responses: I)
    where
        I: IntoIterator<Item = consent::Result>,
    {
        self.presence_responses = responses.into_iter().collect();
    }

    fn dispatch(&mut self, request: Request) -> Result<Reply, TrussedError> {
        match request {
            Request::RandomBytes(req) => {
                let mut bytes = Vec::with_capacity(req.count);
                for _ in 0..req.count {
                    bytes.push(self.random_fill.unwrap_or(self.random_counter));
                    self.random_counter = self.random_counter.wrapping_add(1);
                }
                let message = Message::from_slice(&bytes).expect("random bytes fit message");
                Ok(Reply::from(reply::RandomBytes { bytes: message }))
            }
            Request::WriteFile(req) => {
                let path_key = req.path.as_str().as_bytes().to_vec();
                let data = req.data.as_slice().to_vec();
                self.writes.push((path_key.clone(), data.clone()));
                self.files.insert(path_key, data);
                Ok(Reply::from(reply::WriteFile {}))
            }
            Request::ReadFile(req) => {
                let path_key = req.path.as_str().as_bytes().to_vec();
                if let Some(data) = self.files.get(&path_key) {
                    let message = Message::from_slice(data).expect("stored file fits message");
                    Ok(Reply::from(reply::ReadFile { data: message }))
                } else {
                    Err(TrussedError::FilesystemReadFailure)
                }
            }
            Request::RequestUserConsent(_req) => {
                let result = self
                    .presence_responses
                    .pop_front()
                    .unwrap_or(Ok::<(), consent::Error>(()));
                Ok(Reply::from(reply::RequestUserConsent { result }))
            }
            _ => Err(TrussedError::FunctionNotSupported),
        }
    }
}

impl PollClient for TestClient {
    fn request<Rq: RequestVariant>(&mut self, req: Rq) -> ClientResult<'_, Rq::Reply, Self> {
        assert!(self.pending.is_none(), "a request is already pending");
        let request: Request = req.into();
        self.pending = Some(self.dispatch(request));
        Ok(FutureResult::new(self))
    }

    fn poll(&mut self) -> Poll<Result<Reply, TrussedError>> {
        match self.pending.take() {
            Some(result) => Poll::Ready(result),
            None => Poll::Pending,
        }
    }
}

impl CryptoClient for TestClient {}
impl FilesystemClient for TestClient {}
impl AttestationClient for TestClient {}
impl CertificateClient for TestClient {}
impl CounterClient for TestClient {}
impl ManagementClient for TestClient {}
impl UiClient for TestClient {}
impl TrussedClient for TestClient {}

pub(super) fn request_classic_key_agreement(
    app: &mut CtapApp<TestClient>,
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
pub(super) fn client_pin(
    app: &mut CtapApp<TestClient>,
    entries: Vec<(Value, Value)>,
) -> Result<Vec<u8>, u8> {
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
        app: &mut CtapApp<TestClient>,
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
    app: &mut CtapApp<TestClient>,
    protocol: ClassicPinProtocol,
    padded_new_pin: &[u8],
) -> Result<Vec<u8>, u8> {
    let session = PlatformPinSession::establish(app, protocol, 0x51);
    let new_pin_enc = session.encrypt(padded_new_pin);
    set_pin_encrypted(app, &session, new_pin_enc)
}

/// setPIN with a newPinEnc exactly as given, authenticated correctly.
pub(super) fn set_pin_encrypted(
    app: &mut CtapApp<TestClient>,
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
pub(super) fn get_pin_retries(app: &mut CtapApp<TestClient>) -> (u8, Option<bool>) {
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
    app: &mut CtapApp<TestClient>,
    protocol: ClassicPinProtocol,
    pin: &[u8],
) -> Result<[u8; 32], u8> {
    request_pin_uv_auth_token(app, protocol, pin, 0x05, Vec::new())
}

/// getPinUvAuthTokenUsingPinWithPermissions (0x09) with `pin` over
/// `protocol`: the decrypted pinUvAuthToken.
pub(super) fn get_pin_uv_auth_token(
    app: &mut CtapApp<TestClient>,
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
    app: &mut CtapApp<TestClient>,
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
    app: &mut CtapApp<TestClient>,
    session: &PlatformPinSession,
    pin: &[u8],
) -> Result<[u8; 32], u8> {
    request_pin_uv_auth_token_with(app, session, pin, 0x05, Vec::new())
}

fn request_pin_uv_auth_token_with(
    app: &mut CtapApp<TestClient>,
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
pub(super) fn es256_credential(rp_id: &str, credential_id: &[u8]) -> StoredCredential {
    let (public_key, secret_key) = crate::create_credential(CoseAlg::ES256);
    StoredCredential {
        rp_id: rp_id.into(),
        user_id: vec![0x01],
        user_name: None,
        user_display_name: None,
        alg: CoseAlg::ES256 as i32,
        credential_id: credential_id.to_vec(),
        public_key,
        secret_key: secret_key.to_bytes(),
        cred_random_with_uv: Some(vec![0x10; 32]),
        cred_random_without_uv: Some(vec![0x20; 32]),
        cred_protect: Some(1),
        sign_count: 0,
    }
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
/// getPinUvAuthTokenUsingPinWithPermissions over `protocol` would.
pub(super) fn install_pin_uv_auth_token(
    app: &mut CtapApp<TestClient>,
    protocol: ClassicPinProtocol,
    token: [u8; 32],
    permissions: u8,
    rp_id: Option<&str>,
) {
    app.pin_state
        .issue_pin_uv_auth_token(protocol, token, permissions, rp_id.map(str::to_string));
}
