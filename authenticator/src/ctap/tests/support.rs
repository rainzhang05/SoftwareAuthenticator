//! Test doubles and PIN/UV auth protocol helpers shared by the test modules.

use crate::ctap::cbor::{canonical_map, canonical_sort};
use crate::ctap::pin::protocol::{HmacSha256, PIN_UV_AUTH_PROTOCOL_CLASSIC};
use crate::ctap::CtapApp;
use crate::{ClassicPinProtocol, PinUvSessionKeys};

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
    files: HashMap<Vec<u8>, Vec<u8>>,
    presence_responses: VecDeque<consent::Result>,
}

impl TestClient {
    pub(super) fn new() -> Self {
        Self::default()
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
                    bytes.push(self.random_counter);
                    self.random_counter = self.random_counter.wrapping_add(1);
                }
                let message = Message::from_slice(&bytes).expect("random bytes fit message");
                Ok(Reply::from(reply::RandomBytes { bytes: message }))
            }
            Request::WriteFile(req) => {
                let path_key = req.path.as_str().as_bytes().to_vec();
                let data = req.data.as_slice().to_vec();
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
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
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

pub(super) fn derive_classic_session(
    protocol: ClassicPinProtocol,
    auth_entries: &[(Value, Value)],
    platform_secret: &P256SecretKey,
) -> (PinUvSessionKeys, Vec<u8>, Vec<(Value, Value)>) {
    let auth_public = authenticator_public_key(auth_entries);
    let platform_public = platform_secret.public_key().to_encoded_point(false);
    let shared = diffie_hellman(platform_secret.to_nonzero_scalar(), auth_public.as_affine());
    let auth_encoded = auth_public.to_encoded_point(false);
    let mut hasher = Sha256::new();
    hasher.update(auth_encoded.as_bytes());
    hasher.update(platform_public.as_bytes());
    let transcript_hash = hasher.finalize().to_vec();
    let shared_bytes = shared.raw_secret_bytes();
    let keys = crate::derive_classic_pin_uv_session_keys(protocol, shared_bytes.as_ref());
    let platform_entries = classic_platform_key_entries(&platform_public);
    (keys, transcript_hash, platform_entries)
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

pub(super) fn classic_pin_auth(
    protocol: ClassicPinProtocol,
    keys: &PinUvSessionKeys,
    data: &[u8],
) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(&keys.auth_key).expect("valid MAC key");
    mac.update(data);
    let full = mac.finalize().into_bytes();
    match protocol {
        ClassicPinProtocol::V1 | ClassicPinProtocol::V2 => full[..16].to_vec(),
    }
}
