//! Stateful CTAP: a sequence of requests against one engine, the harness
//! acting as a platform that can set and change a PIN, obtain
//! pinUvAuthTokens and authenticate makeCredential, getAssertion and
//! credentialManagement and authenticatorConfig with them, and use credBlob,
//! minPinLength, hmac-secret and
//! hmac-secret-mc, while the fuzzer chooses the parameters (right, wrong or
//! missing) and mixes in structure-aware and raw requests and presence
//! denials.
//!
//! Invariants, besides those of `ctap_request` for every response:
//! * setPIN only succeeds while no PIN is set, and changePIN and the token
//!   subcommands only with the right PIN; the right PIN is never answered
//!   with CTAP2_ERR_PIN_INVALID except the legacy forced-change refusal;
//!   a pinUvAuthToken decrypts to 32 bytes;
//! * a new credential's authenticator data carries the RP ID hash of the
//!   request, the AT flag and a credential ID of the form its "rk" option
//!   asks for: 33 bytes starting 0x01 for a stored discoverable credential,
//!   107 bytes starting 0x02 for a sealed non-discoverable one, or 33 bytes
//!   starting 0x00 for a stored non-discoverable RSA credential;
//! * getAssertion, getNextAssertion and credential enumeration only return
//!   credentials this engine created and has not deleted, and getAssertion
//!   and getNextAssertion only for the RP ID requested; getNextAssertion only
//!   succeeds right after a getAssertion that reported more credentials;
//! * hmac-secret and hmac-secret-mc return one output per salt;
//! * credBlob returns the blob accepted at creation, or an empty byte string;
//! * the minimum PIN length never falls without reset;
//! * alwaysUv prevents makeCredential and getAssertion with up=true from
//!   succeeding without pinUvAuthParam.

use crate::cbor::{self, bytes, decode_map, get_int, get_text, int, text};
use crate::engine::Engine;
use crate::platform::{Session, authenticate, pin_hash, protocol_value};
use crate::requests::{self, Overrides, command};
use arbitrary::{Arbitrary, Result, Unstructured};
use ciborium::value::Value;
use pqkey_ctap::ctap::CtapApp;
use pqkey_ctap::ctap::constants::*;
use pqkey_ctap::store::MemoryStore;
use pqkey_ctap::{ClassicPinProtocol, CoseAlg};
use sha2::{Digest, Sha256};

const MAX_STEPS: usize = 24;

const PINS: &[&[u8]] = &[
    b"1234",
    b"123",
    b"correct horse battery staple",
    "\u{1F510}\u{1F510}\u{1F510}\u{1F510}".as_bytes(),
    b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
];

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Auth {
    /// No pinUvAuthParam.
    None,
    /// Computed with the current pinUvAuthToken.
    Token,
    /// The right length but the wrong value.
    Wrong,
    /// Zero length: authenticator selection.
    Empty,
}

#[derive(Arbitrary, Debug)]
enum Op {
    SetPin {
        v2: bool,
        pin: u8,
        bad_auth: bool,
        pad_to: u8,
    },
    ChangePin {
        v2: bool,
        right_pin: bool,
        new_pin: u8,
    },
    GetToken {
        v2: bool,
        right_pin: bool,
        legacy: bool,
        permissions: u8,
        rp: Option<u8>,
    },
    MakeCredential {
        cred_blob: Option<u8>,
        min_pin_length: bool,
        hmac_secret_mc: Option<(bool, bool)>,
        auth: Auth,
        rp: u8,
        /// Ask for a discoverable credential rather than generating options.
        rk: bool,
        /// One supported algorithm, by its index in `CoseAlg::ALL`, rather
        /// than generated pubKeyCredParams.
        alg: Option<u8>,
    },
    GetAssertion {
        cred_blob: bool,
        auth: Auth,
        rp: u8,
        hmac_secret: Option<(bool, bool)>,
        /// Leave the allowList out, so every discoverable credential counts.
        discoverable: bool,
        up: bool,
    },
    GetNextAssertion,
    /// What a platform does before credential management: set a PIN if
    /// there is none, then get a token with the right PIN.
    Enroll {
        v2: bool,
        permissions: u8,
        rp: Option<u8>,
    },
    CredentialManagement {
        auth: Auth,
        subcommand: u8,
    },
    AuthenticatorConfig {
        auth: Auth,
        subcommand: u8,
        minimum: Option<u8>,
        rp_ids: Option<Vec<u8>>,
        force_change: Option<bool>,
        complexity: Option<bool>,
    },
    GetInfo,
    GetPinRetries,
    Reset,
    Presence(u8),
    Structured,
    Raw,
}

struct Credential {
    cred_blob: Option<Vec<u8>>,
    id: Vec<u8>,
    rp_id: String,
}

type HmacInput = (Option<Value>, Option<(Session, usize)>);

struct Platform {
    engine: Engine,
    /// The PIN the authenticator has, as far as the platform knows.
    pin: Option<Vec<u8>>,
    token: Option<(ClassicPinProtocol, [u8; 32])>,
    credentials: Vec<Credential>,
    /// The RP ID of the getAssertion whose further credentials
    /// getNextAssertion may return.
    assertion_rp: Option<String>,
    minimum: u8,
    always_uv: bool,
    force_change: bool,
    min_pin_length_rp_ids: Vec<String>,
}

fn protocol(v2: bool) -> ClassicPinProtocol {
    if v2 {
        ClassicPinProtocol::V2
    } else {
        ClassicPinProtocol::V1
    }
}

/// Mostly the first two RP IDs, so credentials and assertions meet.
fn rp_id(choice: u8) -> &'static str {
    let ids = requests::RP_IDS;
    if choice < 0xC0 {
        ids[usize::from(choice) % 2]
    } else {
        ids[usize::from(choice) % ids.len()]
    }
}

/// Mostly the permission sets a platform asks for, sometimes any.
fn permission_set(choice: u8) -> u8 {
    const SETS: [u8; 8] = [0x04, 0x01, 0x02, 0x03, 0x05, 0x07, 0x20, 0x27];
    if choice < 0xC0 {
        SETS[usize::from(choice) % SETS.len()]
    } else {
        choice & 0x7f
    }
}

fn status(response: &[u8]) -> u8 {
    response.first().copied().unwrap_or(0xFF)
}

/// The PIN a paddedPin holds: everything up to the last non-zero byte.
fn unpadded(padded: &[u8]) -> &[u8] {
    let end = padded
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |last| last + 1);
    &padded[..end]
}

fn acceptable_pin(pin: &[u8], minimum: u8) -> bool {
    pin.len() <= 63
        && std::str::from_utf8(pin).is_ok_and(|pin| pin.chars().count() >= usize::from(minimum))
}

impl Platform {
    fn new(engine: Engine) -> Self {
        Self {
            engine,
            pin: None,
            token: None,
            credentials: Vec::new(),
            assertion_rp: None,
            minimum: 4,
            always_uv: false,
            force_change: false,
            min_pin_length_rp_ids: Vec::new(),
        }
    }

    fn call(&mut self, request: &[u8]) -> Vec<u8> {
        let response = self.engine.call(request);
        self.observe(request, &response);
        response
    }

    fn known(&self, id: &[u8]) -> Option<&Credential> {
        self.credentials
            .iter()
            .find(|credential| credential.id == id)
    }

    fn known_ids(&self) -> Vec<Vec<u8>> {
        self.credentials.iter().map(|c| c.id.clone()).collect()
    }

    /// Check what a successful response says against what the platform
    /// knows, and learn from it.
    fn observe(&mut self, request: &[u8], response: &[u8]) {
        let Some(&code) = request.first() else {
            return;
        };
        let assertion_rp = if code == CTAP_CMD_GET_NEXT_ASSERTION {
            self.assertion_rp.clone()
        } else {
            self.assertion_rp.take()
        };
        if status(response) != CTAP2_OK {
            if code == CTAP_CMD_GET_NEXT_ASSERTION {
                self.assertion_rp = None;
            }
            return;
        }
        let parameters = match CtapApp::decode_request_parameters(&request[1..]) {
            Some(Value::Map(parameters)) => parameters,
            _ => Vec::new(),
        };
        let body = decode_map(&response[1..]).unwrap_or_default();
        match code {
            CTAP_CMD_MAKE_CREDENTIAL => {
                if self.always_uv {
                    assert!(
                        get_int(&parameters, 8).is_some(),
                        "alwaysUv makeCredential succeeded without pinUvAuthParam"
                    );
                }
                let Some(Value::Map(rp)) = get_int(&parameters, 2) else {
                    panic!("makeCredential succeeded without rp");
                };
                let Some(Value::Text(rp_id)) = get_text(rp, "id") else {
                    panic!("makeCredential succeeded without rp.id");
                };
                let Some(Value::Bytes(auth_data)) = get_int(&body, 2) else {
                    panic!("makeCredential response without authData");
                };
                assert!(auth_data.len() >= 55, "attested authData too short");
                assert_eq!(
                    auth_data[..32],
                    Sha256::digest(rp_id.as_bytes())[..],
                    "rpIdHash"
                );
                assert_ne!(auth_data[32] & 0x40, 0, "AT flag");
                let length = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
                let discoverable = matches!(
                    get_int(&parameters, 7),
                    Some(Value::Map(options))
                        if matches!(get_text(options, "rk"), Some(Value::Bool(true)))
                );
                let (expected_length, marker) = if discoverable {
                    (33, 0x01)
                } else {
                    let public_key: Value = ciborium::de::from_reader(&auth_data[55 + length..])
                        .expect("credential public key");
                    let Value::Map(public_key) = public_key else {
                        panic!("credential public key is a map");
                    };
                    // An RSA key (kty 3) does not fit a sealed ID, so it is
                    // stored.
                    let kty = get_int(&public_key, 1);
                    if matches!(kty, Some(Value::Integer(kty)) if i128::from(*kty) == 3) {
                        (33, 0x00)
                    } else {
                        (107, 0x02)
                    }
                };
                assert_eq!(length, expected_length, "credential ID length");
                assert_eq!(auth_data[55], marker, "credential ID marker");
                let mut remaining = &auth_data[55 + length..];
                let _: Value = ciborium::de::from_reader(&mut remaining).expect("public key");
                let outputs = decode_map(remaining).unwrap_or_default();
                let requested = matches!(
                    get_int(&parameters, 6),
                    Some(Value::Map(inputs))
                        if matches!(get_text(inputs, "minPinLength"), Some(Value::Bool(true)))
                );
                let authorized = self.min_pin_length_rp_ids.contains(rp_id);
                if requested && authorized {
                    assert_eq!(
                        get_text(&outputs, "minPinLength"),
                        Some(&int(i64::from(self.minimum))),
                        "current minimum PIN length"
                    );
                    assert_ne!(auth_data[32] & 0x80, 0, "minPinLength without ED flag");
                } else {
                    assert!(
                        get_text(&outputs, "minPinLength").is_none(),
                        "minimum disclosed without an authorized request"
                    );
                }
                self.credentials.push(Credential {
                    cred_blob: match (get_int(&parameters, 6), auth_data.get(55 + length..)) {
                        (Some(Value::Map(inputs)), Some(mut rest)) => {
                            let _: Value =
                                ciborium::de::from_reader(&mut rest).expect("public key");
                            let outputs = decode_map(rest).unwrap_or_default();
                            if matches!(get_text(&outputs, "credBlob"), Some(Value::Bool(true))) {
                                match get_text(inputs, "credBlob") {
                                    Some(Value::Bytes(blob)) => Some(blob.clone()),
                                    _ => panic!("stored blob without input"),
                                }
                            } else {
                                None
                            }
                        }
                        _ => None,
                    },
                    id: auth_data[55..55 + length].to_vec(),
                    rp_id: rp_id.clone(),
                });
            }
            CTAP_CMD_GET_ASSERTION | CTAP_CMD_GET_NEXT_ASSERTION => {
                if code == CTAP_CMD_GET_ASSERTION && self.always_uv {
                    let up = !matches!(
                        get_int(&parameters, 5),
                        Some(Value::Map(options))
                            if matches!(get_text(options, "up"), Some(Value::Bool(false)))
                    );
                    if up {
                        assert!(
                            get_int(&parameters, 6).is_some(),
                            "alwaysUv getAssertion with up=true succeeded without pinUvAuthParam"
                        );
                    }
                }
                let rp_id = if code == CTAP_CMD_GET_ASSERTION {
                    match get_int(&parameters, 1) {
                        Some(Value::Text(rp_id)) => rp_id.clone(),
                        _ => panic!("getAssertion succeeded without rpId"),
                    }
                } else {
                    assertion_rp
                        .clone()
                        .expect("getNextAssertion succeeded with nothing pending")
                };
                let Some(Value::Map(descriptor)) = get_int(&body, 1) else {
                    panic!("assertion without credential");
                };
                let Some(Value::Bytes(id)) = get_text(descriptor, "id") else {
                    panic!("assertion credential without id");
                };
                let credential = self
                    .known(id)
                    .expect("an assertion with a credential this engine does not have");
                assert_eq!(credential.rp_id, rp_id, "an assertion for another RP");
                let Some(Value::Bytes(auth_data)) = get_int(&body, 2) else {
                    panic!("assertion without authData");
                };
                assert_eq!(
                    auth_data[..32],
                    Sha256::digest(rp_id.as_bytes())[..],
                    "rpIdHash"
                );
                if auth_data[32] & 0x80 != 0 {
                    let outputs = decode_map(&auth_data[37..]).expect("extensions");
                    if let Some(Value::Bytes(blob)) = get_text(&outputs, "credBlob") {
                        assert_eq!(
                            blob.as_slice(),
                            credential.cred_blob.as_deref().unwrap_or_default(),
                            "credential blob"
                        );
                    }
                }
                if code == CTAP_CMD_GET_ASSERTION {
                    if get_int(&body, 5).is_some() {
                        self.assertion_rp = Some(rp_id);
                    }
                } else {
                    self.assertion_rp = assertion_rp;
                }
            }
            CTAP_CMD_CREDENTIAL_MANAGEMENT => match get_int(&parameters, 1) {
                Some(v) if *v == int(4) || *v == int(5) => {
                    let Some(Value::Map(descriptor)) = get_int(&body, 7) else {
                        panic!("enumerated credential without descriptor");
                    };
                    let Some(Value::Bytes(id)) = get_text(descriptor, "id") else {
                        panic!("enumerated credential without id");
                    };
                    assert!(self.known(id).is_some(), "enumerated an unknown credential");
                }
                Some(v) if *v == int(6) => {
                    let id = match get_int(&parameters, 2) {
                        Some(Value::Map(params)) => match get_int(params, 2) {
                            Some(Value::Map(descriptor)) => get_text(descriptor, "id").cloned(),
                            _ => None,
                        },
                        _ => None,
                    };
                    let Some(Value::Bytes(id)) = id else {
                        panic!("deleted a credential without an id");
                    };
                    self.credentials.retain(|credential| credential.id != id);
                }
                _ => {}
            },
            CTAP_CMD_RESET => {
                self.pin = None;
                self.token = None;
                self.credentials.clear();
                self.minimum = 4;
                self.always_uv = false;
                self.force_change = false;
                self.min_pin_length_rp_ids.clear();
            }
            CTAP_CMD_AUTHENTICATOR_CONFIG => match get_int(&parameters, 1) {
                Some(subcommand) if *subcommand == int(2) => {
                    self.always_uv = !self.always_uv;
                }
                Some(subcommand) if *subcommand == int(3) => {
                    let params = match get_int(&parameters, 2) {
                        Some(Value::Map(params)) => params.as_slice(),
                        None => &[],
                        _ => panic!("config accepted parameters of the wrong type"),
                    };
                    if let Some(minimum) = get_int(params, 1) {
                        let Value::Integer(minimum) = minimum else {
                            panic!("config accepted a non-integer minimum");
                        };
                        let minimum = u8::try_from(i128::from(*minimum)).expect("minimum");
                        assert!(minimum >= self.minimum, "minimum fell without reset");
                        assert!(minimum <= 63, "minimum cannot be met by a PIN");
                        self.minimum = minimum;
                    }
                    if matches!(get_int(params, 3), Some(Value::Bool(true))) {
                        assert!(self.pin.is_some(), "forced change without a PIN");
                        self.force_change = true;
                    }
                    if let Some(pin) = &self.pin {
                        let length = std::str::from_utf8(pin).expect("PIN").chars().count();
                        if length < usize::from(self.minimum) {
                            self.force_change = true;
                        }
                    }
                    if let Some(ids) = get_int(params, 2) {
                        let Value::Array(ids) = ids else {
                            panic!("config accepted RP IDs of the wrong type");
                        };
                        assert!(ids.len() <= 8, "too many authorized RP IDs");
                        if !ids.is_empty() {
                            self.min_pin_length_rp_ids = ids
                                .iter()
                                .map(|id| {
                                    let Value::Text(id) = id else {
                                        panic!("config accepted a non-string RP ID");
                                    };
                                    assert!(id.len() <= 253, "RP ID too long");
                                    id.clone()
                                })
                                .collect();
                        }
                    }
                    assert!(
                        !matches!(get_int(params, 4), Some(Value::Bool(true))),
                        "unsupported PIN complexity policy enabled"
                    );
                    if self.force_change {
                        self.token = None;
                    }
                }
                _ => panic!("unsupported config subcommand succeeded"),
            },
            CTAP_CMD_GET_INFO => {
                assert_eq!(
                    get_int(&body, 0x0D),
                    Some(&int(i64::from(self.minimum))),
                    "minimum differs from the model"
                );
                assert_eq!(
                    get_int(&body, 0x0C),
                    Some(&Value::Bool(self.force_change)),
                    "forcePINChange differs from the model"
                );
                let Some(Value::Map(options)) = get_int(&body, 4) else {
                    panic!("getInfo without options");
                };
                assert_eq!(
                    get_text(options, "alwaysUv"),
                    Some(&Value::Bool(self.always_uv))
                );
                assert_eq!(
                    get_text(options, "makeCredUvNotRqd"),
                    Some(&Value::Bool(!self.always_uv))
                );
            }
            _ => {}
        }
    }

    /// getKeyAgreement, and encapsulation against its key.
    fn session(
        &mut self,
        protocol: ClassicPinProtocol,
        u: &mut Unstructured<'_>,
    ) -> Result<Option<Session>> {
        let request = command(
            CTAP_CMD_CLIENT_PIN,
            &Value::Map(vec![(int(1), protocol_value(protocol)), (int(2), int(2))]),
        );
        let response = self.call(&request);
        let secret = [u.int_in_range(1u8..=0x7f)?; 32];
        let session = Session::establish(protocol, &response, secret);
        assert!(
            session.is_some(),
            "getKeyAgreement did not give a usable key"
        );
        Ok(session)
    }

    fn hmac_input(
        &mut self,
        choice: Option<(bool, bool)>,
        u: &mut Unstructured<'_>,
    ) -> Result<HmacInput> {
        let Some((v2, two_salts)) = choice else {
            return Ok((None, None));
        };
        let protocol = protocol(v2);
        let Some(session) = self.session(protocol, u)? else {
            return Ok((None, None));
        };
        let mut salts = vec![0; if two_salts { 64 } else { 32 }];
        u.fill_buffer(&mut salts)?;
        let encrypted = session.encrypt(&salts, Self::iv(u)?);
        let value = Value::Map(vec![
            (int(1), session.key_agreement.clone()),
            (int(2), bytes(&encrypted)),
            (int(3), bytes(&session.authenticate(&encrypted))),
            (int(4), protocol_value(protocol)),
        ]);
        Ok((Some(value), Some((session, salts.len()))))
    }

    fn iv(u: &mut Unstructured<'_>) -> Result<[u8; 16]> {
        u.arbitrary()
    }

    fn pin_uv_auth(
        &self,
        auth: Auth,
        message: &[u8],
    ) -> (Option<Option<Value>>, Option<Option<Value>>) {
        match (auth, self.token) {
            (Auth::None, _) => (Some(None), Some(None)),
            (Auth::Empty, _) => (Some(Some(bytes(&[]))), Some(Some(int(2)))),
            (Auth::Token, Some((protocol, token))) => (
                Some(Some(bytes(&authenticate(protocol, &token, message)))),
                Some(Some(protocol_value(protocol))),
            ),
            (Auth::Token | Auth::Wrong, token) => {
                let protocol = token.map_or(ClassicPinProtocol::V2, |(protocol, _)| protocol);
                let len = if protocol == ClassicPinProtocol::V1 {
                    16
                } else {
                    32
                };
                (
                    Some(Some(bytes(&vec![0x5A; len]))),
                    Some(Some(protocol_value(protocol))),
                )
            }
        }
    }

    fn step(&mut self, op: Op, u: &mut Unstructured<'_>) -> Result<()> {
        match op {
            Op::SetPin {
                v2,
                pin,
                bad_auth,
                pad_to,
            } => {
                let protocol = protocol(v2);
                let Some(session) = self.session(protocol, u)? else {
                    return Ok(());
                };
                let mut padded = PINS[usize::from(pin) % PINS.len()].to_vec();
                if pin as usize % 7 == 6 {
                    padded = u.arbitrary()?;
                }
                let padded_len = match pad_to % 8 {
                    0 => 32,
                    1 => 80,
                    _ => 64,
                };
                padded.resize(padded_len.max(padded.len().div_ceil(16) * 16), 0);
                let new_pin_enc = session.encrypt(&padded, Self::iv(u)?);
                let mut auth = session.authenticate(&new_pin_enc);
                if bad_auth {
                    auth[0] ^= 1;
                }
                let request = command(
                    CTAP_CMD_CLIENT_PIN,
                    &Value::Map(vec![
                        (int(1), protocol_value(protocol)),
                        (int(2), int(3)),
                        (int(3), session.key_agreement.clone()),
                        (int(4), bytes(&auth)),
                        (int(5), bytes(&new_pin_enc)),
                    ]),
                );
                let response = self.call(&request);
                if status(&response) == CTAP2_OK {
                    assert!(self.pin.is_none(), "setPIN while a PIN is set");
                    assert!(!bad_auth, "setPIN with a wrong pinUvAuthParam");
                    assert_eq!(
                        padded.len(),
                        64,
                        "setPIN with a paddedPin that is not 64 bytes"
                    );
                    let pin = unpadded(&padded);
                    assert!(
                        acceptable_pin(pin, self.minimum),
                        "setPIN accepted a PIN the policy forbids"
                    );
                    self.pin = Some(pin.to_vec());
                    self.token = None;
                    self.force_change = false;
                }
            }
            Op::ChangePin {
                v2,
                right_pin,
                new_pin,
            } => {
                let protocol = protocol(v2);
                let Some(session) = self.session(protocol, u)? else {
                    return Ok(());
                };
                let current = match (&self.pin, right_pin) {
                    (Some(pin), true) => pin.clone(),
                    _ => b"not the PIN".to_vec(),
                };
                let pin_hash_enc = session.encrypt(&pin_hash(&current), Self::iv(u)?);
                let new = PINS[usize::from(new_pin) % PINS.len()];
                let mut padded = new.to_vec();
                padded.resize(64, 0);
                let new_pin_enc = session.encrypt(&padded, Self::iv(u)?);
                let mut message = new_pin_enc.clone();
                message.extend_from_slice(&pin_hash_enc);
                let request = command(
                    CTAP_CMD_CLIENT_PIN,
                    &Value::Map(vec![
                        (int(1), protocol_value(protocol)),
                        (int(2), int(4)),
                        (int(3), session.key_agreement.clone()),
                        (int(4), bytes(&session.authenticate(&message))),
                        (int(5), bytes(&new_pin_enc)),
                        (int(6), bytes(&pin_hash_enc)),
                    ]),
                );
                let response = self.call(&request);
                let knows_pin = right_pin && self.pin.is_some();
                if knows_pin {
                    assert_ne!(
                        status(&response),
                        CTAP2_ERR_PIN_INVALID,
                        "the right PIN refused"
                    );
                }
                if status(&response) == CTAP2_OK {
                    assert!(knows_pin, "changePIN with the wrong PIN");
                    assert!(acceptable_pin(new, self.minimum));
                    if self.force_change {
                        assert_ne!(
                            self.pin.as_deref(),
                            Some(new),
                            "forced change reused the PIN"
                        );
                    }
                    self.pin = Some(new.to_vec());
                    self.token = None;
                    self.force_change = false;
                }
            }
            Op::GetToken {
                v2,
                right_pin,
                legacy,
                permissions,
                rp,
            } => {
                let protocol = protocol(v2);
                let Some(session) = self.session(protocol, u)? else {
                    return Ok(());
                };
                let pin = match (&self.pin, right_pin) {
                    (Some(pin), true) => pin.clone(),
                    _ => b"not the PIN".to_vec(),
                };
                let mut entries = vec![
                    (int(1), protocol_value(protocol)),
                    (int(2), int(if legacy { 5 } else { 9 })),
                    (int(3), session.key_agreement.clone()),
                    (
                        int(6),
                        bytes(&session.encrypt(&pin_hash(&pin), Self::iv(u)?)),
                    ),
                ];
                if !legacy {
                    entries.push((int(9), int(i64::from(permission_set(permissions)))));
                    if let Some(rp) = rp {
                        entries.push((int(10), text(rp_id(rp))));
                    }
                }
                let response = self.call(&command(CTAP_CMD_CLIENT_PIN, &Value::Map(entries)));
                let knows_pin = right_pin && self.pin.is_some();
                if knows_pin && legacy && self.force_change {
                    assert_ne!(
                        status(&response),
                        CTAP2_OK,
                        "legacy token issued while a PIN change is required"
                    );
                } else if knows_pin {
                    assert_ne!(
                        status(&response),
                        CTAP2_ERR_PIN_INVALID,
                        "the right PIN refused"
                    );
                }
                if status(&response) == CTAP2_OK {
                    assert!(knows_pin, "a pinUvAuthToken for the wrong PIN");
                    assert!(
                        !self.force_change,
                        "token issued while a PIN change is required"
                    );
                    let body = decode_map(&response[1..]).expect("a map");
                    let Some(Value::Bytes(encrypted)) = get_int(&body, 2) else {
                        panic!("getPinToken without pinUvAuthToken");
                    };
                    let token = session.decrypt(encrypted).expect("the token decrypts");
                    let token: [u8; 32] = token.try_into().expect("a 32-byte pinUvAuthToken");
                    self.token = Some((protocol, token));
                }
            }
            Op::MakeCredential {
                cred_blob,
                min_pin_length,
                auth,
                rp,
                rk,
                alg,
                hmac_secret_mc,
            } => {
                let cred_blob = if let Some(length) = cred_blob {
                    let mut blob = vec![0; usize::from(length % 35)];
                    u.fill_buffer(&mut blob)?;
                    Some(bytes(&blob))
                } else {
                    None
                };
                let (hmac_secret_mc, salts) = self.hmac_input(hmac_secret_mc, u)?;
                let rp_id = rp_id(rp);
                let hash: [u8; 32] = u.arbitrary()?;
                let (param, protocol) = self.pin_uv_auth(auth, &hash);
                let request = requests::make_credential(
                    u,
                    Overrides {
                        client_data_hash: Some(bytes(&hash)),
                        rp_id: Some(rp_id.to_owned()),
                        pin_uv_auth_param: param,
                        pin_uv_auth_protocol: protocol,
                        known_credentials: self.known_ids(),
                        hmac_secret: None,
                        hmac_secret_mc,
                        cred_blob,
                        min_pin_length: min_pin_length.then_some(Value::Bool(true)),
                        options: rk.then(|| Value::Map(vec![(text("rk"), Value::Bool(true))])),
                        no_allow_list: false,
                        credential_parameters: alg.map(|alg| {
                            let alg = CoseAlg::ALL[usize::from(alg) % CoseAlg::ALL.len()];
                            Value::Array(vec![Value::Map(vec![
                                (text("alg"), int(i64::from(alg.identifier()))),
                                (text("type"), text("public-key")),
                            ])])
                        }),
                    },
                )?;
                let response = self.call(&request);
                if let (CTAP2_OK, Some((session, salt_len))) = (status(&response), salts) {
                    let body = decode_map(&response[1..]).expect("a map");
                    let Some(Value::Bytes(auth_data)) = get_int(&body, 2) else {
                        panic!("authData")
                    };
                    let id_len = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
                    let mut remaining = &auth_data[55 + id_len..];
                    let _: Value = ciborium::de::from_reader(&mut remaining).expect("public key");
                    let extensions = decode_map(remaining).expect("extensions");
                    let Some(Value::Bytes(output)) = get_text(&extensions, "hmac-secret-mc") else {
                        panic!("creation HMAC output")
                    };
                    assert_ne!(auth_data[32] & 0x80, 0, "ED flag");
                    assert_eq!(
                        session.decrypt(output).expect("decrypt output").len(),
                        salt_len
                    );
                }
            }
            Op::GetAssertion {
                cred_blob,
                auth,
                rp,
                hmac_secret,
                discoverable,
                up,
            } => {
                let (hmac_secret, salts) = self.hmac_input(hmac_secret, u)?;
                let rp_id = rp_id(rp);
                let hash: [u8; 32] = u.arbitrary()?;
                let (param, protocol) = self.pin_uv_auth(auth, &hash);
                let request = requests::get_assertion(
                    u,
                    Overrides {
                        client_data_hash: Some(bytes(&hash)),
                        rp_id: Some(rp_id.to_owned()),
                        pin_uv_auth_param: param,
                        pin_uv_auth_protocol: protocol,
                        known_credentials: self.known_ids(),
                        hmac_secret,
                        hmac_secret_mc: None,
                        cred_blob: cred_blob.then_some(Value::Bool(true)),
                        min_pin_length: None,
                        options: Some(Value::Map(vec![(text("up"), Value::Bool(up))])),
                        no_allow_list: discoverable,
                        credential_parameters: None,
                    },
                )?;
                let response = self.call(&request);
                if let (CTAP2_OK, Some((session, salt_len))) = (status(&response), salts) {
                    let body = decode_map(&response[1..]).expect("a map");
                    let Some(Value::Bytes(auth_data)) = get_int(&body, 2) else {
                        panic!("assertion without authData");
                    };
                    assert_ne!(auth_data[32] & 0x80, 0, "hmac-secret without the ED flag");
                    let extensions = decode_map(&auth_data[37..]).expect("an extensions map");
                    let Some(Value::Bytes(output)) = get_text(&extensions, "hmac-secret") else {
                        panic!("no hmac-secret output");
                    };
                    let output = session.decrypt(output).expect("the output decrypts");
                    assert_eq!(output.len(), salt_len, "one output per salt");
                }
            }
            Op::Enroll {
                v2,
                permissions,
                rp,
            } => {
                if self.pin.is_none() {
                    let set_pin = Op::SetPin {
                        v2,
                        pin: 0,
                        bad_auth: false,
                        pad_to: 2,
                    };
                    self.step(set_pin, u)?;
                }
                let get_token = Op::GetToken {
                    v2,
                    right_pin: true,
                    legacy: false,
                    permissions,
                    rp,
                };
                self.step(get_token, u)?;
            }
            Op::GetNextAssertion => {
                self.call(&[CTAP_CMD_GET_NEXT_ASSERTION]);
            }
            Op::CredentialManagement { auth, subcommand } => {
                let subcommand = match subcommand % 16 {
                    sub @ 1..=7 => sub,
                    0 => 2,
                    8..=11 => 4,
                    _ => 6,
                };
                let params = if u.ratio(3, 4)? {
                    Some(requests::credential_management_params(
                        u,
                        &self.known_ids(),
                    )?)
                } else {
                    None
                };
                // getCredsMetadata and enumerateRPsBegin authenticate the
                // subcommand alone (CTAP 2.3 §6.8.2, §6.8.3), the others
                // `subCommand || subCommandParams`.
                let mut message = vec![subcommand];
                if let Some(params) = params.as_ref().filter(|_| !matches!(subcommand, 1 | 2)) {
                    message.extend(cbor::encode(params));
                }
                let (param, protocol) = self.pin_uv_auth(auth, &message);
                let mut entries = vec![(int(1), int(subcommand.into()))];
                if let Some(params) = params {
                    entries.push((int(2), params));
                }
                if let Some(Some(protocol)) = protocol {
                    entries.push((int(3), protocol));
                }
                if let Some(Some(param)) = param {
                    entries.push((int(4), param));
                }
                self.call(&command(
                    CTAP_CMD_CREDENTIAL_MANAGEMENT,
                    &Value::Map(entries),
                ));
            }
            Op::AuthenticatorConfig {
                auth,
                subcommand,
                minimum,
                rp_ids,
                force_change,
                complexity,
            } => {
                let subcommand = match subcommand % 8 {
                    0..=2 => 2,
                    3..=5 => 3,
                    6 => 4,
                    _ => 255,
                };
                let mut params = Vec::new();
                if let Some(minimum) = minimum {
                    params.push((int(1), int(i64::from(minimum))));
                }
                if let Some(ids) = rp_ids {
                    params.push((
                        int(2),
                        Value::Array(ids.into_iter().map(|id| text(rp_id(id))).collect()),
                    ));
                }
                if let Some(force_change) = force_change {
                    params.push((int(3), Value::Bool(force_change)));
                }
                if let Some(complexity) = complexity {
                    params.push((int(4), Value::Bool(complexity)));
                }
                let params = Value::Map(params);
                let mut message = vec![0xFF; 32];
                message.extend_from_slice(&[CTAP_CMD_AUTHENTICATOR_CONFIG, subcommand]);
                message.extend(cbor::encode(&params));
                let (param, protocol) = self.pin_uv_auth(auth, &message);
                let mut entries = vec![(int(1), int(i64::from(subcommand))), (int(2), params)];
                if let Some(Some(protocol)) = protocol {
                    entries.push((int(3), protocol));
                }
                if let Some(Some(param)) = param {
                    entries.push((int(4), param));
                }
                self.call(&command(
                    CTAP_CMD_AUTHENTICATOR_CONFIG,
                    &Value::Map(entries),
                ));
            }
            Op::GetInfo => {
                self.call(&[CTAP_CMD_GET_INFO]);
            }
            Op::GetPinRetries => {
                let request = command(CTAP_CMD_CLIENT_PIN, &Value::Map(vec![(int(2), int(1))]));
                self.call(&request);
            }
            Op::Reset => {
                self.call(&[CTAP_CMD_RESET]);
            }
            Op::Presence(selector) => self.engine.presence().select(selector),
            Op::Structured => {
                let request = requests::any_request(u)?;
                self.call(&request);
            }
            Op::Raw => {
                let request: Vec<u8> = u.arbitrary()?;
                self.call(&request);
            }
        }
        Ok(())
    }
}

/// Run one fuzz input.
pub fn run(data: &[u8]) {
    run_traced(data);
}

/// Run one fuzz input and return the command and status of every request.
pub fn run_traced(data: &[u8]) -> Vec<(u8, u8)> {
    let mut u = Unstructured::new(data);
    let Ok((seed, max_credentials)) = u.arbitrary::<(u64, u8)>() else {
        return Vec::new();
    };
    let store = MemoryStore::new().with_max_credentials(usize::from(max_credentials % 8) + 1);
    let mut platform = Platform::new(Engine::with_store(seed, store));
    for _ in 0..MAX_STEPS {
        let Ok(op) = u.arbitrary::<Op>() else {
            break;
        };
        if platform.step(op, &mut u).is_err() || u.is_empty() {
            break;
        }
    }
    platform.engine.into_trace()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The platform side of the harness is right: it sets a PIN, gets a
    /// token with the credential management permission and authenticates
    /// a credential management request with it.
    #[test]
    fn authenticates_credential_management() {
        let mut p = Platform::new(Engine::new(7));
        let filler = [0x0Fu8; 1 << 12];
        let mut u = Unstructured::new(&filler);
        let ops = [
            Op::SetPin {
                v2: true,
                pin: 0,
                bad_auth: false,
                pad_to: 2,
            },
            Op::GetToken {
                v2: false,
                right_pin: true,
                legacy: false,
                permissions: 0,
                rp: None,
            },
            Op::CredentialManagement {
                auth: Auth::Token,
                subcommand: 1,
            },
        ];
        for op in ops {
            p.step(op, &mut u).unwrap();
        }
        let trace = p.engine.into_trace();
        assert_eq!(
            trace.last(),
            Some(&(CTAP_CMD_CREDENTIAL_MANAGEMENT, CTAP2_OK)),
            "{trace:02x?}"
        );
    }

    #[test]
    fn models_forced_pin_changes_and_reset_for_both_protocols() {
        for v2 in [false, true] {
            let mut p = Platform::new(Engine::new(7));
            let filler = [0x0Fu8; 1 << 14];
            let mut u = Unstructured::new(&filler);
            for op in [
                Op::SetPin {
                    v2,
                    pin: 0,
                    bad_auth: false,
                    pad_to: 2,
                },
                Op::GetToken {
                    v2,
                    right_pin: true,
                    legacy: false,
                    permissions: 6,
                    rp: Some(0),
                },
                Op::AuthenticatorConfig {
                    auth: Auth::Token,
                    subcommand: 3,
                    minimum: Some(8),
                    rp_ids: Some(vec![0]),
                    force_change: None,
                    complexity: Some(false),
                },
            ] {
                p.step(op, &mut u).unwrap();
            }
            assert_eq!(p.minimum, 8);
            assert!(p.force_change);
            assert!(p.token.is_none());
            p.call(&[CTAP_CMD_GET_INFO]);
            for legacy in [false, true] {
                p.step(
                    Op::GetToken {
                        v2,
                        right_pin: true,
                        legacy,
                        permissions: 6,
                        rp: None,
                    },
                    &mut u,
                )
                .unwrap();
                assert_eq!(
                    p.engine.trace.last().unwrap().1,
                    if legacy {
                        CTAP2_ERR_PIN_INVALID
                    } else {
                        CTAP2_ERR_PIN_POLICY_VIOLATION
                    }
                );
            }
            p.step(
                Op::ChangePin {
                    v2,
                    right_pin: true,
                    new_pin: 2,
                },
                &mut u,
            )
            .unwrap();
            assert!(!p.force_change);
            assert_eq!(p.minimum, 8);
            p.call(&[CTAP_CMD_GET_INFO]);
            p.call(&[CTAP_CMD_RESET]);
            p.call(&[CTAP_CMD_GET_INFO]);
            assert_eq!(p.minimum, 4);
            assert!(!p.always_uv);
            assert!(p.min_pin_length_rp_ids.is_empty());
        }
    }

    #[test]
    fn models_raw_configuration_and_the_up_false_exemption() {
        let mut p = Platform::new(Engine::new(9));
        let hash = bytes(&[0x55; 32]);
        let request = command(
            CTAP_CMD_MAKE_CREDENTIAL,
            &Value::Map(vec![
                (int(1), hash.clone()),
                (int(2), Value::Map(vec![(text("id"), text("example.com"))])),
                (int(3), Value::Map(vec![(text("id"), bytes(b"user"))])),
                (
                    int(4),
                    Value::Array(vec![Value::Map(vec![
                        (text("alg"), int(-7)),
                        (text("type"), text("public-key")),
                    ])]),
                ),
            ]),
        );
        assert_eq!(status(&p.call(&request)), CTAP2_OK);
        let credential = p.credentials[0].id.clone();
        let configure = command(
            CTAP_CMD_AUTHENTICATOR_CONFIG,
            &Value::Map(vec![(int(1), int(2))]),
        );
        assert_eq!(status(&p.call(&configure)), CTAP2_OK);
        assert!(p.always_uv);
        assert_eq!(status(&p.call(&request)), CTAP2_ERR_PUAT_REQUIRED);
        for up in [true, false] {
            let assertion = command(
                CTAP_CMD_GET_ASSERTION,
                &Value::Map(vec![
                    (int(1), text("example.com")),
                    (int(2), hash.clone()),
                    (
                        int(3),
                        Value::Array(vec![Value::Map(vec![
                            (text("id"), bytes(&credential)),
                            (text("type"), text("public-key")),
                        ])]),
                    ),
                    (int(5), Value::Map(vec![(text("up"), Value::Bool(up))])),
                ]),
            );
            assert_eq!(
                status(&p.call(&assertion)),
                if up {
                    CTAP2_ERR_PUAT_REQUIRED
                } else {
                    CTAP2_OK
                }
            );
        }
        assert_eq!(status(&p.call(&configure)), CTAP2_OK);
        assert!(!p.always_uv);
    }

    #[test]
    fn observes_config_with_ignored_unassigned_simple_values() {
        let mut p = Platform::new(Engine::new(9));
        let request = [0x0D, 0xA2, 0x01, 0x02, 0x02, 0xA1, 0x05, 0xF0];
        assert_eq!(status(&p.call(&request)), CTAP2_OK);
        assert!(p.always_uv);
        p.call(&[CTAP_CMD_GET_INFO]);
    }
}
