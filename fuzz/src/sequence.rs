//! Stateful CTAP: a sequence of requests against one engine, the harness
//! acting as a platform that can set and change a PIN, obtain
//! pinUvAuthTokens and authenticate makeCredential, getAssertion and
//! credentialManagement with them, and use hmac-secret, while the fuzzer
//! chooses the parameters (right, wrong or missing) and mixes in
//! structure-aware and raw requests and presence denials.
//!
//! Invariants, besides those of `ctap_request` for every response:
//! * setPIN only succeeds while no PIN is set, and changePIN and the token
//!   subcommands only with the right PIN; the right PIN is never answered
//!   with CTAP2_ERR_PIN_INVALID; a pinUvAuthToken decrypts to 32 bytes;
//! * a new credential's authenticator data carries the RP ID hash of the
//!   request, the AT flag and a 33-byte credential ID;
//! * getAssertion, getNextAssertion and credential enumeration only return
//!   credentials this engine created and has not deleted, and getAssertion
//!   and getNextAssertion only for the RP ID requested; getNextAssertion only
//!   succeeds right after a getAssertion that reported more credentials;
//! * hmac-secret returns one output per salt.

use crate::cbor::{self, bytes, decode_map, get_int, get_text, int, text};
use crate::engine::Engine;
use crate::platform::{authenticate, pin_hash, protocol_value, Session};
use crate::requests::{self, command, Overrides};
use arbitrary::{Arbitrary, Result, Unstructured};
use authenticator::ctap::constants::*;
use authenticator::store::MemoryStore;
use authenticator::ClassicPinProtocol;
use ciborium::value::Value;
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
        auth: Auth,
        rp: u8,
        /// Ask for a discoverable credential rather than generating options.
        rk: bool,
        /// One supported algorithm, by index, rather than generated
        /// pubKeyCredParams.
        alg: Option<u8>,
    },
    GetAssertion {
        auth: Auth,
        rp: u8,
        hmac_secret: Option<(bool, bool)>,
        /// Leave the allowList out, so every discoverable credential counts.
        discoverable: bool,
    },
    GetNextAssertion,
    CredentialManagement {
        auth: Auth,
        subcommand: u8,
    },
    GetInfo,
    GetPinRetries,
    Reset,
    Presence(u8),
    Structured,
    Raw,
}

struct Credential {
    id: Vec<u8>,
    rp_id: String,
}

struct Platform {
    engine: Engine,
    /// The PIN the authenticator has, as far as the platform knows.
    pin: Option<Vec<u8>>,
    token: Option<(ClassicPinProtocol, [u8; 32])>,
    credentials: Vec<Credential>,
    /// The RP ID of the getAssertion whose further credentials
    /// getNextAssertion may return.
    assertion_rp: Option<String>,
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
    const SETS: [u8; 6] = [0x04, 0x01, 0x02, 0x03, 0x05, 0x07];
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

fn acceptable_pin(pin: &[u8]) -> bool {
    pin.len() <= 63 && std::str::from_utf8(pin).is_ok_and(|pin| pin.chars().count() >= 4)
}

impl Platform {
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
        let parameters = decode_map(&request[1..]).unwrap_or_default();
        let body = decode_map(&response[1..]).unwrap_or_default();
        match code {
            CTAP_CMD_MAKE_CREDENTIAL => {
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
                assert_eq!(length, 33, "credential ID length");
                self.credentials.push(Credential {
                    id: auth_data[55..55 + length].to_vec(),
                    rp_id: rp_id.clone(),
                });
            }
            CTAP_CMD_GET_ASSERTION | CTAP_CMD_GET_NEXT_ASSERTION => {
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
                        acceptable_pin(pin),
                        "setPIN accepted a PIN the policy forbids"
                    );
                    self.pin = Some(pin.to_vec());
                    self.token = None;
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
                    assert!(acceptable_pin(new));
                    self.pin = Some(new.to_vec());
                    self.token = None;
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
                if knows_pin {
                    assert_ne!(
                        status(&response),
                        CTAP2_ERR_PIN_INVALID,
                        "the right PIN refused"
                    );
                }
                if status(&response) == CTAP2_OK {
                    assert!(knows_pin, "a pinUvAuthToken for the wrong PIN");
                    let body = decode_map(&response[1..]).expect("a map");
                    let Some(Value::Bytes(encrypted)) = get_int(&body, 2) else {
                        panic!("getPinToken without pinUvAuthToken");
                    };
                    let token = session.decrypt(encrypted).expect("the token decrypts");
                    let token: [u8; 32] = token.try_into().expect("a 32-byte pinUvAuthToken");
                    self.token = Some((protocol, token));
                }
            }
            Op::MakeCredential { auth, rp, rk, alg } => {
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
                        options: rk.then(|| Value::Map(vec![(text("rk"), Value::Bool(true))])),
                        no_allow_list: false,
                        credential_parameters: alg.map(|alg| {
                            let alg = [-7, -48, -49, -50][usize::from(alg) % 4];
                            Value::Array(vec![Value::Map(vec![
                                (text("alg"), int(alg)),
                                (text("type"), text("public-key")),
                            ])])
                        }),
                    },
                )?;
                self.call(&request);
            }
            Op::GetAssertion {
                auth,
                rp,
                hmac_secret,
                discoverable,
            } => {
                let mut salts = None;
                let hmac_secret = match hmac_secret {
                    Some((v2, two_salts)) => {
                        let protocol = protocol(v2);
                        let Some(session) = self.session(protocol, u)? else {
                            return Ok(());
                        };
                        let mut salt = vec![0u8; if two_salts { 64 } else { 32 }];
                        u.fill_buffer(&mut salt)?;
                        let salt_enc = session.encrypt(&salt, Self::iv(u)?);
                        let value = Value::Map(vec![
                            (int(1), session.key_agreement.clone()),
                            (int(2), bytes(&salt_enc)),
                            (int(3), bytes(&session.authenticate(&salt_enc))),
                            (int(4), protocol_value(protocol)),
                        ]);
                        salts = Some((session, salt.len()));
                        Some(value)
                    }
                    None => None,
                };
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
                        options: None,
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
                let mut message = vec![subcommand];
                if let Some(params) = &params {
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
    let mut platform = Platform {
        engine: Engine::with_store(seed, store),
        pin: None,
        token: None,
        credentials: Vec::new(),
        assertion_rp: None,
    };
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
        let mut p = Platform {
            engine: Engine::new(7),
            pin: None,
            token: None,
            credentials: Vec::new(),
            assertion_rp: None,
        };
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
}
