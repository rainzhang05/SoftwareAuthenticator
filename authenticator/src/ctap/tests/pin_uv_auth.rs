//! pinUvAuthParam and saltAuth verification: the protocol-aware
//! `authenticate` / `verify` pair (CTAP 2.3 §6.5.6, §6.5.7) and every command
//! path that routes through it.
//!
//! Tests that go on to collect user presence are `#[serial]` so they do not
//! append to the presence tests' shared waiting log while those run.

use super::support::{
    client_pin, encode, es256_credential, get_assertion_request, install_pin_uv_auth_token, int,
    make_credential_request, padded_pin, pin_hash, platform_authenticate, response_auth_data,
    PlatformPinSession, TestClient, FLAG_UV,
};
use crate::ctap::cbor::canonical_map;
use crate::ctap::pin::permissions::{PIN_PERMISSION_CM, PIN_PERMISSION_GA, PIN_PERMISSION_MC};
use crate::ctap::pin::protocol::{authenticate, verify, HmacSha256};
use crate::ctap::pin::state::MAX_PIN_RETRIES;
use crate::ctap::CtapApp;
use crate::ClassicPinProtocol;

use ciborium::{de::from_reader, value::Value};
use hmac::Mac as _;
use serial_test::serial;

use transport_core::ctap::constants::*;

const PROTOCOLS: [ClassicPinProtocol; 2] = [ClassicPinProtocol::V1, ClassicPinProtocol::V2];

// -- authenticate / verify ---------------------------------------------------

const MESSAGE: &[u8] = b"CTAP2 pinUvAuthParam known answer";

/// HMAC-SHA-256 with key `00 01 .. 1f` over `MESSAGE`, computed independently
/// of this crate (Python's `hmac` module).
const MESSAGE_HMAC: [u8; 32] = [
    0x5f, 0x1a, 0x19, 0x2a, 0x92, 0x70, 0xeb, 0xdb, 0xe0, 0x92, 0xfc, 0x0f, 0x3f, 0x33, 0x63, 0x7f,
    0xcd, 0xbc, 0xcb, 0x5b, 0xee, 0xdc, 0x71, 0x76, 0x8d, 0xfe, 0x9b, 0x47, 0xf9, 0xfc, 0x29, 0xa2,
];

fn known_answer_key() -> [u8; 32] {
    core::array::from_fn(|index| index as u8)
}

#[test]
fn authenticate_protocol_one_is_the_first_16_bytes_of_hmac_sha256() {
    let signature = authenticate(ClassicPinProtocol::V1, &known_answer_key(), MESSAGE)
        .expect("authenticate succeeds");
    assert_eq!(signature.as_slice(), &MESSAGE_HMAC[..16]);
}

#[test]
fn authenticate_protocol_two_is_the_full_hmac_sha256() {
    let signature = authenticate(ClassicPinProtocol::V2, &known_answer_key(), MESSAGE)
        .expect("authenticate succeeds");
    assert_eq!(signature.as_slice(), &MESSAGE_HMAC[..]);
}

#[test]
fn verify_protocol_one_accepts_16_bytes_and_rejects_32() {
    let key = known_answer_key();
    assert_eq!(
        verify(ClassicPinProtocol::V1, &key, MESSAGE, &MESSAGE_HMAC[..16]),
        Ok(())
    );
    // The full, otherwise correct, HMAC is not a protocol one signature.
    assert_eq!(
        verify(ClassicPinProtocol::V1, &key, MESSAGE, &MESSAGE_HMAC),
        Err(CTAP2_ERR_PIN_AUTH_INVALID)
    );
}

#[test]
fn verify_protocol_two_accepts_32_bytes_and_rejects_16() {
    let key = known_answer_key();
    assert_eq!(
        verify(ClassicPinProtocol::V2, &key, MESSAGE, &MESSAGE_HMAC),
        Ok(())
    );
    // A correct but truncated (protocol one style) MAC is rejected.
    assert_eq!(
        verify(ClassicPinProtocol::V2, &key, MESSAGE, &MESSAGE_HMAC[..16]),
        Err(CTAP2_ERR_PIN_AUTH_INVALID)
    );
}

#[test]
fn verify_rejects_a_wrong_mac_for_each_protocol() {
    let key = known_answer_key();
    for protocol in PROTOCOLS {
        let correct = platform_authenticate(protocol, &key, MESSAGE);
        for index in 0..correct.len() {
            let mut wrong = correct.clone();
            wrong[index] ^= 0x80;
            assert_eq!(
                verify(protocol, &key, MESSAGE, &wrong),
                Err(CTAP2_ERR_PIN_AUTH_INVALID),
                "{protocol:?} accepted a MAC with byte {index} flipped"
            );
        }
        let mut other_key = key;
        other_key[0] ^= 0x01;
        assert_eq!(
            verify(protocol, &other_key, MESSAGE, &correct),
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            verify(protocol, &key, b"another message", &correct),
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }
}

#[test]
fn verify_rejects_empty_and_overlong_signatures() {
    let key = known_answer_key();
    for protocol in PROTOCOLS {
        let mut overlong = platform_authenticate(protocol, &key, MESSAGE);
        overlong.push(0x00);
        for signature in [Vec::new(), overlong] {
            assert_eq!(
                verify(protocol, &key, MESSAGE, &signature),
                Err(CTAP2_ERR_PIN_AUTH_INVALID),
                "{protocol:?} accepted a {}-byte signature",
                signature.len()
            );
        }
    }
}

// -- Command paths ------------------------------------------------------------

/// How the platform's MAC is produced for a command-path case.
#[derive(Clone, Copy, Debug, PartialEq)]
enum MacCase {
    /// `authenticate` for the protocol the request declares.
    Correct,
    /// The same HMAC at the other protocol's length: truncated to 16 bytes
    /// under protocol two, the full 32 bytes under protocol one.
    OtherProtocolLength,
    /// The right length with one bit flipped.
    WrongValue,
}

const CASES: [(ClassicPinProtocol, MacCase); 6] = [
    (ClassicPinProtocol::V1, MacCase::Correct),
    (ClassicPinProtocol::V1, MacCase::OtherProtocolLength),
    (ClassicPinProtocol::V1, MacCase::WrongValue),
    (ClassicPinProtocol::V2, MacCase::Correct),
    (ClassicPinProtocol::V2, MacCase::OtherProtocolLength),
    (ClassicPinProtocol::V2, MacCase::WrongValue),
];

fn other_protocol(protocol: ClassicPinProtocol) -> ClassicPinProtocol {
    match protocol {
        ClassicPinProtocol::V1 => ClassicPinProtocol::V2,
        ClassicPinProtocol::V2 => ClassicPinProtocol::V1,
    }
}

fn mac(protocol: ClassicPinProtocol, key: &[u8; 32], message: &[u8], variant: MacCase) -> Vec<u8> {
    match variant {
        MacCase::Correct => platform_authenticate(protocol, key, message),
        MacCase::OtherProtocolLength => {
            platform_authenticate(other_protocol(protocol), key, message)
        }
        MacCase::WrongValue => {
            let mut signature = platform_authenticate(protocol, key, message);
            signature[0] ^= 0x01;
            signature
        }
    }
}

fn protocol_id(protocol: ClassicPinProtocol) -> Value {
    int(protocol.identifier().into())
}

#[test]
fn set_pin_verifies_pin_uv_auth_param_per_protocol() {
    for (protocol, variant) in CASES {
        let mut app = CtapApp::new(TestClient::new(), [0x60; 16]);
        let session = PlatformPinSession::establish(&mut app, protocol, 0x11);
        let new_pin_enc = session.encrypt(&padded_pin(b"1234"));
        let param = mac(protocol, &session.keys.auth_key, &new_pin_enc, variant);

        let result = client_pin(
            &mut app,
            vec![
                (int(1), protocol_id(protocol)),
                (int(2), int(0x03)),
                (int(3), session.key_agreement.clone()),
                (int(4), Value::Bytes(param)),
                (int(5), Value::Bytes(new_pin_enc)),
            ],
        );

        if variant == MacCase::Correct {
            assert_eq!(result, Ok(vec![CTAP2_OK]), "{protocol:?}");
            assert!(app.pin_state.is_set());
        } else {
            assert_eq!(
                result,
                Err(CTAP2_ERR_PIN_AUTH_INVALID),
                "{protocol:?} {variant:?}"
            );
            assert!(!app.pin_state.is_set(), "{protocol:?} {variant:?}");
        }
    }
}

#[test]
fn change_pin_verifies_pin_uv_auth_param_per_protocol() {
    for (protocol, variant) in CASES {
        let mut app = CtapApp::new(TestClient::new(), [0x61; 16]);
        app.pin_state.set_pin(pin_hash(b"1234"));
        let session = PlatformPinSession::establish(&mut app, protocol, 0x12);
        let new_pin_enc = session.encrypt(&padded_pin(b"5678"));
        let pin_hash_enc = session.encrypt(&pin_hash(b"1234"));
        let mut message = new_pin_enc.clone();
        message.extend_from_slice(&pin_hash_enc);
        let param = mac(protocol, &session.keys.auth_key, &message, variant);

        let result = client_pin(
            &mut app,
            vec![
                (int(1), protocol_id(protocol)),
                (int(2), int(0x04)),
                (int(3), session.key_agreement.clone()),
                (int(4), Value::Bytes(param)),
                (int(5), Value::Bytes(new_pin_enc)),
                (int(6), Value::Bytes(pin_hash_enc)),
            ],
        );

        if variant == MacCase::Correct {
            assert_eq!(result, Ok(vec![CTAP2_OK]), "{protocol:?}");
            assert_eq!(app.pin_state.pin_hash, Some(pin_hash(b"5678")));
        } else {
            assert_eq!(
                result,
                Err(CTAP2_ERR_PIN_AUTH_INVALID),
                "{protocol:?} {variant:?}"
            );
            // pinUvAuthParam is verified before pinRetries is touched.
            assert_eq!(app.pin_state.pin_hash, Some(pin_hash(b"1234")));
            assert_eq!(app.pin_state.retries(), MAX_PIN_RETRIES);
        }
    }
}

#[test]
#[serial]
fn make_credential_verifies_pin_uv_auth_param_per_protocol() {
    let token = [0x7A; 32];
    let client_hash = [0x42; 32];
    for (protocol, variant) in CASES {
        let mut app = CtapApp::new(TestClient::new(), [0x62; 16]);
        install_pin_uv_auth_token(
            &mut app,
            protocol,
            token,
            PIN_PERMISSION_MC | PIN_PERMISSION_GA,
            None,
        );
        let param = mac(protocol, &token, &client_hash, variant);
        let request = make_credential_request(&client_hash, "example.com", Some((protocol, param)));

        let result = app.handle_make_credential(&request);

        if variant == MacCase::Correct {
            let response = result.unwrap_or_else(|err| panic!("{protocol:?}: {err:#04x}"));
            assert_eq!(response_auth_data(&response)[32] & FLAG_UV, FLAG_UV);
            assert_eq!(app.stored_credentials.len(), 1);
        } else {
            assert_eq!(
                result,
                Err(CTAP2_ERR_PIN_AUTH_INVALID),
                "{protocol:?} {variant:?}"
            );
            assert!(app.stored_credentials.is_empty());
        }
    }
}

#[test]
#[serial]
fn get_assertion_verifies_pin_uv_auth_param_per_protocol() {
    let token = [0x7B; 32];
    let client_hash = [0x43; 32];
    for (protocol, variant) in CASES {
        let mut app = CtapApp::new(TestClient::new(), [0x63; 16]);
        app.stored_credentials
            .push(es256_credential("example.com", &[0xC1]));
        install_pin_uv_auth_token(
            &mut app,
            protocol,
            token,
            PIN_PERMISSION_MC | PIN_PERMISSION_GA,
            None,
        );
        let param = mac(protocol, &token, &client_hash, variant);
        let request =
            get_assertion_request(&client_hash, "example.com", Some((protocol, param)), None);

        let result = app.handle_get_assertion(&request);

        if variant == MacCase::Correct {
            let response = result.unwrap_or_else(|err| panic!("{protocol:?}: {err:#04x}"));
            assert_eq!(response_auth_data(&response)[32] & FLAG_UV, FLAG_UV);
            assert_eq!(app.stored_credentials[0].sign_count, 1);
        } else {
            assert_eq!(
                result,
                Err(CTAP2_ERR_PIN_AUTH_INVALID),
                "{protocol:?} {variant:?}"
            );
            assert_eq!(app.stored_credentials[0].sign_count, 0);
        }
    }
}

#[test]
fn credential_management_verifies_pin_uv_auth_param_per_protocol() {
    const GET_CREDS_METADATA: u8 = 0x01;
    let token = [0x7C; 32];
    for (protocol, variant) in CASES {
        let mut app = CtapApp::new(TestClient::new(), [0x64; 16]);
        app.stored_credentials
            .push(es256_credential("example.com", &[0xC2]));
        install_pin_uv_auth_token(&mut app, protocol, token, PIN_PERMISSION_CM, None);
        let param = mac(protocol, &token, &[GET_CREDS_METADATA], variant);
        let request = canonical_map(vec![
            (int(1), int(GET_CREDS_METADATA.into())),
            (int(3), protocol_id(protocol)),
            (int(4), Value::Bytes(param)),
        ]);

        let result = app.handle_credential_management(&encode(&request));

        if variant == MacCase::Correct {
            let response = result.unwrap_or_else(|err| panic!("{protocol:?}: {err:#04x}"));
            assert_eq!(response[0], CTAP2_OK);
        } else {
            assert_eq!(
                result,
                Err(CTAP2_ERR_PIN_AUTH_INVALID),
                "{protocol:?} {variant:?}"
            );
        }
    }
}

/// `HMAC-SHA-256(CredRandom, salt)` (CTAP 2.3 §12.7).
fn hmac_secret_output(cred_random: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(cred_random).expect("valid MAC key");
    mac.update(salt);
    mac.finalize().into_bytes().to_vec()
}

/// The encrypted "hmac-secret" extension output of a getAssertion or
/// getNextAssertion response.
fn encrypted_hmac_secret_output(response: &[u8]) -> Vec<u8> {
    let auth_data = response_auth_data(response);
    // rpIdHash (32) || flags (1) || signCount (4) || extensions
    let Value::Map(outputs) = from_reader(&auth_data[37..]).expect("extension outputs") else {
        panic!("extension outputs must be a map");
    };
    match outputs
        .into_iter()
        .find(|(key, _)| *key == Value::Text("hmac-secret".into()))
    {
        Some((_, Value::Bytes(encrypted))) => encrypted,
        _ => panic!("hmac-secret output present"),
    }
}

#[test]
#[serial]
fn hmac_secret_verifies_salt_auth_per_protocol() {
    let client_hash = [0x44; 32];
    let salt = [0x99; 32];
    for (protocol, variant) in CASES {
        let mut app = CtapApp::new(TestClient::new(), [0x65; 16]);
        let credential = es256_credential("example.com", &[0xC3]);
        let cred_random_without_uv = credential
            .cred_random_without_uv
            .clone()
            .expect("credRandomWithoutUV");
        app.stored_credentials.push(credential);
        let session = PlatformPinSession::establish(&mut app, protocol, 0x13);
        let salt_enc = session.encrypt(&salt);
        let salt_auth = mac(protocol, &session.keys.auth_key, &salt_enc, variant);
        let extensions = canonical_map(vec![(
            Value::Text("hmac-secret".into()),
            canonical_map(vec![
                (int(1), session.key_agreement.clone()),
                (int(2), Value::Bytes(salt_enc)),
                (int(3), Value::Bytes(salt_auth)),
                (int(4), protocol_id(protocol)),
            ]),
        )]);
        let request = get_assertion_request(&client_hash, "example.com", None, Some(extensions));

        let result = app.handle_get_assertion(&request);

        if variant == MacCase::Correct {
            let response = result.unwrap_or_else(|err| panic!("{protocol:?}: {err:#04x}"));
            let encrypted = encrypted_hmac_secret_output(&response);
            assert_eq!(
                session.decrypt(&encrypted),
                hmac_secret_output(&cred_random_without_uv, &salt)
            );
        } else {
            assert_eq!(
                result,
                Err(CTAP2_ERR_PIN_AUTH_INVALID),
                "{protocol:?} {variant:?}"
            );
        }
    }
}

#[test]
#[serial]
fn hmac_secret_protocol_two_encrypts_each_output_under_its_own_iv() {
    let mut app = CtapApp::new(TestClient::new(), [0x66; 16]);
    let first = es256_credential("example.com", &[0xD1]);
    let mut second = es256_credential("example.com", &[0xD2]);
    second.cred_random_without_uv = Some(vec![0x30; 32]);
    let cred_randoms = [
        first.cred_random_without_uv.clone().expect("credRandom"),
        second.cred_random_without_uv.clone().expect("credRandom"),
    ];
    app.stored_credentials.push(first);
    app.stored_credentials.push(second);

    let session = PlatformPinSession::establish(&mut app, ClassicPinProtocol::V2, 0x14);
    let (salt1, salt2) = ([0x51; 32], [0x52; 32]);
    let salt_enc = session.encrypt(&[salt1, salt2].concat());
    let salt_auth =
        platform_authenticate(ClassicPinProtocol::V2, &session.keys.auth_key, &salt_enc);
    let extensions = canonical_map(vec![(
        Value::Text("hmac-secret".into()),
        canonical_map(vec![
            (int(1), session.key_agreement.clone()),
            (int(2), Value::Bytes(salt_enc)),
            (int(3), Value::Bytes(salt_auth)),
            (int(4), protocol_id(ClassicPinProtocol::V2)),
        ]),
    )]);
    let request = get_assertion_request(&[0x45; 32], "example.com", None, Some(extensions));

    let first_response = app
        .handle_get_assertion(&request)
        .expect("getAssertion succeeds");
    let next_response = app
        .handle_get_next_assertion()
        .expect("getNextAssertion succeeds");

    let outputs = [
        encrypted_hmac_secret_output(&first_response),
        encrypted_hmac_secret_output(&next_response),
    ];
    for (encrypted, cred_random) in outputs.iter().zip(&cred_randoms) {
        // iv (16) || AES-256-CBC(output1 || output2) (64)
        assert_eq!(encrypted.len(), 16 + 64);
        let expected = [
            hmac_secret_output(cred_random, &salt1),
            hmac_secret_output(cred_random, &salt2),
        ]
        .concat();
        assert_eq!(session.decrypt(encrypted), expected);
    }
    assert_ne!(
        outputs[0][..16],
        outputs[1][..16],
        "every encryption draws a fresh IV"
    );
}
