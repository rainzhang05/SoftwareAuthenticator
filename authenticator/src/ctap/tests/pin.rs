//! PIN tests: retry state, key agreement, and the authenticatorClientPIN
//! subcommands over both PIN/UV auth protocols.

use super::support::{
    classic_encrypt, classic_pin_auth, client_pin, derive_classic_session, get_pin_retries,
    get_pin_uv_auth_token, int, padded_pin, pin_hash, request_classic_key_agreement,
    PlatformPinSession, TestClient,
};
use crate::ctap::cbor::canonical_map;
use crate::ctap::pin::permissions::{PIN_PERMISSION_CM, PIN_PERMISSION_GA, PIN_PERMISSION_MC};
use crate::ctap::pin::protocol::{PinProtocolSession, PIN_UV_AUTH_PROTOCOL_CLASSIC};
use crate::ctap::pin::state::{PinState, MAX_CONSECUTIVE_PIN_MISMATCHES, MAX_PIN_RETRIES};
use crate::ctap::CtapApp;
use crate::ClassicPinProtocol;

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey as P256SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use transport_core::ctap::constants::*;

#[test]
fn classic_key_agreement_value_is_canonical() {
    let secret_key = P256SecretKey::from_slice(&[0x13; 32]).expect("valid secret key");
    let public_key = secret_key.public_key().to_encoded_point(false);
    let session = PinProtocolSession {
        protocol: ClassicPinProtocol::V2,
        public_key: public_key.clone(),
        secret_key,
    };

    let value = session.key_agreement_value();
    let x = public_key
        .x()
        .expect("x coordinate present")
        .clone()
        .to_vec();
    let y = public_key
        .y()
        .expect("y coordinate present")
        .clone()
        .to_vec();

    let expected = canonical_map(vec![
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
    ]);

    assert_eq!(value, expected);

    let mut actual_bytes = Vec::new();
    into_writer(&value, &mut actual_bytes).expect("encode classic key agreement map");
    let mut expected_bytes = Vec::new();
    into_writer(&expected, &mut expected_bytes).expect("encode expected classic key agreement map");
    assert_eq!(actual_bytes, expected_bytes);
}

#[test]
fn client_pin_get_retries_reports_available_attempts() {
    let mut app = CtapApp::new(TestClient::new(), [0x30; 16]);
    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x01)),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize getRetries request");
    let response = app
        .handle_client_pin(&payload)
        .expect("getRetries succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode getRetries response") else {
        panic!("response must be a map");
    };
    let retries: i128 = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(0x03)))
        .and_then(|(_, v)| match v {
            Value::Integer(int) => Some(int.clone().into()),
            _ => None,
        })
        .expect("retry count is present");
    assert_eq!(retries, i128::from(MAX_PIN_RETRIES));
    assert!(!map
        .iter()
        .any(|(k, _)| *k == Value::Integer(Integer::from(0x04))));
}

/// One complete PIN check of `candidate`, with nothing persisted in between.
fn check_pin(state: &mut PinState, candidate: &[u8; 16]) -> Result<(), u8> {
    let attempt = state.begin_pin_attempt()?;
    state.finish_pin_attempt(attempt, Some(candidate))
}

#[test]
fn client_pin_get_retries_includes_power_cycle_state_when_blocked() {
    let mut app = CtapApp::new(TestClient::new(), [0x31; 16]);
    let mut pin_hash = [0x11; 16];
    app.pin_state.set_pin(pin_hash);
    let wrong = [0x22; 16];
    for attempt in 0..MAX_CONSECUTIVE_PIN_MISMATCHES {
        let result = check_pin(&mut app.pin_state, &wrong);
        if attempt + 1 < MAX_CONSECUTIVE_PIN_MISMATCHES {
            assert_eq!(result, Err(CTAP2_ERR_PIN_INVALID));
        } else {
            assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_BLOCKED));
        }
    }
    pin_hash.zeroize();

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x01)),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize getRetries request");
    let response = app
        .handle_client_pin(&payload)
        .expect("getRetries succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode getRetries response") else {
        panic!("response must be a map");
    };
    let retries: i128 = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(0x03)))
        .and_then(|(_, v)| match v {
            Value::Integer(int) => Some(int.clone().into()),
            _ => None,
        })
        .expect("retry count is present");
    let expected = MAX_PIN_RETRIES - MAX_CONSECUTIVE_PIN_MISMATCHES;
    assert_eq!(retries, i128::from(expected));
    let power_cycle = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(0x04)))
        .and_then(|(_, v)| match v {
            Value::Bool(flag) => Some(*flag),
            _ => None,
        })
        .expect("power cycle flag present");
    assert!(power_cycle);
}

#[test]
fn pin_auth_blocked_persists_until_power_cycle() {
    let mut pin_state = PinState::new();
    let pin_hash = [0x33; 16];
    pin_state.set_pin(pin_hash);
    let wrong = [0x44; 16];

    for attempt in 0..MAX_CONSECUTIVE_PIN_MISMATCHES {
        let result = check_pin(&mut pin_state, &wrong);
        if attempt + 1 < MAX_CONSECUTIVE_PIN_MISMATCHES {
            assert_eq!(result, Err(CTAP2_ERR_PIN_INVALID));
        } else {
            assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_BLOCKED));
        }
    }

    let retries_after_block = pin_state.retries();
    assert!(pin_state.needs_power_cycle());

    assert_eq!(
        check_pin(&mut pin_state, &pin_hash),
        Err(CTAP2_ERR_PIN_AUTH_BLOCKED)
    );
    assert_eq!(pin_state.retries(), retries_after_block);
    assert_eq!(
        check_pin(&mut pin_state, &wrong),
        Err(CTAP2_ERR_PIN_AUTH_BLOCKED)
    );
    assert_eq!(pin_state.retries(), retries_after_block);

    // Power cycle: the persistent part is restored, the lockout is not.
    let mut restored_state = PinState::from_persistent(pin_state.persistent().clone());
    assert!(!restored_state.needs_power_cycle());
    assert_eq!(restored_state.retries(), retries_after_block);
    assert_eq!(check_pin(&mut restored_state, &pin_hash), Ok(()));
    assert_eq!(restored_state.retries(), MAX_PIN_RETRIES);
}

fn run_classic_pin_flow(protocol: ClassicPinProtocol) {
    let mut app = CtapApp::new(TestClient::new(), [0xA5; 16]);
    let initial_pin = b"123456";
    let changed_pin = b"654321";

    // setPin
    let set_entries = request_classic_key_agreement(&mut app, protocol);
    let set_secret = P256SecretKey::from_slice(&[0x11; 32]).expect("valid secret key");
    let (set_keys, _set_hash, platform_entries) =
        derive_classic_session(protocol, &set_entries, &set_secret);
    let mut new_pin_block = [0u8; 64];
    new_pin_block[..initial_pin.len()].copy_from_slice(initial_pin);
    let set_iv = match protocol {
        ClassicPinProtocol::V1 => None,
        ClassicPinProtocol::V2 => Some([0x10; 16]),
    };
    let new_pin_enc = classic_encrypt(protocol, &set_keys, &new_pin_block, set_iv);
    new_pin_block.zeroize();
    let pin_auth = classic_pin_auth(protocol, &set_keys, &new_pin_enc);
    let set_pin_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(protocol.identifier())),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x03)),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(platform_entries.clone()),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(pin_auth.clone()),
        ),
        (
            Value::Integer(Integer::from(5)),
            Value::Bytes(new_pin_enc.clone()),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&set_pin_request, &mut payload).expect("serialize setPin request");
    let response = app.handle_client_pin(&payload).expect("setPin succeeds");
    assert_eq!(response, vec![CTAP2_OK]);
    assert!(app.pin_state.is_set());

    // changePin
    let change_entries = request_classic_key_agreement(&mut app, protocol);
    let change_secret = P256SecretKey::from_slice(&[0x22; 32]).expect("valid secret key");
    let (change_keys, _change_hash, change_platform_entries) =
        derive_classic_session(protocol, &change_entries, &change_secret);

    let mut hasher = Sha256::new();
    hasher.update(initial_pin);
    let current_hash_digest = hasher.finalize();
    let current_hash = &current_hash_digest[..16];
    let current_iv = match protocol {
        ClassicPinProtocol::V1 => None,
        ClassicPinProtocol::V2 => Some([0x11; 16]),
    };
    let pin_hash_enc = classic_encrypt(protocol, &change_keys, current_hash, current_iv);

    let mut next_pin_block = [0u8; 64];
    next_pin_block[..changed_pin.len()].copy_from_slice(changed_pin);
    let change_iv = match protocol {
        ClassicPinProtocol::V1 => None,
        ClassicPinProtocol::V2 => Some([0x12; 16]),
    };
    let new_pin_enc = classic_encrypt(protocol, &change_keys, &next_pin_block, change_iv);
    next_pin_block.zeroize();

    let mut auth_data = new_pin_enc.clone();
    auth_data.extend_from_slice(&pin_hash_enc);
    let change_pin_auth = classic_pin_auth(protocol, &change_keys, &auth_data);

    let change_pin_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(protocol.identifier())),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x04)),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(change_platform_entries.clone()),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(change_pin_auth.clone()),
        ),
        (
            Value::Integer(Integer::from(5)),
            Value::Bytes(new_pin_enc.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_hash_enc.clone()),
        ),
    ]);
    payload.clear();
    into_writer(&change_pin_request, &mut payload).expect("serialize changePin request");
    let response = app.handle_client_pin(&payload).expect("changePin succeeds");
    assert_eq!(response, vec![CTAP2_OK]);

    hasher = Sha256::new();
    hasher.update(changed_pin);
    let updated_digest = hasher.finalize();
    let mut expected_hash = [0u8; 16];
    expected_hash.copy_from_slice(&updated_digest[..16]);
    assert_eq!(app.pin_state.persistent().pin_hash, Some(expected_hash));

    // getPinToken (legacy)
    let token_entries = request_classic_key_agreement(&mut app, protocol);
    let token_secret = P256SecretKey::from_slice(&[0x33; 32]).expect("valid secret key");
    let (token_keys, _token_hash, token_platform_entries) =
        derive_classic_session(protocol, &token_entries, &token_secret);

    let token_iv = match protocol {
        ClassicPinProtocol::V1 => None,
        ClassicPinProtocol::V2 => Some([0x13; 16]),
    };
    let pin_hash_enc = classic_encrypt(protocol, &token_keys, &expected_hash, token_iv);
    let pin_hash_auth = classic_pin_auth(protocol, &token_keys, &pin_hash_enc);

    let get_token_request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(protocol.identifier())),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x05)),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(token_platform_entries.clone()),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(pin_hash_auth.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_hash_enc.clone()),
        ),
    ]);
    payload.clear();
    into_writer(&get_token_request, &mut payload).expect("serialize getPinToken request");
    let response = app
        .handle_client_pin(&payload)
        .expect("getPinToken succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode getPinToken response") else {
        panic!("response must be a map");
    };
    let encrypted_token = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("encrypted token present");
    let decrypted_token = crate::decrypt_classic_pin_block(protocol, &token_keys, &encrypted_token)
        .expect("token decrypts");
    assert_eq!(decrypted_token.len(), 32);
    let mut expected_token = [0u8; 32];
    expected_token.copy_from_slice(&decrypted_token);
    assert_eq!(app.pin_state.pin_uv_auth_token(), Some(expected_token));
}

#[test]
fn client_pin_token_with_permissions_sets_metadata() {
    let mut app = CtapApp::new(TestClient::new(), [0xA7; 16]);
    let pin = b"1234";
    let mut hasher = Sha256::new();
    hasher.update(pin);
    let digest = hasher.finalize();
    let mut pin_hash = [0u8; 16];
    pin_hash.copy_from_slice(&digest[..16]);
    app.pin_state.set_pin(pin_hash);

    let auth_entries = request_classic_key_agreement(&mut app, ClassicPinProtocol::V2);
    let platform_secret = P256SecretKey::from_slice(&[0x33; 32]).expect("valid platform secret");
    let (keys, _transcript_hash, platform_entries) =
        derive_classic_session(ClassicPinProtocol::V2, &auth_entries, &platform_secret);
    let iv = [0xAA; 16];
    let pin_hash_enc = classic_encrypt(ClassicPinProtocol::V2, &keys, &digest[..16], Some(iv));
    let pin_auth = classic_pin_auth(ClassicPinProtocol::V2, &keys, &pin_hash_enc);

    let request_map = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x09)),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(platform_entries.clone()),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(pin_auth.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_hash_enc.clone()),
        ),
        (
            Value::Integer(Integer::from(9)),
            Value::Integer(Integer::from(
                (PIN_PERMISSION_MC | PIN_PERMISSION_GA) as i32,
            )),
        ),
        (
            Value::Integer(Integer::from(10)),
            Value::Text("example.com".into()),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request_map, &mut payload).expect("serialize permissions request");
    let response = app
        .handle_client_pin(&payload)
        .expect("getPinUvAuthTokenWithPermissions succeeds");
    assert_eq!(response[0], CTAP2_OK);
    assert!(app.pin_state.has_permission(PIN_PERMISSION_MC));
    assert!(app.pin_state.has_permission(PIN_PERMISSION_GA));
    assert!(!app.pin_state.has_permission(PIN_PERMISSION_CM));
    assert_eq!(app.pin_state.permissions_rp_id(), Some("example.com"));
}

#[test]
fn client_pin_get_token_legacy_succeeds_without_pin_uv_auth_param() {
    let mut app = CtapApp::new(TestClient::new(), [0xAA; 16]);
    let pin = b"9876";
    let mut hasher = Sha256::new();
    hasher.update(pin);
    let digest = hasher.finalize();
    let mut pin_hash = [0u8; 16];
    pin_hash.copy_from_slice(&digest[..16]);
    app.pin_state.set_pin(pin_hash);

    let auth_entries = request_classic_key_agreement(&mut app, ClassicPinProtocol::V2);
    let platform_secret = P256SecretKey::from_slice(&[0x55; 32]).expect("valid platform secret");
    let (keys, _transcript_hash, platform_entries) =
        derive_classic_session(ClassicPinProtocol::V2, &auth_entries, &platform_secret);
    let iv = [0xCC; 16];
    let pin_hash_enc = classic_encrypt(ClassicPinProtocol::V2, &keys, &digest[..16], Some(iv));

    let request_map = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x05)),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(platform_entries.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_hash_enc.clone()),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request_map, &mut payload).expect("serialize getPinToken request");
    let response = app
        .handle_client_pin(&payload)
        .expect("getPinToken without pinUvAuthParam succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) =
        from_reader(&response[1..]).expect("decode getPinToken response without pinUvAuthParam")
    else {
        panic!("response must be a map");
    };
    let encrypted_token = map
        .into_iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        })
        .expect("encrypted token present");
    let decrypted_token =
        crate::decrypt_classic_pin_block(ClassicPinProtocol::V2, &keys, &encrypted_token)
            .expect("token decrypts");
    assert_eq!(decrypted_token.len(), 32);
    let mut expected_token = [0u8; 32];
    expected_token.copy_from_slice(&decrypted_token);
    assert_eq!(app.pin_state.pin_uv_auth_token(), Some(expected_token));
}

#[test]
fn client_pin_token_with_permissions_accepts_missing_pin_uv_auth_param() {
    let mut app = CtapApp::new(TestClient::new(), [0xAB; 16]);
    let pin = b"2468";
    let mut hasher = Sha256::new();
    hasher.update(pin);
    let digest = hasher.finalize();
    let mut pin_hash = [0u8; 16];
    pin_hash.copy_from_slice(&digest[..16]);
    app.pin_state.set_pin(pin_hash);

    let auth_entries = request_classic_key_agreement(&mut app, ClassicPinProtocol::V2);
    let platform_secret = P256SecretKey::from_slice(&[0x66; 32]).expect("valid platform secret");
    let (keys, _transcript_hash, platform_entries) =
        derive_classic_session(ClassicPinProtocol::V2, &auth_entries, &platform_secret);
    let iv = [0xDD; 16];
    let pin_hash_enc = classic_encrypt(ClassicPinProtocol::V2, &keys, &digest[..16], Some(iv));

    let request_map = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x09)),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(platform_entries.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_hash_enc.clone()),
        ),
        (
            Value::Integer(Integer::from(9)),
            Value::Integer(Integer::from(
                (PIN_PERMISSION_MC | PIN_PERMISSION_GA) as i32,
            )),
        ),
        (
            Value::Integer(Integer::from(10)),
            Value::Text("example.org".into()),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request_map, &mut payload)
        .expect("serialize getPinUvAuthTokenWithPermissions request");
    let response = app
        .handle_client_pin(&payload)
        .expect("getPinUvAuthTokenWithPermissions without pinUvAuthParam succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) =
        from_reader(&response[1..]).expect("decode getPinUvAuthTokenWithPermissions response")
    else {
        panic!("response must be a map");
    };
    let encrypted_token = map
        .into_iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        })
        .expect("encrypted token present");
    let decrypted_token =
        crate::decrypt_classic_pin_block(ClassicPinProtocol::V2, &keys, &encrypted_token)
            .expect("token decrypts");
    assert_eq!(decrypted_token.len(), 32);
    let mut expected_token = [0u8; 32];
    expected_token.copy_from_slice(&decrypted_token);
    assert_eq!(app.pin_state.pin_uv_auth_token(), Some(expected_token));
    assert!(app.pin_state.has_permission(PIN_PERMISSION_MC));
    assert!(app.pin_state.has_permission(PIN_PERMISSION_GA));
    assert!(!app.pin_state.has_permission(PIN_PERMISSION_CM));
    assert_eq!(app.pin_state.permissions_rp_id(), Some("example.org"));
}

#[test]
fn client_pin_token_with_permissions_requires_rp_id() {
    let mut app = CtapApp::new(TestClient::new(), [0xA8; 16]);
    let pin = b"1234";
    let mut hasher = Sha256::new();
    hasher.update(pin);
    let digest = hasher.finalize();
    let mut pin_hash = [0u8; 16];
    pin_hash.copy_from_slice(&digest[..16]);
    app.pin_state.set_pin(pin_hash);

    let auth_entries = request_classic_key_agreement(&mut app, ClassicPinProtocol::V2);
    let platform_secret = P256SecretKey::from_slice(&[0x44; 32]).expect("valid platform secret");
    let (keys, _transcript_hash, platform_entries) =
        derive_classic_session(ClassicPinProtocol::V2, &auth_entries, &platform_secret);
    let iv = [0xBB; 16];
    let pin_hash_enc = classic_encrypt(ClassicPinProtocol::V2, &keys, &digest[..16], Some(iv));
    let pin_auth = classic_pin_auth(ClassicPinProtocol::V2, &keys, &pin_hash_enc);

    let request_map = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Integer(Integer::from(0x09)),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(platform_entries.clone()),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Bytes(pin_auth.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_hash_enc.clone()),
        ),
        (
            Value::Integer(Integer::from(9)),
            Value::Integer(Integer::from(
                (PIN_PERMISSION_MC | PIN_PERMISSION_GA) as i32,
            )),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request_map, &mut payload).expect("serialize permissions request");
    let result = app.handle_client_pin(&payload);
    assert_eq!(result, Err(CTAP2_ERR_MISSING_PARAMETER));
}

#[test]
fn classic_pin_uv_protocol_flow_v1() {
    run_classic_pin_flow(ClassicPinProtocol::V1);
}

#[test]
fn classic_pin_uv_protocol_flow_v2() {
    run_classic_pin_flow(ClassicPinProtocol::V2);
}

#[test]
fn client_pin_rejects_subcommands_it_does_not_implement() {
    // 0x06 getPinUvAuthTokenUsingUvWithPermissions and 0x07 getUVRetries need
    // built-in user verification; the rest are undefined.  0x103 and 0x109
    // must not be truncated to setPIN and getPinUvAuthTokenUsingPinWithPermissions.
    let subcommands: [i128; 10] = [
        0x00,
        0x06,
        0x07,
        0x08,
        0x0A,
        0xFF,
        0x103,
        0x109,
        -1,
        i128::from(u64::MAX),
    ];
    for subcommand in subcommands {
        let mut app = CtapApp::new(TestClient::new(), [0x3E; 16]);
        let result = client_pin(
            &mut app,
            vec![
                (int(1), int(2)),
                (
                    int(2),
                    Value::Integer(Integer::try_from(subcommand).expect("CBOR integer")),
                ),
            ],
        );
        assert_eq!(
            result,
            Err(CTAP2_ERR_INVALID_SUBCOMMAND),
            "subCommand {subcommand:#x}"
        );
    }
}

#[test]
fn client_pin_requires_an_integer_subcommand() {
    let mut app = CtapApp::new(TestClient::new(), [0x3F; 16]);
    assert_eq!(
        client_pin(&mut app, vec![(int(1), int(2))]),
        Err(CTAP2_ERR_MISSING_PARAMETER)
    );
    assert_eq!(
        client_pin(
            &mut app,
            vec![(int(1), int(2)), (int(2), Value::Text("0x01".into()))]
        ),
        Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
    );
}

#[test]
fn get_key_agreement_requires_a_supported_pin_uv_auth_protocol() {
    let mut app = CtapApp::new(TestClient::new(), [0x40; 16]);
    assert_eq!(
        client_pin(&mut app, vec![(int(2), int(0x02))]),
        Err(CTAP2_ERR_MISSING_PARAMETER)
    );
    for unsupported in [0, 3, -1, 255] {
        assert_eq!(
            client_pin(
                &mut app,
                vec![(int(1), int(unsupported)), (int(2), int(0x02))]
            ),
            Err(CTAP1_ERR_INVALID_PARAMETER),
            "pinUvAuthProtocol {unsupported}"
        );
    }
    assert_eq!(
        client_pin(
            &mut app,
            vec![(int(1), Value::Text("2".into())), (int(2), int(0x02))]
        ),
        Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
    );
    for protocol in [1, 2] {
        let response = client_pin(&mut app, vec![(int(1), int(protocol)), (int(2), int(0x02))]);
        assert_eq!(response.map(|bytes| bytes[0]), Ok(CTAP2_OK));
    }
}

/// A request carrying every parameter `subcommand` needs, with placeholder
/// values: the checks under test all happen before any of them is used.
fn request_with_all_parameters(subcommand: i64, protocol: Option<Value>) -> Vec<(Value, Value)> {
    let mut entries = vec![
        (int(2), int(subcommand)),
        (int(3), canonical_map(vec![(int(1), int(2))])),
        (int(4), Value::Bytes(vec![0; 32])),
        (int(5), Value::Bytes(vec![0; 64])),
        (int(6), Value::Bytes(vec![0; 16])),
    ];
    if subcommand == 0x09 {
        entries.push((int(9), int(0x01)));
        entries.push((int(10), Value::Text("example.com".into())));
    }
    if let Some(protocol) = protocol {
        entries.push((int(1), protocol));
    }
    entries
}

#[test]
fn pin_subcommands_check_parameters_then_the_pin_uv_auth_protocol() {
    // setPIN, changePIN, getPinToken, getPinUvAuthTokenUsingPinWithPermissions
    for subcommand in [0x03, 0x04, 0x05, 0x09] {
        let mut app = CtapApp::new(TestClient::new(), [0x41; 16]);
        if subcommand != 0x03 {
            app.pin_state.set_pin(pin_hash(b"1234"));
        }
        assert_eq!(
            client_pin(&mut app, request_with_all_parameters(subcommand, None)),
            Err(CTAP2_ERR_MISSING_PARAMETER),
            "subCommand {subcommand:#x} without pinUvAuthProtocol"
        );
        assert_eq!(
            client_pin(
                &mut app,
                request_with_all_parameters(subcommand, Some(int(3)))
            ),
            Err(CTAP1_ERR_INVALID_PARAMETER),
            "subCommand {subcommand:#x} with pinUvAuthProtocol 3"
        );
        assert_eq!(
            client_pin(
                &mut app,
                request_with_all_parameters(subcommand, Some(Value::Bytes(vec![2])))
            ),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            "subCommand {subcommand:#x} with a byte-string pinUvAuthProtocol"
        );
        // A missing mandatory parameter is reported before the protocol.
        let mut missing_key_agreement = request_with_all_parameters(subcommand, Some(int(3)));
        missing_key_agreement.retain(|(key, _)| *key != int(3));
        assert_eq!(
            client_pin(&mut app, missing_key_agreement),
            Err(CTAP2_ERR_MISSING_PARAMETER),
            "subCommand {subcommand:#x} without keyAgreement"
        );
        // Nothing was attempted, so no retry was spent.
        assert_eq!(app.pin_state.retries(), MAX_PIN_RETRIES);
    }
}

#[test]
fn get_pin_retries_needs_no_pin_uv_auth_protocol() {
    let mut app = CtapApp::new(TestClient::new(), [0x42; 16]);
    assert_eq!(get_pin_retries(&mut app), (MAX_PIN_RETRIES, None));
    let response = client_pin(&mut app, vec![(int(1), int(3)), (int(2), int(0x01))]);
    assert_eq!(response.map(|bytes| bytes[0]), Ok(CTAP2_OK));
}

#[test]
fn set_pin_when_a_pin_is_already_set_is_pin_auth_invalid() {
    // "If a PIN has already been set, authenticator returns
    // CTAP2_ERR_PIN_AUTH_INVALID error." (CTAP 2.3 §6.5.5.5)
    for protocol in [ClassicPinProtocol::V1, ClassicPinProtocol::V2] {
        let mut app = CtapApp::new(TestClient::new(), [0x43; 16]);
        app.pin_state.set_pin(pin_hash(b"1234"));
        let session = PlatformPinSession::establish(&mut app, protocol, 0x44);
        let new_pin_enc = session.encrypt(&padded_pin(b"5678"));
        let pin_uv_auth_param = classic_pin_auth(protocol, &session.keys, &new_pin_enc);
        let result = client_pin(
            &mut app,
            vec![
                (int(1), int(protocol.identifier().into())),
                (int(2), int(0x03)),
                (int(3), session.key_agreement.clone()),
                (int(4), Value::Bytes(pin_uv_auth_param)),
                (int(5), Value::Bytes(new_pin_enc)),
            ],
        );
        assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_INVALID), "{protocol:?}");
        assert_eq!(app.pin_state.persistent().pin_hash, Some(pin_hash(b"1234")));
    }
}

#[test]
fn get_pin_uv_auth_token_grants_cm_scoped_to_an_rp_id() {
    // cm: "The rpId parameter is optional, if it is present, the pinUvAuthToken
    // can only be used for Credential Management operations on Credentials
    // associated with that RP ID." (CTAP 2.3 §6.5.5.7)
    let mut app = CtapApp::new(TestClient::new(), [0x45; 16]);
    app.pin_state.set_pin(pin_hash(b"1234"));
    let token = get_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        b"1234",
        PIN_PERMISSION_CM.into(),
        Some("example.com"),
    )
    .expect("cm with an rpId is granted");
    assert_eq!(app.pin_state.pin_uv_auth_token(), Some(token));
    assert_eq!(app.pin_state.pin_uv_auth_permissions, PIN_PERMISSION_CM);
    assert_eq!(app.pin_state.permissions_rp_id(), Some("example.com"));
}

#[test]
fn get_pin_uv_auth_token_refuses_permissions_it_cannot_grant() {
    // be, lbw, acfg and pcmr need features this authenticator does not have.
    for permissions in [0x08, 0x10, 0x20, 0x40, 0x04 | 0x40, 0x01 | 0x02 | 0x08] {
        let mut app = CtapApp::new(TestClient::new(), [0x46; 16]);
        app.pin_state.set_pin(pin_hash(b"1234"));
        let result = get_pin_uv_auth_token(
            &mut app,
            ClassicPinProtocol::V2,
            b"1234",
            permissions,
            Some("example.com"),
        );
        assert_eq!(
            result,
            Err(CTAP2_ERR_UNAUTHORIZED_PERMISSION),
            "permissions {permissions:#x}"
        );
        assert_eq!(app.pin_state.pin_uv_auth_token(), None);
        // Refused before the PIN is looked at.
        assert_eq!(app.pin_state.retries(), MAX_PIN_RETRIES);
    }
}

#[test]
fn get_pin_uv_auth_token_rejects_zero_permissions() {
    for permissions in [0, -1] {
        let mut app = CtapApp::new(TestClient::new(), [0x47; 16]);
        app.pin_state.set_pin(pin_hash(b"1234"));
        let result =
            get_pin_uv_auth_token(&mut app, ClassicPinProtocol::V2, b"1234", permissions, None);
        assert_eq!(result, Err(CTAP1_ERR_INVALID_PARAMETER), "{permissions}");
        assert_eq!(app.pin_state.retries(), MAX_PIN_RETRIES);
    }
}

#[test]
fn get_pin_uv_auth_token_ignores_undefined_permissions() {
    // "Undefined permissions present in the permissions parameter are ignored."
    let cases: [(i128, u8); 4] = [
        (0x80 | 0x04, PIN_PERMISSION_CM),
        (0x100 | 0x04, PIN_PERMISSION_CM),
        (i128::from(u64::MAX) & !0x7F | 0x04, PIN_PERMISSION_CM),
        (0x80, 0),
    ];
    for (requested, granted) in cases {
        let mut app = CtapApp::new(TestClient::new(), [0x48; 16]);
        app.pin_state.set_pin(pin_hash(b"1234"));
        let token =
            get_pin_uv_auth_token(&mut app, ClassicPinProtocol::V1, b"1234", requested, None)
                .unwrap_or_else(|err| panic!("permissions {requested:#x}: {err:#04x}"));
        assert_eq!(app.pin_state.pin_uv_auth_token(), Some(token));
        assert_eq!(
            app.pin_state.pin_uv_auth_permissions, granted,
            "permissions {requested:#x}"
        );
    }
}
