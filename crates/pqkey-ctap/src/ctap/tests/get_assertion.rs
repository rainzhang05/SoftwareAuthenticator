//! authenticatorGetAssertion / authenticatorGetNextAssertion tests, including
//! hmac-secret and credProtect.

use super::support::new_app;
use super::support::{
    TestStore, classic_encrypt, classic_pin_auth, corrupt_mac, derive_classic_session,
    install_pin_uv_auth_token, request_classic_key_agreement, token_pin_auth,
};
use super::support::{credential, insert, stored, stored_by_id};
use crate::ctap::cbor::canonical_map;
use crate::ctap::pin::permissions::{PIN_PERMISSION_GA, PIN_PERMISSION_MC};
use crate::ctap::pin::protocol::{HmacSha256, PIN_UV_AUTH_PROTOCOL_CLASSIC};
use crate::{ClassicPinProtocol, CoseAlg, CredentialSecretKey};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use hmac::{KeyInit, Mac};
use p256::{
    SecretKey as P256SecretKey,
    ecdsa::{Signature as P256EcdsaSignature, signature::Verifier},
};
use sha2::{Digest, Sha256};

use crate::ctap::constants::*;

#[test]
fn get_assertion_response_encoding_is_canonical() {
    let mut app = new_app(TestStore::new(), [0x11; 16]);
    let rp_id = "example.com";
    let client_hash = vec![0x22; 32];
    let pin_token = [0x33; 32];
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        pin_token,
        PIN_PERMISSION_MC | PIN_PERMISSION_GA,
        None,
    );

    let pin_uv_auth_param = token_pin_auth(ClassicPinProtocol::V2, &pin_token, &client_hash);

    let user_id = vec![0x44, 0x55];
    let user_name = "user".to_string();
    let user_display = "User".to_string();
    let credential_id = vec![0xAA, 0xBB, 0xCC];
    let alg = CoseAlg::MLDSA44;

    let mut record = credential(rp_id, &user_id, &credential_id, alg);
    record.user_name = Some(user_name.clone());
    record.user_display_name = Some(user_display.clone());
    record.cred_random_with_uv = [0x10; 32];
    record.cred_random_without_uv = [0x20; 32];
    insert(&mut app, &record);

    let request_map = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Text(rp_id.to_string()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(client_hash.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_uv_auth_param.clone()),
        ),
        (
            Value::Integer(Integer::from(7)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&request_map, &mut payload).expect("serialize getAssertion request");
    let response = app
        .handle_get_assertion(&payload)
        .expect("getAssertion succeeds");
    assert_eq!(response[0], CTAP2_OK);

    let sign_count = stored(&app)[0].sign_count;
    assert_eq!(sign_count, 1);
    let Value::Map(entries) = from_reader(&response[1..]).expect("decode getAssertion response")
    else {
        panic!("response must be a map");
    };
    let mut credential_value = None;
    let mut auth_data_value = None;
    let mut signature_value = None;
    let mut user_value = None;
    for (key, value) in entries {
        if let Value::Integer(int) = key {
            let label: i128 = int.into();
            match label {
                1 => credential_value = Some(value),
                2 => auth_data_value = Some(value),
                3 => signature_value = Some(value),
                4 => user_value = Some(value),
                _ => {}
            }
        }
    }

    let credential_map = match credential_value.expect("credential present") {
        Value::Map(map) => canonical_map(map),
        _ => panic!("credential must be a map"),
    };
    let auth_data = auth_data_value.expect("authData present");
    let auth_data_bytes = match &auth_data {
        Value::Bytes(bytes) => bytes,
        _ => panic!("authData must be bytes"),
    };
    assert_eq!(auth_data_bytes[32] & 0x01, 0x01);
    assert_eq!(auth_data_bytes[32] & 0x04, 0x04);
    let signature = signature_value.expect("signature present");
    let user_map = match user_value.expect("user present") {
        Value::Map(map) => canonical_map(map),
        _ => panic!("user must be a map"),
    };

    let expected_map = canonical_map(vec![
        (Value::Integer(Integer::from(1)), credential_map),
        (Value::Integer(Integer::from(2)), auth_data),
        (Value::Integer(Integer::from(3)), signature),
        (Value::Integer(Integer::from(4)), user_map),
    ]);

    let mut expected_bytes = Vec::new();
    into_writer(&expected_map, &mut expected_bytes).expect("encode expected getAssertion map");
    assert_eq!(expected_bytes, &response[1..]);
}

#[test]
fn get_next_assertion_preserves_new_credentials() {
    let mut app = new_app(TestStore::new(), [0x55; 16]);
    let rp_id = "example.com";
    let client_hash = vec![0x66; 32];

    let mut record = credential(rp_id, &[0x01], &[0xA1], CoseAlg::MLDSA44);
    record.user_name = Some("one".into());
    record.user_display_name = Some("One".into());
    record.cred_random_with_uv = [0x10; 32];
    record.cred_random_without_uv = [0x11; 32];
    insert(&mut app, &record);

    let mut record = credential(rp_id, &[0x02], &[0xA2], CoseAlg::MLDSA44);
    record.user_name = Some("two".into());
    record.user_display_name = Some("Two".into());
    record.cred_random_with_uv = [0x12; 32];
    record.cred_random_without_uv = [0x13; 32];
    insert(&mut app, &record);

    let request_map = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Text(rp_id.to_string()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(client_hash.clone()),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&request_map, &mut payload).expect("serialize getAssertion request");
    let response = app
        .handle_get_assertion(&payload)
        .expect("getAssertion succeeds");
    assert_eq!(response[0], CTAP2_OK);
    assert!(app.pending_assertion.is_some());
    // The most recently created credential comes first.
    assert_eq!(stored_by_id(&app, &[0xA2]).sign_count, 1);
    assert_eq!(stored_by_id(&app, &[0xA1]).sign_count, 0);

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode getAssertion response")
    else {
        panic!("response must be a map");
    };
    let mut total_credentials_value = None;
    for (key, value) in entries {
        if let Value::Integer(label) = key
            && label == Integer::from(5)
        {
            total_credentials_value = Some(value);
        }
    }
    let total_credentials = match total_credentials_value.expect("total credential count present") {
        Value::Integer(int) => {
            let count: i128 = int.into();
            count
        }
        _ => panic!("total credential count must be an integer"),
    };
    assert_eq!(total_credentials, 2);

    let mut record = credential("new.example", &[0x03], &[0xA3], CoseAlg::MLDSA44);
    record.user_name = Some("three".into());
    record.cred_random_with_uv = [0x14; 32];
    record.cred_random_without_uv = [0x15; 32];
    insert(&mut app, &record);

    let next_response = app
        .handle_get_next_assertion()
        .expect("getNextAssertion succeeds");
    assert_eq!(next_response[0], CTAP2_OK);
    assert!(app.pending_assertion.is_none());
    assert_eq!(stored(&app).len(), 3);
    assert_eq!(stored_by_id(&app, &[0xA3]).sign_count, 0);
    assert_eq!(stored_by_id(&app, &[0xA2]).sign_count, 1);
    assert_eq!(stored_by_id(&app, &[0xA1]).sign_count, 1);

    let Value::Map(entries) =
        from_reader(&next_response[1..]).expect("decode getNextAssertion response")
    else {
        panic!("next response must be a map");
    };
    for (key, _) in entries {
        if let Value::Integer(label) = key {
            assert_ne!(
                label,
                Integer::from(5),
                "getNextAssertion must omit total count"
            );
        }
    }
}

#[test]
fn get_next_assertion_without_pending_fails() {
    let mut app = new_app(TestStore::new(), [0x77; 16]);
    assert_eq!(app.handle_get_next_assertion(), Err(CTAP2_ERR_NOT_ALLOWED));
}

#[test]
fn get_assertion_without_pin_uv_uses_presence_only() {
    let mut app = new_app(TestStore::new(), [0x11; 16]);
    let rp_id = "example.com";
    let client_hash = vec![0x22; 32];

    let user_id = vec![0x01, 0x02];
    let credential_id = vec![0xAA, 0xBB, 0xCC];
    let alg = CoseAlg::MLDSA44;

    let mut record = credential(rp_id, &user_id, &credential_id, alg);
    record.cred_random_with_uv = [0x30; 32];
    record.cred_random_without_uv = [0x40; 32];
    record.sign_count = 7;
    insert(&mut app, &record);

    let request_map = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Text(rp_id.to_string()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(client_hash.clone()),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&request_map, &mut payload).expect("serialize getAssertion request");
    let response = app
        .handle_get_assertion(&payload)
        .expect("getAssertion succeeds");
    assert_eq!(response[0], CTAP2_OK);

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode getAssertion response")
    else {
        panic!("response must be a map");
    };

    let auth_data_bytes = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("authData bytes present");

    assert_eq!(auth_data_bytes[32] & 0x01, 0x01);
    assert_eq!(auth_data_bytes[32] & 0x04, 0x00);

    let sign_count = stored(&app)[0].sign_count;
    assert_eq!(sign_count, 8);
}

#[test]
fn get_assertion_with_invalid_pin_uv_auth_param_fails() {
    let mut app = new_app(TestStore::new(), [0x11; 16]);
    let rp_id = "example.com";
    let client_hash = vec![0x22; 32];
    let pin_token = [0x33; 32];
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        pin_token,
        PIN_PERMISSION_MC | PIN_PERMISSION_GA,
        None,
    );

    let user_id = vec![0x01, 0x02];
    let credential_id = vec![0xAA, 0xBB, 0xCC];
    let alg = CoseAlg::MLDSA44;

    let mut record = credential(rp_id, &user_id, &credential_id, alg);
    record.cred_random_with_uv = [0x50; 32];
    record.cred_random_without_uv = [0x60; 32];
    insert(&mut app, &record);

    // Right length for protocol two, wrong value.
    let pin_uv_auth_param = corrupt_mac(token_pin_auth(
        ClassicPinProtocol::V2,
        &pin_token,
        &client_hash,
    ));

    let request_map = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Text(rp_id.to_string()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(client_hash.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_uv_auth_param),
        ),
        (
            Value::Integer(Integer::from(7)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&request_map, &mut payload).expect("serialize getAssertion request");
    let result = app.handle_get_assertion(&payload);
    assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_INVALID));
}

#[test]
fn get_assertion_es256_signature_verifies() {
    let mut app = new_app(TestStore::new(), [0x02; 16]);
    let rp_id = "example.com";
    let client_hash = vec![0x99; 32];

    let record = credential(rp_id, &[0x01], &[0xA1, 0xB2], CoseAlg::ES256);
    insert(&mut app, &record);
    let verifying_key = match record.secret_key().expect("ES256 key") {
        CredentialSecretKey::Es256(sk) => *sk.verifying_key(),
        _ => panic!("expected ES256 secret key"),
    };

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Text(rp_id.to_string()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(client_hash.clone()),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize getAssertion request");
    let response = app
        .handle_get_assertion(&payload)
        .expect("getAssertion succeeds");
    assert_eq!(response[0], CTAP2_OK);

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode getAssertion response")
    else {
        panic!("response must be a map");
    };

    let mut auth_data_bytes = None;
    let mut signature_bytes = None;
    for (key, value) in entries {
        if key == Value::Integer(Integer::from(2)) {
            if let Value::Bytes(bytes) = value {
                auth_data_bytes = Some(bytes);
            }
        } else if key == Value::Integer(Integer::from(3))
            && let Value::Bytes(bytes) = value
        {
            signature_bytes = Some(bytes);
        }
    }

    let auth_data_bytes = auth_data_bytes.expect("authData present");
    let signature_bytes = signature_bytes.expect("signature present");

    let mut message = Vec::new();
    message.extend_from_slice(&auth_data_bytes);
    message.extend_from_slice(&client_hash);

    let signature =
        P256EcdsaSignature::from_der(&signature_bytes).expect("signature must be valid DER");
    verifying_key
        .verify(&message, &signature)
        .expect("ES256 signature verifies");
}

#[test]
fn get_assertion_produces_hmac_secret_output() {
    let mut app = new_app(TestStore::new(), [0x42; 16]);
    let pin = b"1234";
    let mut hasher = Sha256::new();
    hasher.update(pin);
    let digest = hasher.finalize();
    let mut pin_hash = [0u8; 16];
    pin_hash.copy_from_slice(&digest[..16]);
    app.pin_state.set_pin(pin_hash);

    let pin_token = [0x55; 32];
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        pin_token,
        PIN_PERMISSION_MC | PIN_PERMISSION_GA,
        None,
    );

    let client_hash = vec![0x77; 32];
    let pin_uv_auth_param = token_pin_auth(ClassicPinProtocol::V2, &pin_token, &client_hash);

    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Bytes(vec![0x01, 0x02]),
    )]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
        ),
    ])]);
    let extensions = canonical_map(vec![(Value::Text("hmac-secret".into()), Value::Bool(true))]);

    let make_credential = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
        (Value::Integer(Integer::from(6)), extensions),
        (
            Value::Integer(Integer::from(7)),
            canonical_map(vec![(Value::Text("rk".into()), Value::Bool(true))]),
        ),
        (
            Value::Integer(Integer::from(8)),
            Value::Bytes(pin_uv_auth_param.clone()),
        ),
        (
            Value::Integer(Integer::from(9)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&make_credential, &mut payload).expect("serialize makeCredential request");
    app.handle_make_credential(&payload)
        .expect("makeCredential succeeds");

    // makeCredential collected user presence, which strips the token of its
    // permissions (CTAP 2.3 §6.1.2 step 14); the platform fetches a new one.
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        pin_token,
        PIN_PERMISSION_MC | PIN_PERMISSION_GA,
        None,
    );

    let auth_entries = request_classic_key_agreement(&mut app, ClassicPinProtocol::V2);
    let platform_secret = P256SecretKey::from_slice(&[0x23; 32]).expect("valid secret key");
    let (session_keys, platform_entries) =
        derive_classic_session(ClassicPinProtocol::V2, &auth_entries, &platform_secret);

    let salt = vec![0x99; 32];
    let salt_enc = classic_encrypt(
        ClassicPinProtocol::V2,
        &session_keys,
        &salt,
        Some([0x3C; 16]),
    );
    let salt_auth = classic_pin_auth(ClassicPinProtocol::V2, &session_keys, &salt_enc);

    let client_hash_assert = vec![0x88; 32];
    let pin_uv_auth_param_assert =
        token_pin_auth(ClassicPinProtocol::V2, &pin_token, &client_hash_assert);

    let hmac_extension = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            canonical_map(platform_entries.clone()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(salt_enc.clone()),
        ),
        (
            Value::Integer(Integer::from(3)),
            Value::Bytes(salt_auth.clone()),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
    ]);
    let extensions = canonical_map(vec![(Value::Text("hmac-secret".into()), hmac_extension)]);

    let get_assertion = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Text("example.com".into()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(client_hash_assert.clone()),
        ),
        (Value::Integer(Integer::from(4)), extensions),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_uv_auth_param_assert.clone()),
        ),
        (
            Value::Integer(Integer::from(7)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&get_assertion, &mut payload).expect("serialize getAssertion request");
    let response = app
        .handle_get_assertion(&payload)
        .expect("getAssertion succeeds");
    assert_eq!(response[0], CTAP2_OK);

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode response map") else {
        panic!("response must be a map");
    };
    let auth_data = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("authData present");
    assert_eq!(auth_data[32] & 0x80, 0x80);

    let extension_bytes = &auth_data[32 + 1 + 4..];
    let Value::Map(extension_map) = from_reader(extension_bytes).expect("decode extensions") else {
        panic!("extensions must be a map");
    };
    let encrypted_output = extension_map
        .iter()
        .find(|(k, _)| *k == Value::Text("hmac-secret".into()))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("encrypted output present");

    // Protocol two: a random 16-byte IV followed by the 32-byte ciphertext.
    assert_eq!(encrypted_output.len(), 16 + 32);
    let decrypted =
        crate::decrypt_classic_pin_block(ClassicPinProtocol::V2, &session_keys, &encrypted_output)
            .expect("decrypt hmac-secret output");
    assert_eq!(decrypted.len(), 32);

    let credentials = stored(&app);
    let credential = &credentials[0];
    let mut expected_mac = HmacSha256::new_from_slice(&credential.cred_random_with_uv)
        .expect("valid MAC key for credential");
    expected_mac.update(&salt);
    let expected = expected_mac.finalize().into_bytes();
    assert_eq!(&decrypted[..], &expected[..]);
}

#[test]
fn get_assertion_rejects_mismatched_rp_binding() {
    let mut app = new_app(TestStore::new(), [0x52; 16]);
    let token = [0xAB; 32];
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        token,
        PIN_PERMISSION_GA,
        Some("other.com"),
    );

    let client_hash = vec![0xCC; 32];
    let pin_uv_auth_param = token_pin_auth(ClassicPinProtocol::V2, &token, &client_hash);

    let credential_id = vec![0xAA, 0xBB];
    let alg = CoseAlg::MLDSA44;
    let record = credential("example.com", &[0x01], &credential_id, alg);
    insert(&mut app, &record);

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Text("example.com".into()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(client_hash.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_uv_auth_param),
        ),
        (
            Value::Integer(Integer::from(7)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize getAssertion request");
    let result = app.handle_get_assertion(&payload);
    assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_INVALID));
}

#[test]
fn cred_protect_enforced_for_user_verification() {
    let mut app = new_app(TestStore::new(), [0x33; 16]);
    let rp_id = "example.com";
    let client_hash = vec![0x55; 32];

    let mut record = credential(rp_id, &[0x02], &[0xBB], CoseAlg::MLDSA44);
    record.cred_random_with_uv = [0x13; 32];
    record.cred_random_without_uv = [0x14; 32];
    insert(&mut app, &record);
    // Created last, so once user verification makes it applicable it is the
    // most recent credential and comes first.
    let mut record = credential(rp_id, &[0x01], &[0xAA], CoseAlg::MLDSA44);
    record.cred_random_with_uv = [0x11; 32];
    record.cred_random_without_uv = [0x12; 32];
    record.cred_protect = 3;
    insert(&mut app, &record);

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Text(rp_id.to_string()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(client_hash.clone()),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize request");
    let response = app
        .handle_get_assertion(&payload)
        .expect("assertion without UV succeeds");
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode response") else {
        panic!("response must be a map");
    };
    let credential_id = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(1)))
        .and_then(|(_, v)| match v {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| *k == Value::Text("id".into()))
                .and_then(|(_, v)| match v {
                    Value::Bytes(bytes) => Some(bytes.clone()),
                    _ => None,
                }),
            _ => None,
        })
        .expect("credential id present");
    assert_eq!(credential_id, vec![0xBB]);

    let pin_token = [0x66; 32];
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        pin_token,
        PIN_PERMISSION_MC | PIN_PERMISSION_GA,
        None,
    );
    let pin_uv_auth_param = token_pin_auth(ClassicPinProtocol::V2, &pin_token, &client_hash);

    let request_with_uv = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Text(rp_id.to_string()),
        ),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(client_hash.clone()),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Bytes(pin_uv_auth_param),
        ),
        (
            Value::Integer(Integer::from(7)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request_with_uv, &mut payload).expect("serialize request");
    let response = app
        .handle_get_assertion(&payload)
        .expect("assertion with UV succeeds");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode response") else {
        panic!("response must be a map");
    };
    let credential_id = map
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(1)))
        .and_then(|(_, v)| match v {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| *k == Value::Text("id".into()))
                .and_then(|(_, v)| match v {
                    Value::Bytes(bytes) => Some(bytes.clone()),
                    _ => None,
                }),
            _ => None,
        })
        .expect("credential id present");
    assert_eq!(credential_id, vec![0xAA]);
}

/// An allowList descriptor whose type is not "public-key" does not denote
/// one of this authenticator's credentials.
#[test]
fn get_assertion_allow_list_ignores_other_credential_types() {
    let mut app = new_app(TestStore::new(), [0x75; 16]);
    insert(
        &mut app,
        &credential("example.com", &[0x01], &[0xC1], CoseAlg::ES256),
    );
    let request = |credential_type: &str| {
        let allow_list = Value::Array(vec![canonical_map(vec![
            (
                Value::Text("type".into()),
                Value::Text(credential_type.into()),
            ),
            (Value::Text("id".into()), Value::Bytes(vec![0xC1])),
        ])]);
        let mut payload = Vec::new();
        into_writer(
            &canonical_map(vec![
                (
                    Value::Integer(Integer::from(1)),
                    Value::Text("example.com".into()),
                ),
                (
                    Value::Integer(Integer::from(2)),
                    Value::Bytes(vec![0x75; 32]),
                ),
                (Value::Integer(Integer::from(3)), allow_list),
            ]),
            &mut payload,
        )
        .expect("serialize getAssertion");
        payload
    };
    assert_eq!(
        app.handle_get_assertion(&request("not-public-key")),
        Err(CTAP2_ERR_NO_CREDENTIALS)
    );
    assert!(app.handle_get_assertion(&request("public-key")).is_ok());
}
