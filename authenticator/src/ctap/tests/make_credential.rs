//! authenticatorMakeCredential tests.

use super::support::TestClient;
use crate::ctap::cbor::canonical_map;
use crate::ctap::make_credential::COSE_ALG_ES256;
use crate::ctap::pin::permissions::{PIN_PERMISSION_GA, PIN_PERMISSION_MC};
use crate::ctap::pin::protocol::{HmacSha256, PIN_UV_AUTH_PROTOCOL_CLASSIC};
use crate::ctap::CtapApp;
use crate::{credential_secret_from_bytes, CoseAlg, CredentialSecretKey};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use hmac::Mac;
use p256::ecdsa::{signature::Signer, Signature as P256EcdsaSignature, SigningKey};

use transport_core::ctap::constants::*;

#[test]
fn make_credential_includes_extensions() {
    let mut app = CtapApp::new(TestClient::new(), [0xAA; 16]);
    let client_hash = vec![0xBB; 32];
    let pin_token = [0xCC; 32];
    app.pin_state
        .set_pin_uv_auth_token(pin_token, PIN_PERMISSION_MC | PIN_PERMISSION_GA, None);

    let mut mac = HmacSha256::new_from_slice(&pin_token).expect("valid token MAC");
    mac.update(&client_hash);
    let pin_uv_auth_param: Vec<u8> = mac.finalize().into_bytes()[..16].to_vec();

    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![
        (Value::Text("id".into()), Value::Bytes(vec![0x01, 0x02])),
        (Value::Text("name".into()), Value::Text("user".into())),
    ]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
        ),
    ])]);
    let extensions = canonical_map(vec![
        (Value::Text("hmac-secret".into()), Value::Bool(true)),
        (
            Value::Text("credProtect".into()),
            Value::Integer(Integer::from(3)),
        ),
    ]);

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
    let response = app
        .handle_make_credential(&payload)
        .expect("makeCredential succeeds");
    assert_eq!(response[0], CTAP2_OK);

    let credential = &app.stored_credentials[0];
    assert_eq!(credential.cred_protect, Some(3));
    assert_eq!(
        credential
            .cred_random_with_uv
            .as_ref()
            .expect("credRandom with UV present")
            .len(),
        32
    );
    assert_eq!(
        credential
            .cred_random_without_uv
            .as_ref()
            .expect("credRandom without UV present")
            .len(),
        32
    );

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

    let mut offset = 32 + 1 + 4; // rpId hash + flags + sign count
    offset += 16; // AAGUID
    offset += 2; // credential ID length field
    offset += credential.credential_id.len();
    offset += credential.public_key.len();

    let extension_bytes = &auth_data[offset..];
    let Value::Map(extension_map) = from_reader(extension_bytes).expect("decode extensions") else {
        panic!("extensions must be a map");
    };
    let hmac_value = extension_map
        .iter()
        .find(|(k, _)| *k == Value::Text("hmac-secret".into()))
        .and_then(|(_, v)| match v {
            Value::Bool(flag) => Some(*flag),
            _ => None,
        })
        .expect("hmac-secret extension present");
    assert!(hmac_value);

    let cred_protect_value: i128 = extension_map
        .iter()
        .find(|(k, _)| *k == Value::Text("credProtect".into()))
        .and_then(|(_, v)| match v {
            Value::Integer(int) => Some(int.clone().into()),
            _ => None,
        })
        .expect("credProtect extension present");
    assert_eq!(cred_protect_value, 3);
}

#[test]
fn make_credential_supports_es256() {
    let mut app = CtapApp::new(TestClient::new(), [0x01; 16]);
    let client_hash = vec![0x10; 32];
    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0xAA]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::ES256 as i32)),
        ),
    ])]);

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);

    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize makeCredential request");
    let response = app
        .handle_make_credential(&payload)
        .expect("makeCredential succeeds");
    assert_eq!(response[0], CTAP2_OK);

    assert_eq!(app.stored_credentials.len(), 1);
    let credential = &app.stored_credentials[0];
    assert_eq!(credential.alg, CoseAlg::ES256 as i32);
    assert_eq!(credential.secret_key.len(), 32);

    let Value::Map(entries) =
        from_reader(credential.public_key.as_slice()).expect("decode ES256 COSE key")
    else {
        panic!("public key must be a map");
    };

    let mut kty = None;
    let mut alg = None;
    let mut crv = None;
    let mut x_len = None;
    let mut y_len = None;

    for (key, value) in entries {
        if let Value::Integer(label) = key {
            let label_value: i128 = label.clone().into();
            match label_value {
                1 => kty = Some(value),
                3 => alg = Some(value),
                -1 => crv = Some(value),
                -2 => {
                    if let Value::Bytes(bytes) = value {
                        x_len = Some(bytes.len());
                    }
                }
                -3 => {
                    if let Value::Bytes(bytes) = value {
                        y_len = Some(bytes.len());
                    }
                }
                _ => {}
            }
        }
    }

    assert_eq!(
        kty,
        Some(Value::Integer(Integer::from(2))),
        "kty must be EC2"
    );
    assert_eq!(
        alg,
        Some(Value::Integer(Integer::from(CoseAlg::ES256 as i32))),
        "alg must be ES256"
    );
    assert_eq!(
        crv,
        Some(Value::Integer(Integer::from(1))),
        "curve must be P-256"
    );
    assert_eq!(x_len, Some(32));
    assert_eq!(y_len, Some(32));

    let reconstructed =
        credential_secret_from_bytes(CoseAlg::ES256, credential.secret_key.as_slice())
            .expect("reconstruct ES256 secret key");
    match reconstructed {
        CredentialSecretKey::Es256(_) => {}
        _ => panic!("expected ES256 secret key variant"),
    }
}

#[test]
fn make_credential_uses_attestation_certificate_when_available() {
    let mut app = CtapApp::new(TestClient::new(), [0xAB; 16]);
    let att_key_bytes = vec![0x13; 32];
    let certificate = vec![0x30, 0x82, 0x00, 0x01];
    app.attestation_private_key = Some(att_key_bytes.clone());
    app.attestation_certificate_chain = Some(vec![certificate.clone()]);

    let client_hash = vec![0x11; 32];
    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0xAA]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
        ),
    ])]);

    let make_credential = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);

    let mut payload = Vec::new();
    into_writer(&make_credential, &mut payload).expect("serialize makeCredential request");
    let response = app
        .handle_make_credential(&payload)
        .expect("makeCredential succeeds");
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
    let att_stmt_entries = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(3)))
        .and_then(|(_, v)| match v {
            Value::Map(map) => Some(map.clone()),
            _ => None,
        })
        .expect("attStmt present");

    let alg_value = att_stmt_entries
        .iter()
        .find(|(k, _)| match k {
            Value::Text(text) => text == "alg",
            _ => false,
        })
        .and_then(|(_, v)| match v {
            Value::Integer(int) => Some(int.clone()),
            _ => None,
        })
        .expect("alg value present");
    let alg_i128: i128 = alg_value.into();
    assert_eq!(alg_i128, i128::from(COSE_ALG_ES256));

    let signature_bytes = att_stmt_entries
        .iter()
        .find(|(k, _)| match k {
            Value::Text(text) => text == "sig",
            _ => false,
        })
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("sig value present");
    let cert_chain = att_stmt_entries
        .iter()
        .find(|(k, _)| match k {
            Value::Text(text) => text == "x5c",
            _ => false,
        })
        .and_then(|(_, v)| match v {
            Value::Array(values) => Some(values.clone()),
            _ => None,
        })
        .expect("x5c present");
    assert_eq!(cert_chain.len(), 1);
    assert_eq!(
        cert_chain[0],
        Value::Bytes(certificate.clone()),
        "certificate chain returned",
    );

    let signing_key = SigningKey::from_slice(&att_key_bytes).expect("valid attestation key");
    let mut message = Vec::with_capacity(auth_data.len() + client_hash.len());
    message.extend_from_slice(&auth_data);
    message.extend_from_slice(&client_hash);
    let expected_signature: P256EcdsaSignature = signing_key.sign(&message);
    let expected_der = expected_signature.to_der();
    assert_eq!(signature_bytes.as_slice(), expected_der.as_bytes());
}

#[test]
fn make_credential_self_attestation_without_attestation_key() {
    let mut app = CtapApp::new(TestClient::new(), [0xCD; 16]);
    let client_hash = vec![0x22; 32];
    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x01]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
        ),
    ])]);

    let make_credential = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);

    let mut payload = Vec::new();
    into_writer(&make_credential, &mut payload).expect("serialize makeCredential request");
    let response = app
        .handle_make_credential(&payload)
        .expect("makeCredential succeeds");
    assert_eq!(response[0], CTAP2_OK);

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode response map") else {
        panic!("response must be a map");
    };
    let fmt_value = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(1)))
        .and_then(|(_, v)| match v {
            Value::Text(text) => Some(text.clone()),
            _ => None,
        })
        .expect("fmt present");
    assert_eq!(fmt_value, "packed");
    let att_stmt_entries = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(3)))
        .and_then(|(_, v)| match v {
            Value::Map(map) => Some(map.clone()),
            _ => None,
        })
        .expect("attStmt present");

    assert!(
        att_stmt_entries.iter().all(|(k, _)| match k {
            Value::Text(text) => text != "x5c",
            _ => true,
        }),
        "x5c should be absent for self attestation",
    );

    let alg_value = att_stmt_entries
        .iter()
        .find(|(k, _)| match k {
            Value::Text(text) => text == "alg",
            _ => false,
        })
        .and_then(|(_, v)| match v {
            Value::Integer(int) => Some(int.clone()),
            _ => None,
        })
        .expect("alg value present");
    let alg_i128: i128 = alg_value.into();
    assert_eq!(alg_i128, i128::from(CoseAlg::MLDSA44 as i32));

    let signature_bytes = att_stmt_entries
        .iter()
        .find(|(k, _)| match k {
            Value::Text(text) => text == "sig",
            _ => false,
        })
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("sig value present");
    assert!(!signature_bytes.is_empty());
}

#[test]
fn make_credential_can_suppress_attestation() {
    let mut app = CtapApp::new(TestClient::new(), [0xDD; 16]);
    app.suppress_attestation(true);

    let client_hash = vec![0x33; 32];
    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x02]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
        ),
    ])]);

    let make_credential = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);

    let mut payload = Vec::new();
    into_writer(&make_credential, &mut payload).expect("serialize makeCredential request");
    let response = app
        .handle_make_credential(&payload)
        .expect("makeCredential succeeds");
    assert_eq!(response[0], CTAP2_OK);
    assert_eq!(app.stored_credentials.len(), 1);

    let Value::Map(entries) = from_reader(&response[1..]).expect("decode response map") else {
        panic!("response must be a map");
    };
    let fmt_value = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(1)))
        .and_then(|(_, v)| match v {
            Value::Text(text) => Some(text.clone()),
            _ => None,
        })
        .expect("fmt present");
    assert_eq!(fmt_value, "none");

    let auth_data = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("authData present");
    assert!(!auth_data.is_empty());

    let att_stmt_entries = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(3)))
        .and_then(|(_, v)| match v {
            Value::Map(map) => Some(map.clone()),
            _ => None,
        })
        .expect("attStmt present");
    assert!(att_stmt_entries.is_empty());
}

#[test]
fn make_credential_requires_mc_permission() {
    let mut app = CtapApp::new(TestClient::new(), [0x51; 16]);
    let token = [0xAA; 32];
    app.pin_state
        .set_pin_uv_auth_token(token, PIN_PERMISSION_GA, None);

    let client_hash = vec![0xBB; 32];
    let mut mac = HmacSha256::new_from_slice(&token).expect("valid MAC key");
    mac.update(&client_hash);
    let pin_uv_auth_param: Vec<u8> = mac.finalize().into_bytes()[..16].to_vec();

    let rp = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text("example.com".into()),
    )]);
    let user = canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x01]))]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
        ),
    ])]);

    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(client_hash.clone()),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
        (
            Value::Integer(Integer::from(8)),
            Value::Bytes(pin_uv_auth_param),
        ),
        (
            Value::Integer(Integer::from(9)),
            Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC)),
        ),
    ]);

    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize makeCredential request");
    let result = app.handle_make_credential(&payload);
    assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_INVALID));
}
