//! authenticatorMakeCredential tests.

use super::support::new_app;
use super::support::{TestStore, install_pin_uv_auth_token, token_pin_auth};
use super::support::{created_credential, stored};
use crate::ctap::AttestationMode;
use crate::ctap::cbor::canonical_map;
use crate::ctap::make_credential::COSE_ALG_ES256;
use crate::ctap::pin::permissions::{PIN_PERMISSION_GA, PIN_PERMISSION_MC};
use crate::ctap::pin::protocol::PIN_UV_AUTH_PROTOCOL_CLASSIC;
use crate::store::{AttestationRecord, PrivateKeyMaterial};
use crate::{ClassicPinProtocol, CoseAlg, CredentialSecretKey};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use p256::ecdsa::{Signature as P256EcdsaSignature, SigningKey, signature::Signer};

use crate::ctap::constants::*;

#[test]
fn make_credential_includes_extensions() {
    let mut app = new_app(TestStore::new(), [0xAA; 16]);
    let client_hash = vec![0xBB; 32];
    let pin_token = [0xCC; 32];
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        pin_token,
        PIN_PERMISSION_MC | PIN_PERMISSION_GA,
        None,
    );

    let pin_uv_auth_param = token_pin_auth(ClassicPinProtocol::V2, &pin_token, &client_hash);

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

    let credential = created_credential(&app, &response, "example.com");
    assert_eq!(credential.cred_protect, 3);
    assert_ne!(
        credential.cred_random_with_uv, credential.cred_random_without_uv,
        "the two CredRandom values are independent"
    );
    let public_key = credential.cose_public_key().expect("derive public key");

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
    offset += public_key.len();

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
            Value::Integer(int) => Some((*int).into()),
            _ => None,
        })
        .expect("credProtect extension present");
    assert_eq!(cred_protect_value, 3);
}

#[test]
fn make_credential_supports_es256() {
    let mut app = new_app(TestStore::new(), [0x01; 16]);
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

    let credential = created_credential(&app, &response, "example.com");
    assert_eq!(credential.alg, CoseAlg::ES256);
    assert!(matches!(
        credential.private_key,
        PrivateKeyMaterial::Es256 { .. }
    ));
    let public_key = credential.cose_public_key().expect("derive public key");

    let Value::Map(entries) = from_reader(public_key.as_slice()).expect("decode ES256 COSE key")
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
            let label_value: i128 = label.into();
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

    let reconstructed = credential
        .secret_key()
        .expect("reconstruct ES256 secret key");
    match reconstructed {
        CredentialSecretKey::Es256(_) => {}
        _ => panic!("expected ES256 secret key variant"),
    }
}

#[test]
fn make_credential_uses_attestation_certificate_when_available() {
    let mut app = new_app(TestStore::new(), [0xAB; 16]);
    app.set_attestation_mode(AttestationMode::Certificate);
    let att_key_bytes = vec![0x13; 32];
    let certificate = vec![0x30, 0x82, 0x00, 0x01];
    app.store
        .set_attestation(&AttestationRecord {
            private_key: att_key_bytes.as_slice().try_into().expect("32 bytes"),
            certificate_chain: vec![certificate.clone()],
        })
        .expect("provision attestation");

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
            Value::Integer(int) => Some(*int),
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
    let mut app = new_app(TestStore::new(), [0xCD; 16]);
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
            Value::Integer(int) => Some(*int),
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
fn make_credential_can_omit_attestation() {
    let mut app = new_app(TestStore::new(), [0xDD; 16]);
    app.set_attestation_mode(AttestationMode::None);

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
    created_credential(&app, &response, "example.com");

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
    let mut app = new_app(TestStore::new(), [0x51; 16]);
    let token = [0xAA; 32];
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        token,
        PIN_PERMISSION_GA,
        None,
    );

    let client_hash = vec![0xBB; 32];
    let pin_uv_auth_param = token_pin_auth(ClassicPinProtocol::V2, &token, &client_hash);

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

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn param(credential_type: &str, alg: Value) -> Value {
    canonical_map(vec![
        (text("type"), text(credential_type)),
        (text("alg"), alg),
    ])
}

fn public_key(alg: i64) -> Value {
    param("public-key", Value::Integer(Integer::from(alg)))
}

/// A makeCredential request with `pub_key_cred_params` and, if given, an
/// excludeList.
fn request_with_params(pub_key_cred_params: Vec<Value>, exclude_list: Option<Value>) -> Vec<u8> {
    let mut entries = vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(vec![0x5C; 32]),
        ),
        (
            Value::Integer(Integer::from(2)),
            canonical_map(vec![(text("id"), text("example.com"))]),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(vec![(text("id"), Value::Bytes(vec![0x01]))]),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Array(pub_key_cred_params),
        ),
    ];
    if let Some(exclude_list) = exclude_list {
        entries.push((Value::Integer(Integer::from(5)), exclude_list));
    }
    let mut payload = Vec::new();
    into_writer(&canonical_map(entries), &mut payload).expect("serialize makeCredential");
    payload
}

/// "If the element specifies an algorithm that is supported by the
/// authenticator, and no algorithm has yet been chosen by this loop, then let
/// the algorithm specified by the current element be the chosen algorithm."
/// (CTAP 2.3 §6.1.2 step 3.1.3)
#[test]
fn make_credential_chooses_the_first_supported_algorithm_in_rp_order() {
    for (params, expected) in [
        (
            vec![public_key(-8), public_key(-49), public_key(-7)],
            CoseAlg::MLDSA65,
        ),
        (
            vec![public_key(-257), public_key(-7), public_key(-50)],
            CoseAlg::ES256,
        ),
        (vec![public_key(-50), public_key(-7)], CoseAlg::MLDSA87),
    ] {
        let mut app = new_app(TestStore::new(), [0x71; 16]);
        let response = app
            .handle_make_credential(&request_with_params(params, None))
            .expect("makeCredential succeeds");
        assert_eq!(
            created_credential(&app, &response, "example.com").alg,
            expected
        );
    }
}

/// An alg outside `i32` whose low 32 bits read -7 is not ES256, an element of
/// another credential type is not a supported algorithm, and ESP256 (-9) is
/// not treated as ES256.
#[test]
fn make_credential_rejects_algorithms_it_does_not_support() {
    for params in [
        vec![public_key((1_i64 << 32) - 7)],
        vec![public_key(-(1_i64 << 32) - 7)],
        vec![param("not-public-key", Value::Integer(Integer::from(-7)))],
        vec![public_key(-9)],
        vec![],
    ] {
        let mut app = new_app(TestStore::new(), [0x72; 16]);
        assert_eq!(
            app.handle_make_credential(&request_with_params(params.clone(), None)),
            Err(CTAP2_ERR_UNSUPPORTED_ALGORITHM),
            "{params:?}"
        );
        assert!(stored(&app).is_empty());
    }
}

/// "This loop chooses the first occurrence of an algorithm identifier
/// supported by this authenticator but always iterates over every element of
/// pubKeyCredParams to validate them." (CTAP 2.3 §6.1.2 step 3)
#[test]
fn make_credential_validates_every_pub_key_cred_params_element() {
    let missing_alg = canonical_map(vec![(text("type"), text("public-key"))]);
    let missing_type = canonical_map(vec![(text("alg"), Value::Integer(Integer::from(-7)))]);
    for (params, status) in [
        (vec![public_key(-7), missing_alg], CTAP2_ERR_INVALID_CBOR),
        (vec![public_key(-7), missing_type], CTAP2_ERR_INVALID_CBOR),
        (
            vec![public_key(-7), param("public-key", text("-7"))],
            CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
        ),
        (
            vec![public_key(-7), Value::Integer(Integer::from(-7))],
            CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
        ),
    ] {
        let mut app = new_app(TestStore::new(), [0x73; 16]);
        assert_eq!(
            app.handle_make_credential(&request_with_params(params.clone(), None)),
            Err(status),
            "{params:?}"
        );
    }
}

/// A descriptor whose type is not "public-key" does not denote one of this
/// authenticator's credentials, whatever its id.
#[test]
fn make_credential_exclude_list_ignores_other_credential_types() {
    let mut app = new_app(TestStore::new(), [0x74; 16]);
    let response = app
        .handle_make_credential(&request_with_params(vec![public_key(-7)], None))
        .expect("first registration");
    let existing = created_credential(&app, &response, "example.com")
        .credential_id
        .clone();

    let descriptor = |credential_type: &str| {
        Value::Array(vec![canonical_map(vec![
            (text("type"), text(credential_type)),
            (text("id"), Value::Bytes(existing.clone())),
        ])])
    };
    let response = app
        .handle_make_credential(&request_with_params(
            vec![public_key(-7)],
            Some(descriptor("not-public-key")),
        ))
        .expect("the excludeList names no credential of this authenticator");
    assert_eq!(response[0], CTAP2_OK);
    assert_eq!(
        app.handle_make_credential(&request_with_params(
            vec![public_key(-7)],
            Some(descriptor("public-key")),
        )),
        Err(CTAP2_ERR_CREDENTIAL_EXCLUDED)
    );
}
