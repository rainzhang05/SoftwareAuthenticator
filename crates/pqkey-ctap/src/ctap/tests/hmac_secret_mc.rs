//! Creation-time PRF evaluation (CTAP 2.3 §12.8).

use super::support::*;
use crate::crypto::verify::verify_signature;
use crate::ctap::cbor::{canonical_map, map_get};
use crate::ctap::constants::*;
use crate::ctap::pin::permissions::{PIN_PERMISSION_GA, PIN_PERMISSION_MC};
use crate::store::CredentialRecord;
use crate::{ClassicPinProtocol, CoseAlg};
use ciborium::{de::from_reader, value::Value};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub(super) const HASH: [u8; 32] = [0x44; 32];
const TOKEN: [u8; 32] = [0x65; 32];
const RP: &str = "example.com";
const PROTOCOLS: [ClassicPinProtocol; 2] = [ClassicPinProtocol::V1, ClassicPinProtocol::V2];

pub(super) fn text(value: &str) -> Value {
    Value::Text(value.into())
}

pub(super) fn creation_request(
    alg: CoseAlg,
    rk: bool,
    extensions: Value,
    auth: Option<ClassicPinProtocol>,
    user: u8,
) -> Vec<u8> {
    let mut entries = vec![
        (int(1), Value::Bytes(HASH.to_vec())),
        (int(2), canonical_map(vec![(text("id"), text(RP))])),
        (
            int(3),
            canonical_map(vec![(text("id"), Value::Bytes(vec![user]))]),
        ),
        (
            int(4),
            Value::Array(vec![canonical_map(vec![
                (text("type"), text("public-key")),
                (text("alg"), int(i64::from(alg.identifier()))),
            ])]),
        ),
        (int(6), extensions),
        (int(7), canonical_map(vec![(text("rk"), Value::Bool(rk))])),
    ];
    if let Some(protocol) = auth {
        entries.push((
            int(8),
            Value::Bytes(token_pin_auth(protocol, &TOKEN, &HASH)),
        ));
        entries.push((int(9), int(protocol.identifier().into())));
    }
    encode(&canonical_map(entries))
}

pub(super) fn extension_outputs(
    response: &[u8],
    credential: Option<&CredentialRecord>,
) -> Vec<(Value, Value)> {
    let data = response_auth_data(response);
    if data[32] & 0x80 == 0 {
        return Vec::new();
    }
    let offset = credential.map_or(37, |record| {
        55 + record.credential_id.len() + record.cose_public_key().unwrap().len()
    });
    let Value::Map(map) = from_reader(&data[offset..]).unwrap() else {
        panic!("extension map")
    };
    map
}

pub(super) fn verify_response(response: &[u8], credential: &CredentialRecord, creation: bool) {
    let Value::Map(map) = from_reader(&response[1..]).unwrap() else {
        panic!("response map")
    };
    let signature = if creation {
        let Value::Map(statement) = map_get(&map, int(3)).unwrap() else {
            panic!("packed attestation")
        };
        map_get(statement, text("sig")).unwrap()
    } else {
        map_get(&map, int(3)).unwrap()
    };
    let Value::Bytes(signature) = signature else {
        panic!("signature")
    };
    let mut message = response_auth_data(response);
    message.extend_from_slice(&HASH);
    verify_signature(
        credential.alg,
        &credential.cose_public_key().unwrap(),
        &message,
        signature,
    )
    .unwrap();
}

pub(super) fn hmac_input(
    session: &PlatformPinSession,
    salts: &[u8],
    protocol: ClassicPinProtocol,
) -> Value {
    let encrypted = session.encrypt(salts);
    canonical_map(vec![
        (int(1), session.key_agreement.clone()),
        (int(2), Value::Bytes(encrypted.clone())),
        (
            int(3),
            Value::Bytes(platform_authenticate(
                protocol,
                &session.keys.auth_key,
                &encrypted,
            )),
        ),
        (int(4), int(protocol.identifier().into())),
    ])
}

fn registration_extensions(input: Value) -> Value {
    canonical_map(vec![
        (text("hmac-secret"), Value::Bool(true)),
        (text("hmac-secret-mc"), input),
    ])
}

/// §12.8 uses the same CredRandom and salts as §12.7, including sealed IDs.
#[test]
fn creation_and_assertion_prfs_match_for_each_uv_state_and_protocol() {
    for protocol in PROTOCOLS {
        for rk in [false, true] {
            for uv in [false, true] {
                for salt_count in [1, 2] {
                    let mut app = test_app([0x65; 16]);
                    let auth = uv.then_some(protocol);
                    if uv {
                        install_pin_uv_auth_token(
                            &mut app,
                            protocol,
                            TOKEN,
                            PIN_PERMISSION_MC,
                            Some(RP),
                        );
                    }
                    let session = PlatformPinSession::establish(&mut app, protocol, 0x13);
                    let salts: Vec<u8> = (0..32 * salt_count).collect();
                    let input = hmac_input(&session, &salts, protocol);
                    let response = app
                        .handle_make_credential(&creation_request(
                            CoseAlg::ES256,
                            rk,
                            registration_extensions(input),
                            auth,
                            1,
                        ))
                        .unwrap();
                    let credential = created_credential(&app, &response, RP);
                    assert_eq!(stored(&app).len(), usize::from(rk));
                    assert_eq!(response_auth_data(&response)[32] & FLAG_UV != 0, uv);
                    verify_response(&response, &credential, true);
                    let outputs = extension_outputs(&response, Some(&credential));
                    assert_eq!(
                        map_get(&outputs, text("hmac-secret")),
                        Some(&Value::Bool(true))
                    );
                    let Value::Bytes(encrypted) =
                        map_get(&outputs, text("hmac-secret-mc")).unwrap()
                    else {
                        panic!("encrypted output")
                    };
                    let created = session.decrypt(encrypted);
                    let random = if uv {
                        &credential.cred_random_with_uv
                    } else {
                        &credential.cred_random_without_uv
                    };
                    let expected: Vec<u8> = salts
                        .chunks(32)
                        .flat_map(|salt| {
                            let mut mac = Hmac::<Sha256>::new_from_slice(random).unwrap();
                            mac.update(salt);
                            mac.finalize().into_bytes().to_vec()
                        })
                        .collect();
                    assert_eq!(created, expected);
                    assert_eq!(created.len(), usize::from(salt_count) * 32);
                    if uv {
                        install_pin_uv_auth_token(
                            &mut app,
                            protocol,
                            TOKEN,
                            PIN_PERMISSION_GA,
                            Some(RP),
                        );
                    }
                    // The extension protocol need not match the PIN token protocol.
                    let other = if protocol == ClassicPinProtocol::V1 {
                        ClassicPinProtocol::V2
                    } else {
                        ClassicPinProtocol::V1
                    };
                    let session = PlatformPinSession::establish(&mut app, other, 0x14);
                    let extension = canonical_map(vec![(
                        text("hmac-secret"),
                        hmac_input(&session, &salts, other),
                    )]);
                    let request = get_assertion_request(
                        &HASH,
                        RP,
                        auth.map(|p| (p, token_pin_auth(p, &TOKEN, &HASH))),
                        Some(extension),
                    );
                    // Supply the sealed credential ID; discoverable enumeration works without it.
                    let Value::Map(mut entries) = from_reader(&request[..]).unwrap() else {
                        panic!("request map")
                    };
                    entries.push((
                        int(3),
                        Value::Array(vec![canonical_map(vec![
                            (text("type"), text("public-key")),
                            (text("id"), Value::Bytes(credential.credential_id.clone())),
                        ])]),
                    ));
                    let response = app
                        .handle_get_assertion(&encode(&canonical_map(entries)))
                        .unwrap();
                    verify_response(&response, &credential, false);
                    let outputs = extension_outputs(&response, None);
                    let Value::Bytes(encrypted) = map_get(&outputs, text("hmac-secret")).unwrap()
                    else {
                        panic!("encrypted output")
                    };
                    assert_eq!(session.decrypt(encrypted), created);
                }
            }
        }
    }
}

#[test]
fn creation_requires_true_hmac_secret_and_reports_typed_input_errors() {
    let key = canonical_map(vec![]);
    for (input, expected) in [
        (Value::Bool(true), CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
        (canonical_map(vec![]), CTAP2_ERR_MISSING_PARAMETER),
        (
            canonical_map(vec![(int(1), Value::Bool(true))]),
            CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
        ),
        (
            canonical_map(vec![(int(1), key.clone()), (int(2), Value::Bool(true))]),
            CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
        ),
        (
            canonical_map(vec![(int(1), key.clone()), (int(2), Value::Bytes(vec![]))]),
            CTAP2_ERR_MISSING_PARAMETER,
        ),
        (
            canonical_map(vec![
                (int(1), key),
                (int(2), Value::Bytes(vec![])),
                (int(3), Value::Bool(true)),
            ]),
            CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
        ),
    ] {
        let mut app = test_app([0x65; 16]);
        assert_eq!(
            app.handle_make_credential(&creation_request(
                CoseAlg::ES256,
                true,
                registration_extensions(input),
                None,
                1
            )),
            Err(expected)
        );
        assert!(stored(&app).is_empty());
    }
    for companion in [None, Some(Value::Bool(false))] {
        let mut entries = vec![(text("hmac-secret-mc"), Value::Bool(true))];
        if let Some(value) = companion {
            entries.push((text("hmac-secret"), value));
        }
        let mut app = test_app([0x65; 16]);
        assert_eq!(
            app.handle_make_credential(&creation_request(
                CoseAlg::ES256,
                true,
                canonical_map(entries),
                None,
                1
            )),
            Err(CTAP2_ERR_MISSING_PARAMETER)
        );
    }
}

#[test]
fn creation_reuses_salt_authentication_decryption_and_key_errors() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0x65; 16]);
        let session = PlatformPinSession::establish(&mut app, protocol, 0x13);
        let Value::Map(valid) = hmac_input(&session, &[0x98; 32], protocol) else {
            panic!("input map")
        };
        let mut cases = Vec::new();
        for length in [0, 15, 16, 31, 32, 33] {
            cases.push((3, Value::Bytes(vec![0; length]), CTAP2_ERR_PIN_AUTH_INVALID));
        }
        for value in [int(0), int(3), int(-1)] {
            cases.push((4, value, CTAP1_ERR_INVALID_PARAMETER));
        }
        cases.push((4, Value::Bool(true), CTAP2_ERR_CBOR_UNEXPECTED_TYPE));
        cases.push((1, canonical_map(vec![]), CTAP1_ERR_INVALID_PARAMETER));
        for (key, value, expected) in cases {
            let mut entries = valid.clone();
            entries.iter_mut().find(|(k, _)| *k == int(key)).unwrap().1 = value;
            assert_eq!(
                app.handle_make_credential(&creation_request(
                    CoseAlg::ES256,
                    true,
                    registration_extensions(canonical_map(entries)),
                    None,
                    1
                )),
                Err(expected),
                "{protocol:?}, field {key}"
            );
            assert!(stored(&app).is_empty());
        }
        for length in [0, 16, 48, 80] {
            let input = hmac_input(&session, &vec![0x98; length], protocol);
            assert_eq!(
                app.handle_make_credential(&creation_request(
                    CoseAlg::ES256,
                    true,
                    registration_extensions(input),
                    None,
                    1
                )),
                Err(CTAP1_ERR_INVALID_PARAMETER)
            );
        }
        let mut bad_key = valid.clone();
        let Value::Map(key) = &mut bad_key[0].1 else {
            panic!("key")
        };
        for (label, value) in key {
            if *label == int(-2) || *label == int(-3) {
                *value = Value::Bytes(vec![0; 32]);
            }
        }
        assert_eq!(
            app.handle_make_credential(&creation_request(
                CoseAlg::ES256,
                true,
                registration_extensions(canonical_map(bad_key)),
                None,
                1
            )),
            Err(CTAP1_ERR_INVALID_PARAMETER)
        );
        let mut truncated = valid.clone();
        let ciphertext = vec![0x98; 17];
        truncated.iter_mut().find(|(k, _)| *k == int(2)).unwrap().1 =
            Value::Bytes(ciphertext.clone());
        truncated.iter_mut().find(|(k, _)| *k == int(3)).unwrap().1 = Value::Bytes(
            platform_authenticate(protocol, &session.keys.auth_key, &ciphertext),
        );
        assert_eq!(
            app.handle_make_credential(&creation_request(
                CoseAlg::ES256,
                true,
                registration_extensions(canonical_map(truncated)),
                None,
                1
            )),
            Err(CTAP1_ERR_INVALID_PARAMETER)
        );
        assert!(stored(&app).is_empty());
    }
}

#[test]
fn omitted_protocol_defaults_to_one_and_rsa_keeps_creation_secrets() {
    for alg in [CoseAlg::ES256, CoseAlg::RS256] {
        let mut app = test_app([0x65; 16]);
        let session = PlatformPinSession::establish(&mut app, ClassicPinProtocol::V1, 0x13);
        let Value::Map(mut input) = hmac_input(&session, &[0x98; 32], ClassicPinProtocol::V1)
        else {
            panic!("input")
        };
        input.retain(|(key, _)| *key != int(4));
        let response = app
            .handle_make_credential(&creation_request(
                alg,
                false,
                registration_extensions(canonical_map(input)),
                None,
                1,
            ))
            .unwrap();
        let credential = created_credential(&app, &response, RP);
        verify_response(&response, &credential, true);
        let outputs = extension_outputs(&response, Some(&credential));
        let Value::Bytes(encrypted) = map_get(&outputs, text("hmac-secret-mc")).unwrap() else {
            panic!("output")
        };
        assert_eq!(session.decrypt(encrypted).len(), 32);
        assert_eq!(stored(&app).len(), usize::from(alg == CoseAlg::RS256));
    }
}

/// Command PIN authorization selects UV; the extension protocol only protects
/// its transport (§§6.1.2, 12.8). No token means no UV, even with a PIN set.
#[test]
fn creation_uv_depends_on_authorization_and_preserves_cred_protect() {
    let mut app = test_app([0x65; 16]);
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        TOKEN,
        PIN_PERMISSION_MC,
        Some(RP),
    );
    let session = PlatformPinSession::establish(&mut app, ClassicPinProtocol::V1, 0x13);
    let mut extensions = vec![
        (text("hmac-secret"), Value::Bool(true)),
        (
            text("hmac-secret-mc"),
            hmac_input(&session, &[0x98; 32], ClassicPinProtocol::V1),
        ),
        (text("credProtect"), int(3)),
    ];
    let response = app
        .handle_make_credential(&creation_request(
            CoseAlg::ES256,
            true,
            canonical_map(extensions.clone()),
            Some(ClassicPinProtocol::V2),
            1,
        ))
        .unwrap();
    let credential = created_credential(&app, &response, RP);
    assert_eq!(credential.cred_protect, 3);
    assert_ne!(response_auth_data(&response)[32] & FLAG_UV, 0);
    assert_eq!(
        map_get(
            &extension_outputs(&response, Some(&credential)),
            text("credProtect")
        ),
        Some(&int(3))
    );
    extensions.retain(|(key, _)| *key != text("credProtect"));
    let response = app
        .handle_make_credential(&creation_request(
            CoseAlg::ES256,
            false,
            canonical_map(extensions),
            None,
            2,
        ))
        .unwrap();
    assert_eq!(response_auth_data(&response)[32] & FLAG_UV, 0);
    let mut app = test_app([0x65; 16]);
    for flag in [None, Some(false), Some(true)] {
        let extensions = flag.map_or_else(
            || canonical_map(vec![]),
            |flag| canonical_map(vec![(text("hmac-secret"), Value::Bool(flag))]),
        );
        let response = app
            .handle_make_credential(&creation_request(
                CoseAlg::ES256,
                false,
                extensions,
                None,
                1,
            ))
            .unwrap();
        let credential = created_credential(&app, &response, RP);
        let outputs = extension_outputs(&response, Some(&credential));
        assert_eq!(outputs.len(), usize::from(flag == Some(true)));
        assert!(map_get(&outputs, text("hmac-secret-mc")).is_none());
    }
}
