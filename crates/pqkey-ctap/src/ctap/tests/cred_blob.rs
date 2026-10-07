//! Credential blob storage and retrieval (CTAP 2.3 §12.2).

use super::hmac_secret_mc::{
    HASH, creation_request, extension_outputs, hmac_input, text, verify_response,
};
use super::support::*;
use crate::ctap::cbor::{canonical_map, map_get};
use crate::ctap::constants::*;
use crate::ctap::pin::permissions::{PIN_PERMISSION_GA, PIN_PERMISSION_MC};
use crate::store::CredentialRecord;
use crate::{ClassicPinProtocol, CoseAlg};
use ciborium::{de::from_reader, value::Value};

const RP: &str = "example.com";
const TOKEN: [u8; 32] = [0x65; 32];

fn assertion_request(
    credential: Option<&CredentialRecord>,
    extensions: Value,
    auth: Option<ClassicPinProtocol>,
) -> Vec<u8> {
    let request = get_assertion_request(
        &HASH,
        RP,
        auth.map(|protocol| (protocol, token_pin_auth(protocol, &TOKEN, &HASH))),
        Some(extensions),
    );
    let Value::Map(mut entries) = from_reader(&request[..]).unwrap() else {
        panic!("map")
    };
    if let Some(credential) = credential {
        entries.push((
            int(3),
            Value::Array(vec![canonical_map(vec![
                (text("type"), text("public-key")),
                (text("id"), Value::Bytes(credential.credential_id.clone())),
            ])]),
        ));
    }
    encode(&canonical_map(entries))
}

fn retrieval() -> Value {
    canonical_map(vec![(text("credBlob"), Value::Bool(true))])
}

#[test]
fn stored_credentials_accept_bounded_blobs_and_sealed_credentials_refuse_them() {
    for (alg, rk, stored_credential) in [
        (CoseAlg::ES256, true, true),
        (CoseAlg::ES256, false, false),
        (CoseAlg::RS256, false, true),
    ] {
        for length in [0, 1, 32, 33] {
            let mut app = test_app([0x73; 16]);
            let blob: Vec<u8> = (0..length).collect();
            let response = app
                .handle_make_credential(&creation_request(
                    alg,
                    rk,
                    canonical_map(vec![(text("credBlob"), Value::Bytes(blob.clone()))]),
                    None,
                    1,
                ))
                .unwrap();
            let credential = created_credential(&app, &response, RP);
            let accepted = stored_credential && length <= 32;
            assert_eq!(credential.cred_blob, accepted.then(|| blob.clone()));
            assert_eq!(
                map_get(
                    &extension_outputs(&response, Some(&credential)),
                    text("credBlob")
                ),
                Some(&Value::Bool(accepted))
            );
            assert_eq!(stored(&app).len(), usize::from(stored_credential));
            verify_response(&response, &credential, true);
            let response = app
                .handle_get_assertion(&assertion_request(Some(&credential), retrieval(), None))
                .unwrap();
            verify_response(&response, &credential, false);
            assert_eq!(
                map_get(&extension_outputs(&response, None), text("credBlob")),
                Some(&Value::Bytes(if accepted { blob } else { Vec::new() }))
            );
            assert_eq!(
                created_credential_blob(&app, &credential),
                credential.cred_blob
            );
        }
    }
}

fn created_credential_blob(app: &TestApp, credential: &CredentialRecord) -> Option<Vec<u8>> {
    app.credential_for_rp(&credential.credential_id, RP)
        .unwrap()
        .unwrap()
        .cred_blob
        .clone()
}

#[test]
fn absent_blobs_and_unrequested_outputs_are_distinct_from_empty_blob_storage() {
    let mut app = test_app([0x73; 16]);
    let response = app
        .handle_make_credential(&creation_request(
            CoseAlg::ES256,
            true,
            canonical_map(vec![]),
            None,
            1,
        ))
        .unwrap();
    let credential = created_credential(&app, &response, RP);
    assert!(credential.cred_blob.is_none());
    assert!(extension_outputs(&response, Some(&credential)).is_empty());
    let response = app
        .handle_get_assertion(&assertion_request(Some(&credential), retrieval(), None))
        .unwrap();
    assert_eq!(
        map_get(&extension_outputs(&response, None), text("credBlob")),
        Some(&Value::Bytes(Vec::new()))
    );
    for extensions in [
        canonical_map(vec![]),
        canonical_map(vec![(text("credBlob"), Value::Bool(false))]),
    ] {
        let response = app
            .handle_get_assertion(&assertion_request(Some(&credential), extensions, None))
            .unwrap();
        assert!(extension_outputs(&response, None).is_empty());
        assert_eq!(response_auth_data(&response)[32] & 0x80, 0);
    }
}

#[test]
fn blob_inputs_have_command_specific_types() {
    for input in [
        Value::Bool(true),
        int(1),
        text("blob"),
        Value::Array(vec![]),
        Value::Null,
    ] {
        let mut app = test_app([0x73; 16]);
        assert_eq!(
            app.handle_make_credential(&creation_request(
                CoseAlg::ES256,
                true,
                canonical_map(vec![(text("credBlob"), input)]),
                None,
                1
            )),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert!(stored(&app).is_empty());
    }
    for input in [Value::Bytes(vec![]), int(1), text("true"), Value::Null] {
        let mut app = test_app([0x73; 16]);
        assert_eq!(
            app.handle_get_assertion(&assertion_request(
                None,
                canonical_map(vec![(text("credBlob"), input)]),
                None
            )),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
    }
}

#[test]
fn retrieval_follows_cred_protect_for_both_pin_protocols() {
    for protocol in [ClassicPinProtocol::V1, ClassicPinProtocol::V2] {
        for policy in 1..=3 {
            for uv in [false, true] {
                for allow_list in [false, true] {
                    let mut app = test_app([0x73; 16]);
                    let response = app
                        .handle_make_credential(&creation_request(
                            CoseAlg::ES256,
                            true,
                            canonical_map(vec![
                                (text("credBlob"), Value::Bytes(vec![0x73; 32])),
                                (text("credProtect"), int(policy)),
                            ]),
                            None,
                            1,
                        ))
                        .unwrap();
                    let credential = created_credential(&app, &response, RP);
                    if uv {
                        install_pin_uv_auth_token(
                            &mut app,
                            protocol,
                            TOKEN,
                            PIN_PERMISSION_GA,
                            Some(RP),
                        );
                    }
                    let result = app.handle_get_assertion(&assertion_request(
                        allow_list.then_some(&credential),
                        retrieval(),
                        uv.then_some(protocol),
                    ));
                    let allowed = uv || policy == 1 || (policy == 2 && allow_list);
                    if allowed {
                        let response = result.unwrap();
                        assert_eq!(response_auth_data(&response)[32] & FLAG_UV != 0, uv);
                        assert_eq!(
                            map_get(&extension_outputs(&response, None), text("credBlob")),
                            Some(&Value::Bytes(vec![0x73; 32]))
                        );
                        verify_response(&response, &credential, false);
                    } else {
                        assert_eq!(result, Err(CTAP2_ERR_NO_CREDENTIALS));
                    }
                }
            }
        }
    }
}

#[test]
fn combined_extensions_and_next_assertions_return_each_credentials_blob() {
    let mut app = test_app([0x73; 16]);
    let protocol = ClassicPinProtocol::V2;
    let mut credentials = Vec::new();
    let session = PlatformPinSession::establish(&mut app, protocol, 0x13);
    let salts = [0x98; 64];
    for user in [1, 2] {
        install_pin_uv_auth_token(&mut app, protocol, TOKEN, PIN_PERMISSION_MC, Some(RP));
        let response = app
            .handle_make_credential(&creation_request(
                CoseAlg::ES256,
                true,
                canonical_map(vec![
                    (text("credBlob"), Value::Bytes(vec![user; 32])),
                    (text("credProtect"), int(3)),
                    (text("hmac-secret"), Value::Bool(true)),
                    (
                        text("hmac-secret-mc"),
                        hmac_input(&session, &salts, protocol),
                    ),
                ]),
                Some(protocol),
                user,
            ))
            .unwrap();
        let credential = created_credential(&app, &response, RP);
        let outputs = extension_outputs(&response, Some(&credential));
        assert_eq!(outputs.len(), 4);
        let Value::Bytes(encrypted) = map_get(&outputs, text("hmac-secret-mc")).unwrap() else {
            panic!("HMAC")
        };
        credentials.push((credential, session.decrypt(encrypted)));
    }
    install_pin_uv_auth_token(&mut app, protocol, TOKEN, PIN_PERMISSION_GA, Some(RP));
    let response = app
        .handle_get_assertion(&assertion_request(
            None,
            canonical_map(vec![
                (text("credBlob"), Value::Bool(true)),
                (text("hmac-secret"), hmac_input(&session, &salts, protocol)),
            ]),
            Some(protocol),
        ))
        .unwrap();
    let next = app.handle_get_next_assertion().unwrap();
    for (response, (credential, created)) in [response, next].iter().zip(credentials.iter().rev()) {
        let outputs = extension_outputs(response, None);
        assert_eq!(outputs.len(), 2);
        assert_eq!(
            map_get(&outputs, text("credBlob")),
            Some(&Value::Bytes(credential.cred_blob.clone().unwrap()))
        );
        let Value::Bytes(encrypted) = map_get(&outputs, text("hmac-secret")).unwrap() else {
            panic!("HMAC")
        };
        assert_eq!(session.decrypt(encrypted), *created);
        verify_response(response, credential, false);
    }
    assert_eq!(app.handle_get_next_assertion(), Err(CTAP2_ERR_NOT_ALLOWED));
}

#[test]
fn blob_only_assertions_allow_up_false_and_reset_erases_the_blob() {
    let mut app = test_app([0x73; 16]);
    let response = app
        .handle_make_credential(&creation_request(
            CoseAlg::ES256,
            true,
            canonical_map(vec![(text("credBlob"), Value::Bytes(vec![0x73; 32]))]),
            None,
            1,
        ))
        .unwrap();
    let credential = created_credential(&app, &response, RP);
    let Value::Map(mut entries) =
        from_reader(&assertion_request(Some(&credential), retrieval(), None)[..]).unwrap()
    else {
        panic!("map")
    };
    entries.push((
        int(5),
        canonical_map(vec![(text("up"), Value::Bool(false))]),
    ));
    let response = app
        .handle_get_assertion(&encode(&canonical_map(entries)))
        .unwrap();
    assert_eq!(response_auth_data(&response)[32] & 0x01, 0);
    assert_eq!(
        map_get(&extension_outputs(&response, None), text("credBlob")),
        Some(&Value::Bytes(vec![0x73; 32]))
    );
    app.handle_reset().unwrap();
    assert!(stored(&app).is_empty());
    assert_eq!(
        app.handle_get_assertion(&assertion_request(Some(&credential), retrieval(), None)),
        Err(CTAP2_ERR_NO_CREDENTIALS)
    );
}

#[test]
fn replacing_an_account_replaces_its_blob() {
    let mut app = test_app([0x73; 16]);
    let response = app
        .handle_make_credential(&creation_request(
            CoseAlg::ES256,
            true,
            canonical_map(vec![(text("credBlob"), Value::Bytes(vec![0x73; 32]))]),
            None,
            1,
        ))
        .unwrap();
    let first = created_credential(&app, &response, RP);
    let response = app
        .handle_make_credential(&creation_request(
            CoseAlg::ES256,
            true,
            canonical_map(vec![(text("credBlob"), Value::Bytes(Vec::new()))]),
            None,
            1,
        ))
        .unwrap();
    let replaced = created_credential(&app, &response, RP);
    assert_eq!(replaced.cred_blob, Some(Vec::new()));
    assert_eq!(stored(&app).len(), 1);
    assert_eq!(
        app.handle_get_assertion(&assertion_request(Some(&first), retrieval(), None)),
        Err(CTAP2_ERR_NO_CREDENTIALS)
    );
}
