//! Large-blob keys stay with discoverable credentials (CTAP 2.3 §12.3).

use super::hmac_secret_mc::{HASH, creation_request, extension_outputs, text, verify_response};
use super::support::*;
use crate::ctap::cbor::{canonical_map, map_get};
use crate::ctap::constants::*;
use crate::ctap::pin::permissions::{PIN_PERMISSION_CM, PIN_PERMISSION_GA, PIN_PERMISSION_MC};
use crate::ctap::presence::PresenceOutcome;
use crate::store::CredentialRecord;
use crate::{ClassicPinProtocol, CoseAlg};
use ciborium::{de::from_reader, value::Value};

const RP: &str = "example.com";
const TOKEN: [u8; 32] = [0x65; 32];

fn extensions(input: Value) -> Value {
    canonical_map(vec![(text("largeBlobKey"), input)])
}

fn parameter(request: &[u8], key: i64, value: Option<Value>) -> Vec<u8> {
    let Value::Map(mut entries) = from_reader(request).unwrap() else {
        panic!("request map")
    };
    entries.retain(|(existing, _)| *existing != int(key));
    if let Some(value) = value {
        entries.push((int(key), value));
    }
    encode(&canonical_map(entries))
}

fn response_key(response: &[u8], member: i64) -> Option<Vec<u8>> {
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(entries) = from_reader(&response[1..]).unwrap() else {
        panic!("response map")
    };
    match map_get(&entries, int(member)) {
        Some(Value::Bytes(key)) => {
            assert_eq!(key.len(), 32);
            Some(key.clone())
        }
        None => None,
        Some(_) => panic!("largeBlobKey byte string"),
    }
}

fn assertion_request(
    credential: Option<&CredentialRecord>,
    input: Option<Value>,
    auth: Option<ClassicPinProtocol>,
) -> Vec<u8> {
    let request = get_assertion_request(
        &HASH,
        RP,
        auth.map(|protocol| (protocol, token_pin_auth(protocol, &TOKEN, &HASH))),
        input.map(extensions),
    );
    if let Some(credential) = credential {
        parameter(
            &request,
            3,
            Some(Value::Array(vec![descriptor(credential)])),
        )
    } else {
        request
    }
}

fn descriptor(credential: &CredentialRecord) -> Value {
    canonical_map(vec![
        (text("type"), text("public-key")),
        (text("id"), Value::Bytes(credential.credential_id.clone())),
    ])
}

fn create(app: &mut TestApp, requested: bool, user: u8) -> (CredentialRecord, Vec<u8>) {
    let response = app
        .handle_make_credential(&creation_request(
            CoseAlg::ES256,
            true,
            if requested {
                extensions(Value::Bool(true))
            } else {
                canonical_map(vec![])
            },
            None,
            user,
        ))
        .unwrap();
    let credential = created_credential(app, &response, RP);
    (credential, response)
}

#[test]
fn creation_returns_a_fresh_key_outside_authenticator_data() {
    let mut app = test_app([0x75; 16]);
    let (first, response) = create(&mut app, true, 1);
    assert_eq!(
        response_key(&response, 5),
        first.large_blob_key.map(Vec::from)
    );
    assert!(first.large_blob_key.is_some());
    assert!(extension_outputs(&response, Some(&first)).is_empty());
    assert_eq!(response_auth_data(&response)[32] & 0x80, 0);
    verify_response(&response, &first, true);
    let (second, response) = create(&mut app, true, 2);
    assert_eq!(
        response_key(&response, 5),
        second.large_blob_key.map(Vec::from)
    );
    assert_ne!(first.large_blob_key, second.large_blob_key);
}

#[test]
fn creation_requires_true_and_an_explicit_discoverable_option() {
    for input in [
        Value::Bool(false),
        int(1),
        text("true"),
        Value::Bytes(vec![1; 32]),
        Value::Array(vec![]),
        Value::Map(vec![]),
        Value::Null,
    ] {
        let mut app = test_app([0x75; 16]);
        assert_eq!(
            app.handle_make_credential(&creation_request(
                CoseAlg::ES256,
                true,
                extensions(input),
                None,
                1,
            )),
            Err(CTAP2_ERR_INVALID_OPTION)
        );
        assert!(stored(&app).is_empty());
    }
    for alg in [CoseAlg::ES256, CoseAlg::RS256] {
        for explicit in [false, true] {
            let mut app = test_app([0x75; 16]);
            let request = creation_request(alg, false, extensions(Value::Bool(true)), None, 1);
            let request = if explicit {
                request
            } else {
                parameter(&request, 7, None)
            };
            assert_eq!(
                app.handle_make_credential(&request),
                Err(CTAP2_ERR_INVALID_OPTION)
            );
            assert!(stored(&app).is_empty());
        }
    }
}

#[test]
fn absent_creation_input_generates_and_returns_no_key() {
    for (alg, rk) in [
        (CoseAlg::ES256, true),
        (CoseAlg::ES256, false),
        (CoseAlg::RS256, false),
    ] {
        let mut app = test_app([0x75; 16]);
        let request = parameter(
            &creation_request(alg, rk, canonical_map(vec![]), None, 1),
            6,
            None,
        );
        let response = app.handle_make_credential(&request).unwrap();
        let credential = created_credential(&app, &response, RP);
        assert!(credential.large_blob_key.is_none());
        assert_eq!(response_key(&response, 5), None);
        let response = app
            .handle_get_assertion(&assertion_request(
                Some(&credential),
                Some(Value::Bool(true)),
                None,
            ))
            .unwrap();
        assert_eq!(response_key(&response, 7), None);
        verify_response(&response, &credential, false);
    }
}

#[test]
fn creation_checks_selection_authentication_exclusion_and_presence_first() {
    let invalid = creation_request(
        CoseAlg::ES256,
        true,
        extensions(Value::Bool(false)),
        None,
        1,
    );
    let mut app = test_app([0x75; 16]);
    assert_eq!(
        app.handle_make_credential(&parameter(&invalid, 8, Some(Value::Bytes(vec![])))),
        Err(CTAP2_ERR_PIN_NOT_SET)
    );
    app.pin_state.set_pin(pin_hash(b"1234"));
    assert_eq!(
        app.handle_make_credential(&invalid),
        Err(CTAP2_ERR_PUAT_REQUIRED)
    );
    for protocol in [ClassicPinProtocol::V1, ClassicPinProtocol::V2] {
        install_pin_uv_auth_token(&mut app, protocol, TOKEN, PIN_PERMISSION_MC, Some(RP));
        let request = creation_request(
            CoseAlg::ES256,
            true,
            extensions(Value::Bool(false)),
            Some(protocol),
            1,
        );
        let request = parameter(
            &request,
            8,
            Some(Value::Bytes(corrupt_mac(token_pin_auth(
                protocol, &TOKEN, &HASH,
            )))),
        );
        assert_eq!(
            app.handle_make_credential(&request),
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }
    let mut app = test_app([0x75; 16]);
    let (credential, _) = create(&mut app, true, 1);
    let excluded = parameter(
        &invalid,
        5,
        Some(Value::Array(vec![descriptor(&credential)])),
    );
    assert_eq!(
        app.handle_make_credential(&excluded),
        Err(CTAP2_ERR_CREDENTIAL_EXCLUDED)
    );
    let (mut app, log) = scripted_app([0x75; 16], [PresenceOutcome::Denied]);
    assert_eq!(
        app.handle_make_credential(&invalid),
        Err(CTAP2_ERR_OPERATION_DENIED)
    );
    assert!(!log.take().is_empty());
    assert!(stored(&app).is_empty());
}

#[test]
fn assertions_return_the_stored_key_only_when_requested() {
    for protocol in [
        None,
        Some(ClassicPinProtocol::V1),
        Some(ClassicPinProtocol::V2),
    ] {
        for allow_list in [false, true] {
            let mut app = test_app([0x75; 16]);
            let (credential, _) = create(&mut app, true, 1);
            for requested in [false, true, true] {
                if let Some(protocol) = protocol {
                    install_pin_uv_auth_token(
                        &mut app,
                        protocol,
                        TOKEN,
                        PIN_PERMISSION_GA,
                        Some(RP),
                    );
                }
                let response = app
                    .handle_get_assertion(&assertion_request(
                        allow_list.then_some(&credential),
                        requested.then_some(Value::Bool(true)),
                        protocol,
                    ))
                    .unwrap();
                assert_eq!(
                    response_key(&response, 7),
                    requested.then(|| credential.large_blob_key.unwrap().to_vec()),
                );
                assert!(extension_outputs(&response, None).is_empty());
                assert_eq!(response_auth_data(&response)[32] & 0x80, 0);
                verify_response(&response, &credential, false);
            }
        }
    }
}

#[test]
fn assertion_input_rejection_follows_authentication_credential_lookup_and_presence() {
    for input in [
        Value::Bool(false),
        int(1),
        text("true"),
        Value::Bytes(vec![1; 32]),
        Value::Array(vec![]),
        Value::Map(vec![]),
        Value::Null,
    ] {
        let mut app = test_app([0x75; 16]);
        assert_eq!(
            app.handle_get_assertion(&assertion_request(None, Some(input.clone()), None)),
            Err(CTAP2_ERR_NO_CREDENTIALS)
        );
        let (credential, _) = create(&mut app, true, 1);
        assert_eq!(
            app.handle_get_assertion(&assertion_request(Some(&credential), Some(input), None)),
            Err(CTAP2_ERR_INVALID_OPTION)
        );
    }
    let (mut app, _) = scripted_app(
        [0x75; 16],
        [PresenceOutcome::Approved, PresenceOutcome::Denied],
    );
    let (credential, _) = create(&mut app, true, 1);
    let invalid = assertion_request(Some(&credential), Some(Value::Bool(false)), None);
    assert_eq!(
        app.handle_get_assertion(&invalid),
        Err(CTAP2_ERR_OPERATION_DENIED)
    );
    assert_eq!(
        app.handle_get_assertion(&parameter(&invalid, 6, Some(Value::Bytes(vec![])))),
        Err(CTAP2_ERR_PIN_NOT_SET)
    );
    for protocol in [ClassicPinProtocol::V1, ClassicPinProtocol::V2] {
        install_pin_uv_auth_token(&mut app, protocol, TOKEN, PIN_PERMISSION_GA, Some(RP));
        let request =
            assertion_request(Some(&credential), Some(Value::Bool(false)), Some(protocol));
        let request = parameter(
            &request,
            6,
            Some(Value::Bytes(corrupt_mac(token_pin_auth(
                protocol, &TOKEN, &HASH,
            )))),
        );
        assert_eq!(
            app.handle_get_assertion(&request),
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }
}

#[test]
fn silent_assertions_return_keys_without_an_extension_in_authenticator_data() {
    let mut app = test_app([0x75; 16]);
    let (credential, _) = create(&mut app, true, 1);
    let request = parameter(
        &assertion_request(Some(&credential), Some(Value::Bool(true)), None),
        5,
        Some(canonical_map(vec![(text("up"), Value::Bool(false))])),
    );
    let response = app.handle_get_assertion(&request).unwrap();
    assert_eq!(
        response_key(&response, 7),
        credential.large_blob_key.map(Vec::from)
    );
    assert_eq!(response_auth_data(&response)[32] & 0x81, 0);
    verify_response(&response, &credential, false);
}

#[test]
fn next_assertions_return_each_credentials_key_and_keep_unkeyed_credentials_unkeyed() {
    for requested in [false, true] {
        let mut app = test_app([0x75; 16]);
        let (first, _) = create(&mut app, true, 1);
        let (unkeyed, _) = create(&mut app, false, 2);
        let (last, _) = create(&mut app, true, 3);
        let first_response = app
            .handle_get_assertion(&assertion_request(
                None,
                requested.then_some(Value::Bool(true)),
                None,
            ))
            .unwrap();
        let responses = [
            first_response,
            app.handle_get_next_assertion().unwrap(),
            app.handle_get_next_assertion().unwrap(),
        ];
        for (response, credential) in responses.iter().zip([last, unkeyed, first]) {
            assert_eq!(
                response_key(response, 7),
                credential
                    .large_blob_key
                    .filter(|_| requested)
                    .map(Vec::from),
            );
            assert!(extension_outputs(response, None).is_empty());
            verify_response(response, &credential, false);
        }
        assert_eq!(app.handle_get_next_assertion(), Err(CTAP2_ERR_NOT_ALLOWED));
    }
}

#[test]
fn keys_follow_credential_protection_for_both_protocols() {
    for protocol in [ClassicPinProtocol::V1, ClassicPinProtocol::V2] {
        for policy in 1..=3 {
            for verified in [false, true] {
                for allow_list in [false, true] {
                    let mut app = test_app([0x75; 16]);
                    let response = app
                        .handle_make_credential(&creation_request(
                            CoseAlg::ES256,
                            true,
                            canonical_map(vec![
                                (text("largeBlobKey"), Value::Bool(true)),
                                (text("credProtect"), int(policy)),
                            ]),
                            None,
                            1,
                        ))
                        .unwrap();
                    let credential = created_credential(&app, &response, RP);
                    if verified {
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
                        Some(Value::Bool(true)),
                        verified.then_some(protocol),
                    ));
                    if verified || policy == 1 || (policy == 2 && allow_list) {
                        let response = result.unwrap();
                        assert_eq!(
                            response_key(&response, 7),
                            credential.large_blob_key.map(Vec::from)
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

fn management_request(protocol: ClassicPinProtocol, subcommand: u8, params: Value) -> Vec<u8> {
    let mut message = vec![subcommand];
    message.extend(encode(&params));
    encode(&canonical_map(vec![
        (int(1), int(i64::from(subcommand))),
        (int(2), params),
        (int(3), int(i64::from(protocol.identifier()))),
        (
            int(4),
            Value::Bytes(token_pin_auth(protocol, &TOKEN, &message)),
        ),
    ]))
}

#[test]
fn enumeration_and_user_updates_preserve_keys_and_deletion_erases_them() {
    for protocol in [ClassicPinProtocol::V1, ClassicPinProtocol::V2] {
        let mut app = test_app([0x75; 16]);
        let (first, _) = create(&mut app, true, 1);
        let (unkeyed, _) = create(&mut app, false, 2);
        let (last, _) = create(&mut app, true, 3);
        install_pin_uv_auth_token(&mut app, protocol, TOKEN, PIN_PERMISSION_CM, None);
        let begin = management_request(
            protocol,
            4,
            canonical_map(vec![(int(1), Value::Bytes(TestApp::cm_hash_rp_id(RP)))]),
        );
        let response = app.handle_credential_management(&begin).unwrap();
        assert_eq!(
            response_key(&response, 11),
            last.large_blob_key.map(Vec::from)
        );
        let next = encode(&canonical_map(vec![(int(1), int(5))]));
        let response = app.handle_credential_management(&next).unwrap();
        assert_eq!(response_key(&response, 11), None);
        let response = app.handle_credential_management(&next).unwrap();
        assert_eq!(
            response_key(&response, 11),
            first.large_blob_key.map(Vec::from)
        );
        assert!(unkeyed.large_blob_key.is_none());
        app.handle_credential_management(&management_request(
            protocol,
            7,
            canonical_map(vec![
                (int(2), descriptor(&last)),
                (
                    int(3),
                    canonical_map(vec![
                        (text("id"), Value::Bytes(last.user_id.clone())),
                        (text("name"), text("renamed")),
                    ]),
                ),
            ]),
        ))
        .unwrap();
        let loaded = stored_by_id(&app, &last.credential_id);
        assert_eq!(loaded.large_blob_key, last.large_blob_key);
        assert_eq!(loaded.user_name.as_deref(), Some("renamed"));
        app.handle_credential_management(&management_request(
            protocol,
            6,
            canonical_map(vec![(int(2), descriptor(&last))]),
        ))
        .unwrap();
        assert!(app.store.get(&last.credential_id).unwrap().is_none());
        assert_eq!(
            app.handle_get_assertion(&assertion_request(
                Some(&last),
                Some(Value::Bool(true)),
                None
            )),
            Err(CTAP2_ERR_NO_CREDENTIALS)
        );
    }
}

#[test]
fn replacement_assigns_a_fresh_key_and_reset_erases_all_keys() {
    let mut app = test_app([0x75; 16]);
    let (first, _) = create(&mut app, true, 1);
    let (replaced, _) = create(&mut app, true, 1);
    assert_ne!(first.large_blob_key, replaced.large_blob_key);
    assert_eq!(stored(&app).len(), 1);
    assert_eq!(
        app.handle_get_assertion(&assertion_request(
            Some(&first),
            Some(Value::Bool(true)),
            None
        )),
        Err(CTAP2_ERR_NO_CREDENTIALS)
    );
    app.handle_reset().unwrap();
    assert!(stored(&app).is_empty());
    assert_eq!(
        app.handle_get_assertion(&assertion_request(
            Some(&replaced),
            Some(Value::Bool(true)),
            None
        )),
        Err(CTAP2_ERR_NO_CREDENTIALS)
    );
}

#[test]
fn restarting_the_engine_preserves_the_same_key() {
    let store = TestStore::new();
    let mut app = new_app(store.clone(), [0x75; 16]);
    let (credential, response) = create(&mut app, true, 1);
    let key = response_key(&response, 5).unwrap();
    drop(app);
    let mut app = new_app(store, [0x75; 16]);
    let response = app
        .handle_get_assertion(&assertion_request(
            Some(&credential),
            Some(Value::Bool(true)),
            None,
        ))
        .unwrap();
    assert_eq!(response_key(&response, 7), Some(key));
    verify_response(&response, &credential, false);
}
