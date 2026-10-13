//! Payment metadata over CTAP, signed bytes, persistence and policy (§12.9).

use super::hmac_secret_mc::{
    HASH, creation_request, extension_outputs, hmac_input, text, verify_response,
};
use super::support::*;
use crate::crypto::verify::verify_signature;
use crate::ctap::CtapApp;
use crate::ctap::cbor::{canonical_map, map_get};
use crate::ctap::constants::*;
use crate::ctap::pin::permissions::{PIN_PERMISSION_CM, PIN_PERMISSION_GA};
use crate::ctap::pin::token::ManualClock;
use crate::ctap::presence::{AutoApprove, PresenceOutcome};
use crate::store::{CredentialRecord, FileStore};
use crate::{ClassicPinProtocol, CoseAlg};
use ciborium::{de::from_reader, value::Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

const RP: &str = "example.com";
const TOKEN: [u8; 32] = [0x65; 32];

fn extensions(input: Option<Value>) -> Value {
    canonical_map(
        input
            .into_iter()
            .map(|v| (text("thirdPartyPayment"), v))
            .collect(),
    )
}

fn parameter(request: &[u8], key: i64, value: Option<Value>) -> Vec<u8> {
    let Value::Map(mut entries) = from_reader(request).unwrap() else {
        panic!("map")
    };
    entries.retain(|(k, _)| *k != int(key));
    entries.extend(value.map(|value| (int(key), value)));
    encode(&canonical_map(entries))
}

fn command(app: &mut TestApp, code: u8, payload: &[u8]) -> Vec<u8> {
    app.call(&[&[code], payload].concat())
}

fn create(
    app: &mut TestApp,
    alg: CoseAlg,
    rk: bool,
    input: Option<bool>,
    user: u8,
) -> CredentialRecord {
    let request = creation_request(alg, rk, extensions(input.map(Value::Bool)), None, user);
    let request = parameter(
        &request,
        3,
        Some(canonical_map(vec![
            (text("id"), Value::Bytes(vec![user])),
            (text("name"), text("alice")),
            (text("displayName"), text("Alice")),
        ])),
    );
    let request = if input.is_none() {
        parameter(&request, 6, None)
    } else {
        request
    };
    let response = command(app, CTAP_CMD_MAKE_CREDENTIAL, &request);
    assert_eq!(response[0], CTAP2_OK);
    let record = created_credential(app, &response, RP);
    assert!(extension_outputs(&response, Some(&record)).is_empty());
    assert_eq!(response_auth_data(&response)[32] & 0x80, 0);
    verify_response(&response, &record, true);
    record
}

fn assertion(
    record: Option<&CredentialRecord>,
    input: Option<Value>,
    auth: Option<ClassicPinProtocol>,
) -> Vec<u8> {
    let request = get_assertion_request(
        &HASH,
        RP,
        auth.map(|p| (p, token_pin_auth(p, &TOKEN, &HASH))),
        input.map(|v| extensions(Some(v))),
    );
    match record {
        Some(record) => parameter(
            &request,
            3,
            Some(Value::Array(vec![canonical_map(vec![
                (text("id"), Value::Bytes(record.credential_id.clone())),
                (text("type"), text("public-key")),
            ])])),
        ),
        None => request,
    }
}

fn counter(response: &[u8]) -> u32 {
    u32::from_be_bytes(response_auth_data(response)[33..37].try_into().unwrap())
}

fn check_output(response: &[u8], record: &CredentialRecord, requested: bool) {
    assert_eq!(response[0], CTAP2_OK);
    verify_response(response, record, false);
    let data = response_auth_data(response);
    assert_eq!(data[32] & 0x80 != 0, requested);
    let outputs = extension_outputs(response, None);
    assert_eq!(
        map_get(&outputs, text("thirdPartyPayment")),
        requested.then_some(&Value::Bool(record.third_party_payment))
    );
    if requested {
        // Prove that the boolean is signed, rather than merely returned.
        let Value::Map(map) = from_reader(&response[1..]).unwrap() else {
            panic!("map")
        };
        let Value::Bytes(signature) = map_get(&map, int(3)).unwrap() else {
            panic!("signature")
        };
        let mut changed = data;
        *changed.last_mut().unwrap() ^= 1; // CBOR true <-> false.
        changed.extend_from_slice(&HASH);
        assert!(
            verify_signature(
                record.alg,
                &record.cose_public_key().unwrap(),
                &changed,
                signature
            )
            .is_err()
        );
    }
}

#[test]
fn enabled_credentials_work_for_every_algorithm_and_both_modalities() {
    for alg in CoseAlg::ALL {
        for rk in [false, true] {
            let mut app = test_app([0x79; 16]);
            let record = create(&mut app, alg, rk, Some(true), 1);
            assert!(record.third_party_payment);
            assert_eq!(record.credential_id.len(), 33);
            assert_eq!(record.credential_id[0], u8::from(rk));
            assert_eq!(stored(&app).len(), 1);
            if !rk {
                assert!(record.user_id.is_empty());
                assert!(record.user_name.is_none() && record.user_display_name.is_none());
                assert_eq!(
                    command(
                        &mut app,
                        CTAP_CMD_GET_ASSERTION,
                        &assertion(None, Some(Value::Bool(true)), None)
                    ),
                    [CTAP2_ERR_NO_CREDENTIALS]
                );
            }
            for expected in 1..=2 {
                let response = command(
                    &mut app,
                    CTAP_CMD_GET_ASSERTION,
                    &assertion(Some(&record), Some(Value::Bool(true)), None),
                );
                check_output(&response, &record, true);
                assert_eq!(counter(&response), expected);
                assert_eq!(
                    stored_by_id(&app, &record.credential_id).sign_count,
                    expected
                );
            }
        }
    }
}

#[test]
fn false_and_absent_are_no_ops_and_legacy_credentials_return_false() {
    for alg in [
        CoseAlg::ES256,
        CoseAlg::MLDSA44,
        CoseAlg::RS256,
        CoseAlg::ESB256,
        CoseAlg::ESB384,
    ] {
        for rk in [false, true] {
            for input in [None, Some(false), Some(true)] {
                let mut app = test_app([0x79; 16]);
                let record = create(&mut app, alg, rk, input, 1);
                let enabled = input == Some(true);
                assert_eq!(record.third_party_payment, enabled);
                let stored_credential = rk || enabled || !alg.is_sealable();
                assert_eq!(stored(&app).len(), usize::from(stored_credential));
                assert_eq!(
                    record.credential_id.len(),
                    if stored_credential { 33 } else { 107 }
                );
                for (index, requested) in [None, Some(false), Some(true)].into_iter().enumerate() {
                    let response = command(
                        &mut app,
                        CTAP_CMD_GET_ASSERTION,
                        &assertion(Some(&record), requested.map(Value::Bool), None),
                    );
                    check_output(&response, &record, requested == Some(true));
                    assert_eq!(counter(&response), index as u32 + 1);
                }
            }
        }
    }
}

#[test]
fn malformed_inputs_return_authenticator_type_errors_without_writes() {
    for input in [
        Value::Null,
        Value::Float(1.0),
        int(0),
        int(1),
        text("true"),
        Value::Bytes(vec![]),
        Value::Array(vec![]),
        canonical_map(vec![]),
    ] {
        for alg in [
            CoseAlg::ES256,
            CoseAlg::MLDSA44,
            CoseAlg::RS256,
            CoseAlg::ESB256,
            CoseAlg::ESB384,
        ] {
            let mut app = test_app([0x79; 16]);
            let payload = creation_request(alg, false, extensions(Some(input.clone())), None, 1);
            assert_eq!(
                command(&mut app, CTAP_CMD_MAKE_CREDENTIAL, &payload),
                [CTAP2_ERR_CBOR_UNEXPECTED_TYPE]
            );
            assert!(stored(&app).is_empty());
            let record = create(&mut app, alg, false, Some(true), 1);
            assert_eq!(
                command(
                    &mut app,
                    CTAP_CMD_GET_ASSERTION,
                    &assertion(Some(&record), Some(input.clone()), None)
                ),
                [CTAP2_ERR_CBOR_UNEXPECTED_TYPE]
            );
            assert_eq!(stored_by_id(&app, &record.credential_id).sign_count, 0);
        }
    }
}

#[test]
fn mixed_next_assertions_use_each_record_and_remember_the_input() {
    for requested in [None, Some(false), Some(true)] {
        let mut app = test_app([0x79; 16]);
        let clock = ManualClock::default();
        app.set_clock(clock.clone());
        let records = [
            create(&mut app, CoseAlg::ES256, true, Some(true), 1),
            create(&mut app, CoseAlg::MLDSA44, true, Some(false), 2),
            create(&mut app, CoseAlg::ES256, true, None, 3),
        ];
        let first = command(
            &mut app,
            CTAP_CMD_GET_ASSERTION,
            &assertion(None, requested.map(Value::Bool), None),
        );
        let Value::Map(map) = from_reader(&first[1..]).unwrap() else {
            panic!("map")
        };
        assert_eq!(map_get(&map, int(5)), Some(&int(3)));
        let responses = [
            first,
            command(&mut app, CTAP_CMD_GET_NEXT_ASSERTION, &[]),
            command(&mut app, CTAP_CMD_GET_NEXT_ASSERTION, &[]),
        ];
        for (response, record) in responses.iter().zip(records.iter().rev()) {
            check_output(response, record, requested == Some(true));
            assert_eq!(counter(response), 1);
        }
        assert_eq!(
            command(&mut app, CTAP_CMD_GET_NEXT_ASSERTION, &[]),
            [CTAP2_ERR_NOT_ALLOWED]
        );
        command(
            &mut app,
            CTAP_CMD_GET_ASSERTION,
            &assertion(None, Some(Value::Bool(true)), None),
        );
        clock.advance(Duration::from_millis(30_001));
        assert_eq!(
            command(&mut app, CTAP_CMD_GET_NEXT_ASSERTION, &[]),
            [CTAP2_ERR_NOT_ALLOWED]
        );
    }
}

fn management(app: &mut TestApp, sub: u8, params: Option<Value>) -> Vec<u8> {
    let mut entries = vec![(int(1), int(sub.into()))];
    if !matches!(sub, 3 | 5) {
        install_pin_uv_auth_token(app, ClassicPinProtocol::V2, TOKEN, PIN_PERMISSION_CM, None);
        let mut message = vec![sub];
        if let Some(params) = &params {
            message.extend(encode(params));
        }
        entries.extend([
            (int(3), int(2)),
            (
                int(4),
                Value::Bytes(token_pin_auth(ClassicPinProtocol::V2, &TOKEN, &message)),
            ),
        ]);
    }
    entries.extend(params.map(|p| (int(2), p)));
    command(
        app,
        CTAP_CMD_CREDENTIAL_MANAGEMENT,
        &encode(&canonical_map(entries)),
    )
}

fn cm_begin(app: &mut TestApp) -> Vec<u8> {
    management(
        app,
        4,
        Some(canonical_map(vec![(
            int(1),
            Value::Bytes(Sha256::digest(RP.as_bytes()).to_vec()),
        )])),
    )
}

fn member(response: &[u8], key: i64) -> Option<Value> {
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).unwrap() else {
        panic!("map")
    };
    map_get(&map, int(key)).cloned()
}

#[test]
fn enumeration_and_user_updates_preserve_both_values() {
    let mut app = test_app([0x79; 16]);
    let enabled = create(&mut app, CoseAlg::ES256, true, Some(true), 1);
    let ordinary = create(&mut app, CoseAlg::ES256, true, None, 2);
    create(&mut app, CoseAlg::ES256, false, Some(true), 3);
    let first = cm_begin(&mut app);
    assert_eq!(member(&first, 9), Some(int(2)));
    assert_eq!(member(&first, 12), Some(Value::Bool(false)));
    assert_eq!(
        member(&management(&mut app, 5, None), 12),
        Some(Value::Bool(true))
    );
    for record in [enabled, ordinary] {
        let params = canonical_map(vec![
            (
                int(2),
                canonical_map(vec![
                    (text("type"), text("public-key")),
                    (text("id"), Value::Bytes(record.credential_id.clone())),
                ]),
            ),
            (
                int(3),
                canonical_map(vec![
                    (text("id"), Value::Bytes(record.user_id.clone())),
                    (text("name"), text("updated")),
                ]),
            ),
        ]);
        assert_eq!(management(&mut app, 7, Some(params)), [CTAP2_OK]);
        let saved = stored_by_id(&app, &record.credential_id);
        assert_eq!(saved.third_party_payment, record.third_party_payment);
        assert_eq!(saved.user_name.as_deref(), Some("updated"));
        let response = command(
            &mut app,
            CTAP_CMD_GET_ASSERTION,
            &assertion(Some(&record), Some(Value::Bool(true)), None),
        );
        check_output(&response, &record, true);
    }
}

#[test]
fn stored_payment_capacity_and_faults_do_not_publish_success() {
    let store = TestStore::with_max_credentials(1);
    let mut app = new_app(store.clone(), [0x79; 16]);
    let payload = creation_request(
        CoseAlg::ES256,
        false,
        extensions(Some(Value::Bool(true))),
        None,
        1,
    );
    store.faults(|f| f.put = true);
    assert_eq!(
        command(&mut app, CTAP_CMD_MAKE_CREDENTIAL, &payload),
        [CTAP2_ERR_PROCESSING]
    );
    assert!(store.credentials().is_empty());
    store.faults(|f| f.put = false);
    let record = create(&mut app, CoseAlg::ES256, false, Some(true), 1);
    assert_eq!(
        command(&mut app, CTAP_CMD_MAKE_CREDENTIAL, &payload),
        [CTAP2_ERR_KEY_STORE_FULL]
    );
    let info = command(&mut app, CTAP_CMD_GET_INFO, &[]);
    assert_eq!(member(&info, 0x14), Some(int(0)));
    let metadata = management(&mut app, 1, None);
    assert_eq!(member(&metadata, 1), Some(int(0)));
    assert_eq!(member(&metadata, 2), Some(int(0)));
    store.faults(|f| f.put = true);
    assert_eq!(
        command(
            &mut app,
            CTAP_CMD_GET_ASSERTION,
            &assertion(Some(&record), Some(Value::Bool(true)), None)
        ),
        [CTAP2_ERR_PROCESSING]
    );
    assert_eq!(store.credential(&record.credential_id).sign_count, 0);
    store.faults(|f| f.put = false);
    let response = command(
        &mut app,
        CTAP_CMD_GET_ASSERTION,
        &assertion(Some(&record), Some(Value::Bool(true)), None),
    );
    check_output(&response, &record, true);
    assert_eq!(counter(&response), 1);
    // An ordinary sealable registration needs no slot, even at capacity.
    create(&mut app, CoseAlg::ES256, false, None, 1);
}

#[test]
fn atomic_replacement_uses_new_metadata_and_failures_keep_old_metadata() {
    for input in [None, Some(false), Some(true)] {
        let enabled = input != Some(true);
        let store = TestStore::with_max_credentials(1);
        let mut app = new_app(store.clone(), [0x79; 16]);
        let old = create(&mut app, CoseAlg::ES256, true, Some(enabled), 1);
        let request = creation_request(
            CoseAlg::ES256,
            true,
            extensions(input.map(Value::Bool)),
            None,
            1,
        );
        store.faults(|f| f.replacement_write = true);
        assert_eq!(
            command(&mut app, CTAP_CMD_MAKE_CREDENTIAL, &request),
            [CTAP2_ERR_PROCESSING]
        );
        assert_eq!(
            store.credential(&old.credential_id).third_party_payment,
            enabled
        );
        store.faults(|f| {
            f.replacement_write = false;
            f.delete = true;
        });
        let new = create(&mut app, CoseAlg::ES256, true, input, 1);
        assert_eq!(new.third_party_payment, !enabled);
        let mut restarted = new_app(store, [0x78; 16]);
        assert_eq!(
            command(
                &mut restarted,
                CTAP_CMD_GET_ASSERTION,
                &assertion(Some(&old), Some(Value::Bool(true)), None)
            ),
            [CTAP2_ERR_NO_CREDENTIALS]
        );
        check_output(
            &command(
                &mut restarted,
                CTAP_CMD_GET_ASSERTION,
                &assertion(Some(&new), Some(Value::Bool(true)), None),
            ),
            &new,
            true,
        );
    }
}

#[test]
fn file_store_restart_counter_updates_and_reset_preserve_then_erase_metadata() {
    let dir = crate::store::test_support::TempDir::new();
    let state = dir.path().join("state");
    let open = || {
        CtapApp::with_file_store(
            FileStore::open(&state).unwrap(),
            AutoApprove,
            &NEVER_INTERRUPTED,
            [0x79; 16],
        )
    };
    let mut app = open();
    let records = [
        create(&mut app, CoseAlg::ES256, false, Some(true), 1),
        create(&mut app, CoseAlg::MLDSA44, true, Some(true), 2),
        create(&mut app, CoseAlg::ESB256, false, None, 3),
        create(&mut app, CoseAlg::ESB256, true, Some(true), 4),
        create(&mut app, CoseAlg::ESB384, false, None, 5),
        create(&mut app, CoseAlg::ESB384, true, Some(true), 6),
    ];
    for expected in 1..=3 {
        drop(app);
        app = open();
        for record in &records {
            let response = command(
                &mut app,
                CTAP_CMD_GET_ASSERTION,
                &assertion(Some(record), Some(Value::Bool(true)), None),
            );
            check_output(&response, record, true);
            assert_eq!(counter(&response), expected);
        }
    }
    assert_eq!(member(&cm_begin(&mut app), 12), Some(Value::Bool(true)));
    assert_eq!(command(&mut app, CTAP_CMD_RESET, &[]), [CTAP2_OK]);
    drop(app);
    app = open();
    for record in &records {
        assert_eq!(
            command(
                &mut app,
                CTAP_CMD_GET_ASSERTION,
                &assertion(Some(record), Some(Value::Bool(true)), None)
            ),
            [CTAP2_ERR_NO_CREDENTIALS]
        );
    }
}

#[test]
fn payment_disclosure_retains_rp_protection_uv_and_presence_rules() {
    for protocol in [ClassicPinProtocol::V1, ClassicPinProtocol::V2] {
        for policy in 1..=3 {
            for verified in [false, true] {
                for allow_list in [false, true] {
                    let mut app = test_app([0x79; 16]);
                    let response = command(
                        &mut app,
                        CTAP_CMD_MAKE_CREDENTIAL,
                        &creation_request(
                            CoseAlg::ES256,
                            true,
                            canonical_map(vec![
                                (text("thirdPartyPayment"), Value::Bool(true)),
                                (text("credProtect"), int(policy)),
                            ]),
                            None,
                            1,
                        ),
                    );
                    let record = created_credential(&app, &response, RP);
                    if verified {
                        install_pin_uv_auth_token(
                            &mut app,
                            protocol,
                            TOKEN,
                            PIN_PERMISSION_GA,
                            Some(RP),
                        );
                    }
                    let response = command(
                        &mut app,
                        CTAP_CMD_GET_ASSERTION,
                        &assertion(
                            allow_list.then_some(&record),
                            Some(Value::Bool(true)),
                            verified.then_some(protocol),
                        ),
                    );
                    if verified || policy == 1 || (policy == 2 && allow_list) {
                        check_output(&response, &record, true);
                        assert_eq!(response_auth_data(&response)[32] & FLAG_UV != 0, verified);
                    } else {
                        assert_eq!(response, [CTAP2_ERR_NO_CREDENTIALS]);
                    }
                }
            }
        }
    }
    let (mut app, _) = scripted_app(
        [0x79; 16],
        [PresenceOutcome::Approved, PresenceOutcome::Denied],
    );
    let record = create(&mut app, CoseAlg::ES256, false, Some(true), 1);
    let request = assertion(Some(&record), Some(Value::Bool(true)), None);
    let wrong_rp = parameter(&request, 1, Some(text("other.example")));
    assert_eq!(
        command(&mut app, CTAP_CMD_GET_ASSERTION, &wrong_rp),
        [CTAP2_ERR_NO_CREDENTIALS]
    );
    assert_eq!(
        command(&mut app, CTAP_CMD_GET_ASSERTION, &request),
        [CTAP2_ERR_OPERATION_DENIED]
    );
    assert_eq!(stored_by_id(&app, &record.credential_id).sign_count, 0);
}

#[test]
fn payment_composes_with_blob_protection_prf_and_large_blob_keys() {
    for alg in [CoseAlg::ES256, CoseAlg::ESB256, CoseAlg::ESB384] {
        for protocol in [ClassicPinProtocol::V1, ClassicPinProtocol::V2] {
            for rk in [false, true] {
                let mut app = test_app([0x79; 16]);
                let session = PlatformPinSession::establish(&mut app, protocol, 0x13);
                let salts = [0x42; 32];
                let mut inputs = vec![
                    (text("thirdPartyPayment"), Value::Bool(true)),
                    (text("credBlob"), Value::Bytes(vec![0x73; 32])),
                    (text("credProtect"), int(2)),
                    (text("hmac-secret"), Value::Bool(true)),
                    (
                        text("hmac-secret-mc"),
                        hmac_input(&session, &salts, protocol),
                    ),
                    (text("minPinLength"), Value::Bool(true)),
                    (text("pinComplexityPolicy"), Value::Bool(true)),
                ];
                if rk {
                    inputs.push((text("largeBlobKey"), Value::Bool(true)));
                }
                let response = command(
                    &mut app,
                    CTAP_CMD_MAKE_CREDENTIAL,
                    &creation_request(alg, rk, canonical_map(inputs), None, 1),
                );
                assert_eq!(response[0], CTAP2_OK);
                let record = created_credential(&app, &response, RP);
                assert!(record.third_party_payment);
                assert_eq!(record.cred_blob, Some(vec![0x73; 32]));
                let creation_outputs = extension_outputs(&response, Some(&record));
                assert!(map_get(&creation_outputs, text("thirdPartyPayment")).is_none());
                assert_eq!(
                    map_get(&creation_outputs, text("credBlob")),
                    Some(&Value::Bool(true))
                );
                verify_response(&response, &record, true);
                let Value::Bytes(mc_output) =
                    map_get(&creation_outputs, text("hmac-secret-mc")).unwrap()
                else {
                    panic!("PRF")
                };
                let mut inputs = vec![
                    (text("thirdPartyPayment"), Value::Bool(true)),
                    (text("credBlob"), Value::Bool(true)),
                    (text("hmac-secret"), hmac_input(&session, &salts, protocol)),
                ];
                if rk {
                    inputs.push((text("largeBlobKey"), Value::Bool(true)));
                }
                let request = parameter(
                    &assertion(Some(&record), None, None),
                    4,
                    Some(canonical_map(inputs)),
                );
                let response = command(&mut app, CTAP_CMD_GET_ASSERTION, &request);
                check_output(&response, &record, true);
                let outputs = extension_outputs(&response, None);
                assert_eq!(
                    map_get(&outputs, text("credBlob")),
                    Some(&Value::Bytes(vec![0x73; 32]))
                );
                let Value::Bytes(ga_output) = map_get(&outputs, text("hmac-secret")).unwrap()
                else {
                    panic!("PRF")
                };
                assert_eq!(session.decrypt(mc_output), session.decrypt(ga_output));
                assert_eq!(
                    member(&response, 7),
                    record.large_blob_key.map(|k| Value::Bytes(k.to_vec()))
                );
                assert_eq!(
                    &response_auth_data(&response)[37..],
                    encode(&canonical_map(outputs))
                );
            }
        }
    }
}
