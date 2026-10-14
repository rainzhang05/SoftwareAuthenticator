//! Preview wire compatibility and isolation from modern permission grants.
use super::support::*;
use crate::crypto::verify::verify_signature;
use crate::ctap::CtapApp;
use crate::ctap::cbor::{canonical_map, map_get};
use crate::ctap::constants::*;
use crate::ctap::pin::permissions::{PIN_PERMISSION_CM, PIN_PERMISSION_MC};
use crate::ctap::pin::token::{ManualClock, TokenGrant, TokenOrigin};
use crate::store::CredentialStore;
use crate::{ClassicPinProtocol, CoseAlg};
use ciborium::{de::from_reader, value::Value};
use std::time::Duration;

const PRE: u8 = CTAP_CMD_CREDENTIAL_MANAGEMENT_PROTOTYPE;
const CM: u8 = CTAP_CMD_CREDENTIAL_MANAGEMENT;
const PIN: &[u8] = b"1234";
const RP: &str = "a.preview.example";
const OTHER: &str = "b.preview.example";
const PROTOCOLS: [ClassicPinProtocol; 2] = [ClassicPinProtocol::V1, ClassicPinProtocol::V2];

fn ready(protocol: ClassicPinProtocol) -> (TestApp, TestStore, [u8; 32]) {
    let store = TestStore::new();
    let mut app = new_app(store.clone(), [0x41; 16]);
    for (id, rp) in [(1, RP), (2, RP), (3, OTHER)] {
        let mut record = credential(rp, &[id], &[id], CoseAlg::ES256);
        record.large_blob_key = Some([id; 32]);
        record.third_party_payment = id == 1;
        record.cred_protect = 2;
        insert(&mut app, &record);
    }
    set_pin_padded(&mut app, protocol, &padded_pin(PIN)).unwrap();
    let token = get_pin_token(&mut app, protocol, PIN).unwrap();
    assert_eq!(app.pin_state.pin_uv_auth_permissions(), 3);
    assert_eq!(
        app.pin_state.token_origin(),
        Some(TokenOrigin::LegacyGetPinToken)
    );
    (app, store, token)
}

fn params_rp(rp: &str) -> Value {
    canonical_map(vec![(int(1), Value::Bytes(CtapApp::cm_hash_rp_id(rp)))])
}
fn params_id(id: &[u8], user: Option<Value>) -> Value {
    let mut entries = vec![(
        int(2),
        canonical_map(vec![
            (Value::Text("id".into()), Value::Bytes(id.to_vec())),
            (Value::Text("type".into()), Value::Text("public-key".into())),
        ]),
    )];
    entries.extend(user.map(|user| (int(3), user)));
    canonical_map(entries)
}
fn request(
    family: u8,
    protocol: ClassicPinProtocol,
    token: &[u8; 32],
    sub: u8,
    params: Option<Value>,
) -> Vec<u8> {
    let mut entries = vec![(int(1), int(sub.into()))];
    if !matches!(sub, 3 | 5) {
        let mut message = vec![sub];
        if !matches!(sub, 1 | 2)
            && let Some(params) = &params
        {
            message.extend(encode(params));
        }
        entries.extend([
            (int(3), int(protocol.identifier().into())),
            (
                int(4),
                Value::Bytes(token_pin_auth(protocol, token, &message)),
            ),
        ]);
    }
    entries.extend(params.map(|params| (int(2), params)));
    [&[family], encode(&canonical_map(entries)).as_slice()].concat()
}
fn manage(
    app: &mut TestApp,
    family: u8,
    protocol: ClassicPinProtocol,
    token: &[u8; 32],
    sub: u8,
    params: Option<Value>,
) -> Vec<u8> {
    app.call(&request(family, protocol, token, sub, params))
}
fn field(response: &[u8], key: i64) -> Value {
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).unwrap() else {
        panic!("map")
    };
    map_get(&map, int(key)).unwrap().clone()
}
fn configure(
    app: &mut TestApp,
    protocol: ClassicPinProtocol,
    token: &[u8; 32],
    params: Value,
) -> Vec<u8> {
    let mut message = vec![0xff; 32];
    message.extend([CTAP_CMD_AUTHENTICATOR_CONFIG, 3]);
    message.extend(encode(&params));
    let body = canonical_map(vec![
        (int(1), int(3)),
        (int(2), params),
        (int(3), int(protocol.identifier().into())),
        (
            int(4),
            Value::Bytes(token_pin_auth(protocol, token, &message)),
        ),
    ]);
    app.call(&[&[CTAP_CMD_AUTHENTICATOR_CONFIG], encode(&body).as_slice()].concat())
}

#[test]
fn legacy_and_modern_tokens_manage_all_seven_operations_with_shared_metadata() {
    for protocol in PROTOCOLS {
        for legacy in [true, false] {
            let (mut app, store, mut token) = ready(protocol);
            if !legacy {
                token = get_pin_uv_auth_token(&mut app, protocol, PIN, 4, None).unwrap();
            }
            assert_eq!(
                field(&manage(&mut app, PRE, protocol, &token, 1, None), 1),
                int(3)
            );
            assert_eq!(
                field(&manage(&mut app, PRE, protocol, &token, 2, None), 5),
                int(2)
            );
            assert_eq!(
                field(&manage(&mut app, PRE, protocol, &token, 3, None), 4),
                Value::Bytes(CtapApp::cm_hash_rp_id(OTHER))
            );
            let first = manage(&mut app, PRE, protocol, &token, 4, Some(params_rp(RP)));
            assert_eq!(field(&first, 9), int(2));
            let second = manage(&mut app, PRE, protocol, &token, 5, None);
            for response in [&first, &second] {
                let Value::Map(desc) = field(response, 7) else {
                    panic!("descriptor")
                };
                let Value::Bytes(id) = map_get(&desc, Value::Text("id".into())).unwrap() else {
                    panic!("id")
                };
                let record = store.credential(id);
                assert_eq!(field(response, 10), int(2));
                assert_eq!(
                    field(response, 11),
                    Value::Bytes(record.large_blob_key.unwrap().to_vec())
                );
                assert_eq!(field(response, 12), Value::Bool(record.third_party_payment));
                assert_eq!(encode(&field(response, 8)), record.keypair().unwrap().1);
            }
            let original = store
                .credentials()
                .into_iter()
                .find(|r| r.rp_id == RP)
                .unwrap();
            let user = canonical_map(vec![
                (
                    Value::Text("id".into()),
                    Value::Bytes(original.user_id.clone()),
                ),
                (Value::Text("name".into()), Value::Text("Updated".into())),
            ]);
            assert_eq!(
                manage(
                    &mut app,
                    PRE,
                    protocol,
                    &token,
                    7,
                    Some(params_id(&original.credential_id, Some(user)))
                ),
                [CTAP2_OK]
            );
            let updated = store.credential(&original.credential_id);
            assert_eq!(updated.user_name.as_deref(), Some("Updated"));
            assert_eq!(updated.user_display_name, None);
            assert_eq!(updated.large_blob_key, original.large_blob_key);
            assert_eq!(updated.third_party_payment, original.third_party_payment);
            assert_eq!(updated.sign_count, original.sign_count);
            assert_eq!(updated.keypair().unwrap().1, original.keypair().unwrap().1);
            assert_eq!(
                manage(
                    &mut app,
                    PRE,
                    protocol,
                    &token,
                    6,
                    Some(params_id(&original.credential_id, None))
                ),
                [CTAP2_OK]
            );
            assert!(store.get(&original.credential_id).unwrap().is_none());
            assert_eq!(
                field(&manage(&mut app, PRE, protocol, &token, 1, None), 1),
                int(2)
            );
            assert_eq!(
                manage(&mut app, PRE, protocol, &token, 5, None),
                [CTAP2_ERR_NOT_ALLOWED]
            );
            assert_eq!(
                manage(&mut app, PRE, protocol, &token, 3, None),
                [CTAP2_ERR_NOT_ALLOWED]
            );
        }
    }
}

#[test]
fn modern_permission_masks_never_impersonate_a_legacy_grant() {
    for protocol in PROTOCOLS {
        let (mut app, _, legacy) = ready(protocol);
        assert_eq!(
            manage(&mut app, CM, protocol, &legacy, 1, None),
            [CTAP2_ERR_PIN_AUTH_INVALID]
        );
        for permissions in 0..=255 {
            let token = [0x57; 32];
            install_pin_uv_auth_token(&mut app, protocol, token, permissions, None);
            let response = manage(&mut app, PRE, protocol, &token, 1, None);
            assert_eq!(
                response[0],
                if permissions & PIN_PERMISSION_CM != 0 {
                    CTAP2_OK
                } else {
                    CTAP2_ERR_PIN_AUTH_INVALID
                },
                "mask {permissions:02x}"
            );
        }
        for permission in [1, 2, 3, 0x10, 0x20, 0x30, 0x80] {
            let rp = (permission & 3 != 0).then_some(RP);
            let token = get_pin_uv_auth_token(&mut app, protocol, PIN, permission, rp).unwrap();
            assert_eq!(
                manage(&mut app, PRE, protocol, &token, 4, Some(params_rp(RP))),
                [CTAP2_ERR_PIN_AUTH_INVALID]
            );
        }
        for permission in [8, 0x44] {
            assert_eq!(
                get_pin_uv_auth_token(&mut app, protocol, PIN, permission, None),
                Err(CTAP2_ERR_UNAUTHORIZED_PERMISSION)
            );
        }
    }
}

#[test]
fn scoped_modern_tokens_and_bound_legacy_tokens_obey_rp_rules() {
    for protocol in PROTOCOLS {
        let (mut app, store, legacy) = ready(protocol);
        app.pin_state
            .authorize_rp_operation(PIN_PERMISSION_MC, RP)
            .unwrap();
        assert_eq!(
            manage(&mut app, PRE, protocol, &legacy, 1, None),
            [CTAP2_ERR_PIN_AUTH_INVALID]
        );
        let token = get_pin_uv_auth_token(&mut app, protocol, PIN, 4, Some(RP)).unwrap();
        for family in [CM, PRE] {
            for sub in [1, 2] {
                assert_eq!(
                    manage(&mut app, family, protocol, &token, sub, None),
                    [CTAP2_ERR_PIN_AUTH_INVALID]
                );
            }
            assert_eq!(
                manage(
                    &mut app,
                    family,
                    protocol,
                    &token,
                    4,
                    Some(params_rp(OTHER))
                ),
                [CTAP2_ERR_PIN_AUTH_INVALID]
            );
            assert_eq!(
                manage(&mut app, family, protocol, &token, 4, Some(params_rp(RP)))[0],
                CTAP2_OK
            );
            assert_eq!(
                manage(&mut app, family, protocol, &token, 5, None)[0],
                CTAP2_OK
            );
            let record = store
                .credentials()
                .into_iter()
                .find(|r| r.rp_id == OTHER)
                .unwrap();
            for sub in [6, 7] {
                assert_eq!(
                    manage(
                        &mut app,
                        family,
                        protocol,
                        &token,
                        sub,
                        Some(params_id(
                            &record.credential_id,
                            Some(canonical_map(vec![(
                                Value::Text("id".into()),
                                Value::Bytes(record.user_id.clone())
                            )]))
                        ))
                    ),
                    [CTAP2_ERR_PIN_AUTH_INVALID]
                );
            }
            assert_eq!(store.credentials().len(), 3);
        }
    }
}

#[test]
fn family_switches_including_malformed_requests_invalidate_both_cursors() {
    for protocol in PROTOCOLS {
        for (family, other) in [(CM, PRE), (PRE, CM)] {
            for malformed in [false, true] {
                let (mut app, _, _) = ready(protocol);
                let token = get_pin_uv_auth_token(&mut app, protocol, PIN, 4, None).unwrap();
                assert_eq!(
                    manage(&mut app, family, protocol, &token, 2, None)[0],
                    CTAP2_OK
                );
                assert_eq!(
                    manage(&mut app, family, protocol, &token, 4, Some(params_rp(RP)))[0],
                    CTAP2_OK
                );
                if malformed {
                    assert_eq!(app.call(&[other, 0xff]), [CTAP2_ERR_INVALID_CBOR]);
                } else {
                    assert_eq!(
                        manage(&mut app, other, protocol, &token, 5, None),
                        [CTAP2_ERR_NOT_ALLOWED]
                    );
                }
                for sub in [3, 5] {
                    assert_eq!(
                        manage(&mut app, family, protocol, &token, sub, None),
                        [CTAP2_ERR_NOT_ALLOWED]
                    );
                }
            }
        }
        let (mut app, _, token) = ready(protocol);
        assert_eq!(
            manage(&mut app, PRE, protocol, &token, 2, None)[0],
            CTAP2_OK
        );
        assert_eq!(
            manage(&mut app, PRE, protocol, &token, 4, Some(params_rp(RP)))[0],
            CTAP2_OK
        );
        for sub in [3, 5] {
            assert_eq!(
                manage(&mut app, PRE, protocol, &token, sub, None)[0],
                CTAP2_OK
            );
        }
        for sub in [3, 5] {
            assert_eq!(
                manage(&mut app, PRE, protocol, &token, sub, None),
                [CTAP2_ERR_NOT_ALLOWED]
            );
        }
    }
}

#[test]
fn continuations_recheck_expiry_consumption_reissue_scope_and_reset() {
    for protocol in PROTOCOLS {
        for family in [CM, PRE] {
            for mode in 0..6 {
                let (mut app, _, _) = ready(protocol);
                let clock = ManualClock::default();
                app.set_clock(clock.clone());
                let mut token = get_pin_token(&mut app, protocol, PIN).unwrap();
                if family == CM {
                    token = get_pin_uv_auth_token(&mut app, protocol, PIN, 4, None).unwrap();
                    install_pin_uv_auth_token(&mut app, protocol, token, 5, None);
                }
                assert_eq!(
                    manage(&mut app, family, protocol, &token, 2, None)[0],
                    CTAP2_OK
                );
                assert_eq!(
                    manage(&mut app, family, protocol, &token, 4, Some(params_rp(RP)))[0],
                    CTAP2_OK
                );
                match mode {
                    0 => clock.advance(Duration::from_secs(600)),
                    1 => app
                        .pin_state
                        .consume_pin_uv_auth_token_after_user_presence(),
                    2 => app.pin_state.issue_pin_uv_auth_token(
                        protocol,
                        token,
                        TokenGrant {
                            origin: if family == PRE {
                                TokenOrigin::LegacyGetPinToken
                            } else {
                                TokenOrigin::PermissionBearing
                            },
                            permissions: if family == PRE { 3 } else { 4 },
                            rp_id: None,
                        },
                    ),
                    3 => {
                        app.pin_state
                            .authorize_rp_operation(PIN_PERMISSION_MC, OTHER)
                            .unwrap();
                    }
                    4 => app.pin_state.invalidate_pin_uv_auth_tokens(),
                    _ => {
                        assert_eq!(app.call(&[CTAP_CMD_RESET]), [CTAP2_OK]);
                    }
                }
                for sub in [3, 5] {
                    assert_eq!(
                        manage(&mut app, family, protocol, &token, sub, None),
                        [CTAP2_ERR_NOT_ALLOWED]
                    );
                }
                if mode != 2 {
                    assert_ne!(
                        manage(&mut app, family, protocol, &token, 1, None)[0],
                        CTAP2_OK
                    );
                }
            }
        }
        let (mut app, _, _) = ready(protocol);
        let clock = ManualClock::default();
        app.set_clock(clock.clone());
        let token = get_pin_token(&mut app, protocol, PIN).unwrap();
        clock.advance(Duration::from_secs(30));
        assert_eq!(
            manage(&mut app, PRE, protocol, &token, 1, None),
            [CTAP2_ERR_PIN_AUTH_INVALID]
        );
        assert_eq!(app.pin_state.token_origin(), None);
    }
}

#[test]
fn malformed_authentication_and_rejected_updates_do_not_change_records_or_retries() {
    for protocol in PROTOCOLS {
        let (mut app, store, token) = ready(protocol);
        let before = store.pin_state_writes();
        let record = store.credentials()[0].clone();
        for (auth, proto, expected) in [
            (
                None,
                Some(int(protocol.identifier().into())),
                CTAP2_ERR_PUAT_REQUIRED,
            ),
            (
                Some(Value::Bytes(vec![0; 32])),
                None,
                CTAP2_ERR_MISSING_PARAMETER,
            ),
            (
                Some(Value::Bytes(vec![0; 32])),
                Some(int(3)),
                CTAP1_ERR_INVALID_PARAMETER,
            ),
            (
                Some(Value::Bool(true)),
                Some(int(1)),
                CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
            ),
            (
                Some(Value::Bytes(vec![])),
                Some(int(protocol.identifier().into())),
                CTAP2_ERR_PIN_AUTH_INVALID,
            ),
            (
                Some(Value::Bytes(vec![0; 17])),
                Some(int(protocol.identifier().into())),
                CTAP2_ERR_PIN_AUTH_INVALID,
            ),
            (
                Some(Value::Bytes(vec![0; 32])),
                Some(Value::Bool(true)),
                CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
            ),
        ] {
            let mut entries = vec![(int(1), int(1))];
            entries.extend(auth.map(|v| (int(4), v)));
            entries.extend(proto.map(|v| (int(3), v)));
            assert_eq!(
                app.call(&[&[PRE], encode(&canonical_map(entries)).as_slice()].concat()),
                [expected]
            );
        }
        let other = if protocol == ClassicPinProtocol::V1 {
            ClassicPinProtocol::V2
        } else {
            ClassicPinProtocol::V1
        };
        assert_eq!(
            manage(&mut app, PRE, other, &token, 1, None),
            [CTAP2_ERR_PIN_AUTH_INVALID]
        );
        for _ in 0..4 {
            assert_eq!(
                manage(
                    &mut app,
                    PRE,
                    protocol,
                    &[0x77; 32],
                    6,
                    Some(params_id(&record.credential_id, None))
                ),
                [CTAP2_ERR_PIN_AUTH_INVALID]
            );
        }
        for (user, status) in [
            (
                canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0xff]))]),
                CTAP1_ERR_INVALID_PARAMETER,
            ),
            (
                canonical_map(vec![
                    (
                        Value::Text("id".into()),
                        Value::Bytes(record.user_id.clone()),
                    ),
                    (Value::Text("name".into()), Value::Bool(false)),
                ]),
                CTAP2_ERR_CBOR_UNEXPECTED_TYPE,
            ),
        ] {
            assert_eq!(
                manage(
                    &mut app,
                    PRE,
                    protocol,
                    &token,
                    7,
                    Some(params_id(&record.credential_id, Some(user)))
                ),
                [status]
            );
        }
        assert_eq!(store.pin_state_writes().len(), before.len());
        assert_eq!(
            store.credential(&record.credential_id).keypair().unwrap().1,
            record.keypair().unwrap().1
        );
        assert_eq!(
            store.credential(&record.credential_id).sign_count,
            record.sign_count
        );
        assert_eq!(get_pin_retries(&mut app), (8, None));
        let ga = get_pin_uv_auth_token(&mut app, protocol, PIN, 2, Some(&record.rp_id)).unwrap();
        let response = app
            .handle_get_assertion(&get_assertion_request(
                &[0x52; 32],
                &record.rp_id,
                Some((protocol, token_pin_auth(protocol, &ga, &[0x52; 32]))),
                None,
            ))
            .unwrap();
        let auth = response_auth_data(&response);
        assert_eq!(
            u32::from_be_bytes(auth[33..37].try_into().unwrap()),
            record.sign_count + 1
        );
        verify_signature(
            record.alg,
            &record.keypair().unwrap().1,
            &[auth.as_slice(), &[0x52; 32]].concat(),
            &match field(&response, 3) {
                Value::Bytes(b) => b,
                _ => panic!("signature"),
            },
        )
        .unwrap();
    }
}

#[test]
fn failed_publication_and_restart_never_mint_or_preserve_legacy_grants() {
    for protocol in PROTOCOLS {
        for unconfirmed in [false, true] {
            for after in [0, 1] {
                let (mut app, store, _) = ready(protocol);
                app.pin_state.invalidate_pin_uv_auth_tokens();
                store.faults(|f| {
                    f.set_pin_state_after = (!unconfirmed).then_some(after);
                    f.pin_state_unconfirmed_after = unconfirmed.then_some(after);
                });
                assert_eq!(
                    get_pin_token(&mut app, protocol, PIN),
                    Err(CTAP2_ERR_PROCESSING)
                );
                assert_eq!(app.pin_state.token_origin(), None);
                store.faults(|f| {
                    f.set_pin_state_after = None;
                    f.pin_state_unconfirmed_after = None;
                });
                let token = get_pin_token(&mut app, protocol, PIN).unwrap();
                assert_eq!(
                    manage(&mut app, PRE, protocol, &token, 1, None)[0],
                    CTAP2_OK
                );
                let mut restarted = new_app(store.clone(), [0x41; 16]);
                assert_eq!(
                    manage(&mut restarted, PRE, protocol, &token, 1, None),
                    [CTAP2_ERR_PIN_AUTH_INVALID]
                );
                assert_eq!(
                    change_pin(&mut app, protocol, PIN, b"5678").unwrap(),
                    [CTAP2_OK]
                );
                assert_eq!(
                    manage(&mut app, PRE, protocol, &token, 1, None),
                    [CTAP2_ERR_PIN_AUTH_INVALID]
                );
            }
        }
        for fail in [false, true] {
            let (mut app, store, _) = ready(protocol);
            let token = get_pin_uv_auth_token(&mut app, protocol, PIN, 0x24, None).unwrap();
            assert_eq!(
                manage(&mut app, PRE, protocol, &token, 2, None)[0],
                CTAP2_OK
            );
            store.faults(|f| f.set_pin_state = fail);
            let params = canonical_map(vec![(int(4), Value::Bool(true))]);
            assert_eq!(
                configure(&mut app, protocol, &token, params),
                [if fail { CTAP2_ERR_PROCESSING } else { CTAP2_OK }]
            );
            store.faults(|f| f.set_pin_state = false);
            assert_eq!(
                manage(&mut app, PRE, protocol, &token, 3, None)[0],
                if fail {
                    CTAP2_OK
                } else {
                    CTAP2_ERR_NOT_ALLOWED
                }
            );
            assert_eq!(get_pin_token(&mut app, protocol, PIN).is_ok(), fail);
        }
    }
}

#[test]
fn preview_enumerates_every_algorithm_and_preserves_keys_after_user_updates() {
    for protocol in PROTOCOLS {
        for alg in CoseAlg::ALL {
            let (mut app, store, token) = ready(protocol);
            let mut record = credential(RP, &[8], &[8], alg);
            record.third_party_payment = true;
            record.large_blob_key = Some([0x87; 32]);
            insert(&mut app, &record);
            let before = record.keypair().unwrap();
            let response = manage(&mut app, PRE, protocol, &token, 4, Some(params_rp(RP)));
            assert_eq!(encode(&field(&response, 8)), before.1, "{alg:?}");
            assert_eq!(field(&response, 12), Value::Bool(true));
            let user = canonical_map(vec![(
                Value::Text("id".into()),
                Value::Bytes(record.user_id.clone()),
            )]);
            assert_eq!(
                manage(
                    &mut app,
                    PRE,
                    protocol,
                    &token,
                    7,
                    Some(params_id(&record.credential_id, Some(user)))
                ),
                [CTAP2_OK]
            );
            let after = store.credential(&record.credential_id);
            assert_eq!(after.keypair().unwrap().1, before.1);
            assert_eq!(after.large_blob_key, record.large_blob_key);
            assert_eq!(after.third_party_payment, record.third_party_payment);
            let signature =
                crate::try_sign_challenge(alg, &after.keypair().unwrap().0, b"auth", b"hash")
                    .unwrap();
            verify_signature(alg, &before.1, b"authhash", &signature).unwrap();
        }
    }
}

#[test]
fn preview_capacity_truncation_and_authenticated_membership_are_shared() {
    for protocol in PROTOCOLS {
        let (mut app, store, token) = ready(protocol);
        let long = "https://very.long.identifier.preview.example";
        let record = credential(long, &[7], &[7], CoseAlg::ES256);
        insert(&mut app, &record);
        let mut hidden = credential(RP, &[], &[&[0][..], &[9; 32][..]].concat(), CoseAlg::ES256);
        hidden.credential_id[0] = 0;
        insert(&mut app, &hidden);
        let meta = manage(&mut app, PRE, protocol, &token, 1, None);
        assert_eq!(field(&meta, 1), int(4));
        assert_eq!(field(&meta, 2), int((store.max_credentials() - 5) as i64));
        let mut rps = vec![manage(&mut app, PRE, protocol, &token, 2, None)];
        for _ in 0..2 {
            rps.push(manage(&mut app, PRE, protocol, &token, 3, None));
        }
        let truncated = rps
            .iter()
            .find(|r| field(r, 4) == Value::Bytes(CtapApp::cm_hash_rp_id(long)))
            .unwrap();
        assert_eq!(
            field(truncated, 3),
            canonical_map(vec![(
                Value::Text("id".into()),
                Value::Text(crate::ctap::credential_management::truncated_rp_id(long))
            )])
        );
        assert_eq!(
            field(
                &manage(&mut app, PRE, protocol, &token, 4, Some(params_rp(RP))),
                9
            ),
            int(2)
        );
        assert_eq!(
            manage(
                &mut app,
                PRE,
                protocol,
                &token,
                6,
                Some(params_id(&[0x01; 33], None))
            ),
            [CTAP2_ERR_NO_CREDENTIALS]
        );
        assert_eq!(
            manage(&mut app, PRE, protocol, &token, 8, None),
            [CTAP2_ERR_INVALID_SUBCOMMAND]
        );
        for sub in [4, 6, 7] {
            assert_eq!(
                manage(&mut app, PRE, protocol, &token, sub, None),
                [CTAP2_ERR_MISSING_PARAMETER]
            );
        }
        assert_eq!(store.credentials().len(), 5);
    }
}
