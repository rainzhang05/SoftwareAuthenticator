//! Configuration, always-UV and minimum PIN policy (CTAP 2.3 §§6.11, 7, 12.5).

use super::hmac_secret_mc::{HASH, extension_outputs, verify_response};
use super::support::*;
use crate::ClassicPinProtocol;
use crate::ctap::CtapApp;
use crate::ctap::cbor::{canonical_map, map_get};
use crate::ctap::constants::*;
use crate::ctap::pin::permissions::{
    PIN_PERMISSION_ACFG, PIN_PERMISSION_CM, PIN_PERMISSION_GA, PIN_PERMISSION_MC,
};
use crate::ctap::pin::token::ManualClock;
use crate::store::{CredentialStore, PinStateRecord};
use ciborium::{de::from_reader, value::Value};
use core::time::Duration;

const PIN: &[u8] = b"12345678";
const TOKEN: [u8; 32] = [0x71; 32];
const RP: &str = "example.com";
const PROTOCOLS: [ClassicPinProtocol; 2] = [ClassicPinProtocol::V1, ClassicPinProtocol::V2];

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn message(subcommand: u8, params: Option<&Value>) -> Vec<u8> {
    let mut message = vec![0xff; 32];
    message.extend_from_slice(&[CTAP_CMD_AUTHENTICATOR_CONFIG, subcommand]);
    if let Some(params) = params {
        message.extend(encode(params));
    }
    message
}

fn request(subcommand: u8, params: Option<Value>, auth: Option<ClassicPinProtocol>) -> Vec<u8> {
    let mut entries = vec![(int(1), int(subcommand.into()))];
    if let Some(protocol) = auth {
        let mac = token_pin_auth(protocol, &TOKEN, &message(subcommand, params.as_ref()));
        entries.push((int(3), int(protocol.identifier().into())));
        entries.push((int(4), Value::Bytes(mac)));
    }
    if let Some(params) = params {
        entries.push((int(2), params));
    }
    encode(&canonical_map(entries))
}

fn configure(
    app: &mut TestApp,
    subcommand: u8,
    params: Option<Value>,
    auth: Option<ClassicPinProtocol>,
) -> Result<Vec<u8>, u8> {
    app.handle_authenticator_config(&request(subcommand, params, auth))
}

fn min_params(length: i64) -> Value {
    canonical_map(vec![(int(1), int(length))])
}

fn info(app: &mut TestApp) -> Vec<(Value, Value)> {
    let response = app.call(&[CTAP_CMD_GET_INFO]);
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(info) = from_reader(&response[1..]).unwrap() else {
        panic!("getInfo map")
    };
    info
}

fn token(app: &mut TestApp, protocol: ClassicPinProtocol, permissions: u8) {
    install_pin_uv_auth_token(app, protocol, TOKEN, permissions, None);
}

#[test]
fn dispatch_logging_and_get_info_advertise_configuration() {
    let mut app = test_app([0x70; 16]);
    let mut command = vec![CTAP_CMD_AUTHENTICATOR_CONFIG];
    command.extend(request(2, None, None));
    assert_eq!(app.call(&command), [CTAP2_OK]);
    assert!(app.pin_state.persistent().always_uv);
    let log = CtapApp::request_log_line(
        &[CTAP_CMD_AUTHENTICATOR_CONFIG, 0xa2, 1, 3, 3, 2],
        &[CTAP2_OK],
    );
    assert!(log.contains("sub=0x03 pinProtocol=0x02"));
    let fields = info(&mut app);
    assert_eq!(map_get(&fields, int(12)), Some(&Value::Bool(false)));
    assert_eq!(map_get(&fields, int(13)), Some(&int(4)));
    assert_eq!(map_get(&fields, int(16)), Some(&int(8)));
    assert_eq!(
        map_get(&fields, int(31)),
        Some(&Value::Array(vec![int(2), int(3)]))
    );
    let Value::Array(extensions) = map_get(&fields, int(2)).unwrap() else {
        panic!("extensions")
    };
    assert!(extensions.contains(&text("minPinLength")));
    assert!(!extensions.contains(&text("pinComplexityPolicy")));
    assert!(map_get(&fields, int(0x1b)).is_none());
    let Value::Map(options) = map_get(&fields, int(4)).unwrap() else {
        panic!("options")
    };
    for (name, value) in [
        ("authnrCfg", true),
        ("alwaysUv", true),
        ("setMinPINLength", true),
        ("makeCredUvNotRqd", false),
    ] {
        assert_eq!(map_get(options, text(name)), Some(&Value::Bool(value)));
    }
    assert!(map_get(options, text("uvAcfg")).is_none());
}

#[test]
fn malformed_requests_and_subcommands_fail_before_authentication() {
    let mut app = test_app([0x71; 16]);
    token(&mut app, ClassicPinProtocol::V2, PIN_PERMISSION_ACFG);
    for payload in [&[][..], &[0xa1, 1][..], &[0xa0, 0][..], &[0xbf, 0xff][..]] {
        assert_eq!(
            app.handle_authenticator_config(payload),
            Err(CTAP2_ERR_INVALID_CBOR)
        );
    }
    assert_eq!(
        app.handle_authenticator_config(&[0x80]),
        Err(CTAP2_ERR_INVALID_CBOR)
    );
    assert_eq!(
        app.handle_authenticator_config(&[0xa0]),
        Err(CTAP2_ERR_MISSING_PARAMETER)
    );
    for number in [-1, 0, 1, 4, 255, 256] {
        let payload = encode(&canonical_map(vec![
            (int(1), int(number)),
            (int(2), Value::Null),
        ]));
        assert_eq!(
            app.handle_authenticator_config(&payload),
            Err(CTAP1_ERR_INVALID_PARAMETER)
        );
    }
    assert_eq!(
        app.handle_authenticator_config(&encode(&canonical_map(vec![(
            int(1),
            text("toggleAlwaysUv")
        ),]))),
        Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
    );
}

#[test]
fn no_pin_configuration_and_toggle_exception_ignore_authentication() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0x72; 16]);
        assert_eq!(
            configure(&mut app, 3, Some(min_params(5)), None),
            Ok(vec![CTAP2_OK])
        );
        assert_eq!(
            configure(&mut app, 2, None, Some(protocol)),
            Ok(vec![CTAP2_OK])
        );
        assert!(app.pin_state.persistent().always_uv);
        assert_eq!(
            configure(&mut app, 3, Some(min_params(6)), None),
            Err(CTAP2_ERR_PUAT_REQUIRED)
        );
        assert_eq!(
            configure(&mut app, 3, Some(min_params(6)), Some(protocol)),
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            configure(&mut app, 2, None, Some(protocol)),
            Ok(vec![CTAP2_OK])
        );
        assert!(!app.pin_state.persistent().always_uv);
        assert_eq!(
            configure(
                &mut app,
                2,
                Some(canonical_map(vec![(int(1), Value::Null)])),
                None
            ),
            Ok(vec![CTAP2_OK])
        );
        assert_eq!(configure(&mut app, 2, None, None), Ok(vec![CTAP2_OK]));
    }
}

#[test]
fn authentication_has_the_specified_order_and_permission() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0x73; 16]);
        token(&mut app, protocol, PIN_PERMISSION_ACFG);
        let payload = |extra: Vec<(Value, Value)>| {
            let mut entries = vec![(int(1), int(2)), (int(2), Value::Null)];
            entries.extend(extra);
            encode(&canonical_map(entries))
        };
        assert_eq!(
            app.handle_authenticator_config(&payload(vec![])),
            Err(CTAP2_ERR_PUAT_REQUIRED)
        );
        assert_eq!(
            app.handle_authenticator_config(&payload(vec![(int(4), Value::Null)])),
            Err(CTAP2_ERR_MISSING_PARAMETER)
        );
        assert_eq!(
            app.handle_authenticator_config(&payload(vec![
                (int(3), int(3)),
                (int(4), Value::Null)
            ])),
            Err(CTAP1_ERR_INVALID_PARAMETER)
        );
        assert_eq!(
            app.handle_authenticator_config(&payload(vec![
                (int(3), Value::Bool(true)),
                (int(4), Value::Null)
            ])),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            app.handle_authenticator_config(&payload(vec![
                (int(3), int(protocol.identifier().into())),
                (int(4), Value::Null)
            ])),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        for length in [0, 15, 16, 17, 31, 32, 33] {
            assert_eq!(
                app.handle_authenticator_config(&payload(vec![
                    (int(3), int(protocol.identifier().into())),
                    (int(4), Value::Bytes(vec![0; length])),
                ])),
                Err(CTAP2_ERR_PIN_AUTH_INVALID)
            );
        }
        for permission in [PIN_PERMISSION_MC, PIN_PERMISSION_GA, PIN_PERMISSION_CM] {
            token(&mut app, protocol, permission);
            assert_eq!(
                configure(&mut app, 2, None, Some(protocol)),
                Err(CTAP2_ERR_PIN_AUTH_INVALID)
            );
        }
        token(&mut app, protocol, PIN_PERMISSION_ACFG);
        assert_eq!(
            configure(&mut app, 2, Some(Value::Null), Some(protocol)),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(
            configure(&mut app, 2, None, Some(protocol)),
            Ok(vec![CTAP2_OK])
        );
        // An acfg token's RP binding does not restrict configuration (§6.11).
        install_pin_uv_auth_token(
            &mut app,
            protocol,
            TOKEN,
            PIN_PERMISSION_ACFG,
            Some("another.example"),
        );
        assert_eq!(
            configure(&mut app, 2, None, Some(protocol)),
            Ok(vec![CTAP2_OK])
        );
    }
}

#[test]
fn authentication_uses_the_entire_original_parameter_map() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0x74; 16]);
        token(&mut app, protocol, PIN_PERMISSION_ACFG);
        let params = canonical_map(vec![
            (int(1), int(4)),
            (int(99), Value::Bytes(vec![0xff, 0, 0x0d])),
        ]);
        let valid = request(3, Some(params.clone()), Some(protocol));
        let Value::Map(mut fields) = from_reader(&valid[..]).unwrap() else {
            panic!("map")
        };
        fields.iter_mut().find(|(key, _)| *key == int(4)).unwrap().1 = Value::Bytes(
            token_pin_auth(protocol, &TOKEN, &message(3, Some(&min_params(4)))),
        );
        assert_eq!(
            app.handle_authenticator_config(&encode(&canonical_map(fields))),
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(app.handle_authenticator_config(&valid), Ok(vec![CTAP2_OK]));
        // Unknown simple values are decoded differently by ciborium. MACs
        // must still use the exact bytes sent by the platform.
        let original = [0xa2, 1, 4, 0x18, 0x63, 0xe0];
        let normalized = [0xa2, 1, 4, 0x18, 0x63, 0xf7];
        for (signed, expected) in [
            (&normalized[..], Err(CTAP2_ERR_PIN_AUTH_INVALID)),
            (&original[..], Ok(vec![CTAP2_OK])),
        ] {
            let mut m = vec![0xff; 32];
            m.extend([0x0d, 3]);
            m.extend(signed);
            let mut payload = vec![0xa4, 1, 3, 2];
            payload.extend(original);
            payload.extend([3, protocol.identifier() as u8, 4]);
            payload.extend(encode(&Value::Bytes(token_pin_auth(protocol, &TOKEN, &m))));
            assert_eq!(app.handle_authenticator_config(&payload), expected);
        }
        // Missing params and an explicitly empty map are different messages.
        let mac = token_pin_auth(protocol, &TOKEN, &message(2, None));
        assert_eq!(
            app.handle_authenticator_config(&encode(&canonical_map(vec![
                (int(1), int(2)),
                (int(2), canonical_map(vec![])),
                (int(3), int(protocol.identifier().into())),
                (int(4), Value::Bytes(mac)),
            ]))),
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        );
        // Overlong integer and indefinite map encodings are malformed CTAP CBOR.
        for raw in [vec![0xa1, 0x18, 1, 4], vec![0xbf, 1, 4, 0xff]] {
            let mut payload = vec![0xa4, 1, 3, 2];
            payload.extend_from_slice(&raw);
            payload.extend([3, protocol.identifier() as u8, 4]);
            let mut m = vec![0xff; 32];
            m.extend([0x0d, 3]);
            m.extend(raw);
            payload.extend(encode(&Value::Bytes(token_pin_auth(protocol, &TOKEN, &m))));
            assert_eq!(
                app.handle_authenticator_config(&payload),
                Err(CTAP2_ERR_INVALID_CBOR)
            );
        }
    }
}

#[test]
fn minimum_policy_checks_errors_in_order_without_mutating() {
    let store = TestStore::new();
    let mut app = new_app(store.clone(), [0x75; 16]);
    configure(&mut app, 3, Some(min_params(8)), None).unwrap();
    let before = store.pin_state().unwrap();
    let too_many = Value::Array(vec![text("a"); 9]);
    for (params, error) in [
        (
            canonical_map(vec![
                (int(1), int(7)),
                (int(3), Value::Bool(true)),
                (int(4), Value::Bool(true)),
                (int(2), too_many.clone()),
            ]),
            CTAP2_ERR_PIN_POLICY_VIOLATION,
        ),
        (
            canonical_map(vec![
                (int(1), int(8)),
                (int(3), Value::Bool(true)),
                (int(4), Value::Bool(true)),
            ]),
            CTAP2_ERR_PIN_NOT_SET,
        ),
        (
            canonical_map(vec![
                (int(4), Value::Bool(true)),
                (int(2), too_many.clone()),
            ]),
            CTAP1_ERR_INVALID_PARAMETER,
        ),
        (
            canonical_map(vec![(int(2), too_many)]),
            CTAP2_ERR_KEY_STORE_FULL,
        ),
        (
            canonical_map(vec![(int(2), Value::Array(vec![text(&"a".repeat(254))]))]),
            CTAP2_ERR_KEY_STORE_FULL,
        ),
        (min_params(64), CTAP1_ERR_INVALID_PARAMETER),
        (min_params(-1), CTAP1_ERR_INVALID_PARAMETER),
    ] {
        assert_eq!(configure(&mut app, 3, Some(params), None), Err(error));
        assert_eq!(store.pin_state().unwrap(), before);
        assert_eq!(app.pin_state.persistent().min_pin_length, 8);
    }
    for (key, value) in [
        (1, Value::Bool(false)),
        (2, text("a")),
        (2, Value::Array(vec![int(1)])),
        (3, int(0)),
        (4, int(0)),
    ] {
        assert_eq!(
            configure(
                &mut app,
                3,
                Some(canonical_map(vec![(int(key), value)])),
                None
            ),
            Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
        );
        assert_eq!(store.pin_state().unwrap(), before);
    }
    configure(
        &mut app,
        3,
        Some(canonical_map(vec![(int(4), Value::Bool(false))])),
        None,
    )
    .unwrap();
    configure(&mut app, 3, Some(min_params(63)), None).unwrap();
    assert_eq!(app.pin_state.persistent().min_pin_length, 63);
}

#[test]
fn rp_lists_replace_only_when_nonempty_and_accept_capacity_boundaries() {
    let mut app = test_app([0x76; 16]);
    let params = |list| canonical_map(vec![(int(2), Value::Array(list))]);
    configure(&mut app, 3, Some(params(vec![text("a"), text("b")])), None).unwrap();
    configure(&mut app, 3, Some(params(vec![])), None).unwrap();
    assert_eq!(app.pin_state.persistent().min_pin_length_rp_ids, ["a", "b"]);
    configure(&mut app, 3, None, None).unwrap();
    assert_eq!(app.pin_state.persistent().min_pin_length_rp_ids, ["a", "b"]);
    configure(&mut app, 3, Some(params(vec![text("c")])), None).unwrap();
    assert_eq!(app.pin_state.persistent().min_pin_length_rp_ids, ["c"]);
    configure(
        &mut app,
        3,
        Some(params(vec![text(&"a".repeat(253)); 8])),
        None,
    )
    .unwrap();
    assert_eq!(app.pin_state.persistent().min_pin_length_rp_ids.len(), 8);
    assert_eq!(
        configure(
            &mut app,
            3,
            Some(params(vec![text(&"é".repeat(127))])),
            None
        ),
        Err(CTAP2_ERR_KEY_STORE_FULL)
    );
}

#[test]
fn force_change_checks_pin_then_refuses_tokens_and_same_pin() {
    for protocol in PROTOCOLS {
        let store = TestStore::new();
        let mut app = new_app(store.clone(), [0x77; 16]);
        set_pin_padded(&mut app, protocol, &padded_pin(PIN)).unwrap();
        assert_eq!(app.pin_state.persistent().pin_code_point_length, 8);
        let issued =
            get_pin_uv_auth_token(&mut app, protocol, PIN, PIN_PERMISSION_ACFG.into(), None)
                .unwrap();
        assert_eq!(app.pin_state.pin_uv_auth_permissions(), PIN_PERMISSION_ACFG);
        // Authenticate with the actual issued token, rather than the test one.
        let params = canonical_map(vec![(int(3), Value::Bool(true))]);
        let mac = token_pin_auth(protocol, &issued, &message(3, Some(&params)));
        let command = encode(&canonical_map(vec![
            (int(1), int(3)),
            (int(2), params),
            (int(3), int(protocol.identifier().into())),
            (int(4), Value::Bytes(mac)),
        ]));
        app.handle_authenticator_config(&command).unwrap();
        assert!(app.pin_state.persistent().force_pin_change);
        assert!(app.pin_state.pin_uv_auth_token().is_none());
        assert!(store.pin_state().unwrap().unwrap().force_pin_change);
        assert_eq!(
            get_pin_token(&mut app, protocol, b"0000"),
            Err(CTAP2_ERR_PIN_INVALID)
        );
        assert_eq!(get_pin_retries(&mut app).0, 7);
        assert_eq!(
            get_pin_token(&mut app, protocol, PIN),
            Err(CTAP2_ERR_PIN_INVALID)
        );
        assert_eq!(get_pin_retries(&mut app).0, 8);
        assert_eq!(
            get_pin_uv_auth_token(
                &mut app,
                protocol,
                b"0000",
                PIN_PERMISSION_ACFG.into(),
                None
            ),
            Err(CTAP2_ERR_PIN_INVALID)
        );
        assert_eq!(
            get_pin_uv_auth_token(&mut app, protocol, PIN, PIN_PERMISSION_ACFG.into(), None),
            Err(CTAP2_ERR_PIN_POLICY_VIOLATION)
        );
        assert_eq!(get_pin_retries(&mut app).0, 8);
        assert_eq!(
            change_pin(&mut app, protocol, PIN, PIN),
            Err(CTAP2_ERR_PIN_POLICY_VIOLATION)
        );
        assert!(app.pin_state.persistent().force_pin_change);
        change_pin(&mut app, protocol, PIN, b"abcdefgh").unwrap();
        assert!(!app.pin_state.persistent().force_pin_change);
        assert!(!store.pin_state().unwrap().unwrap().force_pin_change);
        get_pin_uv_auth_token(
            &mut app,
            protocol,
            b"abcdefgh",
            PIN_PERMISSION_ACFG.into(),
            None,
        )
        .unwrap();
    }
}

#[test]
fn current_minimum_is_enforced_and_lengths_count_unicode_code_points() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0x78; 16]);
        configure(&mut app, 3, Some(min_params(6)), None).unwrap();
        assert_eq!(
            set_pin_padded(&mut app, protocol, &padded_pin("ééééé".as_bytes())),
            Err(CTAP2_ERR_PIN_POLICY_VIOLATION)
        );
        set_pin_padded(&mut app, protocol, &padded_pin("éééééé".as_bytes())).unwrap();
        assert_eq!(app.pin_state.persistent().pin_code_point_length, 6);
        token(&mut app, protocol, PIN_PERMISSION_ACFG);
        configure(&mut app, 3, Some(min_params(7)), Some(protocol)).unwrap();
        assert!(app.pin_state.persistent().force_pin_change);
        assert!(app.pin_state.pin_uv_auth_token().is_none());
        assert_eq!(
            change_pin(&mut app, protocol, "éééééé".as_bytes(), b"abcdef"),
            Err(CTAP2_ERR_PIN_POLICY_VIOLATION)
        );
        change_pin(
            &mut app,
            protocol,
            "éééééé".as_bytes(),
            "ééééééé".as_bytes(),
        )
        .unwrap();
        assert_eq!(app.pin_state.persistent().pin_code_point_length, 7);
        assert!(!app.pin_state.persistent().force_pin_change);
    }
}

#[test]
fn same_pin_is_allowed_without_forced_change_and_false_does_not_clear_it() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0x79; 16]);
        set_pin_padded(&mut app, protocol, &padded_pin(PIN)).unwrap();
        change_pin(&mut app, protocol, PIN, PIN).unwrap();
        token(&mut app, protocol, PIN_PERMISSION_ACFG);
        configure(
            &mut app,
            3,
            Some(canonical_map(vec![(int(3), Value::Bool(true))])),
            Some(protocol),
        )
        .unwrap();
        token(&mut app, protocol, PIN_PERMISSION_ACFG);
        configure(
            &mut app,
            3,
            Some(canonical_map(vec![(int(3), Value::Bool(false))])),
            Some(protocol),
        )
        .unwrap();
        assert!(app.pin_state.persistent().force_pin_change);
        assert!(app.pin_state.pin_uv_auth_token().is_none());
    }
}

#[test]
fn failed_configuration_preserves_tokens_and_saved_state() {
    for protocol in PROTOCOLS {
        let store = TestStore::new();
        let mut app = new_app(store.clone(), [0x7a; 16]);
        set_pin_padded(&mut app, protocol, &padded_pin(PIN)).unwrap();
        token(&mut app, protocol, PIN_PERMISSION_ACFG);
        let before = store.pin_state().unwrap();
        let writes = store.pin_state_writes().len();
        let invalid = canonical_map(vec![
            (int(1), int(9)),
            (int(3), Value::Bool(true)),
            (int(2), Value::Array(vec![text("a"); 9])),
        ]);
        assert_eq!(
            configure(&mut app, 3, Some(invalid), Some(protocol)),
            Err(CTAP2_ERR_KEY_STORE_FULL)
        );
        assert_eq!(store.pin_state().unwrap(), before);
        assert_eq!(store.pin_state_writes().len(), writes);
        assert_eq!(app.pin_state.pin_uv_auth_token(), Some(TOKEN));
        store.faults(|faults| faults.set_pin_state = true);
        assert_eq!(
            configure(&mut app, 3, Some(min_params(9)), Some(protocol)),
            Err(CTAP2_ERR_PROCESSING)
        );
        assert_eq!(
            configure(&mut app, 2, None, Some(protocol)),
            Err(CTAP2_ERR_PROCESSING)
        );
        assert_eq!(store.pin_state().unwrap(), before);
        assert_eq!(app.pin_state.pin_uv_auth_token(), Some(TOKEN));
        assert_eq!(app.pin_state.persistent().min_pin_length, 4);
        assert!(!app.pin_state.persistent().always_uv);
        assert!(!app.pin_state.persistent().force_pin_change);
    }
}

#[test]
fn successful_configuration_preserves_lockout_key_agreement_clock_and_token() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0x7b; 16]);
        set_pin_padded(&mut app, protocol, &padded_pin(PIN)).unwrap();
        for _ in 0..3 {
            let _ = get_pin_token(&mut app, protocol, b"0000");
        }
        let agreement = request_classic_key_agreement(&mut app, protocol);
        let clock = ManualClock::default();
        app.pin_state.set_clock(Box::new(clock.clone()));
        token(&mut app, protocol, PIN_PERMISSION_ACFG);
        let token_id = app.pin_state.pin_uv_auth_token_id();
        configure(&mut app, 2, None, Some(protocol)).unwrap();
        configure(&mut app, 3, Some(min_params(8)), Some(protocol)).unwrap();
        assert_eq!(get_pin_retries(&mut app), (5, Some(true)));
        assert_eq!(request_classic_key_agreement(&mut app, protocol), agreement);
        assert_eq!(app.pin_state.pin_uv_auth_token_id(), token_id);
        assert_eq!(app.pin_state.pin_uv_auth_token(), Some(TOKEN));
        clock.advance(Duration::from_secs(601));
        assert_eq!(
            configure(&mut app, 2, None, Some(protocol)),
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }
}

#[test]
fn always_uv_enforces_registration_and_only_assertions_with_presence() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0x7c; 16]);
        configure(&mut app, 2, None, None).unwrap();
        let mc = make_credential_request(&HASH, RP, None);
        let ga = get_assertion_request(&HASH, RP, None, None);
        assert_eq!(
            app.handle_make_credential(&mc),
            Err(CTAP2_ERR_PUAT_REQUIRED)
        );
        assert_eq!(app.handle_get_assertion(&ga), Err(CTAP2_ERR_PUAT_REQUIRED));
        insert_owned(&mut app, es256_credential(RP, &[0x81]));
        let Value::Map(mut silent) = from_reader(&ga[..]).unwrap() else {
            panic!("map")
        };
        silent.push((
            int(5),
            canonical_map(vec![(text("up"), Value::Bool(false))]),
        ));
        assert_eq!(
            response_auth_data(
                &app.handle_get_assertion(&encode(&canonical_map(silent)))
                    .unwrap()
            )[32]
                & 5,
            0
        );
        set_pin_padded(&mut app, protocol, &padded_pin(PIN)).unwrap();
        assert_eq!(
            app.handle_make_credential(&mc),
            Err(CTAP2_ERR_PUAT_REQUIRED)
        );
        assert_eq!(app.handle_get_assertion(&ga), Err(CTAP2_ERR_PUAT_REQUIRED));
        token(&mut app, protocol, PIN_PERMISSION_MC);
        let response = app
            .handle_make_credential(&make_credential_request(
                &HASH,
                RP,
                Some((protocol, token_pin_auth(protocol, &TOKEN, &HASH))),
            ))
            .unwrap();
        let credential = created_credential(&app, &response, RP);
        assert_eq!(response_auth_data(&response)[32] & 4, 4);
        let descriptor = canonical_map(vec![
            (text("type"), text("public-key")),
            (text("id"), Value::Bytes(credential.credential_id.clone())),
        ]);
        let Value::Map(mut params) = from_reader(&ga[..]).unwrap() else {
            panic!("map")
        };
        params.push((int(3), Value::Array(vec![descriptor])));
        params.push((
            int(5),
            canonical_map(vec![(text("up"), Value::Bool(false))]),
        ));
        let response = app
            .handle_get_assertion(&encode(&canonical_map(params.clone())))
            .unwrap();
        assert_eq!(response_auth_data(&response)[32] & 5, 0);
        params.iter_mut().find(|(key, _)| *key == int(5)).unwrap().1 =
            canonical_map(vec![(text("up"), Value::Bool(true))]);
        assert_eq!(
            app.handle_get_assertion(&encode(&canonical_map(params.clone()))),
            Err(CTAP2_ERR_PUAT_REQUIRED)
        );
        token(&mut app, protocol, PIN_PERMISSION_GA);
        params.push((
            int(6),
            Value::Bytes(token_pin_auth(protocol, &TOKEN, &HASH)),
        ));
        params.push((int(7), int(protocol.identifier().into())));
        assert_eq!(
            response_auth_data(
                &app.handle_get_assertion(&encode(&canonical_map(params)))
                    .unwrap()
            )[32]
                & 5,
            5
        );
    }
}

#[test]
fn minimum_extension_is_requested_authorized_and_signed() {
    let mut app = test_app([0x7d; 16]);
    configure(
        &mut app,
        3,
        Some(canonical_map(vec![
            (int(1), int(9)),
            (int(2), Value::Array(vec![text(RP)])),
        ])),
        None,
    )
    .unwrap();
    for (rp, extension, expected) in [
        (RP, Some(Value::Bool(true)), Some(int(9))),
        ("other.example", Some(Value::Bool(true)), None),
        (RP, Some(Value::Bool(false)), None),
        (RP, None, None),
    ] {
        let Value::Map(mut params) =
            from_reader(&make_credential_request(&HASH, rp, None)[..]).unwrap()
        else {
            panic!("map")
        };
        if let Some(extension) = extension {
            params.push((
                int(6),
                canonical_map(vec![(text("minPinLength"), extension)]),
            ));
        }
        let response = app
            .handle_make_credential(&encode(&canonical_map(params)))
            .unwrap();
        let credential = created_credential(&app, &response, rp);
        assert_eq!(
            map_get(
                &extension_outputs(&response, Some(&credential)),
                text("minPinLength")
            ),
            expected.as_ref()
        );
        verify_response(&response, &credential, true);
    }
    let Value::Map(mut params) =
        from_reader(&make_credential_request(&HASH, RP, None)[..]).unwrap()
    else {
        panic!("map")
    };
    params.push((int(6), canonical_map(vec![(text("minPinLength"), int(1))])));
    assert_eq!(
        app.handle_make_credential(&encode(&canonical_map(params))),
        Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
    );
}

#[test]
fn settings_survive_restart_and_reset_restores_every_default() {
    for protocol in PROTOCOLS {
        let store = TestStore::new();
        let mut app = new_app(store.clone(), [0x7e; 16]);
        set_pin_padded(&mut app, protocol, &padded_pin(PIN)).unwrap();
        token(&mut app, protocol, PIN_PERMISSION_ACFG);
        configure(&mut app, 2, None, Some(protocol)).unwrap();
        configure(
            &mut app,
            3,
            Some(canonical_map(vec![
                (int(1), int(9)),
                (int(2), Value::Array(vec![text(RP)])),
            ])),
            Some(protocol),
        )
        .unwrap();
        let mut restarted = new_app(store.clone(), [0x7e; 16]);
        assert!(restarted.pin_state.persistent().always_uv);
        assert!(restarted.pin_state.persistent().force_pin_change);
        assert_eq!(restarted.pin_state.persistent().min_pin_length, 9);
        assert_eq!(restarted.pin_state.persistent().pin_code_point_length, 8);
        assert_eq!(restarted.pin_state.persistent().min_pin_length_rp_ids, [RP]);
        restarted.call(&[CTAP_CMD_RESET]);
        assert_eq!(store.pin_state().unwrap(), Some(PinStateRecord::default()));
        let fields = info(&mut restarted);
        assert_eq!(map_get(&fields, int(12)), Some(&Value::Bool(false)));
        assert_eq!(map_get(&fields, int(13)), Some(&int(4)));
        assert!(!restarted.pin_state.persistent().always_uv);
        assert!(
            restarted
                .pin_state
                .persistent()
                .min_pin_length_rp_ids
                .is_empty()
        );
        assert_eq!(restarted.pin_state.persistent().pin_code_point_length, 4);
    }
}

#[test]
fn legacy_length_conservatively_forces_change_and_corruption_requires_uv() {
    let store = TestStore::new();
    let mut state = PinStateRecord::default();
    state.pin_hash = Some(pin_hash(PIN));
    store.clone().set_pin_state(&state).unwrap();
    let mut app = new_app(store.clone(), [0x7f; 16]);
    token(&mut app, ClassicPinProtocol::V2, PIN_PERMISSION_ACFG);
    configure(
        &mut app,
        3,
        Some(min_params(5)),
        Some(ClassicPinProtocol::V2),
    )
    .unwrap();
    assert!(app.pin_state.persistent().force_pin_change);
    store.faults(|faults| faults.pin_state = true);
    let mut unreadable = new_app(store.clone(), [0x7f; 16]);
    assert!(unreadable.pin_state.persistent().always_uv);
    assert_eq!(
        unreadable.handle_make_credential(&make_credential_request(&HASH, RP, None)),
        Err(CTAP2_ERR_PUAT_REQUIRED)
    );
    assert_eq!(
        unreadable.handle_get_assertion(&get_assertion_request(&HASH, RP, None, None)),
        Err(CTAP2_ERR_PUAT_REQUIRED)
    );
    assert_eq!(
        get_pin_token(&mut unreadable, ClassicPinProtocol::V2, PIN),
        Err(CTAP2_ERR_PIN_BLOCKED)
    );
    assert_eq!(
        configure(&mut unreadable, 2, None, None),
        Err(CTAP2_ERR_PUAT_REQUIRED)
    );
    store.faults(|faults| faults.pin_state = false);
    assert_eq!(unreadable.call(&[CTAP_CMD_RESET]), [CTAP2_OK]);
    assert!(!unreadable.pin_state.persistent().always_uv);
}
