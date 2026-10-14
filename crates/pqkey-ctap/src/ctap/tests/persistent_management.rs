//! Persistent read-only authority, independent of transient flags and timers.
use super::support::*;
use crate::ClassicPinProtocol;
use crate::ctap::constants::*;
use crate::ctap::pin::token::ManualClock;
use crate::store::CredentialStore;
use ciborium::value::Value;
use core::time::Duration;
use zeroize::Zeroizing;

const PIN: &[u8] = b"1234";
const PROTOCOLS: [ClassicPinProtocol; 2] = [ClassicPinProtocol::V1, ClassicPinProtocol::V2];
fn ready() -> (TestApp, TestStore) {
    let store = TestStore::new();
    let mut app = new_app(store.clone(), [0; 16]);
    set_pin_padded(&mut app, ClassicPinProtocol::V2, &padded_pin(PIN)).unwrap();
    (app, store)
}
fn token(app: &mut TestApp, protocol: ClassicPinProtocol) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(get_pin_uv_auth_token(app, protocol, PIN, 0x40, None).unwrap())
}
fn manage(
    app: &mut TestApp,
    family: u8,
    protocol: ClassicPinProtocol,
    token: &[u8],
    sub: u8,
    params: Option<Value>,
) -> Vec<u8> {
    let mut fields = vec![(int(1), int(sub.into()))];
    let mut message = vec![sub];
    if let Some(params) = params {
        if !matches!(sub, 1 | 2) {
            message.extend(encode(&params));
        }
        fields.push((int(2), params));
    }
    if !matches!(sub, 3 | 5) {
        fields.extend([
            (int(3), int(protocol.identifier().into())),
            (
                int(4),
                Value::Bytes(crate::platform::authenticate(protocol, token, &message)),
            ),
        ]);
    }
    let mut request = vec![family];
    request.extend(encode(&Value::Map(fields)));
    app.call(&request)
}
fn rp() -> Value {
    Value::Map(vec![(
        int(1),
        Value::Bytes(crate::ctap::CtapApp::cm_hash_rp_id("a.example")),
    )])
}
fn populated() -> (TestApp, TestStore) {
    let (mut app, store) = ready();
    for (site, id) in [("a.example", 1), ("a.example", 2), ("b.example", 3)] {
        insert_owned(&mut app, es256_credential(site, &[id]));
    }
    (app, store)
}
#[test]
fn negotiation_masks_undefined_bits_and_rejects_every_defined_combination() {
    for protocol in PROTOCOLS {
        let (mut app, _) = ready();
        for permissions in 1..=0x7f {
            if permissions & 0x40 != 0 && permissions != 0x40 {
                assert_eq!(
                    get_pin_uv_auth_token(&mut app, protocol, PIN, permissions, None),
                    Err(CTAP2_ERR_UNAUTHORIZED_PERMISSION)
                );
            }
        }
        let first = token(&mut app, protocol);
        for permissions in [0x40, 0xc0, (i128::from(u64::MAX) & !0x7f) | 0x40] {
            let repeated = Zeroizing::new(
                get_pin_uv_auth_token(
                    &mut app,
                    protocol,
                    PIN,
                    permissions,
                    Some("ignored.example"),
                )
                .unwrap(),
            );
            assert!(first.as_slice() == repeated.as_slice());
        }
        assert!(app.pin_state.permissions_rp_id().is_none());
        assert!(!app.pin_state.user_verified_flag());
        assert!(!app.pin_state.user_present_flag());
    }
}
#[test]
fn both_protocols_survive_restart_timers_consumption_and_ecdh_regeneration() {
    let (mut app, store) = ready();
    let clock = ManualClock::default();
    app.set_clock(clock.clone());
    let one = token(&mut app, PROTOCOLS[0]);
    let two = token(&mut app, PROTOCOLS[1]);
    assert!(one.as_slice() != two.as_slice());
    for (protocol, secret) in [(PROTOCOLS[0], &one), (PROTOCOLS[1], &two)] {
        let transient =
            Zeroizing::new(get_pin_uv_auth_token(&mut app, protocol, PIN, 4, None).unwrap());
        app.pin_state
            .consume_pin_uv_auth_token_after_user_presence();
        clock.advance(Duration::from_secs(601));
        assert_eq!(
            manage(&mut app, 0x0a, protocol, transient.as_slice(), 1, None),
            [CTAP2_ERR_PIN_AUTH_INVALID]
        );
        assert_eq!(
            manage(&mut app, 0x0a, protocol, secret.as_slice(), 1, None)[0],
            CTAP2_OK
        );
        assert_eq!(
            get_pin_uv_auth_token(&mut app, protocol, b"9999", 0x40, None),
            Err(CTAP2_ERR_PIN_INVALID)
        );
        assert_eq!(
            manage(&mut app, 0x0a, protocol, secret.as_slice(), 1, None)[0],
            CTAP2_OK
        );
        let mut reopened = new_app(store.clone(), [0; 16]);
        assert_eq!(
            manage(&mut reopened, 0x0a, protocol, secret.as_slice(), 1, None)[0],
            CTAP2_OK
        );
        let repeated = token(&mut reopened, protocol);
        assert!(repeated.as_slice() == secret.as_slice());
    }
}
#[test]
fn all_reads_empty_results_and_cursor_authority_isolation() {
    for protocol in PROTOCOLS {
        let (mut empty, _) = ready();
        let secret = token(&mut empty, protocol);
        assert_eq!(
            manage(&mut empty, 0x0a, protocol, secret.as_slice(), 1, None)[0],
            CTAP2_OK
        );
        for (sub, params) in [(2, None), (4, Some(rp()))] {
            assert_eq!(
                manage(&mut empty, 0x0a, protocol, secret.as_slice(), sub, params),
                [CTAP2_ERR_NO_CREDENTIALS]
            );
        }
        let (mut app, _) = populated();
        let secret = token(&mut app, protocol);
        for (sub, params) in [(1, None), (2, None), (4, Some(rp())), (3, None), (5, None)] {
            assert_eq!(
                manage(&mut app, 0x0a, protocol, secret.as_slice(), sub, params)[0],
                CTAP2_OK
            );
        }
        for sub in [3, 5] {
            assert_eq!(
                manage(&mut app, 0x0a, protocol, secret.as_slice(), sub, None),
                [CTAP2_ERR_NOT_ALLOWED]
            );
        }
        manage(&mut app, 0x0a, protocol, secret.as_slice(), 2, None);
        get_pin_token(&mut app, protocol, PIN).unwrap();
        assert_eq!(
            manage(&mut app, 0x0a, protocol, secret.as_slice(), 3, None),
            [CTAP2_ERR_NOT_ALLOWED]
        );
        assert_eq!(
            manage(&mut app, 0x0a, protocol, secret.as_slice(), 1, None)[0],
            CTAP2_OK
        );
        manage(&mut app, 0x0a, protocol, secret.as_slice(), 2, None);
        assert_eq!(
            manage(&mut app, 0x41, protocol, secret.as_slice(), 3, None),
            [CTAP2_ERR_NOT_ALLOWED]
        );
        assert_eq!(
            manage(&mut app, 0x0a, protocol, secret.as_slice(), 3, None),
            [CTAP2_ERR_NOT_ALLOWED]
        );
        let other = if protocol == PROTOCOLS[0] {
            PROTOCOLS[1]
        } else {
            PROTOCOLS[0]
        };
        assert_eq!(
            manage(&mut app, 0x0a, other, secret.as_slice(), 1, None),
            [CTAP2_ERR_PIN_AUTH_INVALID]
        );
    }
}
#[test]
fn persistent_tokens_reject_mutations_preview_and_unrelated_authorization() {
    for protocol in PROTOCOLS {
        let (mut app, store) = populated();
        let secret = token(&mut app, protocol);
        let descriptor = crate::ctap::cbor::canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (Value::Text("id".into()), Value::Bytes(vec![1])),
        ]);
        for sub in [6, 7] {
            let params = Value::Map(vec![
                (int(2), descriptor.clone()),
                (
                    int(3),
                    Value::Map(vec![(Value::Text("id".into()), Value::Bytes(vec![1]))]),
                ),
            ]);
            assert_eq!(
                manage(
                    &mut app,
                    0x0a,
                    protocol,
                    secret.as_slice(),
                    sub,
                    Some(params)
                ),
                [CTAP2_ERR_PIN_AUTH_INVALID]
            );
        }
        for sub in [1, 2, 4] {
            assert_eq!(
                manage(
                    &mut app,
                    0x41,
                    protocol,
                    secret.as_slice(),
                    sub,
                    if sub == 4 { Some(rp()) } else { None }
                ),
                [CTAP2_ERR_PIN_AUTH_INVALID]
            );
        }
        let hash = [0x51; 32];
        let mac = crate::platform::authenticate(protocol, secret.as_slice(), &hash);
        assert_eq!(
            app.handle_make_credential(&make_credential_request(
                &hash,
                "a.example",
                Some((protocol, mac.clone()))
            )),
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(
            app.handle_get_assertion(&get_assertion_request(
                &hash,
                "a.example",
                Some((protocol, mac)),
                None
            )),
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        );
        let mut message = vec![0xff; 32];
        message.extend([0x0d, 2]);
        assert_eq!(
            app.handle_authenticator_config(&encode(&Value::Map(vec![
                (int(1), int(2)),
                (int(3), int(protocol.identifier().into())),
                (
                    int(4),
                    Value::Bytes(crate::platform::authenticate(
                        protocol,
                        secret.as_slice(),
                        &message
                    ))
                )
            ]))),
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        );
        assert_eq!(store.credentials().len(), 3);
        assert!(!app.pin_state.user_verified_flag());
    }
}
#[test]
fn matching_persistent_mac_without_permission_and_unreadable_storage_fail_closed() {
    for protocol in PROTOCOLS {
        let (mut app, mut store) = ready();
        let secret = token(&mut app, protocol);
        let mut state = store.pin_state().unwrap().unwrap();
        state.persistent_tokens[usize::from(protocol.identifier() == 2)]
            .as_mut()
            .unwrap()
            .granted = false;
        store.set_pin_state(&state).unwrap();
        assert_eq!(
            manage(&mut app, 0x0a, protocol, secret.as_slice(), 1, None),
            [CTAP2_ERR_PIN_AUTH_INVALID]
        );
        let secret = token(&mut app, protocol);
        store.faults(|f| f.pin_state = true);
        assert_eq!(
            manage(&mut app, 0x0a, protocol, secret.as_slice(), 1, None),
            [CTAP2_ERR_PROCESSING]
        );
        store.faults(|f| f.pin_state = false);
        assert_eq!(
            manage(&mut app, 0x0a, protocol, secret.as_slice(), 1, None),
            [CTAP2_ERR_PIN_AUTH_INVALID]
        );
    }
}

#[test]
fn repeating_or_zero_entropy_cannot_cross_persistent_permissions_or_publish_rotation() {
    let (mut app, mut store) = ready();
    let mut state = store.pin_state().unwrap().unwrap();
    state.persistent_tokens[0] = Some(crate::store::PersistentTokenRecord {
        secret: [0x61; 32],
        granted: true,
    });
    store.set_pin_state(&state).unwrap();
    app.refresh_persistent_authority().unwrap();
    let writable =
        Zeroizing::new(get_pin_uv_auth_token(&mut app, PROTOCOLS[0], PIN, 0x20, None).unwrap());
    app.rng = Box::new(TestRng::Constant(0x61));
    assert!(matches!(
        get_pin_uv_auth_token(&mut app, PROTOCOLS[1], PIN, 0x40, None),
        Err(CTAP2_ERR_PROCESSING)
    ));
    assert!(matches!(
        get_pin_token(&mut app, PROTOCOLS[1], PIN),
        Err(CTAP2_ERR_PROCESSING)
    ));
    let params = Value::Map(vec![(int(3), Value::Bool(true))]);
    let mut message = vec![0xff; 32];
    message.extend([0x0d, 3]);
    message.extend(encode(&params));
    let request = encode(&Value::Map(vec![
        (int(1), int(3)),
        (int(2), params),
        (int(3), int(1)),
        (
            int(4),
            Value::Bytes(crate::platform::authenticate(
                PROTOCOLS[0],
                writable.as_slice(),
                &message,
            )),
        ),
    ]));
    assert_eq!(
        app.handle_authenticator_config(&request),
        Err(CTAP2_ERR_PROCESSING)
    );
    assert!(!store.pin_state().unwrap().unwrap().force_pin_change);
    assert_eq!(
        manage(&mut app, 0x0a, PROTOCOLS[0], &[0x61; 32], 1, None)[0],
        CTAP2_OK
    );
    app.rng = Box::new(TestRng::Constant(0));
    assert!(matches!(
        get_pin_uv_auth_token(&mut app, PROTOCOLS[1], PIN, 0x40, None),
        Err(CTAP2_ERR_PROCESSING)
    ));
    assert_eq!(
        manage(&mut app, 0x0a, PROTOCOLS[0], &[0x61; 32], 1, None)[0],
        CTAP2_OK
    );
}
