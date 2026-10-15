//! Required classic COSE metadata, shared by every decapsulation consumer.
use super::hmac_secret_mc::{creation_request, extension_outputs, hmac_input, text};
use super::support::*;
use crate::ctap::cbor::{canonical_map, map_get};
use crate::ctap::constants::*;
use crate::ctap::pin::protocol::KeyAgreementKey;
use crate::store::{CredentialStore, FileStore};
use crate::{ClassicPinProtocol, CoseAlg};
use ciborium::value::Value;
use p256::SecretKey;

const PIN: &[u8] = b"1234";
const PROTOCOLS: [ClassicPinProtocol; 2] = [ClassicPinProtocol::V1, ClassicPinProtocol::V2];

/// Alter only public COSE data; the remaining point/ciphertext/MAC is valid.
fn cases(key: &Value) -> Vec<(String, Value, bool)> {
    let mut cases = vec![("standard".into(), key.clone(), true)];
    for (label, wrong) in [(1, 1), (3, -26), (-1, 2), (-2, 0), (-3, 0)] {
        let mut values = vec![
            None,
            Some(Value::Bool(true)),
            Some(text("unexpected")),
            Some(int(wrong)),
        ];
        if label < -1 {
            values.extend([31, 33].map(|len| Some(Value::Bytes(vec![0; len]))));
        } else if label == 3 {
            values.extend([0, -257, i64::MAX].map(|alg| Some(int(alg))));
        }
        for (index, value) in values.into_iter().enumerate() {
            let mut entries = key.as_map().unwrap().clone();
            entries.retain(|(k, _)| *k != int(label));
            if let Some(value) = value {
                entries.push((int(label), value));
            }
            cases.push((
                format!("label {label} case {index}"),
                canonical_map(entries),
                false,
            ));
        }
    }
    let mut off_curve = key.as_map().unwrap().clone();
    for (label, value) in &mut off_curve {
        if *label == int(-2) || *label == int(-3) {
            *value = Value::Bytes(vec![0; 32]);
        }
    }
    cases.push(("off curve".into(), canonical_map(off_curve), false));
    let mut compatible = key.as_map().unwrap().clone();
    compatible.iter_mut().find(|(k, _)| *k == int(3)).unwrap().1 = int(-7);
    cases.push(("OpenSSH -7".into(), canonical_map(compatible), true));
    let mut unknown = key.as_map().unwrap().clone();
    unknown.extend([
        (int(2), Value::Bytes(vec![1])),
        (int(99), Value::Bool(false)),
    ]);
    cases.push((
        "extra kid and unknown label".into(),
        canonical_map(unknown),
        true,
    ));
    cases
}

#[derive(Clone, Copy, Debug)]
enum Consumer {
    Set,
    Change,
    Legacy,
    Transient,
    Persistent,
    Hmac,
    HmacMc,
}
const CONSUMERS: [Consumer; 7] = [
    Consumer::Set,
    Consumer::Change,
    Consumer::Legacy,
    Consumer::Transient,
    Consumer::Persistent,
    Consumer::Hmac,
    Consumer::HmacMc,
];

fn request(
    consumer: Consumer,
    session: &PlatformPinSession,
    key: Value,
    wrong_pin: bool,
) -> Vec<u8> {
    let protocol = session.protocol;
    if matches!(consumer, Consumer::Hmac | Consumer::HmacMc) {
        let mut input = hmac_input(session, &[0x98; 32], protocol)
            .as_map()
            .unwrap()
            .clone();
        input.iter_mut().find(|(k, _)| *k == int(1)).unwrap().1 = key;
        let input = canonical_map(input);
        let (command, payload) = if matches!(consumer, Consumer::Hmac) {
            (
                CTAP_CMD_GET_ASSERTION,
                get_assertion_request(
                    &[0x44; 32],
                    "example.com",
                    None,
                    Some(canonical_map(vec![(text("hmac-secret"), input)])),
                ),
            )
        } else {
            (
                CTAP_CMD_MAKE_CREDENTIAL,
                creation_request(
                    CoseAlg::ES256,
                    false,
                    canonical_map(vec![
                        (text("hmac-secret"), Value::Bool(true)),
                        (text("hmac-secret-mc"), input),
                    ]),
                    None,
                    2,
                ),
            )
        };
        return [vec![command], payload].concat();
    }
    let sub = match consumer {
        Consumer::Set => 3,
        Consumer::Change => 4,
        Consumer::Legacy => 5,
        _ => 9,
    };
    let mut entries = vec![
        (int(1), int(protocol.identifier().into())),
        (int(2), int(sub)),
        (int(3), key),
    ];
    let mut message = Vec::new();
    if matches!(consumer, Consumer::Set | Consumer::Change) {
        let encrypted = session.encrypt(&padded_pin(b"5678"));
        message.extend_from_slice(&encrypted);
        entries.push((int(5), Value::Bytes(encrypted)));
    }
    if !matches!(consumer, Consumer::Set) {
        let encrypted = session.encrypt(&pin_hash(if wrong_pin { b"wrong" } else { PIN }));
        message.extend_from_slice(&encrypted);
        entries.push((int(6), Value::Bytes(encrypted)));
    }
    if matches!(consumer, Consumer::Set | Consumer::Change) {
        entries.push((
            int(4),
            Value::Bytes(classic_pin_auth(protocol, &session.keys, &message)),
        ));
    }
    if matches!(consumer, Consumer::Transient | Consumer::Persistent) {
        entries.push((
            int(9),
            int(if matches!(consumer, Consumer::Persistent) {
                0x40
            } else {
                4
            }),
        ));
    }
    [vec![CTAP_CMD_CLIENT_PIN], encode(&canonical_map(entries))].concat()
}

#[test]
fn required_metadata_precedes_ecdh_and_retains_bounded_compatibility() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0; 16]);
        let session = PlatformPinSession::establish(&mut app, protocol, 0x13);
        // Use the same local key and peer point for every accepted metadata variant.
        for (name, key, accepted) in cases(&session.key_agreement) {
            let result = app.decapsulate(protocol, key.as_map().unwrap());
            if accepted {
                let actual = result.unwrap();
                assert!(
                    actual.auth_key == session.keys.auth_key,
                    "{protocol:?} {name}"
                );
                assert!(
                    actual.encryption_key == session.keys.encryption_key,
                    "{protocol:?} {name}"
                );
            } else {
                assert!(
                    matches!(result, Err(CTAP1_ERR_INVALID_PARAMETER)),
                    "{protocol:?} {name}"
                );
            }
        }
        let emitted = app.key_agreement_key(protocol).unwrap().cose_key();
        assert_eq!(map_get(emitted.as_map().unwrap(), int(3)), Some(&int(-25)));
    }
    let key = KeyAgreementKey::new(SecretKey::from_slice(&[0x11; 32]).unwrap());
    assert_eq!(
        map_get(key.cose_key().as_map().unwrap(), int(3)),
        Some(&int(-25))
    );
}

#[test]
fn every_consumer_rejects_bad_keys_without_later_retry_or_storage_effects() {
    let mut fixture = test_app([0; 16]);
    let template = PlatformPinSession::establish(&mut fixture, PROTOCOLS[0], 0x13);
    for protocol in PROTOCOLS {
        for consumer in CONSUMERS {
            for (index, (name, _, accepted)) in
                cases(&template.key_agreement).into_iter().enumerate()
            {
                for wrong_pin in [false, true] {
                    if wrong_pin && accepted {
                        continue;
                    }
                    let store = TestStore::new();
                    let (mut app, presence) =
                        app_with_store(store.clone(), [0; 16], [], &NEVER_INTERRUPTED);
                    insert_owned(&mut app, es256_credential("example.com", &[1; 33]));
                    if !matches!(consumer, Consumer::Set) {
                        set_pin_padded(&mut app, protocol, &padded_pin(PIN)).unwrap();
                        for other in PROTOCOLS {
                            get_pin_uv_auth_token(&mut app, other, PIN, 0x40, None).unwrap();
                        }
                        get_pin_uv_auth_token(&mut app, protocol, PIN, 4, None).unwrap();
                    }
                    let session = PlatformPinSession::establish(&mut app, protocol, 0x13);
                    let key = cases(&session.key_agreement).swap_remove(index).1;
                    let before = store.pin_state().unwrap();
                    let writes = store.pin_state_writes().len();
                    let credentials = stored(&app);
                    let counter = store.signature_counter().unwrap();
                    let token = app.pin_state.pin_uv_auth_token();
                    let token_id = app.pin_state.pin_uv_auth_token_id();
                    let retries = app.pin_state.retries();
                    let power_cycle = app.pin_state.needs_power_cycle();
                    let generation = app.pin_state.persistent_generation();
                    let agreement = app.key_agreement_key(protocol).unwrap().cose_key();
                    presence.take();
                    crate::ctap::pin::observation::take();
                    let response = app.call(&request(consumer, &session, key, wrong_pin));
                    if accepted {
                        assert_eq!(response[0], CTAP2_OK, "{protocol:?} {consumer:?} {name}");
                        if matches!(
                            consumer,
                            Consumer::Legacy | Consumer::Transient | Consumer::Persistent
                        ) {
                            let body: Value = ciborium::de::from_reader(&response[1..]).unwrap();
                            let encrypted = map_get(body.as_map().unwrap(), int(2))
                                .unwrap()
                                .as_bytes()
                                .unwrap();
                            assert_eq!(
                                encrypted.len(),
                                if protocol == ClassicPinProtocol::V1 {
                                    32
                                } else {
                                    48
                                }
                            );
                        } else if matches!(consumer, Consumer::Hmac | Consumer::HmacMc) {
                            let created = matches!(consumer, Consumer::HmacMc)
                                .then(|| created_credential(&app, &response, "example.com"));
                            let extensions = extension_outputs(&response, created.as_ref());
                            let label = text(if created.is_some() {
                                "hmac-secret-mc"
                            } else {
                                "hmac-secret"
                            });
                            let encrypted =
                                map_get(&extensions, label).unwrap().as_bytes().unwrap();
                            assert_eq!(
                                encrypted.len(),
                                if protocol == ClassicPinProtocol::V1 {
                                    32
                                } else {
                                    48
                                }
                            );
                        }
                        continue;
                    }
                    assert_eq!(
                        response,
                        [CTAP1_ERR_INVALID_PARAMETER],
                        "{protocol:?} {consumer:?} {name}"
                    );
                    assert_eq!(crate::ctap::pin::observation::take(), [0; 3]);
                    assert_eq!(store.pin_state().unwrap(), before);
                    assert_eq!(store.pin_state_writes().len(), writes);
                    assert!(stored(&app) == credentials);
                    assert_eq!(store.signature_counter().unwrap(), counter);
                    assert_eq!(app.pin_state.retries(), retries);
                    assert_eq!(app.pin_state.needs_power_cycle(), power_cycle);
                    assert_eq!(app.pin_state.persistent_generation(), generation);
                    assert!(app.pin_state.pin_uv_auth_token() == token);
                    assert_eq!(app.pin_state.pin_uv_auth_token_id(), token_id);
                    // HMAC extensions follow existing presence/token consumption.
                    if !matches!(consumer, Consumer::Hmac | Consumer::HmacMc) {
                        assert!(presence.take().is_empty());
                        assert_eq!(
                            app.pin_state.pin_uv_auth_permissions(),
                            4 * u8::from(token.is_some())
                        );
                    }
                    let reopened = new_app(store.clone(), [0; 16]);
                    assert_eq!(reopened.pin_state.retries(), retries);
                    assert!(stored(&reopened) == credentials);
                    assert_eq!(
                        app.key_agreement_key(protocol).unwrap().cose_key(),
                        agreement
                    );
                }
            }
        }
    }
}

#[test]
fn malformed_metadata_preserves_pin_preconditions_and_consecutive_mismatches() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0; 16]);
        let session = PlatformPinSession::establish(&mut app, protocol, 0x13);
        let bad = canonical_map(vec![]);
        assert_eq!(
            app.call(&request(Consumer::Change, &session, bad.clone(), false)),
            [CTAP2_ERR_PIN_NOT_SET]
        );
        set_pin_padded(&mut app, protocol, &padded_pin(PIN)).unwrap();
        assert_eq!(
            app.call(&request(Consumer::Set, &session, bad.clone(), false)),
            [CTAP2_ERR_PIN_AUTH_INVALID]
        );
        assert_eq!(
            get_pin_token(&mut app, protocol, b"wrong"),
            Err(CTAP2_ERR_PIN_INVALID)
        );
        let session = PlatformPinSession::establish(&mut app, protocol, 0x13);
        for consumer in [
            Consumer::Change,
            Consumer::Legacy,
            Consumer::Transient,
            Consumer::Persistent,
        ] {
            assert_eq!(
                app.call(&request(consumer, &session, bad.clone(), true)),
                [CTAP1_ERR_INVALID_PARAMETER]
            );
        }
        assert_eq!(
            get_pin_token(&mut app, protocol, b"wrong"),
            Err(CTAP2_ERR_PIN_INVALID)
        );
        assert_eq!(
            get_pin_token(&mut app, protocol, b"wrong"),
            Err(CTAP2_ERR_PIN_AUTH_BLOCKED)
        );
        assert_eq!(
            app.call(&request(Consumer::Legacy, &session, bad, false)),
            [CTAP2_ERR_PIN_AUTH_BLOCKED]
        );
    }
}

#[test]
fn malformed_peer_metadata_does_not_publish_file_store_authority() {
    let dir = crate::store::test_support::TempDir::new();
    for protocol in PROTOCOLS {
        let mut app = crate::ctap::CtapApp::with_file_store(
            FileStore::open(dir.path()).unwrap(),
            crate::ctap::presence::AutoApprove,
            &NEVER_INTERRUPTED,
            [0; 16],
        );
        if !app.pin_state.is_set() {
            set_pin_padded(&mut app, protocol, &padded_pin(PIN)).unwrap();
        }
        get_pin_uv_auth_token(&mut app, protocol, PIN, 0x40, None).unwrap();
        let session = PlatformPinSession::establish(&mut app, protocol, 0x13);
        let before = app.store.pin_state().unwrap();
        for consumer in [
            Consumer::Change,
            Consumer::Legacy,
            Consumer::Transient,
            Consumer::Persistent,
        ] {
            for (_, key, accepted) in cases(&session.key_agreement) {
                if accepted {
                    continue;
                }
                assert_eq!(
                    app.call(&request(consumer, &session, key, true)),
                    [CTAP1_ERR_INVALID_PARAMETER]
                );
                assert_eq!(app.store.pin_state().unwrap(), before);
                assert_eq!(
                    FileStore::open(dir.path()).unwrap().pin_state().unwrap(),
                    before
                );
            }
        }
    }
}
