//! File-backed PIN commands at the publication boundary, in both layouts.

use super::*;
use crate::ClassicPinProtocol;
use crate::ctap::pin_observation as observation;
use crate::platform::{PlatformKeyAgreement, authenticate as mac, padded_pin, pin_hash};

const PIN: &[u8] = b"1234";
const NEW: &[u8] = b"567890";
const PROTOCOLS: [ClassicPinProtocol; 2] = [ClassicPinProtocol::V1, ClassicPinProtocol::V2];
const PRE: [&str; 5] = ["write", "written", "file-flush", "file-flushed", "rename"];
const POST: [&str; 3] = ["renamed", "directory-flush", "directory-flushed"];

struct Session {
    shared: PlatformKeyAgreement,
    agreement: Value,
}

impl Session {
    fn new(app: &mut CtapApp<'_>, protocol: ClassicPinProtocol) -> Self {
        let key = field(
            &call(
                app,
                CTAP_CMD_CLIENT_PIN,
                vec![(int(1), int(protocol.identifier())), (int(2), int(2))],
            ),
            1,
        );
        let Value::Map(key) = key else {
            panic!("key agreement");
        };
        let coordinate = |id| {
            bytes(key.iter().find(|(k, _)| *k == int(id)).unwrap().1.clone())
                .try_into()
                .unwrap()
        };
        let secret = [0x51; 32];
        let shared =
            PlatformKeyAgreement::new(protocol, &coordinate(-2), &coordinate(-3), &secret).unwrap();
        let (x, y) = shared.public_key();
        let agreement = Value::Map(vec![
            (int(1), int(2)),
            (int(3), int(-25)),
            (int(-1), int(1)),
            (int(-2), Value::Bytes(x.to_vec())),
            (int(-3), Value::Bytes(y.to_vec())),
        ]);
        Self { shared, agreement }
    }

    fn encrypted(&self, value: &[u8]) -> Vec<u8> {
        self.shared.encrypt(value, [0x53; 16]).unwrap()
    }

    fn command(&self, app: &mut CtapApp<'_>, sub: i32, mut fields: Vec<(Value, Value)>) -> Vec<u8> {
        let mut parameters = vec![
            (int(1), int(self.shared.protocol().identifier())),
            (int(2), int(sub)),
            (int(3), self.agreement.clone()),
        ];
        parameters.append(&mut fields);
        call(app, CTAP_CMD_CLIENT_PIN, parameters)
    }

    fn set(&self, app: &mut CtapApp<'_>) -> Vec<u8> {
        let encrypted = self.encrypted(&padded_pin(PIN).unwrap()[..]);
        self.command(
            app,
            3,
            vec![
                (int(4), Value::Bytes(self.shared.authenticate(&encrypted))),
                (int(5), Value::Bytes(encrypted)),
            ],
        )
    }

    fn change(&self, app: &mut CtapApp<'_>) -> Vec<u8> {
        self.change_to(app, NEW)
    }

    fn change_to(&self, app: &mut CtapApp<'_>, pin: &[u8]) -> Vec<u8> {
        let new = self.encrypted(&padded_pin(pin).unwrap()[..]);
        let old = self.encrypted(&pin_hash(PIN)[..]);
        let message = [new.as_slice(), old.as_slice()].concat();
        self.command(
            app,
            4,
            vec![
                (int(4), Value::Bytes(self.shared.authenticate(&message))),
                (int(5), Value::Bytes(new)),
                (int(6), Value::Bytes(old)),
            ],
        )
    }

    fn token(&self, app: &mut CtapApp<'_>, pin: &[u8]) -> Vec<u8> {
        self.command(
            app,
            9,
            vec![
                (int(6), Value::Bytes(self.encrypted(&pin_hash(pin)[..]))),
                (int(9), int(0x24)),
            ],
        )
    }
}

fn fault<T>(failing: &'static str, write: usize, operation: impl FnOnce() -> T) -> T {
    let mut current = 0;
    fsio::with_hook(
        Box::new(move |event, path| {
            if event == "write" {
                current += 1;
            }
            if current == write && event == failing {
                Err(failure(path))
            } else {
                Ok(())
            }
        }),
        operation,
    )
}

fn configure(
    app: &mut CtapApp<'_>,
    protocol: ClassicPinProtocol,
    token: Option<&[u8]>,
    sub: u8,
    params: Option<Value>,
) -> Vec<u8> {
    let mut message = vec![0xff; 32];
    message.extend_from_slice(&[CTAP_CMD_AUTHENTICATOR_CONFIG, sub]);
    let mut fields = vec![(int(1), int(sub.into()))];
    if let Some(params) = params {
        ciborium::ser::into_writer(&params, &mut message).unwrap();
        fields.push((int(2), params));
    }
    if let Some(token) = token {
        fields.extend([
            (int(3), int(protocol.identifier())),
            (int(4), Value::Bytes(mac(protocol, token, &message))),
        ]);
    }
    call(app, CTAP_CMD_AUTHENTICATOR_CONFIG, fields)
}

fn options(app: &mut CtapApp<'_>) -> Value {
    field(&app.call(&[CTAP_CMD_GET_INFO]), 4)
}

#[test]
fn set_and_change_pin_keep_live_and_restarted_engines_on_the_published_pin() {
    for managed in [false, true] {
        for protocol in PROTOCOLS {
            for change in [false, true] {
                for failing in PRE.into_iter().chain(POST) {
                    let scratch = TempDir::new();
                    let path = scratch.path().join("state");
                    setup(&path, managed);
                    let mut engine = app(&path);
                    let session = Session::new(&mut engine, protocol);
                    let old_token = if change {
                        assert_eq!(session.set(&mut engine), [CTAP2_OK]);
                        Some(
                            session
                                .shared
                                .decrypt(&bytes(field(&session.token(&mut engine, PIN), 2)))
                                .unwrap(),
                        )
                    } else {
                        None
                    };
                    let response = fault(failing, if change { 3 } else { 1 }, || {
                        if change {
                            session.change(&mut engine)
                        } else {
                            session.set(&mut engine)
                        }
                    });
                    let committed = POST.contains(&failing);
                    assert_eq!(
                        response,
                        [if committed {
                            CTAP2_OK
                        } else {
                            CTAP2_ERR_PROCESSING
                        }],
                        "{managed} {protocol:?} {change} {failing}"
                    );
                    let stored = FileStore::open(&path)
                        .unwrap()
                        .pin_state()
                        .unwrap()
                        .unwrap();
                    let expected = if change && committed {
                        Some(NEW)
                    } else if change || committed {
                        Some(PIN)
                    } else {
                        None
                    };
                    assert_eq!(stored.pin_hash, expected.map(|pin| *pin_hash(pin)));
                    if let Some(old_token) = old_token {
                        assert_eq!(
                            configure(&mut engine, protocol, Some(&old_token), 2, None),
                            [if committed {
                                CTAP2_ERR_PIN_AUTH_INVALID
                            } else {
                                CTAP2_OK
                            }]
                        );
                    }
                    let mut restarted = app(&path);
                    assert_eq!(options(&mut engine), options(&mut restarted));
                    for instance in [&mut engine, &mut restarted] {
                        let session = Session::new(instance, protocol);
                        if let Some(expected) = expected {
                            assert_eq!(session.token(instance, expected)[0], CTAP2_OK);
                            if change {
                                assert_eq!(
                                    session.token(instance, if committed { PIN } else { NEW }),
                                    [CTAP2_ERR_PIN_INVALID]
                                );
                            }
                        } else {
                            assert_eq!(session.token(instance, PIN), [CTAP2_ERR_PIN_NOT_SET]);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn published_minimum_and_forced_change_invalidate_tokens_and_apply_on_restart() {
    for managed in [false, true] {
        for protocol in PROTOCOLS {
            for failing in PRE.into_iter().chain(POST) {
                let scratch = TempDir::new();
                let path = scratch.path().join("state");
                setup(&path, managed);
                let mut engine = app(&path);
                let session = Session::new(&mut engine, protocol);
                assert_eq!(session.set(&mut engine), [CTAP2_OK]);
                let token = session
                    .shared
                    .decrypt(&bytes(field(&session.token(&mut engine, PIN), 2)))
                    .unwrap();
                let params = Value::Map(vec![
                    (int(1), int(6)),
                    (int(2), Value::Array(vec![text(RP)])),
                    (int(3), Value::Bool(true)),
                ]);
                let response = fault(failing, 1, || {
                    configure(&mut engine, protocol, Some(&token), 3, Some(params))
                });
                let committed = POST.contains(&failing);
                assert_eq!(
                    response,
                    [if committed {
                        CTAP2_OK
                    } else {
                        CTAP2_ERR_PROCESSING
                    }]
                );
                let stored = FileStore::open(&path)
                    .unwrap()
                    .pin_state()
                    .unwrap()
                    .unwrap();
                assert_eq!(stored.force_pin_change, committed);
                assert_eq!(stored.min_pin_length, if committed { 6 } else { 4 });
                assert_eq!(
                    stored.min_pin_length_rp_ids,
                    if committed { vec![RP] } else { vec![] }
                );
                assert_eq!(
                    configure(&mut engine, protocol, Some(&token), 2, None),
                    [if committed {
                        CTAP2_ERR_PIN_AUTH_INVALID
                    } else {
                        CTAP2_OK
                    }]
                );
                let mut restarted = app(&path);
                assert_eq!(options(&mut engine), options(&mut restarted));
                for (index, instance) in [&mut engine, &mut restarted].into_iter().enumerate() {
                    let response = instance.call(&[CTAP_CMD_GET_INFO]);
                    assert_eq!(field(&response, 12), Value::Bool(committed && index == 0));
                    assert_eq!(field(&response, 13), int(if committed { 6 } else { 4 }));
                    let session = Session::new(instance, protocol);
                    assert_eq!(
                        session.token(instance, PIN)[0],
                        if committed && index == 1 {
                            CTAP2_ERR_PIN_INVALID
                        } else if committed {
                            CTAP2_ERR_PIN_POLICY_VIOLATION
                        } else {
                            CTAP2_OK
                        }
                    );
                    if committed && index == 0 {
                        assert_eq!(session.change(instance), [CTAP2_OK]);
                    }
                }
            }
        }
    }
}

#[test]
fn published_complexity_invalidates_tokens_and_applies_on_restart() {
    for managed in [false, true] {
        for protocol in PROTOCOLS {
            for failing in PRE.into_iter().chain(POST) {
                let scratch = TempDir::new();
                let path = scratch.path().join("state");
                setup(&path, managed);
                let mut engine = app(&path);
                let session = Session::new(&mut engine, protocol);
                assert_eq!(session.set(&mut engine), [CTAP2_OK]);
                let token = session
                    .shared
                    .decrypt(&bytes(field(&session.token(&mut engine, PIN), 2)))
                    .unwrap();
                let params = Value::Map(vec![
                    (int(1), int(6)),
                    (int(2), Value::Array(vec![text(RP)])),
                    (int(4), Value::Bool(true)),
                ]);
                let response = fault(failing, 1, || {
                    configure(&mut engine, protocol, Some(&token), 3, Some(params))
                });
                let committed = POST.contains(&failing);
                assert_eq!(
                    response,
                    [if committed {
                        CTAP2_OK
                    } else {
                        CTAP2_ERR_PROCESSING
                    }]
                );
                let stored = FileStore::open(&path)
                    .unwrap()
                    .pin_state()
                    .unwrap()
                    .unwrap();
                assert_eq!(stored.force_pin_change, committed);
                assert_eq!(stored.pin_complexity_policy, committed);
                assert_eq!(stored.min_pin_length, if committed { 6 } else { 4 });
                assert_eq!(
                    stored.min_pin_length_rp_ids,
                    if committed { vec![RP] } else { vec![] }
                );
                assert_eq!(
                    configure(&mut engine, protocol, Some(&token), 2, None),
                    [if committed {
                        CTAP2_ERR_PIN_AUTH_INVALID
                    } else {
                        CTAP2_OK
                    }]
                );
                let mut restarted = app(&path);
                assert_eq!(options(&mut engine), options(&mut restarted));
                for instance in [&mut engine, &mut restarted] {
                    let response = instance.call(&[CTAP_CMD_GET_INFO]);
                    assert_eq!(field(&response, 12), Value::Bool(committed));
                    assert_eq!(field(&response, 13), int(if committed { 6 } else { 4 }));
                    let session = Session::new(instance, protocol);
                    assert_eq!(
                        session.token(instance, PIN)[0],
                        if committed {
                            CTAP2_ERR_PIN_POLICY_VIOLATION
                        } else {
                            CTAP2_OK
                        }
                    );
                }
            }
        }
    }
}

#[test]
fn real_file_unconfirmed_retry_debits_stop_before_verification_and_restart_recovers() {
    for managed in [false, true] {
        for protocol in PROTOCOLS {
            for failing in POST {
                let scratch = TempDir::new();
                let path = scratch.path().join("state");
                setup(&path, managed);
                let mut engine = app(&path);
                let session = Session::new(&mut engine, protocol);
                assert_eq!(session.set(&mut engine), [CTAP2_OK]);
                observation::take();
                assert_eq!(
                    fault(failing, 1, || session.token(&mut engine, PIN)),
                    [CTAP2_ERR_PROCESSING]
                );
                assert_eq!(observation::take(), [0, 0, 0]);
                assert_eq!(
                    FileStore::open(&path)
                        .unwrap()
                        .pin_state()
                        .unwrap()
                        .unwrap()
                        .pin_retries,
                    7
                );
                assert_eq!(
                    field(
                        &call(&mut app(&path), CTAP_CMD_CLIENT_PIN, vec![(int(2), int(1))]),
                        3
                    ),
                    int(7)
                );
                assert_eq!(session.token(&mut engine, PIN)[0], CTAP2_OK);
            }
        }
    }
}

#[test]
fn reset_final_default_publication_commits_only_after_prior_work() {
    for managed in [false, true] {
        for failing in ["rename", "renamed", "directory-flush", "directory-flushed"] {
            let scratch = TempDir::new();
            let path = scratch.path().join("state");
            let (id, _, record) = setup(&path, managed);
            provision(&path);
            FileStore::open(&path)
                .unwrap()
                .set_pin_state(&policy())
                .unwrap();
            let mut engine = app(&path);
            let mut final_write = false;
            let response = fsio::with_hook(
                Box::new(move |event, path| {
                    if event == "rename" && path.ends_with(PIN_STATE_FILE) {
                        final_write = true;
                    }
                    if final_write && event == failing {
                        Err(failure(path))
                    } else {
                        Ok(())
                    }
                }),
                || engine.call(&[CTAP_CMD_RESET]),
            );
            let committed = failing != "rename";
            assert_eq!(
                response,
                [if committed {
                    CTAP2_OK
                } else {
                    CTAP2_ERR_PROCESSING
                }]
            );
            assert_ne!(assertion(&mut engine, &id)[0], CTAP2_OK);
            if committed {
                assert_eq!(options(&mut engine), options(&mut app(&path)));
                assert_defaults(&path, managed, &id, &record);
            } else {
                assert!(FileStore::open(&path).unwrap().pin_state().is_err());
                assert_eq!(app(&path).call(&[CTAP_CMD_RESET]), [CTAP2_OK]);
                assert_defaults(&path, managed, &id, &record);
            }
        }
    }
}

fn disclosed_minimum(app: &mut CtapApp<'_>, rp: &str) -> Option<Value> {
    let response = call(
        app,
        CTAP_CMD_MAKE_CREDENTIAL,
        vec![
            (int(1), Value::Bytes(HASH.to_vec())),
            (int(2), Value::Map(vec![(text("id"), text(rp))])),
            (
                int(3),
                Value::Map(vec![(text("id"), Value::Bytes(vec![3]))]),
            ),
            (
                int(4),
                Value::Array(vec![Value::Map(vec![
                    (text("alg"), int(-7)),
                    (text("type"), text("public-key")),
                ])]),
            ),
            (
                int(6),
                Value::Map(vec![(text("minPinLength"), Value::Bool(true))]),
            ),
        ],
    );
    let data = bytes(field(&response, 2));
    if data[32] & 0x80 == 0 {
        return None;
    }
    let length = usize::from(u16::from_be_bytes(data[53..55].try_into().unwrap()));
    let mut rest = &data[55 + length..];
    let _: Value = ciborium::de::from_reader(&mut rest).unwrap();
    let Value::Map(extensions) = ciborium::de::from_reader::<Value, _>(rest).unwrap() else {
        panic!("extensions");
    };
    extensions
        .into_iter()
        .find(|(key, _)| *key == text("minPinLength"))
        .map(|(_, value)| value)
}

#[test]
fn published_rp_disclosure_and_always_uv_are_observable_without_restart() {
    for managed in [false, true] {
        for failing in PRE.into_iter().chain(POST) {
            let scratch = TempDir::new();
            let path = scratch.path().join("state");
            setup(&path, managed);
            let mut engine = app(&path);
            let params = |minimum, rp| {
                Some(Value::Map(vec![
                    (int(1), int(minimum)),
                    (int(2), Value::Array(vec![text(rp)])),
                ]))
            };
            assert_eq!(
                configure(
                    &mut engine,
                    ClassicPinProtocol::V2,
                    None,
                    3,
                    params(4, "other.example")
                ),
                [CTAP2_OK]
            );
            let committed = POST.contains(&failing);
            assert_eq!(
                fault(failing, 1, || configure(
                    &mut engine,
                    ClassicPinProtocol::V2,
                    None,
                    3,
                    params(6, RP)
                )),
                [if committed {
                    CTAP2_OK
                } else {
                    CTAP2_ERR_PROCESSING
                }]
            );
            let mut restarted = app(&path);
            for instance in [&mut engine, &mut restarted] {
                assert_eq!(disclosed_minimum(instance, RP), committed.then_some(int(6)));
                assert_eq!(
                    disclosed_minimum(instance, "other.example"),
                    (!committed).then_some(int(4))
                );
            }
            assert_eq!(
                fault(failing, 1, || configure(
                    &mut engine,
                    ClassicPinProtocol::V2,
                    None,
                    2,
                    None
                )),
                [if committed {
                    CTAP2_OK
                } else {
                    CTAP2_ERR_PROCESSING
                }]
            );
            let mut restarted = app(&path);
            for instance in [&mut engine, &mut restarted] {
                let Value::Array(versions) = field(&instance.call(&[CTAP_CMD_GET_INFO]), 1) else {
                    panic!("versions");
                };
                assert_eq!(versions.contains(&text("U2F_V2")), !committed);
                assert_eq!(instance.call_u2f(&[0, 3, 0, 0]), b"U2F_V2\x90\0");
                let mut registration = vec![0, 1, 0, 0, 64];
                registration.extend([0x42; 64]);
                let response = instance.call_u2f(&registration);
                assert_eq!(
                    &response[response.len() - 2..],
                    if committed {
                        SW_COMMAND_NOT_ALLOWED
                    } else {
                        SW_NO_ERROR
                    }
                    .to_be_bytes()
                );
            }
        }
    }
}

#[test]
fn real_file_restoration_faults_never_issue_a_token_and_recover() {
    for managed in [false, true] {
        for protocol in PROTOCOLS {
            for failing in PRE.into_iter().chain(POST) {
                let scratch = TempDir::new();
                let path = scratch.path().join("state");
                setup(&path, managed);
                let mut engine = app(&path);
                let session = Session::new(&mut engine, protocol);
                assert_eq!(session.set(&mut engine), [CTAP2_OK]);
                observation::take();
                assert_eq!(
                    fault(failing, 2, || session.token(&mut engine, PIN)),
                    [CTAP2_ERR_PROCESSING]
                );
                assert_eq!(observation::take(), [1, 1, 0]);
                let expected = if POST.contains(&failing) { 8 } else { 7 };
                assert_eq!(
                    FileStore::open(&path)
                        .unwrap()
                        .pin_state()
                        .unwrap()
                        .unwrap()
                        .pin_retries,
                    expected
                );
                assert_eq!(
                    field(
                        &call(&mut engine, CTAP_CMD_CLIENT_PIN, vec![(int(2), int(1))]),
                        3
                    ),
                    int(expected.into())
                );
                assert_eq!(session.token(&mut engine, PIN)[0], CTAP2_OK);
                let mut restarted = app(&path);
                let session = Session::new(&mut restarted, protocol);
                assert_eq!(session.token(&mut restarted, PIN)[0], CTAP2_OK);
            }
        }
    }
}

#[test]
fn reset_reports_unconfirmed_metadata_even_when_defaults_are_flushed() {
    let scratch = TempDir::new();
    let path = scratch.path().join("state");
    let (id, _, record) = setup(&path, true);
    let mut store = FileStore::open(&path).unwrap();
    let outcome = fsio::with_hook(
        Box::new(|event, path| {
            if event == "published" {
                Err(failure(path))
            } else {
                Ok(())
            }
        }),
        || store.clear(),
    )
    .unwrap();
    assert_eq!(outcome, CommitDurability::Unconfirmed);
    assert_defaults(&path, true, &id, &record);
}

#[test]
fn legacy_and_corrupt_complexity_records_preserve_file_store_authority() {
    for managed in [false, true] {
        for invalid in [None, Some(Value::Null), Some(Value::Bool(true))] {
            let scratch = TempDir::new();
            let path = scratch.path().join("state");
            setup(&path, managed);
            let mut store = FileStore::open(&path).unwrap();
            let record = PinStateRecord {
                pin_hash: Some(*pin_hash(PIN)),
                min_pin_length_rp_ids: Vec::new(),
                persistent_tokens: [None, None],
                ..PinStateRecord::default()
            };
            store.set_pin_state(&record).unwrap();
            let encoded = codec::encode_pin_state(&record).unwrap();
            let Value::Map(mut fields) = ciborium::de::from_reader(&encoded[..]).unwrap() else {
                panic!("record")
            };
            fields.retain(|(key, _)| *key != int(10));
            if let Some(value) = invalid.clone() {
                fields.push((int(10), value.clone()));
                if value == Value::Bool(true) {
                    fields.push((int(10), value));
                }
            }
            let mut plaintext = Vec::new();
            ciborium::ser::into_writer(&Value::Map(fields), &mut plaintext).unwrap();
            let keys = store.credential_keys().unwrap().unwrap();
            let encrypted = envelope::seal(
                &keys.record,
                RecordType::PinState,
                PIN_STATE_FILE,
                &plaintext,
            )
            .unwrap();
            fs::write(path.join(PIN_STATE_FILE), &encrypted).unwrap();
            let mut engine = app(&path);
            let session = Session::new(&mut engine, ClassicPinProtocol::V2);
            if invalid.is_none() {
                assert!(!store.pin_state().unwrap().unwrap().pin_complexity_policy);
                assert_eq!(session.token(&mut engine, PIN)[0], CTAP2_OK);
            } else {
                assert!(store.pin_state().is_err());
                assert_eq!(session.token(&mut engine, PIN), [CTAP2_ERR_PIN_BLOCKED]);
                assert_eq!(session.set(&mut engine), [CTAP2_ERR_PIN_AUTH_INVALID]);
                assert_eq!(fs::read(path.join(PIN_STATE_FILE)).unwrap(), encrypted);
                assert_eq!(engine.call(&[CTAP_CMD_RESET]), [CTAP2_OK]);
                assert!(!store.pin_state().unwrap().unwrap().pin_complexity_policy);
            }
        }
    }
}

#[test]
fn complexity_replacement_publishes_once_after_confirmed_authorization() {
    for managed in [false, true] {
        for protocol in PROTOCOLS {
            for write in 1..=3 {
                for failing in PRE.into_iter().chain(POST) {
                    let scratch = TempDir::new();
                    let path = scratch.path().join("state");
                    setup(&path, managed);
                    let mut engine = app(&path);
                    let session = Session::new(&mut engine, protocol);
                    assert_eq!(session.set(&mut engine), [CTAP2_OK]);
                    let token = session
                        .shared
                        .decrypt(&bytes(field(&session.token(&mut engine, PIN), 2)))
                        .unwrap();
                    assert_eq!(
                        configure(
                            &mut engine,
                            protocol,
                            Some(&token),
                            3,
                            Some(Value::Map(vec![(int(4), Value::Bool(true))]))
                        ),
                        [CTAP2_OK]
                    );
                    observation::take();
                    let response =
                        fault(failing, write, || session.change_to(&mut engine, b"Ab12"));
                    let published = write == 3 && POST.contains(&failing);
                    assert_eq!(
                        response,
                        [if published {
                            CTAP2_OK
                        } else {
                            CTAP2_ERR_PROCESSING
                        }]
                    );
                    let seen = observation::take();
                    assert_eq!(seen[0], usize::from(write > 1));
                    assert_eq!(seen[1], usize::from(write > 1));
                    let saved = FileStore::open(&path)
                        .unwrap()
                        .pin_state()
                        .unwrap()
                        .unwrap();
                    assert!(saved.pin_complexity_policy);
                    assert_eq!(saved.force_pin_change, !published);
                    assert_eq!(
                        saved.pin_hash,
                        Some(*pin_hash(if published { b"Ab12" } else { PIN }))
                    );
                    for instance in [&mut engine, &mut app(&path)] {
                        let session = Session::new(instance, protocol);
                        assert_eq!(
                            session.token(instance, if published { b"Ab12" } else { PIN })[0],
                            if published {
                                CTAP2_OK
                            } else {
                                CTAP2_ERR_PIN_POLICY_VIOLATION
                            }
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn first_pin_obeys_only_published_complexity_configuration() {
    for managed in [false, true] {
        for protocol in PROTOCOLS {
            for failing in PRE.into_iter().chain(POST) {
                let scratch = TempDir::new();
                let path = scratch.path().join("state");
                setup(&path, managed);
                let mut engine = app(&path);
                let published = POST.contains(&failing);
                assert_eq!(
                    fault(failing, 1, || configure(
                        &mut engine,
                        protocol,
                        None,
                        3,
                        Some(Value::Map(vec![(int(4), Value::Bool(true))]))
                    )),
                    [if published {
                        CTAP2_OK
                    } else {
                        CTAP2_ERR_PROCESSING
                    }]
                );
                for instance in [&mut engine, &mut app(&path)] {
                    let session = Session::new(instance, protocol);
                    // Each independent live/reopened engine sees the same preceding policy.
                    assert_eq!(
                        session.set(instance),
                        [if published {
                            CTAP2_ERR_PIN_POLICY_VIOLATION
                        } else {
                            CTAP2_OK
                        }]
                    );
                }
            }
        }
    }
}

impl Session {
    fn read_only(&self, app: &mut CtapApp<'_>, pin: &[u8]) -> Vec<u8> {
        self.command(
            app,
            9,
            vec![
                (int(6), Value::Bytes(self.encrypted(&pin_hash(pin)[..]))),
                (int(9), int(0x40)),
            ],
        )
    }
}
fn persistent_metadata(
    app: &mut CtapApp<'_>,
    protocol: ClassicPinProtocol,
    secret: &[u8],
) -> Vec<u8> {
    call(
        app,
        CTAP_CMD_CREDENTIAL_MANAGEMENT,
        vec![
            (int(1), int(1)),
            (int(3), int(protocol.identifier())),
            (int(4), Value::Bytes(mac(protocol, secret, &[1]))),
        ],
    )
}

#[test]
fn missing_pin_authority_before_first_persistent_grant_fails_closed() {
    for managed in [false, true] {
        for protocol in PROTOCOLS {
            let scratch = TempDir::new();
            let path = scratch.path().join("state");
            setup(&path, managed);
            let mut engine = app(&path);
            let session = Session::new(&mut engine, protocol);
            assert_eq!(session.set(&mut engine)[0], CTAP2_OK);
            fs::remove_file(path.join(PIN_STATE_FILE)).unwrap();

            assert_eq!(session.read_only(&mut engine, PIN)[0], CTAP2_ERR_PROCESSING);
            assert!(
                FileStore::open(&path)
                    .unwrap()
                    .pin_state()
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                session.read_only(&mut engine, PIN)[0],
                CTAP2_ERR_PIN_BLOCKED
            );
            assert!(
                FileStore::open(&path)
                    .unwrap()
                    .pin_state()
                    .unwrap()
                    .is_none()
            );
            engine.set_reset_window(None);
            assert_eq!(engine.call(&[CTAP_CMD_RESET])[0], CTAP2_OK);
            let recovered = Session::new(&mut engine, protocol);
            assert_eq!(recovered.set(&mut engine)[0], CTAP2_OK);
            assert_eq!(recovered.read_only(&mut engine, PIN)[0], CTAP2_OK);
        }
    }
}

#[test]
fn persistent_grant_publication_and_retry_writes_require_confirmed_durability() {
    for managed in [false, true] {
        for protocol in PROTOCOLS {
            for write in 1..=3 {
                for failing in PRE.into_iter().chain(POST) {
                    let scratch = TempDir::new();
                    let path = scratch.path().join("state");
                    setup(&path, managed);
                    let mut engine = app(&path);
                    let session = Session::new(&mut engine, protocol);
                    assert_eq!(session.set(&mut engine), [CTAP2_OK]);
                    let response = fault(failing, write, || session.read_only(&mut engine, PIN));
                    assert_eq!(
                        response,
                        [CTAP2_ERR_PROCESSING],
                        "{managed} {protocol:?} {write} {failing}"
                    );
                    let record = FileStore::open(&path)
                        .unwrap()
                        .pin_state()
                        .unwrap()
                        .unwrap();
                    let granted = record.persistent_tokens[usize::from(protocol.identifier() == 2)]
                        .as_ref()
                        .is_some_and(|t| t.granted);
                    assert_eq!(granted, write == 3 && POST.contains(&failing));
                    if let Some(token) =
                        record.persistent_tokens[usize::from(protocol.identifier() == 2)].as_ref()
                    {
                        let mut reopened = app(&path);
                        assert_eq!(
                            persistent_metadata(&mut engine, protocol, &token.secret)[0],
                            if granted {
                                CTAP2_OK
                            } else {
                                CTAP2_ERR_PIN_AUTH_INVALID
                            }
                        );
                        assert_eq!(
                            persistent_metadata(&mut reopened, protocol, &token.secret)[0],
                            if granted {
                                CTAP2_OK
                            } else {
                                CTAP2_ERR_PIN_AUTH_INVALID
                            }
                        );
                    }
                    let retry = Session::new(&mut engine, protocol);
                    assert_eq!(retry.read_only(&mut engine, PIN)[0], CTAP2_OK);
                }
            }
        }
    }
}
#[test]
fn persistent_rotation_is_atomic_with_pin_and_forcing_policy_publication() {
    for managed in [false, true] {
        for protocol in PROTOCOLS {
            for action in 0..3 {
                for failing in PRE.into_iter().chain(POST) {
                    let scratch = TempDir::new();
                    let path = scratch.path().join("state");
                    setup(&path, managed);
                    let mut engine = app(&path);
                    let session = Session::new(&mut engine, protocol);
                    assert_eq!(session.set(&mut engine), [CTAP2_OK]);
                    let mut secrets = Vec::new();
                    for selected in PROTOCOLS {
                        let selected_session = Session::new(&mut engine, selected);
                        secrets.push(
                            selected_session
                                .shared
                                .decrypt(&bytes(field(
                                    &selected_session.read_only(&mut engine, PIN),
                                    2,
                                )))
                                .unwrap(),
                        );
                    }
                    let writable = session
                        .shared
                        .decrypt(&bytes(field(&session.token(&mut engine, PIN), 2)))
                        .unwrap();
                    let response = fault(failing, if action == 0 { 3 } else { 1 }, || {
                        if action == 0 {
                            session.change(&mut engine)
                        } else {
                            let params = if action == 1 {
                                Value::Map(vec![(int(1), int(6))])
                            } else {
                                Value::Map(vec![(int(4), Value::Bool(true))])
                            };
                            configure(&mut engine, protocol, Some(&writable), 3, Some(params))
                        }
                    });
                    let committed = POST.contains(&failing);
                    assert_eq!(
                        response,
                        [if committed {
                            CTAP2_OK
                        } else {
                            CTAP2_ERR_PROCESSING
                        }]
                    );
                    let mut reopened = app(&path);
                    for (selected, secret) in PROTOCOLS.into_iter().zip(&secrets) {
                        for instance in [&mut engine, &mut reopened] {
                            assert_eq!(
                                persistent_metadata(instance, selected, secret)[0],
                                if committed {
                                    CTAP2_ERR_PIN_AUTH_INVALID
                                } else {
                                    CTAP2_OK
                                }
                            );
                        }
                    }
                }
            }
        }
    }
}
#[test]
fn persistent_reset_failures_reconcile_published_root_and_explicit_retry() {
    for managed in [false, true] {
        for protocol in PROTOCOLS {
            for failing in PRE.into_iter().chain(POST).chain(["remove", "removed"]) {
                let scratch = TempDir::new();
                let path = scratch.path().join("state");
                setup(&path, managed);
                let mut engine = app(&path);
                let session = Session::new(&mut engine, protocol);
                assert_eq!(session.set(&mut engine), [CTAP2_OK]);
                let secret = session
                    .shared
                    .decrypt(&bytes(field(&session.read_only(&mut engine, PIN), 2)))
                    .unwrap();
                let response = fsio::with_hook(
                    Box::new(move |event, path| {
                        if event == failing {
                            Err(failure(path))
                        } else {
                            Ok(())
                        }
                    }),
                    || engine.call(&[CTAP_CMD_RESET]),
                );
                assert_eq!(response, [CTAP2_ERR_PROCESSING]);
                let authoritative = FileStore::open(&path).unwrap().pin_state();
                let preceding = authoritative
                    .as_ref()
                    .ok()
                    .and_then(|r| r.as_ref())
                    .is_some_and(|r| {
                        r.persistent_tokens[usize::from(protocol.identifier() == 2)]
                            .as_ref()
                            .is_some_and(|t| t.granted)
                    });
                let mut reopened = app(&path);
                for instance in [&mut engine, &mut reopened] {
                    let result = persistent_metadata(instance, protocol, &secret)[0];
                    if preceding {
                        assert_eq!(result, CTAP2_OK);
                    } else {
                        assert_ne!(result, CTAP2_OK);
                    }
                }
                assert_eq!(engine.call(&[CTAP_CMD_RESET]), [CTAP2_OK]);
                assert_ne!(
                    persistent_metadata(&mut engine, protocol, &secret)[0],
                    CTAP2_OK
                );
                assert_ne!(
                    persistent_metadata(&mut app(&path), protocol, &secret)[0],
                    CTAP2_OK
                );
            }
        }
    }
}

#[test]
fn credential_update_faults_clear_cursors_without_rotating_persistent_authority() {
    for managed in [false, true] {
        for protocol in PROTOCOLS {
            for failing in PRE.into_iter().chain(POST) {
                let scratch = TempDir::new();
                let path = scratch.path().join("state");
                let (_, _, record) = setup(&path, managed);
                let mut store = FileStore::open(&path).unwrap();
                let mut second = record.clone();
                second.credential_id = vec![2; 33];
                second.user_id = vec![3];
                store.put(&second).unwrap();
                second.credential_id = vec![3; 33];
                second.rp_id = "other.example".into();
                store.put(&second).unwrap();
                let mut engine = app(&path);
                let session = Session::new(&mut engine, protocol);
                assert_eq!(session.set(&mut engine), [CTAP2_OK]);
                let readonly = session
                    .shared
                    .decrypt(&bytes(field(&session.read_only(&mut engine, PIN), 2)))
                    .unwrap();
                let writable = session
                    .shared
                    .decrypt(&bytes(field(&session.token(&mut engine, PIN), 2)))
                    .unwrap();
                let manage = |engine: &mut CtapApp<'_>, sub: u8, params: Option<Value>| {
                    let mut message = vec![sub];
                    let mut fields = vec![(int(1), int(sub.into()))];
                    if let Some(params) = params {
                        ciborium::ser::into_writer(&params, &mut message).unwrap();
                        fields.push((int(2), params));
                    }
                    fields.extend([
                        (int(3), int(protocol.identifier())),
                        (int(4), Value::Bytes(mac(protocol, &writable, &message))),
                    ]);
                    call(engine, CTAP_CMD_CREDENTIAL_MANAGEMENT, fields)
                };
                assert_eq!(manage(&mut engine, 2, None)[0], CTAP2_OK);
                assert_eq!(
                    manage(
                        &mut engine,
                        4,
                        Some(Value::Map(vec![(
                            int(1),
                            Value::Bytes(Sha256::digest(RP.as_bytes()).to_vec())
                        )]))
                    )[0],
                    CTAP2_OK
                );
                let params = Value::Map(vec![
                    (
                        int(2),
                        Value::Map(vec![
                            (text("id"), Value::Bytes(record.credential_id.clone())),
                            (text("type"), text("public-key")),
                        ]),
                    ),
                    (
                        int(3),
                        Value::Map(vec![
                            (text("id"), Value::Bytes(record.user_id.clone())),
                            (text("name"), text("changed")),
                        ]),
                    ),
                ]);
                let directory = if managed {
                    path.join(MANAGED_DIR).join(RECORDS_DIR)
                } else {
                    path.join(CREDENTIALS_DIR)
                };
                let response = fsio::with_hook(
                    Box::new(move |event, path| {
                        if event == failing && path.starts_with(&directory) {
                            Err(failure(path))
                        } else {
                            Ok(())
                        }
                    }),
                    || manage(&mut engine, 7, Some(params)),
                );
                assert_eq!(response, [CTAP2_ERR_PROCESSING]);
                for sub in [3, 5] {
                    assert_eq!(
                        call(
                            &mut engine,
                            CTAP_CMD_CREDENTIAL_MANAGEMENT,
                            vec![(int(1), int(sub))]
                        ),
                        [CTAP2_ERR_NOT_ALLOWED]
                    );
                }
                let store = FileStore::open(&path).unwrap();
                let updated = store.get(&record.credential_id).unwrap().unwrap();
                assert_eq!(
                    updated.user_name.as_deref(),
                    POST.contains(&failing).then_some("changed")
                );
                assert_eq!(updated.sign_count, 7);
                assert_eq!(
                    persistent_metadata(&mut engine, protocol, &readonly)[0],
                    CTAP2_OK
                );
                assert_eq!(
                    persistent_metadata(&mut app(&path), protocol, &readonly)[0],
                    CTAP2_OK
                );
            }
        }
    }
}
