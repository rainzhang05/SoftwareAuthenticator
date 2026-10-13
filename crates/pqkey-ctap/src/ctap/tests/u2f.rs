//! U2F framing, presence policy and credentials shared with CTAP2.

use super::support::{
    NEVER_INTERRUPTED, PresenceEvent, TestApp, TestStore, app_with_store, credential, insert,
    pin_hash, response_auth_data, scripted_app, test_app,
};
use crate::ctap::presence::{PresenceOperation, PresenceOutcome};
use crate::ctap::u2f::*;
use crate::store::{CredentialStore, PinStateRecord, PrivateKeyMaterial};
use crate::{CoseAlg, CryptoError, KeyKind};
use ciborium::value::{Integer, Value};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256};

const RP: &str = "u2f.example";
const CHALLENGE: [u8; 32] = [0x42; 32];

fn application() -> [u8; 32] {
    Sha256::digest(RP.as_bytes()).into()
}

fn apdu(ins: u8, control: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0, ins, control, 0, 0];
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn register_request() -> Vec<u8> {
    apdu(1, 0, &[CHALLENGE.as_slice(), &application()].concat())
}

fn auth_request(control: u8, handle: &[u8], app: &[u8; 32]) -> Vec<u8> {
    let mut data = CHALLENGE.to_vec();
    data.extend_from_slice(app);
    data.push(handle.len() as u8);
    data.extend_from_slice(handle);
    apdu(2, control, &data)
}

fn data(response: &[u8]) -> &[u8] {
    assert!(response.len() >= 2);
    assert_eq!(&response[response.len() - 2..], SW_NO_ERROR.to_be_bytes());
    &response[..response.len() - 2]
}

fn register(app: &mut TestApp) -> Vec<u8> {
    let response = app.call_u2f(&register_request());
    let response = data(&response);
    assert_eq!(response[0], 5);
    assert_eq!(response[1], 4);
    assert_eq!(response[66], 107);
    response.to_vec()
}

fn handle(registration: &[u8]) -> &[u8] {
    &registration[67..67 + usize::from(registration[66])]
}

fn verify_auth(response: &[u8], public: &[u8], app: &[u8; 32], up: u8) -> u32 {
    let response = data(response);
    assert_eq!(response[0], up);
    let message = [app.as_slice(), &response[..5], &CHALLENGE].concat();
    VerifyingKey::from_sec1_bytes(public)
        .unwrap()
        .verify(&message, &Signature::from_der(&response[5..]).unwrap())
        .unwrap();
    u32::from_be_bytes(response[1..5].try_into().unwrap())
}

fn ctap(app: &mut TestApp, ins: u8, entries: Vec<(i32, Value)>) -> Vec<u8> {
    let mut request = vec![ins];
    let map = Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Integer(Integer::from(k)), v))
            .collect(),
    );
    ciborium::ser::into_writer(&map, &mut request).unwrap();
    app.call(&request)
}

fn descriptor(id: &[u8]) -> Value {
    Value::Map(vec![
        (Value::Text("id".into()), Value::Bytes(id.to_vec())),
        (Value::Text("type".into()), Value::Text("public-key".into())),
    ])
}

fn assert_ctap(app: &mut TestApp, id: &[u8]) -> Vec<u8> {
    ctap(
        app,
        2,
        vec![
            (1, Value::Text(RP.into())),
            (2, Value::Bytes(CHALLENGE.to_vec())),
            (3, Value::Array(vec![descriptor(id)])),
        ],
    )
}

#[test]
fn version_accepts_client_framing_and_le_values() {
    let mut app = test_app([9; 16]);
    for request in [
        vec![0, 3, 0, 0],
        vec![0, 3, 0, 0, 0],
        vec![0, 3, 0, 0, 1],
        vec![0, 3, 0, 0, 0, 0, 0],
        vec![0, 3, 0, 0, 0, 0, 1],
        vec![0, 3, 0, 0, 0, 0, 0, 0, 0],
        vec![0, 3, 0, 0, 0, 0, 0, 0, 1],
    ] {
        assert_eq!(app.call_u2f(&request), b"U2F_V2\x90\0");
        assert!(!requests_presence(&request));
    }
}

#[test]
fn apdu_errors_and_truncations_never_request_presence() {
    let (mut app, log) = scripted_app([1; 16], []);
    for (request, status) in [
        (vec![], SW_WRONG_LENGTH),
        (vec![0, 1, 0], SW_WRONG_LENGTH),
        (vec![1, 3, 0, 0], SW_CLA_NOT_SUPPORTED),
        (vec![0, 0xff, 0, 0], SW_INS_NOT_SUPPORTED),
        (vec![0, 3, 1, 0], SW_WRONG_PARAMETERS),
        (vec![0, 1, 0, 1], SW_WRONG_PARAMETERS),
        (vec![0, 2, 0, 0], SW_WRONG_PARAMETERS),
        (vec![0, 3, 0, 0, 0, 0], SW_WRONG_LENGTH),
        (vec![0, 3, 0, 0, 0, 0, 0, 0], SW_WRONG_LENGTH),
        (apdu(3, 0, &[1]), SW_WRONG_LENGTH),
    ] {
        assert_eq!(app.call_u2f(&request), status.to_be_bytes());
    }
    let request = register_request();
    for len in 0..request.len() {
        assert_eq!(
            app.call_u2f(&request[..len]),
            SW_WRONG_LENGTH.to_be_bytes(),
            "{len}"
        );
    }
    let request = auth_request(3, &[0; 107], &application());
    for len in 0..request.len() {
        assert_eq!(
            app.call_u2f(&request[..len]),
            SW_WRONG_LENGTH.to_be_bytes(),
            "{len}"
        );
    }
    for extra in [vec![0], vec![0, 0, 0]] {
        let mut request = register_request();
        request.extend(extra);
        assert_eq!(app.call_u2f(&request), SW_WRONG_LENGTH.to_be_bytes());
    }
    assert!(log.take().is_empty());
}

#[test]
fn a_wrong_handle_length_or_unknown_handle_fails_before_presence() {
    let (mut app, log) = scripted_app([15; 16], []);
    for declared in [0, 106, 108, 255] {
        let mut request = auth_request(3, &[0; 107], &application());
        request[71] = declared;
        assert_eq!(app.call_u2f(&request), SW_WRONG_LENGTH.to_be_bytes());
    }
    assert_eq!(
        app.call_u2f(&auth_request(3, &[0; 107], &application())),
        SW_WRONG_DATA.to_be_bytes()
    );
    assert!(log.take().is_empty());
}

#[test]
fn stored_counter_write_failure_is_an_internal_error() {
    let store = TestStore::new();
    let (mut app, _) = app_with_store(store.clone(), [16; 16], [], &NEVER_INTERRUPTED);
    let id = [vec![0], vec![1; 32]].concat();
    insert(&mut app, &credential(RP, &[], &id, CoseAlg::ES256));
    store.faults(|f| f.put = true);
    assert_eq!(
        app.call_u2f(&auth_request(8, &id, &application())),
        SW_INTERNAL_ERROR.to_be_bytes()
    );
    assert_eq!(app.store.get(&id).unwrap().unwrap().sign_count, 0);
}

#[test]
fn registration_accepts_short_and_extended_lengths_with_optional_le() {
    let mut app = test_app([2; 16]);
    let body = [CHALLENGE.as_slice(), &application()].concat();
    for short in [false, true] {
        for le in [false, true] {
            let mut request = if short {
                [vec![0, 1, 0, 0, 64], body.clone()].concat()
            } else {
                apdu(1, 0, &body)
            };
            if le {
                request.extend(vec![0; if short { 1 } else { 2 }]);
            }
            assert!(requests_presence(&request));
            assert_eq!(data(&app.call_u2f(&request))[66], 107);
        }
    }
}

#[test]
fn u2f_and_ctap2_share_a_sealed_credential_and_counter() {
    let mut app = test_app([3; 16]);
    let registration = register(&mut app);
    assert!(app.store.list().unwrap().is_empty());
    let id = handle(&registration);
    assert_eq!(
        app.call_u2f(&auth_request(7, id, &application())),
        SW_CONDITIONS_NOT_SATISFIED.to_be_bytes()
    );
    assert_eq!(app.store.signature_counter().unwrap(), 0);
    let first = app.call_u2f(&auth_request(3, id, &application()));
    assert_eq!(
        verify_auth(&first, &registration[1..66], &application(), 1),
        1
    );
    let response = assert_ctap(&mut app, id);
    let auth = response_auth_data(&response);
    assert_eq!(auth[..32], application());
    assert_eq!(auth[32], 1);
    assert_eq!(u32::from_be_bytes(auth[33..37].try_into().unwrap()), 2);
    let second = app.call_u2f(&auth_request(8, id, &application()));
    assert_eq!(
        verify_auth(&second, &registration[1..66], &application(), 0),
        3
    );
    assert_eq!(app.store.signature_counter().unwrap(), 3);
    let response = ctap(
        &mut app,
        2,
        vec![
            (1, Value::Text(RP.into())),
            (2, Value::Bytes(CHALLENGE.to_vec())),
        ],
    );
    assert_eq!(
        response,
        [super::super::constants::CTAP2_ERR_NO_CREDENTIALS]
    );
}

#[test]
fn ctap2_non_discoverable_es256_credentials_work_over_u2f() {
    for (payment, protection) in [false, true]
        .into_iter()
        .flat_map(|payment| (1..=3).map(move |policy| (payment, policy)))
    {
        let mut app = test_app([4; 16]);
        let response = ctap(
            &mut app,
            1,
            vec![
                (1, Value::Bytes(CHALLENGE.to_vec())),
                (
                    2,
                    Value::Map(vec![(Value::Text("id".into()), Value::Text(RP.into()))]),
                ),
                (
                    3,
                    Value::Map(vec![(Value::Text("id".into()), Value::Bytes(vec![1]))]),
                ),
                (
                    4,
                    Value::Array(vec![Value::Map(vec![
                        (Value::Text("alg".into()), Value::Integer((-7).into())),
                        (Value::Text("type".into()), Value::Text("public-key".into())),
                    ])]),
                ),
                (
                    6,
                    Value::Map(vec![
                        (
                            Value::Text("credProtect".into()),
                            Value::Integer(protection.into()),
                        ),
                        (
                            Value::Text("thirdPartyPayment".into()),
                            Value::Bool(payment),
                        ),
                    ]),
                ),
            ],
        );
        let auth = response_auth_data(&response);
        let length = usize::from(u16::from_be_bytes([auth[53], auth[54]]));
        let id = &auth[55..55 + length];
        assert_eq!(length, if payment { 33 } else { 107 });
        assert_eq!(
            app.call_u2f(&auth_request(7, id, &application())),
            if protection == 3 {
                SW_WRONG_DATA
            } else {
                SW_CONDITIONS_NOT_SATISFIED
            }
            .to_be_bytes()
        );
        if protection != 3 {
            let record = app.credential_for_rp(id, RP).unwrap().unwrap();
            let key = record.secret_key().unwrap();
            let crate::CredentialSecretKey::P256(key) = key else {
                panic!("ES256 key")
            };
            assert_eq!(
                verify_auth(
                    &app.call_u2f(&auth_request(3, id, &application())),
                    key.verifying_key().to_sec1_point(false).as_bytes(),
                    &application(),
                    1,
                ),
                1
            );
            let assertion = ctap(
                &mut app,
                2,
                vec![
                    (1, Value::Text(RP.into())),
                    (2, Value::Bytes(CHALLENGE.to_vec())),
                    (3, Value::Array(vec![descriptor(id)])),
                    (
                        4,
                        Value::Map(vec![(
                            Value::Text("thirdPartyPayment".into()),
                            Value::Bool(true),
                        )]),
                    ),
                ],
            );
            let auth = response_auth_data(&assertion);
            assert_eq!(u32::from_be_bytes(auth[33..37].try_into().unwrap()), 2);
            let output: Value = ciborium::de::from_reader(&auth[37..]).unwrap();
            assert_eq!(
                output,
                Value::Map(vec![(
                    Value::Text("thirdPartyPayment".into()),
                    Value::Bool(payment)
                )])
            );
            let Value::Map(response) = ciborium::de::from_reader(&assertion[1..]).unwrap() else {
                panic!("map")
            };
            let signature = response
                .iter()
                .find(|(key, _)| *key == Value::Integer(3.into()))
                .unwrap()
                .1
                .as_bytes()
                .unwrap();
            let message = [auth.as_slice(), &CHALLENGE].concat();
            key.verifying_key()
                .verify(&message, &Signature::from_der(signature).unwrap())
                .unwrap();
            assert_eq!(
                app.credential_for_rp(id, RP)
                    .unwrap()
                    .unwrap()
                    .third_party_payment,
                payment
            );
        }
    }
}

#[test]
fn stored_credential_eligibility_and_counters_match_the_sealed_path() {
    let mut app = test_app([5; 16]);
    for protection in [1, 2, 3] {
        for discoverable in [false, true] {
            let id = [vec![u8::from(discoverable)], vec![protection; 32]].concat();
            let mut record = credential(RP, &[], &id, CoseAlg::ES256);
            record.cred_protect = protection;
            record.sign_count = 42;
            insert(&mut app, &record);
            let expected = if discoverable || protection == 3 {
                SW_WRONG_DATA
            } else {
                SW_CONDITIONS_NOT_SATISFIED
            };
            assert_eq!(
                app.call_u2f(&auth_request(7, &id, &application())),
                expected.to_be_bytes()
            );
            let response = app.call_u2f(&auth_request(3, &id, &application()));
            if expected == SW_WRONG_DATA {
                assert_eq!(response, SW_WRONG_DATA.to_be_bytes());
            } else {
                assert_eq!(
                    u32::from_be_bytes(data(&response)[1..5].try_into().unwrap()),
                    43
                );
                assert_eq!(app.store.get(&id).unwrap().unwrap().sign_count, 43);
                let auth = response_auth_data(&assert_ctap(&mut app, &id));
                assert_eq!(u32::from_be_bytes(auth[33..37].try_into().unwrap()), 44);
            }
        }
    }
}

#[test]
fn other_algorithms_wrong_applications_and_foreign_or_tampered_handles_are_refused() {
    let mut app = test_app([6; 16]);
    for alg in CoseAlg::ALL
        .into_iter()
        .filter(|alg| *alg != CoseAlg::ES256)
    {
        let id = [vec![0], vec![alg.identifier() as u8; 32]].concat();
        let mut record = credential(RP, &[], &id, CoseAlg::ES256);
        record.alg = alg;
        record.private_key = match alg.key_kind() {
            KeyKind::P256Scalar => record.private_key.clone(),
            KeyKind::Seed => PrivateKeyMaterial::Seed { seed: [1; 32] },
            KeyKind::RsaPrimes => PrivateKeyMaterial::RsaPrimes {
                primes: crate::rsa_fixture::PRIMES,
            },
        };
        insert(&mut app, &record);
        for control in [3, 7, 8] {
            assert_eq!(
                app.call_u2f(&auth_request(control, &id, &application())),
                SW_WRONG_DATA.to_be_bytes(),
                "{alg:?}"
            );
        }
        if alg.is_sealable() {
            let material = record.private_key.sealable().unwrap();
            record.credential_id = app
                .seal_credential(&mut record, &material, &application())
                .unwrap();
            for control in [3, 7, 8] {
                assert_eq!(
                    app.call_u2f(&auth_request(
                        control,
                        &record.credential_id,
                        &application()
                    )),
                    SW_WRONG_DATA.to_be_bytes(),
                    "sealed {alg:?}"
                );
            }
        }
    }
    let registration = register(&mut app);
    let id = handle(&registration);
    for control in [3, 7, 8] {
        assert_eq!(
            app.call_u2f(&auth_request(control, id, &[0; 32])),
            SW_WRONG_DATA.to_be_bytes()
        );
        assert_eq!(
            test_app([7; 16]).call_u2f(&auth_request(control, id, &application())),
            SW_WRONG_DATA.to_be_bytes()
        );
        let mut bad = id.to_vec();
        bad[20] ^= 1;
        assert_eq!(
            app.call_u2f(&auth_request(control, &bad, &application())),
            SW_WRONG_DATA.to_be_bytes()
        );
        assert_eq!(
            app.call_u2f(&auth_request(control, &[], &application())),
            SW_WRONG_DATA.to_be_bytes()
        );
    }
}

#[test]
fn presence_outcomes_are_u2f_status_words_and_silent_requests_do_not_prompt() {
    for outcome in [
        PresenceOutcome::Denied,
        PresenceOutcome::TimedOut,
        PresenceOutcome::Cancelled,
    ] {
        let (mut app, log) = scripted_app([8; 16], [outcome]);
        assert_eq!(
            app.call_u2f(&register_request()),
            SW_CONDITIONS_NOT_SATISFIED.to_be_bytes()
        );
        let events = log.take();
        assert!(events.iter().any(|e| matches!(e,PresenceEvent::Asked(r) if r.operation == PresenceOperation::U2fRegister && r.rp_id.is_none())));
        let registration = register(&mut app);
        log.take();
        app.call_u2f(&auth_request(7, handle(&registration), &application()));
        app.call_u2f(&auth_request(8, handle(&registration), &application()));
        assert!(log.take().is_empty());
    }
}

#[test]
fn always_uv_gates_every_authentication_control_and_pin_does_not() {
    let (mut app, log) = scripted_app([10; 16], []);
    let registration = register(&mut app);
    log.take();
    app.pin_state.set_pin(pin_hash(b"1234"));
    assert_eq!(data(&app.call_u2f(&register_request()))[0], 5);
    assert_eq!(
        data(&app.call_u2f(&auth_request(3, handle(&registration), &application())))[0],
        1
    );
    ctap(&mut app, 0x0d, vec![(1, Value::Integer(2.into()))]);
    // With a PIN, configuration needs a token; use the persistent policy.
    let mut state = app.pin_state.persistent().clone();
    state.always_uv = true;
    app.pin_state.adopt_persistent(state);
    log.take();
    assert_eq!(
        app.call_u2f(&register_request()),
        SW_COMMAND_NOT_ALLOWED.to_be_bytes()
    );
    for control in [3, 7, 8] {
        assert_eq!(
            app.call_u2f(&auth_request(
                control,
                handle(&registration),
                &application()
            )),
            SW_COMMAND_NOT_ALLOWED.to_be_bytes()
        );
    }
    assert_eq!(
        app.call_u2f(&[0, 1, 0, 0]),
        SW_COMMAND_NOT_ALLOWED.to_be_bytes()
    );
    assert_eq!(data(&app.call_u2f(&[0, 3, 0, 0])), b"U2F_V2");
    assert!(log.take().is_empty());
}

#[test]
fn failures_and_saturation_do_not_return_an_unpersisted_counter() {
    let store = TestStore::new();
    let (mut app, _) = app_with_store(store.clone(), [11; 16], [], &NEVER_INTERRUPTED);
    let registration = register(&mut app);
    store.faults(|f| f.set_signature_counter = true);
    assert_eq!(
        app.call_u2f(&auth_request(8, handle(&registration), &application())),
        SW_INTERNAL_ERROR.to_be_bytes()
    );
    store.faults(|f| {
        f.set_signature_counter = false;
        f.signature_counter = true;
    });
    assert_eq!(
        app.call_u2f(&auth_request(8, handle(&registration), &application())),
        SW_INTERNAL_ERROR.to_be_bytes()
    );
    store.faults(|f| f.signature_counter = false);
    app.store.set_signature_counter(u32::MAX).unwrap();
    for _ in 0..2 {
        assert_eq!(
            verify_auth(
                &app.call_u2f(&auth_request(8, handle(&registration), &application())),
                &registration[1..66],
                &application(),
                0
            ),
            u32::MAX
        );
    }
    app.set_key_generator(|_| Err(CryptoError::Randomness));
    assert_eq!(
        app.call_u2f(&register_request()),
        SW_INTERNAL_ERROR.to_be_bytes()
    );
    store.faults(|f| f.pin_state = true);
    let (mut unreadable, log) = app_with_store(store, [12; 16], [], &NEVER_INTERRUPTED);
    assert_eq!(
        unreadable.call_u2f(&register_request()),
        SW_COMMAND_NOT_ALLOWED.to_be_bytes()
    );
    assert!(log.take().is_empty());
}

#[test]
fn reset_and_restart_observe_the_same_u2f_credentials() {
    let mut store = TestStore::new();
    let (mut app, _) = app_with_store(store.clone(), [13; 16], [], &NEVER_INTERRUPTED);
    let registration = register(&mut app);
    verify_auth(
        &app.call_u2f(&auth_request(8, handle(&registration), &application())),
        &registration[1..66],
        &application(),
        0,
    );
    drop(app);
    let (mut app, _) = app_with_store(store.clone(), [13; 16], [], &NEVER_INTERRUPTED);
    assert_eq!(
        verify_auth(
            &app.call_u2f(&auth_request(8, handle(&registration), &application())),
            &registration[1..66],
            &application(),
            0
        ),
        2
    );
    assert_eq!(app.call(&[7]), [0]);
    assert_eq!(
        app.call_u2f(&auth_request(7, handle(&registration), &application())),
        SW_WRONG_DATA.to_be_bytes()
    );
    let mut state = PinStateRecord::default();
    state.always_uv = true;
    store.set_pin_state(&state).unwrap();
    let (mut app, _) = app_with_store(store, [13; 16], [], &NEVER_INTERRUPTED);
    assert_eq!(
        app.call_u2f(&register_request()),
        SW_COMMAND_NOT_ALLOWED.to_be_bytes()
    );
}

#[test]
fn complexity_and_forced_pin_change_do_not_independently_block_u2f() {
    for force_pin_change in [false, true] {
        let store = TestStore::new();
        store
            .clone()
            .set_pin_state(&PinStateRecord {
                pin_hash: force_pin_change.then_some(pin_hash(b"1234")),
                pin_complexity_policy: true,
                force_pin_change,
                min_pin_length_rp_ids: Vec::new(),
                ..PinStateRecord::default()
            })
            .unwrap();
        let (mut app, _) = app_with_store(store, [14; 16], [], &NEVER_INTERRUPTED);
        let registration = register(&mut app);
        verify_auth(
            &app.call_u2f(&auth_request(8, handle(&registration), &application())),
            &registration[1..66],
            &application(),
            0,
        );
        assert_eq!(data(&app.call_u2f(&[0, 3, 0, 0])), b"U2F_V2");
    }
}
