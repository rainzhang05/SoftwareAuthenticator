//! How the engine uses its credential store: the overwrite rule, signature
//! counter persistence, store failures, PIN state persistence and the
//! fail-closed handling of an unreadable PIN state, and attestation.

use super::support::{
    NEVER_INTERRUPTED, TestApp, TestStore, app_with_store, credential, get_pin_retries,
    get_pin_token, insert, padded_pin, pin_hash, set_pin_padded, stored, test_app,
};
use crate::ClassicPinProtocol;
use crate::CoseAlg;
use crate::ctap::AttestationMode;
use crate::ctap::cbor::canonical_map;
use crate::ctap::pin::state::{MAX_CONSECUTIVE_PIN_MISMATCHES, MAX_PIN_RETRIES};
use crate::store::{CredentialStore, PinStateRecord};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};

use crate::ctap::constants::*;

const RP_ID: &str = "example.com";
const PIN: &[u8] = b"1234";

fn make_credential_payload(rp_id: &str, user_id: &[u8], rk: Option<bool>) -> Vec<u8> {
    let rp = canonical_map(vec![(Value::Text("id".into()), Value::Text(rp_id.into()))]);
    let user = canonical_map(vec![(
        Value::Text("id".into()),
        Value::Bytes(user_id.to_vec()),
    )]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::ES256 as i32)),
        ),
    ])]);
    let mut entries = vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(vec![0x42; 32]),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ];
    if let Some(rk) = rk {
        entries.push((
            Value::Integer(Integer::from(7)),
            canonical_map(vec![(Value::Text("rk".into()), Value::Bool(rk))]),
        ));
    }
    let mut payload = Vec::new();
    into_writer(&canonical_map(entries), &mut payload).expect("serialize makeCredential");
    payload
}

fn get_assertion_payload() -> Vec<u8> {
    let request = canonical_map(vec![
        (Value::Integer(Integer::from(1)), Value::Text(RP_ID.into())),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(vec![0x43; 32]),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize getAssertion");
    payload
}

/// The credential ID in a makeCredential response's attested credential data.
fn registered_id(response: &[u8]) -> Vec<u8> {
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(entries) = from_reader(&response[1..]).expect("decode response") else {
        panic!("response must be a map");
    };
    let auth_data = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("authData");
    let length = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
    auth_data[55..55 + length].to_vec()
}

fn register(app: &mut TestApp, rp_id: &str, user_id: &[u8], rk: Option<bool>) -> Vec<u8> {
    let response = app
        .handle_make_credential(&make_credential_payload(rp_id, user_id, rk))
        .expect("makeCredential succeeds");
    registered_id(&response)
}

fn ids(app: &TestApp) -> Vec<Vec<u8>> {
    stored(app)
        .into_iter()
        .map(|record| record.credential_id.clone())
        .collect()
}

/// CTAP 2.3 §6.1.2 step 17.2.
#[test]
fn discoverable_registration_overwrites_the_same_account() {
    let mut app = test_app([0x61; 16]);
    let old = register(&mut app, RP_ID, &[0x01], Some(true));
    let other_user = register(&mut app, RP_ID, &[0x02], Some(true));
    let other_rp = register(&mut app, "other.example", &[0x01], Some(true));

    let new = register(&mut app, RP_ID, &[0x01], Some(true));
    assert_ne!(new, old);
    assert_eq!(ids(&app), [new.clone(), other_rp, other_user]);
    assert!(app.store.get(&old).unwrap().is_none(), "the old ID is gone");
}

#[test]
fn non_discoverable_registration_does_not_overwrite() {
    for rk in [None, Some(false)] {
        let mut app = test_app([0x62; 16]);
        let first = register(&mut app, RP_ID, &[0x01], rk);
        let second = register(&mut app, RP_ID, &[0x01], rk);
        assert_eq!(ids(&app), [second, first], "{rk:?}");
    }
}

#[test]
fn overwrite_succeeds_in_a_full_store_and_new_accounts_do_not() {
    let (mut app, _) = app_with_store(
        TestStore::with_max_credentials(1),
        [0x63; 16],
        [],
        &NEVER_INTERRUPTED,
    );
    register(&mut app, RP_ID, &[0x01], Some(true));
    let new = register(&mut app, RP_ID, &[0x01], Some(true));
    assert_eq!(ids(&app), std::slice::from_ref(&new));

    assert_eq!(
        app.handle_make_credential(&make_credential_payload(RP_ID, &[0x02], Some(true))),
        Err(CTAP2_ERR_KEY_STORE_FULL)
    );
    assert_eq!(ids(&app), [new]);
}

#[test]
fn a_failed_registration_stores_nothing() {
    let store = TestStore::new();
    let (mut app, _) = app_with_store(store.clone(), [0x64; 16], [], &NEVER_INTERRUPTED);
    store.faults(|faults| faults.put = true);
    assert_eq!(
        app.handle_make_credential(&make_credential_payload(RP_ID, &[0x01], Some(true))),
        Err(CTAP2_ERR_PROCESSING)
    );
    assert_eq!(store.credentials().len(), 0);
}

#[test]
fn signature_counter_is_persisted_before_the_signature_is_returned() {
    let store = TestStore::new();
    let (mut app, _) = app_with_store(store.clone(), [0x65; 16], [], &NEVER_INTERRUPTED);
    insert(
        &mut app,
        &credential(RP_ID, &[0x01], &[0xC1], CoseAlg::MLDSA44),
    );

    app.handle_get_assertion(&get_assertion_payload())
        .expect("getAssertion succeeds");
    assert_eq!(store.credential(&[0xC1]).sign_count, 1);

    store.faults(|faults| faults.put = true);
    assert_eq!(
        app.handle_get_assertion(&get_assertion_payload()),
        Err(CTAP2_ERR_PROCESSING),
        "no signature for a counter that was not saved"
    );
    store.faults(|faults| faults.put = false);
    assert_eq!(store.credential(&[0xC1]).sign_count, 1);

    app.handle_get_assertion(&get_assertion_payload())
        .expect("getAssertion succeeds again");
    assert_eq!(store.credential(&[0xC1]).sign_count, 2);
}

#[test]
fn next_assertion_persists_its_counter_too() {
    let store = TestStore::new();
    let (mut app, _) = app_with_store(store.clone(), [0x66; 16], [], &NEVER_INTERRUPTED);
    insert(
        &mut app,
        &credential(RP_ID, &[0x01], &[0xD1], CoseAlg::ES256),
    );
    insert(
        &mut app,
        &credential(RP_ID, &[0x02], &[0xD2], CoseAlg::ES256),
    );

    app.handle_get_assertion(&get_assertion_payload())
        .expect("getAssertion succeeds");
    store.faults(|faults| faults.put = true);
    assert_eq!(app.handle_get_next_assertion(), Err(CTAP2_ERR_PROCESSING));
    assert_eq!(store.credential(&[0xD1]).sign_count, 0);
}

/// A store that cannot be read must never look like an empty one.
#[test]
fn store_read_errors_are_not_reported_as_missing_credentials() {
    let store = TestStore::new();
    let (mut app, _) = app_with_store(store.clone(), [0x67; 16], [], &NEVER_INTERRUPTED);
    insert(
        &mut app,
        &credential(RP_ID, &[0x01], &[0xE1], CoseAlg::ES256),
    );

    store.faults(|faults| faults.list = true);
    assert_eq!(
        app.handle_get_assertion(&get_assertion_payload()),
        Err(CTAP2_ERR_PROCESSING)
    );
    // The overwrite rule has to look for existing accounts.
    assert_eq!(
        app.handle_make_credential(&make_credential_payload(RP_ID, &[0x01], Some(true))),
        Err(CTAP2_ERR_PROCESSING)
    );
    store.faults(|faults| faults.list = false);

    store.faults(|faults| faults.get = true);
    let exclude = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(vec![0x42; 32]),
        ),
        (
            Value::Integer(Integer::from(2)),
            canonical_map(vec![(Value::Text("id".into()), Value::Text(RP_ID.into()))]),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x09]))]),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Array(vec![canonical_map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (Value::Text("alg".into()), Value::Integer(Integer::from(-7))),
            ])]),
        ),
        (
            Value::Integer(Integer::from(5)),
            Value::Array(vec![canonical_map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (Value::Text("id".into()), Value::Bytes(vec![0xE1])),
            ])]),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&exclude, &mut payload).unwrap();
    assert_eq!(
        app.handle_make_credential(&payload),
        Err(CTAP2_ERR_PROCESSING)
    );
    store.faults(|faults| faults.get = false);
    assert_eq!(store.credentials().len(), 1);
}

#[test]
fn exclude_list_only_matches_credentials_of_the_same_relying_party() {
    let mut app = test_app([0x68; 16]);
    let id = register(&mut app, "other.example", &[0x01], None);
    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(vec![0x42; 32]),
        ),
        (
            Value::Integer(Integer::from(2)),
            canonical_map(vec![(Value::Text("id".into()), Value::Text(RP_ID.into()))]),
        ),
        (
            Value::Integer(Integer::from(3)),
            canonical_map(vec![(Value::Text("id".into()), Value::Bytes(vec![0x01]))]),
        ),
        (
            Value::Integer(Integer::from(4)),
            Value::Array(vec![canonical_map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (Value::Text("alg".into()), Value::Integer(Integer::from(-7))),
            ])]),
        ),
        (
            Value::Integer(Integer::from(5)),
            Value::Array(vec![canonical_map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (Value::Text("id".into()), Value::Bytes(id)),
            ])]),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request, &mut payload).unwrap();
    assert!(app.handle_make_credential(&payload).is_ok());
}

/// Only the PIN hash and the retry counter survive a restart; the
/// consecutive-mismatch lockout is volatile.
#[test]
fn only_the_pin_hash_and_retry_counter_are_persisted() {
    let store = TestStore::new();
    let (mut app, _) = app_with_store(store.clone(), [0x69; 16], [], &NEVER_INTERRUPTED);
    set_pin_padded(&mut app, ClassicPinProtocol::V2, &padded_pin(PIN)).expect("setPIN");
    for _ in 0..MAX_CONSECUTIVE_PIN_MISMATCHES {
        let _ = get_pin_token(&mut app, ClassicPinProtocol::V2, b"0000");
    }
    assert_eq!(get_pin_retries(&mut app), (MAX_PIN_RETRIES - 3, Some(true)));
    assert_eq!(
        store.pin_state().unwrap(),
        Some(PinStateRecord {
            pin_hash: Some(pin_hash(PIN)),
            pin_retries: MAX_PIN_RETRIES - 3,
            consecutive_failures: 0,
            pin_auth_blocked: false,
        })
    );

    let (mut restarted, _) = app_with_store(store.clone(), [0x69; 16], [], &NEVER_INTERRUPTED);
    assert_eq!(get_pin_retries(&mut restarted), (MAX_PIN_RETRIES - 3, None));
    get_pin_token(&mut restarted, ClassicPinProtocol::V2, PIN).expect("correct PIN");
}

/// CTAP 2.3 §6.5.5.7: the spent retry is persisted before the PIN is
/// compared, and a PIN is never compared if that write fails.
#[test]
fn a_pin_is_not_compared_unless_the_spent_retry_is_persisted() {
    let store = TestStore::new();
    let (mut app, _) = app_with_store(store.clone(), [0x6A; 16], [], &NEVER_INTERRUPTED);
    set_pin_padded(&mut app, ClassicPinProtocol::V2, &padded_pin(PIN)).expect("setPIN");

    store.faults(|faults| faults.set_pin_state = true);
    for pin in [PIN, b"0000".as_slice()] {
        assert_eq!(
            get_pin_token(&mut app, ClassicPinProtocol::V2, pin),
            Err(CTAP2_ERR_PROCESSING),
            "no token and no PIN verdict without a persisted retry"
        );
    }
    store.faults(|faults| faults.set_pin_state = false);
    assert_eq!(
        store.pin_state().unwrap().map(|state| state.pin_retries),
        Some(MAX_PIN_RETRIES)
    );
    get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).expect("correct PIN");
}

/// An unreadable PIN state fails closed: set, blocked, never overwritten,
/// and recoverable only by a reset.
#[test]
fn unreadable_pin_state_is_treated_as_set_and_blocked_until_reset() {
    let store = TestStore::new();
    store.faults(|faults| faults.pin_state = true);
    let (mut app, _) = app_with_store(store.clone(), [0x6B; 16], [], &NEVER_INTERRUPTED);

    assert!(app.pin_state.is_set(), "never acts as if no PIN is set");
    assert_eq!(get_pin_retries(&mut app), (0, None));
    for pin in [PIN, b"0000".as_slice()] {
        assert_eq!(
            get_pin_token(&mut app, ClassicPinProtocol::V2, pin),
            Err(CTAP2_ERR_PIN_BLOCKED)
        );
    }
    assert_ne!(
        set_pin_padded(&mut app, ClassicPinProtocol::V2, &padded_pin(PIN)),
        Ok(vec![CTAP2_OK]),
        "a new PIN cannot be set over the unreadable one"
    );
    assert_eq!(
        store.pin_state_writes(),
        [],
        "the unreadable record is not overwritten"
    );

    store.faults(|faults| faults.pin_state = false);
    assert_eq!(app.handle_reset(), Ok(vec![CTAP2_OK]));
    assert!(!app.pin_state.is_set());
    assert_eq!(get_pin_retries(&mut app), (MAX_PIN_RETRIES, None));
    set_pin_padded(&mut app, ClassicPinProtocol::V2, &padded_pin(PIN)).expect("setPIN after reset");
    assert_eq!(
        store.pin_state().unwrap().map(|state| state.pin_hash),
        Some(Some(pin_hash(PIN)))
    );
}

#[test]
fn reset_clears_the_store_and_a_failed_reset_keeps_the_pin() {
    let store = TestStore::new();
    let (mut app, _) = app_with_store(store.clone(), [0x6C; 16], [], &NEVER_INTERRUPTED);
    register(&mut app, RP_ID, &[0x01], Some(true));
    set_pin_padded(&mut app, ClassicPinProtocol::V2, &padded_pin(PIN)).expect("setPIN");

    store.faults(|faults| faults.clear = true);
    assert_eq!(app.handle_reset(), Err(CTAP2_ERR_PROCESSING));
    assert!(app.pin_state.is_set());
    store.faults(|faults| faults.clear = false);

    assert_eq!(app.handle_reset(), Ok(vec![CTAP2_OK]));
    assert!(!app.pin_state.is_set());
    assert_eq!(store.credentials().len(), 0);
    assert_eq!(store.pin_state().unwrap(), Some(PinStateRecord::default()));
}

#[test]
fn unreadable_attestation_falls_back_to_self_attestation() {
    let store = TestStore::new();
    store.faults(|faults| faults.attestation = true);
    let (mut app, _) = app_with_store(store, [0x6D; 16], [], &NEVER_INTERRUPTED);
    app.set_attestation_mode(AttestationMode::Certificate);
    let response = app
        .handle_make_credential(&make_credential_payload(RP_ID, &[0x01], None))
        .expect("makeCredential succeeds");
    let Value::Map(entries) = from_reader(&response[1..]).unwrap() else {
        panic!("map");
    };
    let att_stmt = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(3)))
        .map(|(_, v)| v.clone())
        .expect("attStmt");
    let Value::Map(att_stmt) = att_stmt else {
        panic!("attStmt map");
    };
    assert!(
        att_stmt
            .iter()
            .all(|(k, _)| *k != Value::Text("x5c".into()))
    );
    assert!(att_stmt.contains(&(
        Value::Text("alg".into()),
        Value::Integer(Integer::from(CoseAlg::ES256 as i32))
    )));
}
