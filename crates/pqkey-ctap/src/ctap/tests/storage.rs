//! How the engine uses its credential store: the overwrite rule, signature
//! counter persistence, store failures, PIN state persistence, the
//! fail-closed handling of an unreadable PIN state and the read errors that
//! fail only one command, and attestation.

use super::large_blobs::write_request;
use super::support::{
    FLAG_UV, NEVER_INTERRUPTED, TestApp, TestRng, TestStore, app_with_store, change_pin,
    client_pin, credential, get_pin_retries, get_pin_token, get_pin_uv_auth_token, insert, int,
    make_credential_request, new_app, padded_pin, pin_hash, response_auth_data, set_pin_padded,
    stored, test_app, token_pin_auth,
};
use super::u2f::register_request;
use crate::ClassicPinProtocol;
use crate::CoseAlg;
use crate::ctap::cbor::canonical_map;
use crate::ctap::pin::permissions::{PIN_PERMISSION_LBW, PIN_PERMISSION_MC};
use crate::ctap::pin::state::{MAX_CONSECUTIVE_PIN_MISMATCHES, MAX_PIN_RETRIES};
use crate::ctap::presence::AutoApprove;
use crate::ctap::u2f::SW_COMMAND_NOT_ALLOWED;
use crate::ctap::{AttestationMode, CtapApp};
use crate::store::{
    Corruption, CredentialStore, FileKeySource, FileStore, INITIAL_LARGE_BLOB_ARRAY, KeyDomain,
    KeySource, PinStateRecord, RootKey, StoreError, test_support::TempDir,
};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ctap::constants::*;

const RP_ID: &str = "example.com";
const PIN: &[u8] = b"1234";

#[test]
fn credential_binding_accepts_the_rp_hash_without_hashing_it_again() {
    use sha2::{Digest, Sha256};
    let mut app = test_app([0x69; 16]);
    for rk in [false, true] {
        let id = register(&mut app, RP_ID, &[1], Some(rk));
        let hash = Sha256::digest(RP_ID.as_bytes()).into();
        let record = app.credential_for_hash(&id, &hash).unwrap().unwrap();
        assert_eq!(record.credential_id, id);
        assert_eq!(record.rp_id, if rk { RP_ID } else { "" });
        assert!(app.credential_for_hash(&id, &[0; 32]).unwrap().is_none());
        assert!(app.credential_for_rp(&id, RP_ID).unwrap().is_some());
    }
}

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
            Value::Integer(Integer::from(CoseAlg::ES256.identifier())),
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

/// A non-discoverable registration overwrites nothing: both credentials of
/// the same account stay usable, and neither takes room in the store.
#[test]
fn non_discoverable_registration_does_not_overwrite() {
    for rk in [None, Some(false)] {
        let mut app = test_app([0x62; 16]);
        let first = register(&mut app, RP_ID, &[0x01], rk);
        let second = register(&mut app, RP_ID, &[0x01], rk);
        assert_ne!(first, second);
        assert!(ids(&app).is_empty(), "{rk:?}");
        for id in [&first, &second] {
            assert!(
                app.credential_for_rp(id, RP_ID).expect("look up").is_some(),
                "{rk:?}"
            );
        }
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

fn assertion_with_id(id: &[u8]) -> Vec<u8> {
    let mut request: Value = from_reader(get_assertion_payload().as_slice()).unwrap();
    request.as_map_mut().unwrap().push((
        Value::Integer(Integer::from(3)),
        Value::Array(vec![canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (Value::Text("id".into()), Value::Bytes(id.to_vec())),
        ])]),
    ));
    let mut bytes = Vec::new();
    into_writer(&request, &mut bytes).unwrap();
    bytes
}

#[test]
fn failed_full_replacement_preserves_the_original_and_unrelated_accounts() {
    let store = TestStore::with_max_credentials(2);
    let (mut app, _) = app_with_store(store.clone(), [0x81; 16], [], &NEVER_INTERRUPTED);
    let original = register(&mut app, RP_ID, &[1], Some(true));
    let unrelated = register(&mut app, RP_ID, &[2], Some(true));
    let before = store.credentials();
    store.faults(|faults| faults.replacement_write = true);
    assert_eq!(
        app.handle_make_credential(&make_credential_payload(RP_ID, &[1], Some(true))),
        Err(CTAP2_ERR_PROCESSING)
    );
    assert_eq!(store.credentials(), before);
    store.faults(|faults| faults.replacement_write = false);
    for id in [&original, &unrelated] {
        assert_eq!(
            app.handle_get_assertion(&assertion_with_id(id)).unwrap()[0],
            CTAP2_OK
        );
    }
    let replacement = register(&mut app, RP_ID, &[1], Some(true));
    assert_ne!(replacement, original);
    assert_eq!(
        app.handle_get_assertion(&assertion_with_id(&original)),
        Err(CTAP2_ERR_NO_CREDENTIALS)
    );
    assert_eq!(store.credentials().len(), 2);
}

#[test]
fn successful_replacement_rejects_old_ids_despite_cleanup_failure() {
    let store = TestStore::with_max_credentials(3);
    let (mut app, _) = app_with_store(store.clone(), [0x82; 16], [], &NEVER_INTERRUPTED);
    let original = register(&mut app, RP_ID, &[1], Some(true));
    let unrelated = register(&mut app, RP_ID, &[2], Some(true));
    store.faults(|faults| faults.delete = true);
    let replacement = register(&mut app, RP_ID, &[1], Some(true));
    assert_ne!(replacement, original);
    assert_eq!(store.credentials().len(), 2);
    assert_eq!(
        app.handle_get_assertion(&assertion_with_id(&original)),
        Err(CTAP2_ERR_NO_CREDENTIALS)
    );
    assert_eq!(
        app.handle_get_assertion(&assertion_with_id(&replacement))
            .unwrap()[0],
        CTAP2_OK
    );
    let (mut restarted, _) = app_with_store(store.clone(), [0x82; 16], [], &NEVER_INTERRUPTED);
    assert_eq!(
        restarted.handle_get_assertion(&assertion_with_id(&original)),
        Err(CTAP2_ERR_NO_CREDENTIALS)
    );
    store.faults(|faults| faults.delete = false);
    restarted.store.delete(&replacement).unwrap();
    assert_eq!(
        restarted.handle_get_assertion(&assertion_with_id(&original)),
        Err(CTAP2_ERR_NO_CREDENTIALS)
    );
    assert_eq!(
        restarted
            .handle_get_assertion(&assertion_with_id(&unrelated))
            .unwrap()[0],
        CTAP2_OK
    );
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

/// PIN settings and the retry counter survive a restart; the
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
            min_pin_length_rp_ids: Vec::new(),
            persistent_tokens: [None, None],
            ..PinStateRecord::default()
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

/// A new PIN is used only once it is stored.  If writing it fails, setPIN
/// and changePIN fail, and the PIN in force, in memory as on disk, is the one
/// there was before.
#[test]
fn a_new_pin_that_cannot_be_stored_is_not_used() {
    let store = TestStore::new();
    let (mut app, _) = app_with_store(store.clone(), [0x6D; 16], [], &NEVER_INTERRUPTED);

    store.faults(|faults| faults.set_pin_state = true);
    assert_eq!(
        set_pin_padded(&mut app, ClassicPinProtocol::V2, &padded_pin(PIN)),
        Err(CTAP2_ERR_PROCESSING)
    );
    assert!(!app.pin_state.is_set(), "no PIN after a failed setPIN");
    store.faults(|faults| faults.set_pin_state = false);
    set_pin_padded(&mut app, ClassicPinProtocol::V2, &padded_pin(PIN)).expect("setPIN");

    // changePIN writes the spent retry and, the current PIN being right, the
    // restored retries; the third write, of the new PIN, fails.
    store.faults(|faults| faults.set_pin_state_after = Some(2));
    assert_eq!(
        change_pin(&mut app, ClassicPinProtocol::V2, PIN, b"5678"),
        Err(CTAP2_ERR_PROCESSING)
    );
    store.faults(|faults| faults.set_pin_state_after = None);
    assert_eq!(
        store.pin_state().unwrap().and_then(|state| state.pin_hash),
        Some(pin_hash(PIN))
    );
    assert_eq!(get_pin_retries(&mut app), (MAX_PIN_RETRIES, None));
    get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).expect("the old PIN is still the PIN");
    assert_eq!(
        get_pin_token(&mut app, ClassicPinProtocol::V2, b"5678"),
        Err(CTAP2_ERR_PIN_INVALID)
    );
}

/// An unreadable PIN state fails closed: set, blocked, never overwritten,
/// and recoverable only by a reset.
#[test]
fn unreadable_pin_state_is_treated_as_set_and_blocked_until_reset() {
    let store = TestStore::new();
    store.faults(|faults| faults.pin_state = true);
    let (mut app, _) = app_with_store(store.clone(), [0x6B; 16], [], &NEVER_INTERRUPTED);

    assert!(app.pin_state.is_set(), "never acts as if no PIN is set");
    assert_eq!(app.save_persistent_pin_state(), Err(CTAP2_ERR_PROCESSING));
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

/// getInfo's clientPin and alwaysUv options.
fn pin_options(app: &mut TestApp) -> (bool, bool) {
    let response = app.handle_get_info().expect("getInfo succeeds");
    let Value::Map(info) = from_reader(&response[1..]).expect("decode getInfo") else {
        panic!("getInfo must be a map");
    };
    let Some((_, Value::Map(options))) = info
        .into_iter()
        .find(|(key, _)| *key == Value::Integer(Integer::from(4)))
    else {
        panic!("getInfo has options");
    };
    let option = |name: &str| {
        options
            .iter()
            .find_map(|(key, value)| match value {
                Value::Bool(set) if *key == Value::Text(name.into()) => Some(*set),
                _ => None,
            })
            .expect("the option is present")
    };
    (option("clientPin"), option("alwaysUv"))
}

/// Whether `token`, from getPinToken, still authorizes a registration with
/// user verification.
fn token_authorizes(app: &mut TestApp, token: &[u8; 32]) -> bool {
    let hash = [0x45; 32];
    let pin_uv_auth_param = token_pin_auth(ClassicPinProtocol::V2, token, &hash);
    let request = make_credential_request(
        &hash,
        RP_ID,
        Some((ClassicPinProtocol::V2, pin_uv_auth_param)),
    );
    app.handle_make_credential(&request)
        .is_ok_and(|response| response_auth_data(&response)[32] & FLAG_UV != 0)
}

/// Set `PIN`, take a token, then spend a retry on a wrong PIN, which leaves
/// the token in use.  Returns the token.
fn pin_with_token_and_spent_retry(app: &mut TestApp) -> [u8; 32] {
    set_pin_padded(app, ClassicPinProtocol::V2, &padded_pin(PIN)).expect("setPIN");
    let token = get_pin_token(app, ClassicPinProtocol::V2, PIN).expect("correct PIN");
    assert_eq!(
        get_pin_token(app, ClassicPinProtocol::V2, b"0000"),
        Err(CTAP2_ERR_PIN_INVALID)
    );
    token
}

/// A read of the backing storage that failed.
fn io_error() -> StoreError {
    StoreError::Io {
        path: "pin-state".into(),
        source: std::io::Error::other("injected failure"),
    }
}

/// One error of every other kind.
fn closing_errors() -> [StoreError; 6] {
    [
        StoreError::Corrupt {
            object: "pin-state".into(),
            reason: Corruption::Authentication,
        },
        StoreError::KeyUnavailable {
            domain: KeyDomain::Credential,
            detail: "injected failure".into(),
        },
        StoreError::CredentialSetUnavailable {
            object: "credential-set".into(),
            detail: "injected failure".into(),
        },
        StoreError::Full { max: 1 },
        StoreError::InvalidRecord("injected failure"),
        StoreError::Random,
    ]
}

/// An I/O error while the engine rereads its PIN state, during getInfo or a
/// token request, fails only that command: getInfo answers from the live
/// state, and the token request is refused before a retry is spent.  Issued
/// tokens keep working, and the next command reads the store again, rather
/// than finding a PIN blocked until a restart.
#[test]
fn an_io_error_rereading_the_pin_state_fails_only_that_command() {
    for during_token_request in [false, true] {
        let store = TestStore::new();
        let (mut app, _) = app_with_store(store.clone(), [0x6E; 16], [], &NEVER_INTERRUPTED);
        let token = pin_with_token_and_spent_retry(&mut app);
        let writes = store.pin_state_writes().len();

        store.faults(|faults| faults.pin_state_errors.push_back(io_error()));
        if during_token_request {
            assert_eq!(
                get_pin_token(&mut app, ClassicPinProtocol::V2, PIN),
                Err(CTAP2_ERR_PROCESSING)
            );
        } else {
            assert_eq!(pin_options(&mut app), (true, false), "the live state");
        }
        store.faults(|faults| assert!(faults.pin_state_errors.is_empty(), "the read failed"));
        assert_eq!(store.pin_state_writes().len(), writes, "no retry was spent");

        assert!(token_authorizes(&mut app, &token));
        assert_eq!(pin_options(&mut app), (true, false));
        assert_eq!(get_pin_retries(&mut app).0, MAX_PIN_RETRIES - 1);
        assert_eq!(
            store.pin_state().unwrap().map(|state| state.pin_retries),
            Some(MAX_PIN_RETRIES - 1),
            "the count reported is the stored one"
        );
        get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).expect("correct PIN");
    }
}

/// Every other error rereading the PIN state still fails closed, until reset:
/// the PIN is set and blocked, alwaysUv is on and issued tokens stop working,
/// even once the record reads again, and nothing is written over it.  A
/// restart reads the record again.
#[test]
fn any_other_error_rereading_the_pin_state_still_fails_closed() {
    for err in closing_errors() {
        let name = err.to_string();
        let store = TestStore::new();
        let (mut app, _) = app_with_store(store.clone(), [0x6F; 16], [], &NEVER_INTERRUPTED);
        let token = pin_with_token_and_spent_retry(&mut app);
        let writes = store.pin_state_writes().len();

        store.faults(|faults| faults.pin_state_errors.push_back(err));
        assert_eq!(pin_options(&mut app), (true, true), "{name}");
        assert!(!token_authorizes(&mut app, &token), "{name}");
        assert_eq!(get_pin_retries(&mut app).0, 0, "{name}");
        assert_eq!(
            get_pin_token(&mut app, ClassicPinProtocol::V2, PIN),
            Err(CTAP2_ERR_PIN_BLOCKED),
            "{name}"
        );
        assert_eq!(pin_options(&mut app), (true, true), "{name}");
        assert_eq!(store.pin_state_writes().len(), writes, "{name}");

        let mut restarted = new_app(store.clone(), [0x6F; 16]);
        assert_eq!(
            get_pin_retries(&mut restarted).0,
            MAX_PIN_RETRIES - 1,
            "{name}"
        );
        get_pin_token(&mut restarted, ClassicPinProtocol::V2, PIN).expect("correct PIN");
    }
}

/// An app over `store` whose reads of the PIN state fail with an I/O error at
/// start-up and then `more` times.
fn start_with_io_errors(store: &TestStore, more: usize) -> TestApp {
    store.faults(|faults| {
        faults
            .pin_state_errors
            .extend(std::iter::repeat_with(io_error).take(more + 1));
    });
    new_app(store.clone(), [0x71; 16])
}

/// An I/O error reading the PIN state at start-up does not block the PIN: the
/// next command that depends on the state reads it again, failing with
/// CTAP2_ERR_PROCESSING while the read keeps failing, then answers from the
/// stored state.
#[test]
fn an_io_error_reading_the_pin_state_at_start_up_is_retried_by_the_next_command() {
    for failing_again in [false, true] {
        let store = TestStore::new();
        pin_with_token_and_spent_retry(&mut new_app(store.clone(), [0x71; 16]));
        let writes = store.pin_state_writes().len();

        let mut app = start_with_io_errors(&store, usize::from(failing_again));
        if failing_again {
            assert_eq!(
                client_pin(&mut app, vec![(int(2), int(0x01))]),
                Err(CTAP2_ERR_PROCESSING),
                "getPINRetries while the read fails"
            );
        }
        store.faults(|faults| assert!(faults.pin_state_errors.is_empty(), "every read failed"));
        assert_eq!(
            store.pin_state_writes().len(),
            writes,
            "nothing was written"
        );

        assert_eq!(get_pin_retries(&mut app), (MAX_PIN_RETRIES - 1, None));
        get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).expect("correct PIN");
        assert_eq!(pin_options(&mut app), (true, false));
    }
}

/// Each command that answers from a PIN state start-up could not read reads
/// it first: a token request is not refused as blocked, a registration and an
/// assertion are not refused for want of user verification, and setPIN works
/// on a store that holds no PIN state.  While the read fails they fail with
/// CTAP2_ERR_PROCESSING, and getInfo answers from the closed state.
#[test]
fn every_command_that_depends_on_a_pin_state_unread_at_start_up_reads_it_first() {
    let store = TestStore::new();
    let mut app = new_app(store.clone(), [0x72; 16]);
    pin_with_token_and_spent_retry(&mut app);
    let id = register(&mut app, RP_ID, &[0x01], None);
    drop(app);
    let writes = store.pin_state_writes().len();

    let mut app = start_with_io_errors(&store, 1);
    assert_eq!(
        get_pin_token(&mut app, ClassicPinProtocol::V2, PIN),
        Err(CTAP2_ERR_PROCESSING)
    );
    get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).expect("correct PIN");

    let registration = make_credential_payload(RP_ID, &[0x02], None);
    let mut app = start_with_io_errors(&store, 1);
    assert_eq!(
        app.handle_make_credential(&registration),
        Err(CTAP2_ERR_PROCESSING)
    );
    app.handle_make_credential(&registration)
        .expect("no user verification required");

    let mut app = start_with_io_errors(&store, 1);
    assert_eq!(
        app.handle_get_assertion(&assertion_with_id(&id)),
        Err(CTAP2_ERR_PROCESSING)
    );
    app.handle_get_assertion(&assertion_with_id(&id))
        .expect("no user verification required");

    let mut app = start_with_io_errors(&store, 1);
    assert_eq!(pin_options(&mut app), (true, true), "the closed state");
    assert_eq!(pin_options(&mut app), (true, false));
    assert_eq!(
        store.pin_state_writes().len(),
        writes + 2,
        "only the token request's debit and restoration"
    );

    let fresh = TestStore::new();
    let mut app = start_with_io_errors(&fresh, 1);
    assert_eq!(
        set_pin_padded(&mut app, ClassicPinProtocol::V2, &padded_pin(PIN)),
        Err(CTAP2_ERR_PROCESSING)
    );
    assert_eq!(fresh.pin_state_writes(), []);
    set_pin_padded(&mut app, ClassicPinProtocol::V2, &padded_pin(PIN)).expect("no PIN was set");
    assert_eq!(get_pin_retries(&mut app), (MAX_PIN_RETRIES, None));
}

/// Any other error reading the PIN state at start-up still fails closed until
/// reset, although the record reads again afterwards: the PIN is set and
/// blocked, user verification is required, and nothing is written.  A restart
/// reads the record again.
#[test]
fn any_other_error_reading_the_pin_state_at_start_up_still_fails_closed() {
    for err in closing_errors() {
        let name = err.to_string();
        let store = TestStore::new();
        pin_with_token_and_spent_retry(&mut new_app(store.clone(), [0x73; 16]));
        let writes = store.pin_state_writes().len();

        store.faults(|faults| faults.pin_state_errors.push_back(err));
        let mut app = new_app(store.clone(), [0x73; 16]);
        store.faults(|faults| assert!(faults.pin_state_errors.is_empty(), "{name}"));
        assert_eq!(pin_options(&mut app), (true, true), "{name}");
        assert_eq!(get_pin_retries(&mut app).0, 0, "{name}");
        assert_eq!(
            get_pin_token(&mut app, ClassicPinProtocol::V2, PIN),
            Err(CTAP2_ERR_PIN_BLOCKED),
            "{name}"
        );
        assert_eq!(
            app.handle_make_credential(&make_credential_payload(RP_ID, &[0x02], None)),
            Err(CTAP2_ERR_PUAT_REQUIRED),
            "{name}"
        );
        assert_eq!(store.pin_state_writes().len(), writes, "{name}");

        let mut restarted = new_app(store.clone(), [0x73; 16]);
        assert_eq!(
            get_pin_retries(&mut restarted).0,
            MAX_PIN_RETRIES - 1,
            "{name}"
        );
        get_pin_token(&mut restarted, ClassicPinProtocol::V2, PIN).expect("correct PIN");
    }
}

/// The same over the real store, as the daemon starts it: a `pin-state` that
/// cannot be read while the engine is built (a directory in its place) is read
/// by the next command once it is back.
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "the test moves the PIN state aside and back directly, outside the store's wrappers"
)]
fn over_a_file_store_a_pin_state_unreadable_at_start_up_is_read_by_the_next_command() {
    let dir = TempDir::new();
    let state = dir.path().join("state");
    let open = || {
        CtapApp::with_file_store(
            FileStore::open(&state).unwrap(),
            AutoApprove,
            &NEVER_INTERRUPTED,
            [0x74; 16],
        )
    };
    pin_with_token_and_spent_retry(&mut open());

    let pin_state = state.join("pin-state");
    let aside = dir.path().join("pin-state");
    fs::rename(&pin_state, &aside).unwrap();
    fs::create_dir(&pin_state).unwrap();
    let mut app = open();
    assert!(matches!(app.store.pin_state(), Err(StoreError::Io { .. })));
    fs::remove_dir(&pin_state).unwrap();
    fs::rename(&aside, &pin_state).unwrap();
    assert_eq!(get_pin_retries(&mut app).0, MAX_PIN_RETRIES - 1);
    get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).expect("correct PIN");
}

/// A PIN state unread at start-up that then reads as damaged, or fails with
/// any other error that closes authority, fails closed until reset as a
/// start-up read of it would have: the command that read it fails, and the
/// engine stays closed although the record reads again afterwards.  A restart
/// reads the record again.
#[test]
fn a_pin_state_unread_at_start_up_that_then_reads_as_damaged_fails_closed() {
    for err in closing_errors() {
        let name = err.to_string();
        let store = TestStore::new();
        pin_with_token_and_spent_retry(&mut new_app(store.clone(), [0x75; 16]));
        let writes = store.pin_state_writes().len();

        store.faults(|faults| {
            faults.pin_state_errors.push_back(io_error());
            faults.pin_state_errors.push_back(err);
        });
        let mut app = new_app(store.clone(), [0x75; 16]);
        assert_eq!(
            client_pin(&mut app, vec![(int(2), int(0x01))]),
            Err(CTAP2_ERR_PROCESSING),
            "{name}: getPINRetries reads the damage"
        );
        store.faults(|faults| assert!(faults.pin_state_errors.is_empty(), "{name}"));
        assert_eq!(get_pin_retries(&mut app).0, 0, "{name}");
        assert_eq!(
            get_pin_token(&mut app, ClassicPinProtocol::V2, PIN),
            Err(CTAP2_ERR_PIN_BLOCKED),
            "{name}"
        );
        assert_eq!(pin_options(&mut app), (true, true), "{name}");
        assert_eq!(
            app.handle_make_credential(&make_credential_payload(RP_ID, &[0x02], None)),
            Err(CTAP2_ERR_PUAT_REQUIRED),
            "{name}"
        );
        assert_eq!(store.pin_state_writes().len(), writes, "{name}");

        let mut restarted = new_app(store.clone(), [0x75; 16]);
        assert_eq!(
            get_pin_retries(&mut restarted).0,
            MAX_PIN_RETRIES - 1,
            "{name}"
        );
        get_pin_token(&mut restarted, ClassicPinProtocol::V2, PIN).expect("correct PIN");
    }
}

/// A key source whose rotation publishes the new key and then fails, as a
/// reset can fail after publishing, and whose next load then fails with an
/// I/O error.
struct RotationFailsAfterPublishing {
    keys: FileKeySource,
    fail_next_load: AtomicBool,
}

impl KeySource for RotationFailsAfterPublishing {
    fn load(&self, domain: KeyDomain) -> Result<Option<RootKey>, StoreError> {
        if self.fail_next_load.swap(false, Ordering::SeqCst) {
            return Err(io_error());
        }
        self.keys.load(domain)
    }

    fn create(&self, domain: KeyDomain) -> Result<RootKey, StoreError> {
        self.keys.create(domain)
    }

    fn rotate(&self, domain: KeyDomain) -> Result<RootKey, StoreError> {
        self.keys.rotate(domain)?;
        self.fail_next_load.store(true, Ordering::SeqCst);
        Err(io_error())
    }
}

/// A reset that fails after publishing a new key, and whose read to reconcile
/// the engine with the store then fails with an I/O error, does not leave the
/// old authority in force: the engine closes it until the next read, as at
/// start-up.  The token issued before the reset no longer authorizes a
/// large-blob write or a registration, and U2F is refused under the closed
/// state's always-UV.
#[test]
fn an_io_error_reconciling_a_failed_reset_closes_authority() {
    let dir = TempDir::new();
    let state = dir.path().join("state");
    let keys = RotationFailsAfterPublishing {
        keys: FileKeySource::new(state.join("keys")),
        fail_next_load: AtomicBool::new(false),
    };
    let mut app = CtapApp::new(
        FileStore::open_with_key_source(&state, keys).unwrap(),
        TestRng::new(0x76),
        AutoApprove,
        &NEVER_INTERRUPTED,
        [0x76; 16],
    );
    app.set_reset_window(None);
    set_pin_padded(&mut app, ClassicPinProtocol::V2, &padded_pin(PIN)).expect("setPIN");
    let permissions = PIN_PERMISSION_MC | PIN_PERMISSION_LBW;
    let token = get_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        PIN,
        permissions.into(),
        Some(RP_ID),
    )
    .expect("correct PIN");

    assert_eq!(app.handle_reset(), Err(CTAP2_ERR_PROCESSING));
    assert!(
        matches!(app.store.pin_state(), Err(StoreError::Corrupt { .. })),
        "the new key is published, so the old PIN state no longer authenticates"
    );
    let blob = INITIAL_LARGE_BLOB_ARRAY;
    assert_eq!(
        app.call(&write_request(
            0,
            Some(blob.len()),
            &blob,
            Some((ClassicPinProtocol::V2, &token))
        )),
        [CTAP2_ERR_PIN_AUTH_INVALID]
    );
    let registration = app.call_u2f(&register_request());
    assert_eq!(
        registration[registration.len() - 2..],
        SW_COMMAND_NOT_ALLOWED.to_be_bytes()
    );
    let hash = [0x45; 32];
    let pin_uv_auth_param = token_pin_auth(ClassicPinProtocol::V2, &token, &hash);
    assert_eq!(
        app.handle_make_credential(&make_credential_request(
            &hash,
            RP_ID,
            Some((ClassicPinProtocol::V2, pin_uv_auth_param)),
        )),
        Err(CTAP2_ERR_PROCESSING),
        "it reads the PIN state first, and finds it damaged"
    );
    assert_eq!(get_pin_retries(&mut app).0, 0);
}

/// The same when the failed reset had published the default state: the token
/// issued before it does not register with user verification.
#[test]
fn an_io_error_reconciling_a_reset_that_published_defaults_drops_the_old_token() {
    let store = TestStore::new();
    let (mut app, _) = app_with_store(store.clone(), [0x77; 16], [], &NEVER_INTERRUPTED);
    set_pin_padded(&mut app, ClassicPinProtocol::V2, &padded_pin(PIN)).expect("setPIN");
    let token = get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).expect("correct PIN");

    store.faults(|faults| {
        faults.clear_after_publishing = true;
        faults.pin_state_errors.push_back(io_error());
    });
    assert_eq!(app.handle_reset(), Err(CTAP2_ERR_PROCESSING));
    store.faults(|faults| assert!(faults.pin_state_errors.is_empty(), "the read failed"));
    assert!(!token_authorizes(&mut app, &token));
    assert_eq!(
        pin_options(&mut app),
        (false, false),
        "the published defaults"
    );
}

/// The same over the real store: `keys/credential.key` unreadable during one
/// getInfo (a directory in its place, which fails to read even as root) costs
/// nothing, while a `pin-state` that fails authentication still fails closed,
/// even once it is put back.
#[test]
#[expect(
    clippy::disallowed_methods,
    reason = "the test moves the key file aside and back directly, outside the store's wrappers"
)]
fn over_a_file_store_an_unreadable_key_fails_one_command_but_damage_fails_closed() {
    let dir = TempDir::new();
    let state = dir.path().join("state");
    let open = || {
        CtapApp::with_file_store(
            FileStore::open(&state).unwrap(),
            AutoApprove,
            &NEVER_INTERRUPTED,
            [0x70; 16],
        )
    };
    let mut app = open();
    let token = pin_with_token_and_spent_retry(&mut app);

    let key = FileStore::open(&state)
        .unwrap()
        .key_source()
        .key_path(KeyDomain::Credential);
    let aside = dir.path().join("credential.key");
    fs::rename(&key, &aside).unwrap();
    fs::create_dir(&key).unwrap();
    assert!(matches!(app.store.pin_state(), Err(StoreError::Io { .. })));
    assert_eq!(pin_options(&mut app), (true, false), "the live state");
    fs::remove_dir(&key).unwrap();
    fs::rename(&aside, &key).unwrap();
    assert!(token_authorizes(&mut app, &token));
    assert_eq!(get_pin_retries(&mut app).0, MAX_PIN_RETRIES - 1);
    get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).expect("correct PIN");

    let pin_state = state.join("pin-state");
    let intact = fs::read(&pin_state).unwrap();
    let mut damaged = intact.clone();
    *damaged.last_mut().unwrap() ^= 0x01;
    fs::write(&pin_state, &damaged).unwrap();
    assert!(matches!(
        app.store.pin_state(),
        Err(StoreError::Corrupt { .. })
    ));
    assert_eq!(pin_options(&mut app), (true, true));
    fs::write(&pin_state, &intact).unwrap();
    assert_eq!(get_pin_retries(&mut app).0, 0);
    assert_eq!(
        get_pin_token(&mut app, ClassicPinProtocol::V2, PIN),
        Err(CTAP2_ERR_PIN_BLOCKED)
    );
    assert_eq!(fs::read(&pin_state).unwrap(), intact, "nothing written");

    drop(app);
    let mut restarted = open();
    assert_eq!(get_pin_retries(&mut restarted).0, MAX_PIN_RETRIES);
    get_pin_token(&mut restarted, ClassicPinProtocol::V2, PIN).expect("correct PIN");
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
        Value::Integer(Integer::from(CoseAlg::ES256.identifier()))
    )));
}
