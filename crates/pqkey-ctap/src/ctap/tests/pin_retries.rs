//! The PIN retry state machine (CTAP 2.3 §6.5.2.3) on its own, and as
//! authenticatorClientPIN drives and persists it.

use super::support::new_app;
use super::support::TestApp;
use super::support::{
    client_pin, get_pin_retries, get_pin_token, int, padded_pin, pin_hash, PlatformPinSession,
    TestStore,
};
use crate::ctap::pin::state::{
    PersistentPinState, PinRetryState, MAX_CONSECUTIVE_PIN_MISMATCHES, MAX_PIN_RETRIES,
};
use crate::ClassicPinProtocol;

use crate::store::{CredentialStore, PinStateRecord};
use ciborium::value::Value;

use crate::ctap::constants::*;

const PIN: &[u8] = b"1234";
const WRONG: [u8; 16] = [0x5A; 16];

fn state_with_pin() -> PinRetryState {
    let mut state = PinRetryState::default();
    state.set_pin(pin_hash(PIN));
    state
}

fn state_with_retries(pin_retries: u8) -> PinRetryState {
    PinRetryState::power_up(PersistentPinState {
        pin_hash: Some(pin_hash(PIN)),
        pin_retries,
    })
}

/// One complete check of `candidate` (`None`: pinHashEnc did not decrypt).
fn attempt(state: &mut PinRetryState, candidate: Option<&[u8]>) -> Result<(), u8> {
    let attempt = state.begin_attempt()?;
    state.finish_attempt(attempt, candidate)
}

fn power_cycle(state: &PinRetryState) -> PinRetryState {
    PinRetryState::power_up(state.persistent().clone())
}

// -- The state machine ----------------------------------------------------------

#[test]
fn a_new_state_has_no_pin_and_the_maximum_retries() {
    let mut state = PinRetryState::default();
    assert!(!state.is_set());
    assert_eq!(state.retries(), MAX_PIN_RETRIES);
    assert!(!state.power_cycle_required());
    assert_eq!(state.check_attempt_allowed(), Err(CTAP2_ERR_PIN_NOT_SET));
    assert!(matches!(state.begin_attempt(), Err(CTAP2_ERR_PIN_NOT_SET)));
    assert_eq!(state.retries(), MAX_PIN_RETRIES);
}

#[test]
fn the_maximum_is_eight_retries_and_three_consecutive_mismatches() {
    assert_eq!(MAX_PIN_RETRIES, 8);
    assert_eq!(MAX_CONSECUTIVE_PIN_MISMATCHES, 3);
}

#[test]
fn the_correct_pin_resets_retries_and_the_mismatch_count() {
    let mut state = state_with_pin();
    assert_eq!(
        attempt(&mut state, Some(&WRONG)),
        Err(CTAP2_ERR_PIN_INVALID)
    );
    assert_eq!(
        attempt(&mut state, Some(&WRONG)),
        Err(CTAP2_ERR_PIN_INVALID)
    );
    assert_eq!(state.retries(), MAX_PIN_RETRIES - 2);

    assert_eq!(attempt(&mut state, Some(&pin_hash(PIN))), Ok(()));
    assert_eq!(state.retries(), MAX_PIN_RETRIES);

    // Two more mismatches are not "3 consecutive mismatches".
    assert_eq!(
        attempt(&mut state, Some(&WRONG)),
        Err(CTAP2_ERR_PIN_INVALID)
    );
    assert_eq!(
        attempt(&mut state, Some(&WRONG)),
        Err(CTAP2_ERR_PIN_INVALID)
    );
    assert!(!state.power_cycle_required());
}

#[test]
fn setting_a_pin_resets_retries_and_the_mismatch_count() {
    let mut state = state_with_retries(5);
    assert_eq!(
        attempt(&mut state, Some(&WRONG)),
        Err(CTAP2_ERR_PIN_INVALID)
    );
    assert_eq!(
        attempt(&mut state, Some(&WRONG)),
        Err(CTAP2_ERR_PIN_INVALID)
    );

    state.set_pin(pin_hash(b"5678"));
    assert_eq!(state.persistent().pin_hash, Some(pin_hash(b"5678")));
    assert_eq!(state.retries(), MAX_PIN_RETRIES);
    assert_eq!(
        attempt(&mut state, Some(&WRONG)),
        Err(CTAP2_ERR_PIN_INVALID)
    );
    assert!(!state.power_cycle_required());
}

#[test]
fn a_retry_is_consumed_before_the_pin_is_compared() {
    let mut state = state_with_pin();
    let pending = state.begin_attempt().expect("attempt allowed");
    // This is what the caller persists before comparing, correct PIN or not.
    let persisted = state.persistent().clone();
    assert_eq!(persisted.pin_retries, MAX_PIN_RETRIES - 1);

    // Power is cut before the comparison finishes: the retry stays spent.
    let restarted = PinRetryState::power_up(persisted);
    assert_eq!(restarted.retries(), MAX_PIN_RETRIES - 1);

    // Had the comparison finished, the correct PIN would restore the maximum.
    assert_eq!(state.finish_attempt(pending, Some(&pin_hash(PIN))), Ok(()));
    assert_eq!(state.retries(), MAX_PIN_RETRIES);
}

#[test]
fn an_error_or_a_mismatch_costs_exactly_one_retry() {
    let correct = pin_hash(PIN);
    let mut too_long = correct.to_vec();
    too_long.push(0x00);
    let candidates: [Option<&[u8]>; 4] =
        [None, Some(&correct[..15]), Some(&too_long), Some(&WRONG)];
    let mut state = state_with_pin();
    for candidate in candidates {
        state = power_cycle(&state);
        let before = state.retries();
        assert_eq!(
            attempt(&mut state, candidate),
            Err(CTAP2_ERR_PIN_INVALID),
            "{candidate:?}"
        );
        assert_eq!(state.retries(), before - 1, "{candidate:?}");
    }
}

#[test]
fn three_consecutive_mismatches_require_a_power_cycle() {
    let mut state = state_with_pin();
    assert_eq!(
        attempt(&mut state, Some(&WRONG)),
        Err(CTAP2_ERR_PIN_INVALID)
    );
    assert_eq!(
        attempt(&mut state, Some(&WRONG)),
        Err(CTAP2_ERR_PIN_INVALID)
    );
    assert_eq!(
        attempt(&mut state, Some(&WRONG)),
        Err(CTAP2_ERR_PIN_AUTH_BLOCKED)
    );
    assert!(state.power_cycle_required());
    assert_eq!(state.retries(), MAX_PIN_RETRIES - 3);

    // Not even the correct PIN gets compared, and no retry is spent.
    assert_eq!(
        state.check_attempt_allowed(),
        Err(CTAP2_ERR_PIN_AUTH_BLOCKED)
    );
    assert_eq!(
        attempt(&mut state, Some(&pin_hash(PIN))),
        Err(CTAP2_ERR_PIN_AUTH_BLOCKED)
    );
    assert_eq!(state.retries(), MAX_PIN_RETRIES - 3);
}

#[test]
fn a_power_cycle_clears_the_lockout_but_not_the_retries() {
    let mut state = state_with_pin();
    for _ in 0..MAX_CONSECUTIVE_PIN_MISMATCHES {
        let _ = attempt(&mut state, Some(&WRONG));
    }
    assert!(state.power_cycle_required());

    let mut restarted = power_cycle(&state);
    assert!(!restarted.power_cycle_required());
    assert_eq!(restarted.retries(), MAX_PIN_RETRIES - 3);
    assert_eq!(attempt(&mut restarted, Some(&pin_hash(PIN))), Ok(()));
    assert_eq!(restarted.retries(), MAX_PIN_RETRIES);
}

#[test]
fn exhausted_retries_block_even_the_correct_pin_until_reset() {
    let mut state = state_with_pin();
    let mut results = Vec::new();
    for _ in 0..MAX_PIN_RETRIES {
        if state.power_cycle_required() {
            state = power_cycle(&state);
        }
        results.push(attempt(&mut state, Some(&WRONG)));
    }
    assert_eq!(
        results,
        [
            Err(CTAP2_ERR_PIN_INVALID),
            Err(CTAP2_ERR_PIN_INVALID),
            Err(CTAP2_ERR_PIN_AUTH_BLOCKED),
            Err(CTAP2_ERR_PIN_INVALID),
            Err(CTAP2_ERR_PIN_INVALID),
            Err(CTAP2_ERR_PIN_AUTH_BLOCKED),
            Err(CTAP2_ERR_PIN_INVALID),
            Err(CTAP2_ERR_PIN_BLOCKED),
        ]
    );
    assert_eq!(state.retries(), 0);

    for mut state in [power_cycle(&state), state] {
        assert!(!state.power_cycle_required());
        assert_eq!(state.check_attempt_allowed(), Err(CTAP2_ERR_PIN_BLOCKED));
        assert_eq!(
            attempt(&mut state, Some(&pin_hash(PIN))),
            Err(CTAP2_ERR_PIN_BLOCKED)
        );
        assert_eq!(state.retries(), 0);
    }

    // authenticatorReset starts over from a fresh state.
    let mut reset = PinRetryState::default();
    reset.set_pin(pin_hash(PIN));
    assert_eq!(attempt(&mut reset, Some(&pin_hash(PIN))), Ok(()));
}

#[test]
fn a_mismatch_on_the_last_retry_is_pin_blocked_rather_than_auth_blocked() {
    let mut state = state_with_retries(3);
    assert_eq!(
        attempt(&mut state, Some(&WRONG)),
        Err(CTAP2_ERR_PIN_INVALID)
    );
    assert_eq!(
        attempt(&mut state, Some(&WRONG)),
        Err(CTAP2_ERR_PIN_INVALID)
    );
    // Third consecutive mismatch and the last retry: PIN_BLOCKED wins.
    assert_eq!(
        attempt(&mut state, Some(&WRONG)),
        Err(CTAP2_ERR_PIN_BLOCKED)
    );
    assert_eq!(state.retries(), 0);
}

#[test]
fn the_correct_pin_on_the_last_retry_succeeds() {
    let mut state = state_with_retries(1);
    assert_eq!(attempt(&mut state, Some(&pin_hash(PIN))), Ok(()));
    assert_eq!(state.retries(), MAX_PIN_RETRIES);
}

#[test]
fn power_up_clamps_stored_retries_to_the_maximum() {
    for stored in [MAX_PIN_RETRIES, MAX_PIN_RETRIES + 1, u8::MAX] {
        assert_eq!(state_with_retries(stored).retries(), MAX_PIN_RETRIES);
    }
    assert_eq!(
        state_with_retries(0).check_attempt_allowed(),
        Err(CTAP2_ERR_PIN_BLOCKED)
    );
}

// -- clientPIN and persistence ----------------------------------------------------

/// An authenticator whose PIN is `PIN`, set through setPIN.
/// The store is returned too, to inspect what was persisted and to restart on.
fn app_with_pin() -> (TestApp, TestStore) {
    let store = TestStore::new();
    let mut app = new_app(store.clone(), [0x70; 16]);
    let session = PlatformPinSession::establish(&mut app, ClassicPinProtocol::V2, 0x31);
    let new_pin_enc = session.encrypt(&padded_pin(PIN));
    let pin_uv_auth_param =
        super::support::classic_pin_auth(ClassicPinProtocol::V2, &session.keys, &new_pin_enc);
    let response = client_pin(
        &mut app,
        vec![
            (int(1), int(2)),
            (int(2), int(0x03)),
            (int(3), session.key_agreement.clone()),
            (int(4), Value::Bytes(pin_uv_auth_param)),
            (int(5), Value::Bytes(new_pin_enc)),
        ],
    );
    assert_eq!(response, Ok(vec![CTAP2_OK]));
    (app, store)
}

/// Stop the daemon and start it again on the same storage.
fn restart(app: TestApp, store: &TestStore) -> TestApp {
    let aaguid = app.aaguid;
    drop(app);
    new_app(store.clone(), aaguid)
}

#[test]
fn get_pin_token_persists_the_spent_retry_before_comparing() {
    let (mut app, store) = app_with_pin();
    let before = store.pin_state_writes().len();

    get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).expect("correct PIN");
    let writes = &store.pin_state_writes()[before..];
    let retries: Vec<u8> = writes.iter().map(|file| file.pin_retries).collect();
    // The decrement is on disk before the (successful) comparison's reset.
    assert_eq!(retries, [MAX_PIN_RETRIES - 1, MAX_PIN_RETRIES]);

    let before = store.pin_state_writes().len();
    assert_eq!(
        get_pin_token(&mut app, ClassicPinProtocol::V2, b"9999"),
        Err(CTAP2_ERR_PIN_INVALID)
    );
    let writes = &store.pin_state_writes()[before..];
    assert_eq!(writes[0].pin_retries, MAX_PIN_RETRIES - 1);
    assert_eq!(
        writes.last().map(|file| file.pin_retries),
        Some(MAX_PIN_RETRIES - 1)
    );
}

#[test]
fn change_pin_persists_the_spent_retry_before_comparing() {
    let (mut app, store) = app_with_pin();
    let before = store.pin_state_writes().len();

    let session = PlatformPinSession::establish(&mut app, ClassicPinProtocol::V1, 0x32);
    let new_pin_enc = session.encrypt(&padded_pin(b"5678"));
    let pin_hash_enc = session.encrypt(&pin_hash(PIN));
    let mut message = new_pin_enc.clone();
    message.extend_from_slice(&pin_hash_enc);
    let pin_uv_auth_param =
        super::support::classic_pin_auth(ClassicPinProtocol::V1, &session.keys, &message);
    let response = client_pin(
        &mut app,
        vec![
            (int(1), int(1)),
            (int(2), int(0x04)),
            (int(3), session.key_agreement.clone()),
            (int(4), Value::Bytes(pin_uv_auth_param)),
            (int(5), Value::Bytes(new_pin_enc)),
            (int(6), Value::Bytes(pin_hash_enc)),
        ],
    );
    assert_eq!(response, Ok(vec![CTAP2_OK]));

    let writes = &store.pin_state_writes()[before..];
    assert_eq!(writes[0].pin_retries, MAX_PIN_RETRIES - 1);
    assert_eq!(writes[0].pin_hash, Some(pin_hash(PIN)));
    let last = writes.last().expect("new PIN persisted");
    assert_eq!(last.pin_retries, MAX_PIN_RETRIES);
    assert_eq!(last.pin_hash, Some(pin_hash(b"5678")));
}

#[test]
fn restart_clears_the_power_cycle_lockout_but_keeps_retries() {
    let (mut app, store) = app_with_pin();
    let results: Vec<_> = (0..MAX_CONSECUTIVE_PIN_MISMATCHES)
        .map(|_| get_pin_token(&mut app, ClassicPinProtocol::V2, b"0000").map(|_| ()))
        .collect();
    assert_eq!(
        results,
        [
            Err(CTAP2_ERR_PIN_INVALID),
            Err(CTAP2_ERR_PIN_INVALID),
            Err(CTAP2_ERR_PIN_AUTH_BLOCKED),
        ]
    );
    assert_eq!(
        get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).map(|_| ()),
        Err(CTAP2_ERR_PIN_AUTH_BLOCKED)
    );
    assert_eq!(get_pin_retries(&mut app), (MAX_PIN_RETRIES - 3, Some(true)));

    // The lockout is not written to storage.
    let file = store.pin_state_writes().pop().expect("PIN state persisted");
    assert_eq!(
        file,
        PinStateRecord {
            pin_hash: Some(pin_hash(PIN)),
            pin_retries: MAX_PIN_RETRIES - 3,
            consecutive_failures: 0,
            pin_auth_blocked: false,
        }
    );

    let mut app = restart(app, &store);
    assert_eq!(get_pin_retries(&mut app), (MAX_PIN_RETRIES - 3, None));
    get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).expect("correct PIN after restart");
    assert_eq!(get_pin_retries(&mut app), (MAX_PIN_RETRIES, None));
}

#[test]
fn restart_keeps_an_exhausted_pin_blocked() {
    let (mut app, store) = app_with_pin();
    let mut last = Ok(());
    for _ in 0..MAX_PIN_RETRIES {
        if get_pin_retries(&mut app).1 == Some(true) {
            app = restart(app, &store);
        }
        last = get_pin_token(&mut app, ClassicPinProtocol::V1, b"0000").map(|_| ());
    }
    assert_eq!(last, Err(CTAP2_ERR_PIN_BLOCKED));
    let file = store.pin_state_writes().pop().expect("PIN state persisted");
    assert_eq!(file.pin_retries, 0);
    // Only the PIN hash and pinRetries are persistent state.
    assert!(!file.pin_auth_blocked);
    assert_eq!(file.consecutive_failures, 0);

    let mut app = restart(app, &store);
    assert_eq!(get_pin_retries(&mut app), (0, None));
    assert_eq!(
        get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).map(|_| ()),
        Err(CTAP2_ERR_PIN_BLOCKED)
    );
    assert_eq!(get_pin_retries(&mut app), (0, None));
}

#[test]
fn start_up_ignores_a_stored_power_cycle_lockout() {
    // What an earlier daemon wrote after three wrong PINs.
    let mut store = TestStore::new();
    store
        .set_pin_state(&PinStateRecord {
            pin_hash: Some(pin_hash(PIN)),
            pin_retries: MAX_PIN_RETRIES - 3,
            consecutive_failures: 3,
            pin_auth_blocked: true,
        })
        .expect("store PIN state");

    let mut app = new_app(store, [0x71; 16]);
    assert!(app.pin_state.is_set());
    assert_eq!(get_pin_retries(&mut app), (MAX_PIN_RETRIES - 3, None));
    get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).expect("correct PIN");
    assert_eq!(get_pin_retries(&mut app), (MAX_PIN_RETRIES, None));
}
