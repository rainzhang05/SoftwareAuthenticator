//! authenticatorReset (CTAP 2.3 §6.6).

use super::support::{es256_credential, pin_hash, scripted_app, stored, PresenceLog, TestApp};
use crate::ctap::pin::token::ManualClock;
use crate::ctap::presence::PresenceOutcome;
use crate::ctap::RESET_WINDOW_AFTER_POWER_UP;

use core::time::Duration;

use crate::ctap::constants::*;

/// An app with a PIN and a credential, on a clock that starts at power-up.
fn powered_up_app(outcomes: Vec<PresenceOutcome>) -> (TestApp, PresenceLog, ManualClock) {
    let (mut app, log) = scripted_app([0x7A; 16], outcomes);
    let clock = ManualClock::default();
    app.pin_state.set_clock(Box::new(clock.clone()));
    app.pin_state.set_pin(pin_hash(b"1234"));
    app.store
        .put(&es256_credential("example.com", &[0x7A]))
        .expect("store credential");
    (app, log, clock)
}

#[test]
fn reset_within_10_seconds_of_power_up_succeeds() {
    let (mut app, log, clock) = powered_up_app(vec![]);
    clock.advance(RESET_WINDOW_AFTER_POWER_UP);
    assert_eq!(app.handle_reset(), Ok(vec![CTAP2_OK]));
    assert_eq!(log.take().len(), 3, "user presence was collected");
    assert!(stored(&app).is_empty());
    assert!(!app.pin_state.is_set());
}

/// "If the request comes after 10 seconds of powering up, the authenticator
/// returns CTAP2_ERR_NOT_ALLOWED."
#[test]
fn reset_later_than_10_seconds_after_power_up_is_not_allowed() {
    let (mut app, log, clock) = powered_up_app(vec![]);
    clock.advance(RESET_WINDOW_AFTER_POWER_UP + Duration::from_millis(1));
    assert_eq!(app.handle_reset(), Err(CTAP2_ERR_NOT_ALLOWED));
    assert!(log.take().is_empty(), "the user is not asked");
    assert_eq!(stored(&app).len(), 1);
    assert!(app.pin_state.is_set());
}

/// "If user presence is explicitly denied, the authenticator returns
/// CTAP2_ERR_OPERATION_DENIED. If a user action timeout occurs, the
/// authenticator returns CTAP2_ERR_USER_ACTION_TIMEOUT."
#[test]
fn reset_requires_user_presence() {
    for (outcome, status) in [
        (PresenceOutcome::Denied, CTAP2_ERR_OPERATION_DENIED),
        (PresenceOutcome::TimedOut, CTAP2_ERR_USER_ACTION_TIMEOUT),
    ] {
        let (mut app, _, _) = powered_up_app(vec![outcome]);
        assert_eq!(app.handle_reset(), Err(status), "{outcome:?}");
        assert_eq!(stored(&app).len(), 1);
    }
}

#[test]
fn a_test_rig_can_lift_the_power_up_window() {
    let (mut app, log, clock) = powered_up_app(vec![]);
    app.set_reset_window(None);
    clock.advance(Duration::from_secs(3600));
    assert_eq!(app.handle_reset(), Ok(vec![CTAP2_OK]));
    assert_eq!(log.take().len(), 3, "user presence is still collected");
}
