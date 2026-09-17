//! User-presence tests: what the engine asks for, how each outcome maps to a
//! CTAP status, keepalive signalling and cancellation.

use super::support::{
    scripted_app, scripted_app_with_interrupt, PresenceEvent, PresenceLog, SeenRequest, TestClient,
    NEVER_INTERRUPTED,
};
use crate::ctap::cbor::canonical_map;
use crate::ctap::presence::{
    presence_status, AutoApprove, Cancellation, PresenceOperation, PresenceOutcome,
    PresenceRequest, UserPresence, DEFAULT_PRESENCE_TIMEOUT,
};
use crate::ctap::{CtapApp, InterruptFlag};
use crate::CoseAlg;

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;

use crate::ctap::constants::*;

const RP_ID: &str = "example.com";

fn make_credential_payload() -> Vec<u8> {
    let rp = canonical_map(vec![(Value::Text("id".into()), Value::Text(RP_ID.into()))]);
    let user = canonical_map(vec![
        (Value::Text("id".into()), Value::Bytes(vec![0x01])),
        (Value::Text("name".into()), Value::Text("alice".into())),
        (
            Value::Text("displayName".into()),
            Value::Text("Alice".into()),
        ),
    ]);
    let params = Value::Array(vec![canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("alg".into()),
            Value::Integer(Integer::from(CoseAlg::ES256 as i32)),
        ),
    ])]);
    let request = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Bytes(vec![0x20; 32]),
        ),
        (Value::Integer(Integer::from(2)), rp),
        (Value::Integer(Integer::from(3)), user),
        (Value::Integer(Integer::from(4)), params),
    ]);
    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize makeCredential request");
    payload
}

fn get_assertion_payload() -> Vec<u8> {
    let request = canonical_map(vec![
        (Value::Integer(Integer::from(1)), Value::Text(RP_ID.into())),
        (
            Value::Integer(Integer::from(2)),
            Value::Bytes(vec![0x51; 32]),
        ),
    ]);
    let mut payload = Vec::new();
    into_writer(&request, &mut payload).expect("serialize getAssertion request");
    payload
}

/// The flags byte of the authenticator data in a successful response.
fn auth_data_flags(response: &[u8]) -> u8 {
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(entries) = from_reader(&response[1..]).expect("decode response map") else {
        panic!("response must be a map");
    };
    let auth_data = entries
        .iter()
        .find(|(k, _)| *k == Value::Integer(Integer::from(2)))
        .and_then(|(_, v)| match v {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        })
        .expect("authData present");
    auth_data[32]
}

/// The events of one presence request that ended without panicking.
fn asked(request: SeenRequest) -> Vec<PresenceEvent> {
    vec![
        PresenceEvent::Waiting(true),
        PresenceEvent::Asked(request),
        PresenceEvent::Waiting(false),
    ]
}

fn register_request() -> SeenRequest {
    SeenRequest {
        user_name: Some("alice".into()),
        user_display_name: Some("Alice".into()),
        ..SeenRequest::new(PresenceOperation::Register, Some(RP_ID))
    }
}

/// An app holding one credential for [`RP_ID`], with an empty presence log
/// and `outcomes` scripted for the requests that follow.
fn app_with_credential(
    outcomes: impl IntoIterator<Item = PresenceOutcome>,
) -> (CtapApp<TestClient>, PresenceLog) {
    let script: Vec<_> = std::iter::once(PresenceOutcome::Approved)
        .chain(outcomes)
        .collect();
    let (mut app, log) = scripted_app([0x24; 16], script);
    app.handle_make_credential(&make_credential_payload())
        .expect("makeCredential succeeds");
    log.take();
    (app, log)
}

#[test]
fn make_credential_asks_the_user_to_register() {
    let (mut app, log) = scripted_app([0x21; 16], [PresenceOutcome::Approved]);
    let response = app
        .handle_make_credential(&make_credential_payload())
        .expect("makeCredential succeeds");

    assert_eq!(log.take(), asked(register_request()));
    assert_eq!(auth_data_flags(&response) & 0x01, 0x01, "UP flag");
}

#[test]
fn make_credential_refused_or_timed_out_is_operation_denied() {
    for outcome in [PresenceOutcome::Denied, PresenceOutcome::TimedOut] {
        let (mut app, log) = scripted_app([0x22; 16], [outcome]);
        assert_eq!(
            app.handle_make_credential(&make_credential_payload()),
            Err(CTAP2_ERR_OPERATION_DENIED),
            "{outcome:?}"
        );
        assert!(app.stored_credentials.is_empty(), "{outcome:?}");
        assert_eq!(log.take(), asked(register_request()), "{outcome:?}");
    }
}

#[test]
fn make_credential_returns_keepalive_cancel_when_cancelled() {
    let (mut app, log) = scripted_app([0x23; 16], [PresenceOutcome::Cancelled]);
    assert_eq!(
        app.handle_make_credential(&make_credential_payload()),
        Err(CTAP2_ERR_KEEPALIVE_CANCEL)
    );
    assert!(app.stored_credentials.is_empty());
    assert_eq!(log.take(), asked(register_request()));
}

#[test]
fn make_credential_recovers_after_cancellation() {
    let (mut app, log) = scripted_app(
        [0x25; 16],
        [PresenceOutcome::Cancelled, PresenceOutcome::Approved],
    );
    let payload = make_credential_payload();
    assert_eq!(
        app.handle_make_credential(&payload),
        Err(CTAP2_ERR_KEEPALIVE_CANCEL)
    );
    assert_eq!(log.take(), asked(register_request()));

    let response = app
        .handle_make_credential(&payload)
        .expect("makeCredential succeeds after cancellation");
    assert_eq!(response[0], CTAP2_OK);
    assert_eq!(app.stored_credentials.len(), 1);
    assert_eq!(log.take(), asked(register_request()));
}

/// A request the platform cancelled before the engine got to ask for
/// presence must not be shown to the user at all.
#[test]
fn cancelled_request_is_not_shown_to_the_user() {
    static CANCELLED: InterruptFlag = InterruptFlag::new();
    CANCELLED.set_working();
    assert!(CANCELLED.interrupt());

    let (mut app, log) = scripted_app_with_interrupt([0x26; 16], [], &CANCELLED);
    assert_eq!(
        app.handle_make_credential(&make_credential_payload()),
        Err(CTAP2_ERR_KEEPALIVE_CANCEL)
    );
    assert_eq!(log.take(), []);
    assert!(app.stored_credentials.is_empty());
}

#[test]
fn get_assertion_asks_the_user_to_sign_in() {
    let (mut app, log) = app_with_credential([PresenceOutcome::Approved]);
    let response = app
        .handle_get_assertion(&get_assertion_payload())
        .expect("getAssertion succeeds");

    assert_eq!(
        log.take(),
        asked(SeenRequest::new(
            PresenceOperation::Authenticate,
            Some(RP_ID)
        ))
    );
    assert_eq!(auth_data_flags(&response) & 0x01, 0x01, "UP flag");
}

#[test]
fn get_assertion_refused_timed_out_or_cancelled_signs_nothing() {
    for (outcome, status) in [
        (PresenceOutcome::Denied, CTAP2_ERR_OPERATION_DENIED),
        (PresenceOutcome::TimedOut, CTAP2_ERR_OPERATION_DENIED),
        (PresenceOutcome::Cancelled, CTAP2_ERR_KEEPALIVE_CANCEL),
    ] {
        let (mut app, log) = app_with_credential([outcome]);
        assert_eq!(
            app.handle_get_assertion(&get_assertion_payload()),
            Err(status),
            "{outcome:?}"
        );
        assert_eq!(app.stored_credentials[0].sign_count, 0, "{outcome:?}");
        assert!(app.pending_assertion.is_none(), "{outcome:?}");
        assert_eq!(
            log.take(),
            asked(SeenRequest::new(
                PresenceOperation::Authenticate,
                Some(RP_ID)
            )),
            "{outcome:?}"
        );
    }
}

#[test]
fn reset_asks_the_user_and_erases_nothing_unless_approved() {
    for (outcome, status) in [
        (PresenceOutcome::Denied, CTAP2_ERR_OPERATION_DENIED),
        (PresenceOutcome::TimedOut, CTAP2_ERR_USER_ACTION_TIMEOUT),
        (PresenceOutcome::Cancelled, CTAP2_ERR_KEEPALIVE_CANCEL),
    ] {
        let (mut app, log) = app_with_credential([outcome]);
        assert_eq!(app.handle_reset(), Err(status), "{outcome:?}");
        assert_eq!(app.stored_credentials.len(), 1, "{outcome:?}");
        assert_eq!(
            log.take(),
            asked(SeenRequest::new(PresenceOperation::Reset, None)),
            "{outcome:?}"
        );
    }

    let (mut app, log) = app_with_credential([PresenceOutcome::Approved]);
    assert_eq!(app.handle_reset(), Ok(vec![CTAP2_OK]));
    assert!(app.stored_credentials.is_empty());
    assert_eq!(
        log.take(),
        asked(SeenRequest::new(PresenceOperation::Reset, None))
    );
}

#[test]
fn presence_timeout_is_passed_to_the_implementation() {
    let (mut app, log) = scripted_app([0x28; 16], []);
    app.set_presence_timeout(Duration::from_secs(45));
    app.handle_make_credential(&make_credential_payload())
        .expect("makeCredential succeeds");
    assert_eq!(
        log.take(),
        asked(SeenRequest {
            timeout: Duration::from_secs(45),
            ..register_request()
        })
    );
}

/// CTAP 2.3 §6.1.2 step 14.2.1.2 and §6.2.2 step 9.2.1.2 (declined or timed
/// out: OPERATION_DENIED), §6.6 (reset: denied is OPERATION_DENIED, a user
/// action timeout is USER_ACTION_TIMEOUT), §11.2.9.1.5 (cancelled:
/// KEEPALIVE_CANCEL).
#[test]
fn presence_outcomes_map_to_ctap_status_codes() {
    use PresenceOperation::*;
    use PresenceOutcome::*;

    let expected = [
        (Register, Denied, CTAP2_ERR_OPERATION_DENIED),
        (Register, TimedOut, CTAP2_ERR_OPERATION_DENIED),
        (Register, Cancelled, CTAP2_ERR_KEEPALIVE_CANCEL),
        (Authenticate, Denied, CTAP2_ERR_OPERATION_DENIED),
        (Authenticate, TimedOut, CTAP2_ERR_OPERATION_DENIED),
        (Authenticate, Cancelled, CTAP2_ERR_KEEPALIVE_CANCEL),
        (Reset, Denied, CTAP2_ERR_OPERATION_DENIED),
        (Reset, TimedOut, CTAP2_ERR_USER_ACTION_TIMEOUT),
        (Reset, Cancelled, CTAP2_ERR_KEEPALIVE_CANCEL),
        (CredentialManagement, Denied, CTAP2_ERR_OPERATION_DENIED),
        (
            CredentialManagement,
            TimedOut,
            CTAP2_ERR_USER_ACTION_TIMEOUT,
        ),
        (CredentialManagement, Cancelled, CTAP2_ERR_KEEPALIVE_CANCEL),
    ];
    for (operation, outcome, status) in expected {
        assert_eq!(
            presence_status(operation, outcome),
            Err(status),
            "{operation:?} {outcome:?}"
        );
    }
    for operation in [Register, Authenticate, Reset, CredentialManagement] {
        assert_eq!(
            presence_status(operation, Approved),
            Ok(()),
            "{operation:?}"
        );
    }
}

/// A presence implementation that fails while the user is being asked.
struct PanickingPresence;

impl UserPresence for PanickingPresence {
    fn confirm(
        &mut self,
        _request: &PresenceRequest<'_>,
        _cancellation: Cancellation<'_>,
    ) -> PresenceOutcome {
        panic!("presence implementation failed on purpose");
    }
}

#[test]
fn waiting_for_the_user_ends_even_if_the_presence_implementation_panics() {
    let mut app = CtapApp::new(
        TestClient::new(),
        PanickingPresence,
        &NEVER_INTERRUPTED,
        [0x29; 16],
    );
    let log = PresenceLog::default();
    let keepalive_log = log.clone();
    app.set_keepalive_callback(move |waiting| keepalive_log.record_waiting(waiting));

    let payload = make_credential_payload();
    let result = catch_unwind(AssertUnwindSafe(|| app.handle_make_credential(&payload)));
    assert!(result.is_err(), "the panic propagates");
    assert_eq!(
        log.take(),
        [PresenceEvent::Waiting(true), PresenceEvent::Waiting(false)]
    );
}

#[test]
fn auto_approve_approves_every_request() {
    let flag = InterruptFlag::new();
    let mut presence = AutoApprove;
    for operation in [
        PresenceOperation::Register,
        PresenceOperation::Authenticate,
        PresenceOperation::Reset,
        PresenceOperation::CredentialManagement,
    ] {
        let request = PresenceRequest::new(operation, DEFAULT_PRESENCE_TIMEOUT);
        assert_eq!(
            presence.confirm(&request, Cancellation::new(&flag)),
            PresenceOutcome::Approved
        );
    }
}

#[test]
fn cancellation_reports_the_interrupt_flag() {
    let flag = InterruptFlag::new();
    assert!(!Cancellation::new(&flag).is_cancelled());
    flag.set_working();
    assert!(!Cancellation::new(&flag).is_cancelled());
    assert!(flag.interrupt());
    assert!(Cancellation::new(&flag).is_cancelled());
}
