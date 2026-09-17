//! authenticatorGetAssertion and authenticatorGetNextAssertion: user
//! verification and presence options, credential selection, the user member
//! and the getNextAssertion timer (CTAP 2.3 §6.2.2, §6.3).

use super::support::{
    credential, encode, install_pin_uv_auth_token, int, pin_hash, response_auth_data, scripted_app,
    token_pin_auth, PresenceEvent, PresenceLog, SeenRequest, TestApp, FLAG_UV,
};
use crate::ctap::cbor::canonical_map;

use crate::ctap::pin::permissions::PIN_PERMISSION_GA;
use crate::ctap::pin::token::{ManualClock, MAX_USAGE_TIME_PERIOD};
use crate::ctap::presence::{PresenceOperation, PresenceOutcome};
use crate::ctap::storage::CREDENTIAL_ID_LENGTH;
use crate::store::CredentialRecord;
use crate::{ClassicPinProtocol, CoseAlg};

use ciborium::{de::from_reader, value::Value};
use core::time::Duration;

use crate::ctap::constants::*;

const RP_ID: &str = "example.com";
const CLIENT_DATA_HASH: [u8; 32] = [0x6A; 32];
const FLAG_UP: u8 = 0x01;
const TOKEN: [u8; 32] = [0x6B; 32];
/// "If timer since the last call [...] is greater than 30 seconds" (CTAP 2.3 §6.3).
const GET_NEXT_ASSERTION_TIMEOUT: Duration = Duration::from_secs(30);

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

/// An ID of the form makeCredential gives a discoverable (`discoverable`)
/// or non-discoverable credential.
fn credential_id(discoverable: bool, tag: u8) -> Vec<u8> {
    let mut id = vec![tag; CREDENTIAL_ID_LENGTH];
    id[0] = u8::from(discoverable);
    id
}

fn named_credential(id: &[u8], user_id: u8) -> CredentialRecord {
    let mut record = credential(RP_ID, &[user_id], id, CoseAlg::ES256);
    record.user_name = Some(format!("user{user_id}"));
    record.user_display_name = Some(format!("User {user_id}"));
    record
}

fn app_with(
    credentials: &[CredentialRecord],
    outcomes: Vec<PresenceOutcome>,
) -> (TestApp, PresenceLog) {
    let (mut app, log) = scripted_app([0x6C; 16], outcomes);
    for record in credentials {
        app.store.put(record).expect("store credential");
    }
    (app, log)
}

fn request(extra: Vec<(Value, Value)>) -> Vec<u8> {
    let mut entries = vec![
        (int(1), text(RP_ID)),
        (int(2), Value::Bytes(CLIENT_DATA_HASH.to_vec())),
    ];
    entries.extend(extra);
    encode(&canonical_map(entries))
}

fn allow_list(ids: &[&[u8]]) -> (Value, Value) {
    (
        int(3),
        Value::Array(
            ids.iter()
                .map(|id| {
                    canonical_map(vec![
                        (text("type"), text("public-key")),
                        (text("id"), Value::Bytes(id.to_vec())),
                    ])
                })
                .collect(),
        ),
    )
}

fn options(entries: &[(&str, bool)]) -> (Value, Value) {
    (
        int(5),
        canonical_map(
            entries
                .iter()
                .map(|(key, value)| (text(key), Value::Bool(*value)))
                .collect(),
        ),
    )
}

fn pin_uv_auth() -> Vec<(Value, Value)> {
    vec![
        (
            int(6),
            Value::Bytes(token_pin_auth(
                ClassicPinProtocol::V2,
                &TOKEN,
                &CLIENT_DATA_HASH,
            )),
        ),
        (int(7), int(2)),
    ]
}

fn install_token(app: &mut TestApp) {
    install_pin_uv_auth_token(app, ClassicPinProtocol::V2, TOKEN, PIN_PERMISSION_GA, None);
}

fn member(response: &[u8], key: i64) -> Option<Value> {
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).expect("decode response") else {
        panic!("response must be a map");
    };
    map.into_iter()
        .find_map(|(k, v)| (k == int(key)).then_some(v))
}

fn user_member(response: &[u8]) -> Option<Vec<(Value, Value)>> {
    member(response, 4).map(|user| match user {
        Value::Map(entries) => entries,
        other => panic!("user must be a map, not {other:?}"),
    })
}

fn flags(response: &[u8]) -> u8 {
    response_auth_data(response)[32]
}

/// "User identifiable information (name, DisplayName, icon) inside the
/// publicKeyCredentialUserEntity MUST NOT be returned if user verification is
/// not done by the authenticator." (CTAP 2.3 §6.2.2 step 12)
#[test]
fn user_names_are_returned_only_with_user_verification() {
    let id = credential_id(true, 0xA1);
    let (mut app, _) = app_with(&[named_credential(&id, 1)], vec![]);

    let response = app
        .handle_get_assertion(&request(vec![]))
        .expect("getAssertion");
    assert_eq!(
        user_member(&response),
        Some(vec![(text("id"), Value::Bytes(vec![1]))])
    );

    install_token(&mut app);
    let response = app
        .handle_get_assertion(&request(pin_uv_auth()))
        .expect("getAssertion with user verification");
    assert_eq!(flags(&response) & FLAG_UV, FLAG_UV);
    let user = user_member(&response).expect("user");
    assert!(user.contains(&(text("name"), text("user1"))), "{user:?}");
    assert!(
        user.contains(&(text("displayName"), text("User 1"))),
        "{user:?}"
    );
}

/// The user member is returned for discoverable credentials, which need at
/// least the user id, and left out for server-side credentials, for which it
/// "is OPTIONAL" (CTAP 2.3 §6.2.2, user (0x04)).
#[test]
fn the_user_member_is_returned_for_discoverable_credentials_only() {
    let discoverable = credential_id(true, 0xA2);
    let server_side = credential_id(false, 0xA3);
    let (mut app, _) = app_with(
        &[
            named_credential(&discoverable, 2),
            named_credential(&server_side, 3),
        ],
        vec![],
    );

    let response = app
        .handle_get_assertion(&request(vec![allow_list(&[&discoverable])]))
        .expect("discoverable credential");
    assert_eq!(
        user_member(&response),
        Some(vec![(text("id"), Value::Bytes(vec![2]))])
    );

    let response = app
        .handle_get_assertion(&request(vec![allow_list(&[&server_side])]))
        .expect("server-side credential");
    assert_eq!(user_member(&response), None);
}

/// "up" false asks for a silent assertion: no user presence is collected and
/// the "up" bit is false (CTAP 2.3 §6.2.2 step 9, "Silent authentication").
#[test]
fn up_false_makes_a_silent_assertion() {
    let id = credential_id(true, 0xA4);
    let (mut app, log) = app_with(&[named_credential(&id, 4)], vec![]);
    let response = app
        .handle_get_assertion(&request(vec![options(&[("up", false)])]))
        .expect("silent assertion");
    assert_eq!(flags(&response) & (FLAG_UP | FLAG_UV), 0);
    assert!(log.take().is_empty(), "no presence request");

    let response = app
        .handle_get_assertion(&request(vec![options(&[("up", true)])]))
        .expect("assertion with presence");
    assert_eq!(flags(&response) & FLAG_UP, FLAG_UP);
    assert_eq!(log.take().len(), 3);
}

/// hmac-secret: "If "up" is set to false, the authenticator returns
/// CTAP2_ERR_UNSUPPORTED_OPTION." (CTAP 2.3 §12.7)
#[test]
fn hmac_secret_needs_user_presence() {
    let id = credential_id(true, 0xA5);
    let (mut app, _) = app_with(&[named_credential(&id, 5)], vec![]);
    let hmac_secret = (
        int(4),
        canonical_map(vec![(
            text("hmac-secret"),
            canonical_map(vec![
                (int(1), canonical_map(vec![])),
                (int(2), Value::Bytes(vec![0; 32])),
                (int(3), Value::Bytes(vec![0; 32])),
                (int(4), int(2)),
            ]),
        )]),
    );
    assert_eq!(
        app.handle_get_assertion(&request(vec![hmac_secret, options(&[("up", false)])])),
        Err(CTAP2_ERR_UNSUPPORTED_OPTION)
    );
}

/// "If the allowList parameter is present: Select any credential from the
/// applicable credentials list. Delete the numberOfCredentials member."
/// (CTAP 2.3 §6.2.2 step 11.1)
#[test]
fn an_allow_list_selects_a_single_credential() {
    let first = credential_id(true, 0xB1);
    let second = credential_id(false, 0xB2);
    let (mut app, _) = app_with(
        &[named_credential(&first, 1), named_credential(&second, 2)],
        vec![],
    );
    let response = app
        .handle_get_assertion(&request(vec![allow_list(&[&first, &second])]))
        .expect("getAssertion");
    assert_eq!(member(&response, 5), None, "numberOfCredentials");
    assert_eq!(app.handle_get_next_assertion(), Err(CTAP2_ERR_NOT_ALLOWED));
}

fn discoverable_pair() -> (TestApp, PresenceLog, ManualClock) {
    let (mut app, log) = app_with(
        &[
            named_credential(&credential_id(true, 0xC1), 1),
            named_credential(&credential_id(true, 0xC2), 2),
            named_credential(&credential_id(true, 0xC3), 3),
        ],
        vec![],
    );
    let clock = ManualClock::default();
    app.pin_state.set_clock(Box::new(clock.clone()));
    (app, log, clock)
}

/// "If timer since the last call to authenticatorGetAssertion/
/// authenticatorGetNextAssertion is greater than 30 seconds, discard the
/// current authenticatorGetAssertion state and return
/// CTAP2_ERR_NOT_ALLOWED. [...] Reset the timer." (CTAP 2.3 §6.3)
#[test]
fn get_next_assertion_times_out_30_seconds_after_the_last_assertion() {
    let (mut app, _, clock) = discoverable_pair();
    let response = app
        .handle_get_assertion(&request(vec![]))
        .expect("getAssertion");
    assert_eq!(member(&response, 5), Some(int(3)));

    // Each call resets the timer.
    clock.advance(GET_NEXT_ASSERTION_TIMEOUT);
    app.handle_get_next_assertion().expect("second credential");
    clock.advance(GET_NEXT_ASSERTION_TIMEOUT + Duration::from_millis(1));
    assert_eq!(app.handle_get_next_assertion(), Err(CTAP2_ERR_NOT_ALLOWED));
    // The state was discarded.
    assert_eq!(app.handle_get_next_assertion(), Err(CTAP2_ERR_NOT_ALLOWED));
}

/// "An authenticator MUST discard the state for a stateful command command if
/// the pinUvAuthToken that authenticated the state initializing command
/// expires" (CTAP 2.3 §6).
#[test]
fn get_next_assertion_ends_when_the_authenticating_token_expires() {
    let (mut app, _, clock) = discoverable_pair();
    install_token(&mut app);
    // A silent assertion uses the token without consuming its permissions.
    let mut silent = pin_uv_auth();
    silent.push(options(&[("up", false)]));
    app.handle_get_assertion(&request(silent))
        .expect("silent getAssertion");

    // Ten seconds before the token's max usage time period ends.
    clock.advance(MAX_USAGE_TIME_PERIOD - Duration::from_secs(10));
    app.handle_get_assertion(&request(pin_uv_auth()))
        .expect("getAssertion with user verification");
    clock.advance(Duration::from_secs(5));
    let response = app
        .handle_get_next_assertion()
        .expect("the token is still in use");
    let user = user_member(&response).expect("user");
    assert!(user.iter().any(|(key, _)| *key == text("name")), "{user:?}");

    // Ten seconds after the last assertion, well inside 30 seconds, but the
    // token has expired.
    clock.advance(Duration::from_secs(10));
    assert_eq!(app.handle_get_next_assertion(), Err(CTAP2_ERR_NOT_ALLOWED));
}

/// "Platforms MUST NOT include the "uv" option key if the authenticator does
/// not support built-in user verification", and one that does gets
/// CTAP2_ERR_INVALID_OPTION, unless a pinUvAuthParam takes precedence;
/// "If the "rk" option is present then: Return CTAP2_ERR_UNSUPPORTED_OPTION."
/// (CTAP 2.3 §6.2.2 step 4)
#[test]
fn get_assertion_options_uv_and_rk() {
    let id = credential_id(true, 0xD1);
    let (mut app, _) = app_with(&[named_credential(&id, 1)], vec![]);
    assert_eq!(
        app.handle_get_assertion(&request(vec![options(&[("uv", true)])])),
        Err(CTAP2_ERR_INVALID_OPTION)
    );
    for rk in [false, true] {
        assert_eq!(
            app.handle_get_assertion(&request(vec![options(&[("rk", rk)])])),
            Err(CTAP2_ERR_UNSUPPORTED_OPTION)
        );
    }
    app.handle_get_assertion(&request(vec![options(&[("uv", false)])]))
        .expect("uv false is the default");

    install_token(&mut app);
    let mut extra = pin_uv_auth();
    extra.push(options(&[("uv", true)]));
    let response = app
        .handle_get_assertion(&request(extra))
        .expect("pinUvAuthParam takes precedence over uv");
    assert_eq!(flags(&response) & FLAG_UV, FLAG_UV);
}

/// The account a sign-in prompt names, if any.
fn prompted_account(log: &PresenceLog) -> Option<(Option<String>, Option<String>)> {
    log.take().into_iter().find_map(|event| match event {
        PresenceEvent::Asked(request) => {
            assert_eq!(request.operation, PresenceOperation::Authenticate);
            assert_eq!(request.rp_id.as_deref(), Some(RP_ID));
            Some((request.user_name, request.user_display_name))
        }
        PresenceEvent::Waiting(_) => None,
    })
}

/// When getAssertion applies to a single discoverable credential, the prompt
/// names its account, while the response still leaves name and displayName
/// out without user verification: "User identifiable information (name,
/// DisplayName, icon) inside the publicKeyCredentialUserEntity MUST NOT be
/// returned if user verification is not done by the authenticator." (CTAP
/// 2.3 §6.2.2 step 12)
#[test]
fn the_prompt_names_the_account_of_a_single_discoverable_credential() {
    let id = credential_id(true, 0xE1);
    for extra in [vec![], vec![allow_list(&[&id])]] {
        let (mut app, log) = app_with(&[named_credential(&id, 1)], vec![]);
        let response = app
            .handle_get_assertion(&request(extra))
            .expect("getAssertion");
        assert_eq!(
            prompted_account(&log),
            Some((Some("user1".into()), Some("User 1".into())))
        );
        let user = user_member(&response).expect("user");
        assert_eq!(user, vec![(text("id"), Value::Bytes(vec![1]))]);
    }
}

/// With several credentials to choose from, or a non-discoverable one, which
/// has no account stored with it, the prompt names only the relying party.
#[test]
fn the_prompt_names_no_account_otherwise() {
    let (mut app, log) = app_with(
        &[
            named_credential(&credential_id(true, 0xE2), 1),
            named_credential(&credential_id(true, 0xE3), 2),
        ],
        vec![],
    );
    app.handle_get_assertion(&request(vec![]))
        .expect("getAssertion");
    assert_eq!(prompted_account(&log), Some((None, None)));

    let id = credential_id(false, 0xE4);
    let (mut app, log) = app_with(&[named_credential(&id, 3)], vec![]);
    app.handle_get_assertion(&request(vec![allow_list(&[&id])]))
        .expect("getAssertion");
    assert_eq!(prompted_account(&log), Some((None, None)));
}

/// A zero length pinUvAuthParam asks the user to select the authenticator and
/// reports whether a PIN is set (CTAP 2.3 §6.2.2 step 1).
#[test]
fn a_zero_length_pin_uv_auth_param_asks_for_a_touch() {
    let id = credential_id(true, 0xD2);
    for (pin_set, outcome, status) in [
        (false, PresenceOutcome::Approved, CTAP2_ERR_PIN_NOT_SET),
        (true, PresenceOutcome::Approved, CTAP2_ERR_PIN_INVALID),
        (true, PresenceOutcome::Denied, CTAP2_ERR_OPERATION_DENIED),
        (false, PresenceOutcome::TimedOut, CTAP2_ERR_OPERATION_DENIED),
        (
            false,
            PresenceOutcome::Cancelled,
            CTAP2_ERR_KEEPALIVE_CANCEL,
        ),
    ] {
        let (mut app, log) = app_with(&[named_credential(&id, 1)], vec![outcome]);
        if pin_set {
            app.pin_state.set_pin(pin_hash(b"1234"));
        }
        let sign_count = app.store.get(&id).expect("get").expect("stored").sign_count;
        assert_eq!(
            app.handle_get_assertion(&request(vec![(int(6), Value::Bytes(vec![]))])),
            Err(status)
        );
        assert_eq!(
            log.take(),
            vec![
                PresenceEvent::Waiting(true),
                PresenceEvent::Asked(SeenRequest::new(PresenceOperation::Select, None)),
                PresenceEvent::Waiting(false),
            ]
        );
        let after = app.store.get(&id).expect("get").expect("stored").sign_count;
        assert_eq!(after, sign_count, "nothing was signed");
    }
}
