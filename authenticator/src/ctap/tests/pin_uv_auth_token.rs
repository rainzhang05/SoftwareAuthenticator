//! pinUvAuthToken state (CTAP 2.3 §6.5.2.1, §6.5.3.2): the usage timer, the
//! userPresent and userVerified flags, permissions consumption and binding.

use super::support::new_app;
use super::support::{
    encode, es256_credential, get_assertion_request, get_pin_token, get_pin_uv_auth_token, int,
    make_credential_request, pin_hash, response_auth_data, set_pin_padded, token_pin_auth,
    TestClient, FLAG_UV,
};
use crate::ctap::cbor::canonical_map;
use crate::ctap::pin::permissions::{PIN_PERMISSION_CM, PIN_PERMISSION_GA, PIN_PERMISSION_MC};
use crate::ctap::pin::token::{
    ManualClock, INITIAL_USAGE_TIME_LIMIT, MAX_USAGE_TIME_PERIOD, USER_PRESENT_TIME_LIMIT,
};
use crate::ctap::CtapApp;
use crate::ClassicPinProtocol;

use ciborium::value::Value;
use core::time::Duration;

use crate::ctap::constants::*;

const PIN: &[u8] = b"1234";
const PROTOCOLS: [ClassicPinProtocol; 2] = [ClassicPinProtocol::V1, ClassicPinProtocol::V2];
const MILLISECOND: Duration = Duration::from_millis(1);

/// An authenticator with `PIN` set, a manual clock and one credential.
fn app_with_clock() -> (CtapApp<TestClient>, ManualClock) {
    let mut app = new_app(TestClient::new(), [0x80; 16]);
    let clock = ManualClock::default();
    app.pin_state.set_clock(Box::new(clock.clone()));
    app.pin_state.set_pin(pin_hash(PIN));
    app.stored_credentials
        .push(es256_credential("example.com", &[0xF1]));
    (app, clock)
}

/// getCredsMetadata, which checks the token without consuming it.
fn creds_metadata(
    app: &mut CtapApp<TestClient>,
    protocol: ClassicPinProtocol,
    token: &[u8; 32],
) -> Result<(), u8> {
    let request = canonical_map(vec![
        (int(1), int(0x01)),
        (int(3), int(protocol.identifier().into())),
        (
            int(4),
            Value::Bytes(token_pin_auth(protocol, token, &[0x01])),
        ),
    ]);
    app.handle_credential_management(&encode(&request))
        .map(|_| ())
}

fn make_credential(
    app: &mut CtapApp<TestClient>,
    protocol: ClassicPinProtocol,
    token: &[u8; 32],
    rp_id: &str,
) -> Result<Vec<u8>, u8> {
    let client_hash = [0x5C; 32];
    let param = token_pin_auth(protocol, token, &client_hash);
    app.handle_make_credential(&make_credential_request(
        &client_hash,
        rp_id,
        Some((protocol, param)),
    ))
}

fn get_assertion(
    app: &mut CtapApp<TestClient>,
    protocol: ClassicPinProtocol,
    token: &[u8; 32],
) -> Result<Vec<u8>, u8> {
    let client_hash = [0x5D; 32];
    let param = token_pin_auth(protocol, token, &client_hash);
    app.handle_get_assertion(&get_assertion_request(
        &client_hash,
        "example.com",
        Some((protocol, param)),
        None,
    ))
}

fn cm_token(app: &mut CtapApp<TestClient>, protocol: ClassicPinProtocol) -> [u8; 32] {
    get_pin_uv_auth_token(app, protocol, PIN, PIN_PERMISSION_CM.into(), None)
        .expect("cm token issued")
}

// -- The usage timer ---------------------------------------------------------------------

#[test]
fn an_unused_token_expires_at_the_initial_usage_time_limit() {
    assert_eq!(INITIAL_USAGE_TIME_LIMIT, Duration::from_secs(30));
    for protocol in PROTOCOLS {
        let (mut app, clock) = app_with_clock();
        let token = cm_token(&mut app, protocol);
        clock.advance(INITIAL_USAGE_TIME_LIMIT);
        assert_eq!(
            creds_metadata(&mut app, protocol, &token),
            Err(CTAP2_ERR_PIN_AUTH_INVALID),
            "{protocol:?}"
        );
        assert_eq!(app.pin_state.pin_uv_auth_token(), None);

        // Just inside the limit it still works.
        let token = cm_token(&mut app, protocol);
        clock.advance(INITIAL_USAGE_TIME_LIMIT - MILLISECOND);
        assert_eq!(creds_metadata(&mut app, protocol, &token), Ok(()));
    }
}

#[test]
fn a_used_token_lasts_until_the_max_usage_time_period() {
    assert_eq!(MAX_USAGE_TIME_PERIOD, Duration::from_secs(600));
    for protocol in PROTOCOLS {
        let (mut app, clock) = app_with_clock();
        let token = cm_token(&mut app, protocol);
        clock.advance(Duration::from_secs(10));
        assert_eq!(creds_metadata(&mut app, protocol, &token), Ok(()));

        // Long past the initial usage time limit, but used in time.
        clock.advance(MAX_USAGE_TIME_PERIOD - Duration::from_secs(10) - MILLISECOND);
        assert_eq!(creds_metadata(&mut app, protocol, &token), Ok(()));

        clock.advance(MILLISECOND);
        assert_eq!(
            creds_metadata(&mut app, protocol, &token),
            Err(CTAP2_ERR_PIN_AUTH_INVALID),
            "{protocol:?}"
        );
        assert_eq!(app.pin_state.pin_uv_auth_token(), None);
    }
}

#[test]
fn a_failed_verification_does_not_count_as_using_the_token() {
    let (mut app, clock) = app_with_clock();
    let token = cm_token(&mut app, ClassicPinProtocol::V2);
    let mut wrong = token;
    wrong[0] ^= 0x01;
    assert_eq!(
        creds_metadata(&mut app, ClassicPinProtocol::V2, &wrong),
        Err(CTAP2_ERR_PIN_AUTH_INVALID)
    );
    clock.advance(INITIAL_USAGE_TIME_LIMIT);
    assert_eq!(
        creds_metadata(&mut app, ClassicPinProtocol::V2, &token),
        Err(CTAP2_ERR_PIN_AUTH_INVALID)
    );
}

// -- Flags ----------------------------------------------------------------------------------

#[test]
fn a_new_token_is_user_verified_but_not_user_present() {
    // getPinToken and getPinUvAuthTokenUsingPinWithPermissions call
    // beginUsingPinUvAuthToken(userIsPresent: false).
    let (mut app, _clock) = app_with_clock();
    assert!(!app.pin_state.user_verified_flag());
    get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).expect("token issued");
    assert!(app.pin_state.user_verified_flag());
    assert!(!app.pin_state.user_present_flag());
}

#[test]
fn the_user_present_flag_lapses_after_the_user_present_time_limit() {
    let (mut app, clock) = app_with_clock();
    app.pin_state
        .begin_using_pin_uv_auth_token_with_user_presence(
            ClassicPinProtocol::V2,
            [0x42; 32],
            PIN_PERMISSION_CM,
        );
    assert!(app.pin_state.user_present_flag());
    clock.advance(USER_PRESENT_TIME_LIMIT - MILLISECOND);
    assert!(app.pin_state.user_present_flag());
    creds_metadata(&mut app, ClassicPinProtocol::V2, &[0x42; 32]).expect("token used");
    clock.advance(MILLISECOND);
    assert!(!app.pin_state.user_present_flag());
    // The token itself is still in use.
    assert!(app.pin_state.user_verified_flag());
    assert_eq!(
        creds_metadata(&mut app, ClassicPinProtocol::V2, &[0x42; 32]),
        Ok(())
    );
}

#[test]
fn make_credential_consumes_the_token() {
    for protocol in PROTOCOLS {
        let (mut app, _clock) = app_with_clock();
        let token = get_pin_uv_auth_token(
            &mut app,
            protocol,
            PIN,
            (PIN_PERMISSION_MC | PIN_PERMISSION_GA | PIN_PERMISSION_CM).into(),
            Some("example.com"),
        )
        .expect("token issued");
        let response = make_credential(&mut app, protocol, &token, "example.com")
            .unwrap_or_else(|err| panic!("{protocol:?}: {err:#04x}"));
        assert_eq!(response_auth_data(&response)[32] & FLAG_UV, FLAG_UV);

        // "Call clearUserPresentFlag(), clearUserVerifiedFlag(), and
        // clearPinUvAuthTokenPermissionsExceptLbw()." (CTAP 2.3 §6.1.2 step 14)
        assert!(!app.pin_state.user_verified_flag());
        assert_eq!(app.pin_state.pin_uv_auth_permissions(), 0);
        for result in [
            make_credential(&mut app, protocol, &token, "example.com").map(|_| ()),
            get_assertion(&mut app, protocol, &token).map(|_| ()),
            creds_metadata(&mut app, protocol, &token),
        ] {
            assert_eq!(result, Err(CTAP2_ERR_PIN_AUTH_INVALID), "{protocol:?}");
        }
    }
}

#[test]
fn get_assertion_consumes_the_token() {
    for protocol in PROTOCOLS {
        let (mut app, _clock) = app_with_clock();
        let token = get_pin_token(&mut app, protocol, PIN).expect("token issued");
        get_assertion(&mut app, protocol, &token)
            .unwrap_or_else(|err| panic!("{protocol:?}: {err:#04x}"));
        assert!(!app.pin_state.user_verified_flag());
        assert_eq!(app.pin_state.pin_uv_auth_permissions(), 0);
        assert_eq!(
            get_assertion(&mut app, protocol, &token),
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        );
    }
}

#[test]
fn collecting_presence_without_a_pin_uv_auth_param_also_consumes_an_in_use_token() {
    // The clear functions are called whenever user presence was collected;
    // "These functions are no-ops if there is not an in-use pinUvAuthToken."
    let (mut app, _clock) = app_with_clock();
    let token = get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).expect("token issued");
    let request = make_credential_request(&[0x5E; 32], "example.com", None);
    app.handle_make_credential(&request)
        .expect("makeCredential without UV");
    assert_eq!(
        get_assertion(&mut app, ClassicPinProtocol::V2, &token),
        Err(CTAP2_ERR_PIN_AUTH_INVALID)
    );
}

#[test]
fn credential_management_does_not_consume_the_token() {
    let (mut app, _clock) = app_with_clock();
    let token = cm_token(&mut app, ClassicPinProtocol::V1);
    for _ in 0..3 {
        assert_eq!(
            creds_metadata(&mut app, ClassicPinProtocol::V1, &token),
            Ok(())
        );
    }
    assert_eq!(app.pin_state.pin_uv_auth_permissions(), PIN_PERMISSION_CM);
}

// -- Binding --------------------------------------------------------------------------------

#[test]
fn a_get_pin_token_token_is_bound_to_the_first_rp_it_is_used_for() {
    // "If the pinUvAuthToken does not have a permissions RP ID associated:
    // Associate the request's rp.id parameter value with the pinUvAuthToken
    // as its permissions RP ID." (CTAP 2.3 §6.1.2 step 11.1.6)
    let (mut app, _clock) = app_with_clock();
    let token = get_pin_token(&mut app, ClassicPinProtocol::V2, PIN).expect("token issued");
    assert_eq!(app.pin_state.permissions_rp_id(), None);
    make_credential(&mut app, ClassicPinProtocol::V2, &token, "first.example")
        .expect("makeCredential");
    assert_eq!(
        app.pin_state.permissions_rp_id().as_deref(),
        Some("first.example")
    );
}

#[test]
fn a_token_bound_to_an_rp_refuses_other_rps() {
    let (mut app, _clock) = app_with_clock();
    let token = get_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        PIN,
        PIN_PERMISSION_MC.into(),
        Some("other.example"),
    )
    .expect("token issued");
    assert_eq!(
        make_credential(&mut app, ClassicPinProtocol::V2, &token, "example.com"),
        Err(CTAP2_ERR_PIN_AUTH_INVALID)
    );
    assert!(app.stored_credentials.len() == 1);
}

#[test]
fn a_token_only_verifies_under_the_protocol_it_was_issued_over() {
    // "Each PIN/UV auth protocol maintains its own pinUvAuthToken" (§6.5).
    for (issued, used) in [
        (ClassicPinProtocol::V1, ClassicPinProtocol::V2),
        (ClassicPinProtocol::V2, ClassicPinProtocol::V1),
    ] {
        let (mut app, _clock) = app_with_clock();
        let token = cm_token(&mut app, issued);
        assert_eq!(
            creds_metadata(&mut app, used, &token),
            Err(CTAP2_ERR_PIN_AUTH_INVALID),
            "issued over {issued:?}, used over {used:?}"
        );
        assert_eq!(creds_metadata(&mut app, issued, &token), Ok(()));
    }
}

// -- Token lifecycle ------------------------------------------------------------------------

#[test]
fn a_new_token_replaces_the_previous_one() {
    let (mut app, _clock) = app_with_clock();
    let first = cm_token(&mut app, ClassicPinProtocol::V2);
    let second = cm_token(&mut app, ClassicPinProtocol::V2);
    assert_eq!(
        creds_metadata(&mut app, ClassicPinProtocol::V2, &first),
        Err(CTAP2_ERR_PIN_AUTH_INVALID)
    );
    assert_eq!(
        creds_metadata(&mut app, ClassicPinProtocol::V2, &second),
        Ok(())
    );
}

#[test]
fn a_wrong_pin_leaves_the_current_token_alone() {
    let (mut app, _clock) = app_with_clock();
    let token = cm_token(&mut app, ClassicPinProtocol::V2);
    assert_eq!(
        get_pin_token(&mut app, ClassicPinProtocol::V2, b"0000").map(|_| ()),
        Err(CTAP2_ERR_PIN_INVALID)
    );
    assert_eq!(
        creds_metadata(&mut app, ClassicPinProtocol::V2, &token),
        Ok(())
    );
}

#[test]
fn setting_a_pin_stops_the_token() {
    // changePIN "calls resetPinUvAuthToken() for all pinUvAuthProtocols"
    // (CTAP 2.3 §6.5.5.6); set_pin is shared by setPIN and changePIN.
    let (mut app, _clock) = app_with_clock();
    let token = cm_token(&mut app, ClassicPinProtocol::V2);
    app.pin_state.set_pin(pin_hash(b"5678"));
    assert_eq!(
        creds_metadata(&mut app, ClassicPinProtocol::V2, &token),
        Err(CTAP2_ERR_PIN_AUTH_INVALID)
    );
}

#[test]
fn reset_keeps_the_injected_clock() {
    let (mut app, clock) = app_with_clock();
    assert_eq!(app.handle_reset(), Ok(vec![CTAP2_OK]));
    set_pin_padded(
        &mut app,
        ClassicPinProtocol::V2,
        &super::support::padded_pin(PIN),
    )
    .expect("setPIN after reset");
    let token = cm_token(&mut app, ClassicPinProtocol::V2);
    clock.advance(INITIAL_USAGE_TIME_LIMIT);
    assert_eq!(
        creds_metadata(&mut app, ClassicPinProtocol::V2, &token),
        Err(CTAP2_ERR_PIN_AUTH_INVALID)
    );
}
