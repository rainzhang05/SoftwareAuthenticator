//! authenticatorMakeCredential user verification, user presence and
//! excludeList rules (CTAP 2.3 §6.1.2).

use super::support::{
    FLAG_UV, PresenceEvent, SeenRequest, TestApp, encode, install_pin_uv_auth_token, int, pin_hash,
    response_auth_data, scripted_app, stored, token_pin_auth,
};
use crate::ctap::cbor::canonical_map;
use crate::ctap::pin::permissions::PIN_PERMISSION_MC;
use crate::ctap::presence::{PresenceOperation, PresenceOutcome};
use crate::{ClassicPinProtocol, CoseAlg};

use ciborium::{de::from_reader, value::Value};

use crate::ctap::constants::*;

const RP_ID: &str = "example.com";
const CLIENT_DATA_HASH: [u8; 32] = [0x3D; 32];
const FLAG_UP: u8 = 0x01;

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

/// A makeCredential request for an ES256 credential with `extra` parameters.
fn request(extra: Vec<(Value, Value)>) -> Vec<u8> {
    let mut entries = vec![
        (int(1), Value::Bytes(CLIENT_DATA_HASH.to_vec())),
        (int(2), canonical_map(vec![(text("id"), text(RP_ID))])),
        (
            int(3),
            canonical_map(vec![(text("id"), Value::Bytes(vec![0x01]))]),
        ),
        (
            int(4),
            Value::Array(vec![canonical_map(vec![
                (text("type"), text("public-key")),
                (text("alg"), int(CoseAlg::ES256 as i64)),
            ])]),
        ),
    ];
    entries.extend(extra);
    encode(&canonical_map(entries))
}

fn options(entries: &[(&str, bool)]) -> (Value, Value) {
    (
        int(7),
        canonical_map(
            entries
                .iter()
                .map(|(key, value)| (text(key), Value::Bool(*value)))
                .collect(),
        ),
    )
}

fn pin_uv_auth(protocol: ClassicPinProtocol, token: &[u8; 32]) -> Vec<(Value, Value)> {
    vec![
        (
            int(8),
            Value::Bytes(token_pin_auth(protocol, token, &CLIENT_DATA_HASH)),
        ),
        (int(9), int(protocol.identifier().into())),
    ]
}

fn exclude_list(credential_id: &[u8]) -> (Value, Value) {
    (
        int(5),
        Value::Array(vec![canonical_map(vec![
            (text("type"), text("public-key")),
            (text("id"), Value::Bytes(credential_id.to_vec())),
        ])]),
    )
}

fn asked_to_register() -> Vec<PresenceEvent> {
    vec![
        PresenceEvent::Waiting(true),
        PresenceEvent::Asked(SeenRequest::new(PresenceOperation::Register, Some(RP_ID))),
        PresenceEvent::Waiting(false),
    ]
}

fn app(outcomes: Vec<PresenceOutcome>) -> (TestApp, super::support::PresenceLog) {
    scripted_app([0x5D; 16], outcomes)
}

fn flags(response: &[u8]) -> u8 {
    response_auth_data(response)[32]
}

/// makeCredUvNotRqd is advertised: "Authenticators SHOULD include this option
/// with the value true." (CTAP 2.3 §6.4)
#[test]
fn get_info_advertises_make_cred_uv_not_rqd() {
    let (mut app, _) = app(vec![]);
    let response = app.handle_get_info().expect("getInfo");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode") else {
        panic!("map");
    };
    let options = map
        .into_iter()
        .find_map(|(key, value)| match value {
            Value::Map(options) if key == int(4) => Some(options),
            _ => None,
        })
        .expect("options");
    assert!(options.contains(&(text("makeCredUvNotRqd"), Value::Bool(true))));
}

/// With a PIN set, a discoverable credential needs a pinUvAuthParam: "The
/// authenticator is protected by some form of user verification. The "uv"
/// option is set to false. The pinUvAuthParam parameter is not present. The
/// "rk" option is present and set to true. Then: If ClientPin option ID is
/// true [...] end the operation by returning CTAP2_ERR_PUAT_REQUIRED."
/// (CTAP 2.3 §6.1.2 step 7.1)
#[test]
fn a_discoverable_credential_with_a_pin_set_requires_a_pin_uv_auth_param() {
    let (mut app, log) = app(vec![]);
    app.pin_state.set_pin(pin_hash(b"1234"));
    assert_eq!(
        app.handle_make_credential(&request(vec![options(&[("rk", true)])])),
        Err(CTAP2_ERR_PUAT_REQUIRED)
    );
    assert!(log.take().is_empty(), "no user presence is collected");
    assert!(stored(&app).is_empty());
}

/// With makeCredUvNotRqd a non-discoverable credential needs no user
/// verification (CTAP 2.3 §6.1.2 step 10).
#[test]
fn a_non_discoverable_credential_with_a_pin_set_needs_no_user_verification() {
    for extra in [vec![], vec![options(&[("rk", false)])]] {
        let (mut app, log) = app(vec![]);
        app.pin_state.set_pin(pin_hash(b"1234"));
        let response = app
            .handle_make_credential(&request(extra))
            .expect("makeCredential succeeds");
        assert_eq!(flags(&response) & (FLAG_UP | FLAG_UV), FLAG_UP);
        assert_eq!(log.take(), asked_to_register());
    }
}

/// "If the "uv" option is true then: If the authenticator does not support a
/// built-in user verification method end the operation by returning
/// CTAP2_ERR_INVALID_OPTION." (CTAP 2.3 §6.1.2 step 5.3)
#[test]
fn the_uv_option_without_built_in_user_verification_is_invalid() {
    for pin_set in [false, true] {
        let (mut app, log) = app(vec![]);
        if pin_set {
            app.pin_state.set_pin(pin_hash(b"1234"));
        }
        assert_eq!(
            app.handle_make_credential(&request(vec![options(&[("uv", true)])])),
            Err(CTAP2_ERR_INVALID_OPTION),
            "PIN set: {pin_set}"
        );
        assert!(log.take().is_empty());
    }
}

/// "If the pinUvAuthParam is present, let the "uv" option be treated as being
/// present with the value false." "pinUvAuthParam and the "uv" option are
/// processed as mutually exclusive with pinUvAuthParam taking precedence."
/// (CTAP 2.3 §6.1.2 step 5.2)
#[test]
fn a_pin_uv_auth_param_takes_precedence_over_the_uv_option() {
    for uv in [false, true] {
        let (mut app, _) = app(vec![]);
        let token = [0x5E; 32];
        install_pin_uv_auth_token(
            &mut app,
            ClassicPinProtocol::V2,
            token,
            PIN_PERMISSION_MC,
            None,
        );
        let mut extra = pin_uv_auth(ClassicPinProtocol::V2, &token);
        extra.push(options(&[("uv", uv), ("rk", true)]));
        let response = app
            .handle_make_credential(&request(extra))
            .expect("makeCredential succeeds");
        assert_eq!(flags(&response) & FLAG_UV, FLAG_UV, "uv option {uv}");
    }
}

/// "If authenticator supports either pinUvAuthToken or clientPin features and
/// the platform sends a zero length pinUvAuthParam: Request evidence of user
/// interaction [...]. If the user declines permission, or the operation times
/// out, then end the operation by returning CTAP2_ERR_OPERATION_DENIED. If
/// evidence of user interaction is provided in this step then return either
/// CTAP2_ERR_PIN_NOT_SET if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN has
/// been set." (CTAP 2.3 §6.1.2 step 1)  The user is asked to select the
/// authenticator: "This is done for backwards compatibility with CTAP2.0
/// platforms in the case where [...] the user has to select which
/// authenticator to get the pinUvAuthToken from."
#[test]
fn a_zero_length_pin_uv_auth_param_asks_for_a_touch() {
    let touch = || {
        vec![
            PresenceEvent::Waiting(true),
            PresenceEvent::Asked(SeenRequest::new(PresenceOperation::Select, None)),
            PresenceEvent::Waiting(false),
        ]
    };
    // Step 1 comes before the pinUvAuthProtocol check of step 2.
    for extra in [
        vec![(int(8), Value::Bytes(vec![]))],
        vec![(int(8), Value::Bytes(vec![])), (int(9), int(2))],
    ] {
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
            let (mut app, log) = app(vec![outcome]);
            if pin_set {
                app.pin_state.set_pin(pin_hash(b"1234"));
            }
            assert_eq!(
                app.handle_make_credential(&request(extra.clone())),
                Err(status),
                "PIN set {pin_set}, {outcome:?}"
            );
            assert_eq!(log.take(), touch());
            assert!(stored(&app).is_empty());
        }
    }
}

/// "Let userPresentFlagValue be false. [...] If userPresentFlagValue is false,
/// then: Wait for user presence. Regardless of whether user presence is
/// obtained or the authenticator times out, terminate this procedure and
/// return CTAP2_ERR_CREDENTIAL_EXCLUDED." (CTAP 2.3 §6.1.2 step 12.1)
#[test]
fn an_excluded_credential_is_reported_after_user_presence() {
    for outcome in [
        PresenceOutcome::Approved,
        PresenceOutcome::Denied,
        PresenceOutcome::TimedOut,
    ] {
        let (mut app, log) = app(vec![PresenceOutcome::Approved, outcome]);
        app.handle_make_credential(&request(vec![]))
            .expect("first registration");
        let existing = stored(&app)[0].credential_id.clone();
        log.take();

        assert_eq!(
            app.handle_make_credential(&request(vec![exclude_list(&existing)])),
            Err(CTAP2_ERR_CREDENTIAL_EXCLUDED),
            "{outcome:?}"
        );
        assert_eq!(log.take(), asked_to_register(), "{outcome:?}");
        assert_eq!(stored(&app).len(), 1);
    }

    let (mut app, _) = app(vec![PresenceOutcome::Approved, PresenceOutcome::Cancelled]);
    app.handle_make_credential(&request(vec![]))
        .expect("first registration");
    let existing = stored(&app)[0].credential_id.clone();
    assert_eq!(
        app.handle_make_credential(&request(vec![exclude_list(&existing)])),
        Err(CTAP2_ERR_KEEPALIVE_CANCEL)
    );
}

/// A credential with credProtect userVerificationRequired only excludes when
/// user verification was performed: "Else (implying user verification was not
/// collected in Step 11), remove the credential from the excludeList and
/// continue parsing the rest of the list." (CTAP 2.3 §6.1.2 step 12.2)
#[test]
fn a_user_verification_required_credential_excludes_only_with_user_verification() {
    let (mut app, _) = app(vec![]);
    let cred_protect = (int(6), canonical_map(vec![(text("credProtect"), int(3))]));
    app.handle_make_credential(&request(vec![cred_protect]))
        .expect("first registration");
    let existing = stored(&app)[0].credential_id.clone();

    app.handle_make_credential(&request(vec![exclude_list(&existing)]))
        .expect("not excluded without user verification");
    assert_eq!(stored(&app).len(), 2);

    let token = [0x5F; 32];
    install_pin_uv_auth_token(
        &mut app,
        ClassicPinProtocol::V2,
        token,
        PIN_PERMISSION_MC,
        None,
    );
    let mut extra = pin_uv_auth(ClassicPinProtocol::V2, &token);
    extra.push(exclude_list(&existing));
    assert_eq!(
        app.handle_make_credential(&request(extra)),
        Err(CTAP2_ERR_CREDENTIAL_EXCLUDED)
    );
}

/// "If the authenticator is not enterprise attestation capable [...] then
/// end the operation by returning CTAP1_ERR_INVALID_PARAMETER." (CTAP 2.3
/// §6.1.2 step 8)
#[test]
fn enterprise_attestation_is_not_supported() {
    let (mut app, _) = app(vec![]);
    assert_eq!(
        app.handle_make_credential(&request(vec![(int(0x0A), int(1))])),
        Err(CTAP1_ERR_INVALID_PARAMETER)
    );
}

/// "up" false: "The value false will cause a CTAP2_ERR_INVALID_OPTION
/// response regardless of authenticator version." (CTAP 2.3 §6.1)
#[test]
fn the_up_option_false_is_invalid() {
    let (mut app, _) = app(vec![]);
    assert_eq!(
        app.handle_make_credential(&request(vec![options(&[("up", false)])])),
        Err(CTAP2_ERR_INVALID_OPTION)
    );
}

fn request_for_user(user: Value) -> Vec<u8> {
    let entries = vec![
        (int(1), Value::Bytes(CLIENT_DATA_HASH.to_vec())),
        (int(2), canonical_map(vec![(text("id"), text(RP_ID))])),
        (int(3), user),
        (
            int(4),
            Value::Array(vec![canonical_map(vec![
                (text("type"), text("public-key")),
                (text("alg"), int(CoseAlg::ES256 as i64)),
            ])]),
        ),
    ];
    encode(&canonical_map(entries))
}

/// "A user handle is an opaque byte sequence with a maximum size of 64
/// bytes" ([WebAuthn] §5.4.3): a longer user.id is an invalid item length.
#[test]
fn a_user_handle_longer_than_64_bytes_is_rejected() {
    let (mut app, _) = app(vec![]);
    for (length, accepted) in [(64, true), (65, false)] {
        let user = canonical_map(vec![(text("id"), Value::Bytes(vec![0x07; length]))]);
        let result = app.handle_make_credential(&request_for_user(user));
        if accepted {
            assert!(result.is_ok(), "{length} bytes");
        } else {
            assert_eq!(result, Err(CTAP1_ERR_INVALID_LENGTH), "{length} bytes");
        }
    }
}

/// user.name and user.displayName are stored truncated to 64 bytes, at a
/// character boundary ([WebAuthn] §5.4.1, §5.4.3).
#[test]
fn user_names_are_truncated_to_64_bytes() {
    let (mut app, _) = app(vec![]);
    // 63 ASCII bytes followed by a two-byte character straddling the limit.
    let name = format!("{}é and more", "n".repeat(63));
    let display_name = "d".repeat(100);
    let user = canonical_map(vec![
        (text("id"), Value::Bytes(vec![0x07])),
        (text("name"), text(&name)),
        (text("displayName"), text(&display_name)),
    ]);
    app.handle_make_credential(&request_for_user(user))
        .expect("makeCredential succeeds");
    let credential = &stored(&app)[0];
    assert_eq!(credential.user_name.as_deref(), Some(&name[..63]));
    assert_eq!(
        credential.user_display_name.as_deref(),
        Some(&display_name[..64])
    );
}
