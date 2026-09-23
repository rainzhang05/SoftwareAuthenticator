//! Command dispatch and the request log.

use super::support::{TestApp, encode, int, test_app};
use crate::ctap::CtapApp;
use crate::ctap::cbor::canonical_map;

use ciborium::value::Value;

use crate::ctap::constants::*;

fn request(command: u8, entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut request = vec![command];
    request.extend(encode(&canonical_map(entries)));
    request
}

#[test]
fn request_log_reads_client_pin_subcommand_and_protocol_from_their_keys() {
    // pinUvAuthProtocol (0x01) = 1, subCommand (0x02) = getPinToken (0x05).
    let request = request(
        CTAP_CMD_CLIENT_PIN,
        vec![(int(1), int(1)), (int(2), int(5))],
    );
    let line = CtapApp::request_log_line(&request, &[CTAP2_OK]);
    assert!(line.contains("sub=0x05 pinProtocol=0x01"), "{line}");
}

#[test]
fn request_log_reads_credential_management_subcommand_and_protocol_from_their_keys() {
    // subCommand (0x01) = enumerateCredentialsBegin, pinUvAuthProtocol (0x03) = 2.
    let request = request(
        CTAP_CMD_CREDENTIAL_MANAGEMENT,
        vec![(int(1), int(4)), (int(3), int(2))],
    );
    let line = CtapApp::request_log_line(&request, &[CTAP2_OK]);
    assert!(line.contains("sub=0x04 pinProtocol=0x02"), "{line}");
}

#[test]
fn request_log_counts_the_response_with_and_without_its_status_byte() {
    let request = [CTAP_CMD_GET_INFO];
    let line = CtapApp::request_log_line(&request, &[CTAP2_OK, 0xA1, 0x01, 0x02]);
    assert!(
        line.ends_with("req_bcnt=1 resp_bcnt=4 resp_payload_len=3"),
        "{line}"
    );
    assert!(line.contains("sub=n/a pinProtocol=n/a"), "{line}");
}

/// Send `request` through [`CtapApp::call`], checking that the answer fits a
/// CTAPHID message.
pub(super) fn call(app: &mut TestApp, request: &[u8]) -> Vec<u8> {
    let response = app.call(request);
    assert!(response.len() <= MAX_RESPONSE_SIZE, "response too long");
    response
}

/// The authenticator has no biometric sensor, so it implements neither
/// authenticatorBioEnrollment (0x09) nor the FIDO_2_1_PRE prototype (0x40):
/// "If an authenticator receives a command code it does not implement, it
/// MUST return CTAP1_ERR_INVALID_COMMAND." (CTAP 2.3 §8.1)
#[test]
fn bio_enrollment_commands_are_not_implemented() {
    let mut app = test_app([0x09; 16]);
    // {subCommand (0x02): 0x06}; the parameters do not matter.
    for command in [CTAP_CMD_BIO_ENROLLMENT, CTAP_CMD_BIO_ENROLLMENT_PROTOTYPE] {
        let request = request(command, vec![(int(2), int(0x06))]);
        assert_eq!(call(&mut app, &request), [CTAP1_ERR_INVALID_COMMAND]);
    }
}

/// A CTAPHID_CBOR message carries at least the command byte (CTAP 2.3
/// §11.2.9.1.2).  The transport answers an empty one with a CTAPHID error
/// before it gets here; the engine, asked anyway, answers
/// CTAP1_ERR_INVALID_LENGTH.
#[test]
fn an_empty_request_is_an_invalid_length() {
    let mut app = test_app([0x0E; 16]);
    assert_eq!(call(&mut app, &[]), [CTAP1_ERR_INVALID_LENGTH]);
}

mod get_next_assertion_state {
    use super::super::support::{TestApp, credential, encode, int, scripted_app};
    use super::call;
    use crate::CoseAlg;
    use crate::ctap::RESET_WINDOW_AFTER_POWER_UP;
    use crate::ctap::cbor::canonical_map;
    use crate::ctap::pin::token::ManualClock;
    use crate::ctap::presence::PresenceOutcome;
    use crate::ctap::storage::CREDENTIAL_ID_LENGTH;

    use ciborium::value::Value;
    use core::time::Duration;

    use crate::ctap::constants::*;

    const RP_ID: &str = "example.com";

    /// An app with three discoverable credentials for [`RP_ID`], whose user
    /// answers presence requests with `outcomes` and then approves, on a
    /// clock that starts at power-up.
    fn three_credentials(outcomes: Vec<PresenceOutcome>) -> (TestApp, ManualClock) {
        let (mut app, _) = scripted_app([0x5D; 16], outcomes);
        let clock = ManualClock::default();
        app.pin_state.set_clock(Box::new(clock.clone()));
        for tag in 1..=3u8 {
            let mut id = vec![tag; CREDENTIAL_ID_LENGTH];
            id[0] = 1;
            app.store
                .put(&credential(RP_ID, &[tag], &id, CoseAlg::ES256))
                .expect("store credential");
        }
        (app, clock)
    }

    /// getAssertion, which finds three credentials.
    fn begin(app: &mut TestApp) {
        let mut request = vec![CTAP_CMD_GET_ASSERTION];
        request.extend(encode(&canonical_map(vec![
            (int(1), Value::Text(RP_ID.into())),
            (int(2), Value::Bytes(vec![0x5E; 32])),
        ])));
        let response = call(app, &request);
        assert_eq!(response[0], CTAP2_OK, "getAssertion");
    }

    fn get_next_assertion(app: &mut TestApp) -> u8 {
        call(app, &[CTAP_CMD_GET_NEXT_ASSERTION])[0]
    }

    /// Without anything in between, getNextAssertion returns the other two.
    #[test]
    fn get_next_assertion_follows_get_assertion() {
        let (mut app, _) = three_credentials(vec![]);
        begin(&mut app);
        assert_eq!(get_next_assertion(&mut app), CTAP2_OK);
        assert_eq!(get_next_assertion(&mut app), CTAP2_OK);
        assert_eq!(get_next_assertion(&mut app), CTAP2_ERR_NOT_ALLOWED);
    }

    /// "The authenticator MAY maintain state based on the assumption that
    /// each stateful command is exclusively preceded by either another
    /// instance of the same command, or by the corresponding state
    /// initializing command [...]. If this pattern is violated then the
    /// authenticator MAY fail any stateful command with the error
    /// CTAP2_ERR_NOT_ALLOWED." (CTAP 2.3 §6)  Every other request, whatever
    /// its outcome, ends the getAssertion state.
    #[test]
    fn any_other_request_discards_the_get_assertion_state() {
        let malformed = |command: u8| vec![command, 0xFF];
        let intervening: Vec<(&str, Vec<u8>)> = vec![
            ("getInfo", vec![CTAP_CMD_GET_INFO]),
            (
                "malformed makeCredential",
                malformed(CTAP_CMD_MAKE_CREDENTIAL),
            ),
            ("malformed getAssertion", malformed(CTAP_CMD_GET_ASSERTION)),
            ("malformed clientPIN", malformed(CTAP_CMD_CLIENT_PIN)),
            (
                "malformed credentialManagement",
                malformed(CTAP_CMD_CREDENTIAL_MANAGEMENT),
            ),
            ("unimplemented bioEnrollment", vec![CTAP_CMD_BIO_ENROLLMENT]),
            ("undefined command", vec![0x3F]),
            ("empty request", vec![]),
        ];
        for (name, request) in intervening {
            let (mut app, _) = three_credentials(vec![]);
            begin(&mut app);
            call(&mut app, &request);
            assert_eq!(
                get_next_assertion(&mut app),
                CTAP2_ERR_NOT_ALLOWED,
                "after {name}"
            );
        }
    }

    /// authenticatorReset that fails, because it comes too late after
    /// power-up or the user does not approve it, ends the state too.
    #[test]
    fn a_failed_reset_discards_the_get_assertion_state() {
        let (mut app, clock) = three_credentials(vec![]);
        begin(&mut app);
        clock.advance(RESET_WINDOW_AFTER_POWER_UP + Duration::from_millis(1));
        assert_eq!(call(&mut app, &[CTAP_CMD_RESET]), [CTAP2_ERR_NOT_ALLOWED]);
        assert_eq!(get_next_assertion(&mut app), CTAP2_ERR_NOT_ALLOWED);

        let (mut app, _) =
            three_credentials(vec![PresenceOutcome::Approved, PresenceOutcome::Denied]);
        begin(&mut app);
        assert_eq!(
            call(&mut app, &[CTAP_CMD_RESET]),
            [CTAP2_ERR_OPERATION_DENIED]
        );
        assert_eq!(get_next_assertion(&mut app), CTAP2_ERR_NOT_ALLOWED);
    }
}
