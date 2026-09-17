//! Command dispatch and the request log.

use super::support::{encode, int, test_app, TestApp};
use crate::ctap::cbor::canonical_map;
use crate::ctap::CtapApp;

use ciborium::value::Value;
use ctaphid_app::{App, Command};
use heapless_bytes::Bytes;

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

/// Send `request` through `App::call` into a CTAPHID-sized response buffer.
pub(super) fn call(app: &mut TestApp, request: &[u8]) -> Vec<u8> {
    let mut response = Bytes::<MAX_RESPONSE_SIZE>::new();
    App::<MAX_RESPONSE_SIZE>::call(app, Command::Cbor, request, &mut response)
        .expect("CTAPHID_CBOR is answered");
    response.to_vec()
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
