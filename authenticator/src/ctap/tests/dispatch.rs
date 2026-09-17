//! Command dispatch and the request log.

use super::support::{encode, int};
use crate::ctap::cbor::canonical_map;
use crate::ctap::CtapApp;

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
