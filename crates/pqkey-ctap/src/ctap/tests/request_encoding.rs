//! The encoding of request parameters (CTAP 2.3 §8): "All decoders SHOULD
//! reject CBOR that is not validly encoded in the CTAP2 canonical CBOR
//! encoding form and SHOULD reject messages with duplicate map keys." and
//! "Authenticators SHOULD return the CTAP2_ERR_INVALID_CBOR error if received
//! CBOR does not conform to the requirements above."

use super::dispatch::call;
use super::support::test_app;

use crate::ctap::constants::*;

/// The commands that take parameters.
const COMMANDS: [u8; 4] = [
    CTAP_CMD_MAKE_CREDENTIAL,
    CTAP_CMD_GET_ASSERTION,
    CTAP_CMD_CLIENT_PIN,
    CTAP_CMD_CREDENTIAL_MANAGEMENT,
];

/// `payload` sent with every command that takes parameters, and each answer.
fn statuses(payload: &[u8]) -> Vec<u8> {
    COMMANDS
        .iter()
        .map(|&command| {
            let mut app = test_app([0x8E; 16]);
            let mut request = vec![command];
            request.extend_from_slice(payload);
            call(&mut app, &request)[0]
        })
        .collect()
}

fn assert_rejected(name: &str, payload: &[u8]) {
    assert_eq!(
        statuses(payload),
        [CTAP2_ERR_INVALID_CBOR; 4],
        "{name}: {payload:02x?}"
    );
}

/// authenticatorClientPIN getPinRetries, {pinUvAuthProtocol (0x01): 2,
/// subCommand (0x02): 1}, with `extra` spliced into the map as its last
/// entries, `entries` counting them all.
fn get_pin_retries(entries: u8, extra: &[u8]) -> Vec<u8> {
    let mut request = vec![CTAP_CMD_CLIENT_PIN, 0xA0 | entries, 0x01, 0x02, 0x02, 0x01];
    request.extend_from_slice(extra);
    request
}

#[test]
fn a_canonical_get_pin_retries_request_is_answered() {
    let mut app = test_app([0x8E; 16]);
    assert_eq!(call(&mut app, &get_pin_retries(2, &[]))[0], CTAP2_OK);
}

/// "If map keys are present that an implementation does not understand,
/// they MUST be ignored." (CTAP 2.3 §8)  Keys of other major types sort after
/// integers, text keys by length first, and "The representations of any
/// floating-point values are not changed", so a half-precision float is as
/// canonical as a double.
#[test]
fn canonical_unknown_keys_and_floats_are_accepted() {
    // {..., 3: 1.5 (half), 4: 1.5 (double), -1: null, "b": 1, "aa": 2}
    let mut extra = vec![0x03, 0xF9, 0x3F, 0x00];
    extra.extend_from_slice(&[0x04, 0xFB, 0x3F, 0xF8, 0, 0, 0, 0, 0, 0]);
    extra.extend_from_slice(&[0x20, 0xF6, 0x61, b'b', 0x01, 0x62, b'a', b'a', 0x02]);
    let mut app = test_app([0x8E; 16]);
    assert_eq!(call(&mut app, &get_pin_retries(7, &extra))[0], CTAP2_OK);
}

#[test]
fn bytes_after_the_parameters_are_rejected() {
    // {2: 1} followed by 0x00, and by a second map.
    assert_rejected("trailing byte", &[0xA1, 0x02, 0x01, 0x00]);
    assert_rejected("trailing map", &[0xA1, 0x02, 0x01, 0xA0]);
    let mut app = test_app([0x8E; 16]);
    let mut request = get_pin_retries(2, &[]);
    request.push(0x00);
    assert_eq!(call(&mut app, &request), [CTAP2_ERR_INVALID_CBOR]);
}

#[test]
fn duplicate_map_keys_are_rejected() {
    assert_rejected("duplicate integer key", &[0xA2, 0x02, 0x01, 0x02, 0x01]);
    // {1: {"id": h'01', "id": h'01'}}
    assert_rejected(
        "duplicate text key in a nested map",
        &[
            0xA1, 0x01, 0xA2, 0x62, b'i', b'd', 0x41, 0x01, 0x62, b'i', b'd', 0x41, 0x01,
        ],
    );
    let mut app = test_app([0x8E; 16]);
    // getPinRetries with subCommand given twice.
    assert_eq!(
        call(&mut app, &get_pin_retries(3, &[0x02, 0x01])),
        [CTAP2_ERR_INVALID_CBOR]
    );
}

/// "The keys in every map MUST be sorted lowest value to highest. [...] If
/// the major types are different, the one with the lower value in numerical
/// order sorts earlier. If two keys have different lengths, the shorter one
/// sorts earlier; If two keys have the same length, the one with the lower
/// value in (byte-wise) lexical order sorts earlier."
#[test]
fn unsorted_map_keys_are_rejected() {
    assert_rejected("2 before 1", &[0xA2, 0x02, 0x01, 0x01, 0x01]);
    assert_rejected("24 before 23", &[0xA2, 0x18, 0x18, 0x01, 0x17, 0x01]);
    assert_rejected("-1 before 1", &[0xA2, 0x20, 0x01, 0x01, 0x01]);
    assert_rejected("\"a\" before 1", &[0xA2, 0x61, b'a', 0x01, 0x01, 0x01]);
    assert_rejected(
        "\"aa\" before \"b\"",
        &[0xA2, 0x62, b'a', b'a', 0x01, 0x61, b'b', 0x01],
    );
    assert_rejected(
        "\"b\" before \"a\"",
        &[0xA2, 0x61, b'b', 0x01, 0x61, b'a', 0x01],
    );
    // {1: {"type": "public-key", "id": h'01'}}: "id" sorts first.
    let mut nested = vec![0xA1, 0x01, 0xA2, 0x64];
    nested.extend_from_slice(b"type");
    nested.push(0x6A);
    nested.extend_from_slice(b"public-key");
    nested.extend_from_slice(&[0x62, b'i', b'd', 0x41, 0x01]);
    assert_rejected("unsorted nested map", &nested);
}

/// "Integers MUST be encoded as small as possible." and "The expression of
/// lengths in major types 2 through 5 MUST be as short as possible."
#[test]
fn longer_than_necessary_encodings_are_rejected() {
    assert_rejected("key 2 in one extra byte", &[0xA1, 0x18, 0x02, 0x01]);
    assert_rejected("value 1 in one extra byte", &[0xA1, 0x02, 0x18, 0x01]);
    assert_rejected("255 in two extra bytes", &[0xA1, 0x02, 0x19, 0x00, 0xFF]);
    assert_rejected(
        "65535 in four extra bytes",
        &[0xA1, 0x02, 0x1A, 0x00, 0x00, 0xFF, 0xFF],
    );
    assert_rejected(
        "2^32 - 1 in eight extra bytes",
        &[0xA1, 0x02, 0x1B, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF],
    );
    assert_rejected("-1 in one extra byte", &[0xA1, 0x02, 0x38, 0x00]);
    assert_rejected("byte string length", &[0xA1, 0x02, 0x58, 0x01, 0x00]);
    assert_rejected("text string length", &[0xA1, 0x02, 0x78, 0x01, b'a']);
    assert_rejected("array length", &[0xA1, 0x02, 0x98, 0x00]);
    assert_rejected("map length", &[0xB8, 0x01, 0x02, 0x01]);
    assert_rejected("false in one extra byte", &[0xA1, 0x02, 0xF8, 0x14]);
}

/// "Indefinite-length items MUST be made into definite-length items."
#[test]
fn indefinite_lengths_are_rejected() {
    assert_rejected("map", &[0xBF, 0x02, 0x01, 0xFF]);
    assert_rejected("array", &[0xA1, 0x02, 0x9F, 0x01, 0xFF]);
    assert_rejected("byte string", &[0xA1, 0x02, 0x5F, 0x41, 0x00, 0xFF]);
    assert_rejected("text string", &[0xA1, 0x02, 0x7F, 0x61, b'a', 0xFF]);
}

/// "Tags as defined in Section 3.4 in [RFC8949] MUST NOT be present."
#[test]
fn tags_are_rejected() {
    // {2: 1(1)}, {2: 2(h'01')}
    assert_rejected("epoch time tag", &[0xA1, 0x02, 0xC1, 0x01]);
    assert_rejected("bignum tag", &[0xA1, 0x02, 0xC2, 0x41, 0x01]);
}

#[test]
fn malformed_cbor_is_rejected() {
    assert_rejected("no parameters", &[]);
    assert_rejected("truncated map", &[0xA2, 0x02, 0x01]);
    assert_rejected("truncated byte string", &[0xA1, 0x02, 0x42, 0x00]);
    assert_rejected("reserved additional information", &[0xA1, 0x02, 0x1C]);
    assert_rejected("break outside an indefinite item", &[0xA1, 0x02, 0xFF]);
    assert_rejected("invalid UTF-8", &[0xA1, 0x02, 0x61, 0xFF]);
    assert_rejected("not a map", &[0x80]);
}
