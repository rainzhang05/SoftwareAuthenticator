//! Serialized large-blob array transfers and write authorization (§6.10.2).

use super::support::*;
use crate::ClassicPinProtocol;
use crate::ctap::CtapApp;
use crate::ctap::cbor::{canonical_map, map_get};
use crate::ctap::constants::*;
use crate::ctap::large_blobs::MAX_FRAGMENT_LENGTH;
use crate::ctap::pin::permissions::{PIN_PERMISSION_LBW, PIN_PERMISSION_MC};
use crate::ctap::pin::token::ManualClock;
use crate::store::{CredentialStore, INITIAL_LARGE_BLOB_ARRAY, MAX_SERIALIZED_LARGE_BLOB_ARRAY};
use ciborium::{de::from_reader, value::Value};
use core::time::Duration;
use sha2::{Digest, Sha256};

const TOKEN: [u8; 32] = [0x86; 32];
const PROTOCOLS: [ClassicPinProtocol; 2] = [ClassicPinProtocol::V1, ClassicPinProtocol::V2];

fn request(entries: Vec<(Value, Value)>) -> Vec<u8> {
    let mut request = vec![CTAP_CMD_LARGE_BLOBS];
    request.extend(encode(&canonical_map(entries)));
    request
}

fn array(length: usize) -> Vec<u8> {
    assert!(length >= 17);
    // The authenticator must accept opaque bytes with a valid hash even
    // when a platform would not interpret them as a CBOR array.
    let mut bytes: Vec<u8> = (0..length - 16).map(|index| index as u8).collect();
    bytes.extend_from_slice(&Sha256::digest(&bytes)[..16]);
    bytes
}

fn message(offset: u32, fragment: &[u8]) -> Vec<u8> {
    let mut message = vec![0xff; 32];
    message.extend([0x0c, 0]);
    message.extend(offset.to_le_bytes());
    message.extend(Sha256::digest(fragment));
    message
}

fn write_request(
    offset: u32,
    length: Option<usize>,
    fragment: &[u8],
    auth: Option<(ClassicPinProtocol, &[u8; 32])>,
) -> Vec<u8> {
    let mut entries = vec![
        (int(2), Value::Bytes(fragment.to_vec())),
        (int(3), int(offset.into())),
    ];
    if let Some(length) = length {
        entries.push((int(4), int(length as i64)));
    }
    if let Some((protocol, token)) = auth {
        entries.push((
            int(5),
            Value::Bytes(token_pin_auth(protocol, token, &message(offset, fragment))),
        ));
        entries.push((int(6), int(protocol.identifier().into())));
    }
    request(entries)
}

fn read(app: &mut TestApp, offset: usize, count: usize) -> Vec<u8> {
    let response = app.call(&request(vec![
        (int(1), int(count as i64)),
        (int(3), int(offset as i64)),
    ]));
    assert_eq!(response[0], CTAP2_OK);
    let Value::Map(map) = from_reader(&response[1..]).unwrap() else {
        panic!("large blob response map")
    };
    assert_eq!(map.len(), 1);
    let Value::Bytes(bytes) = map_get(&map, int(1)).unwrap() else {
        panic!("large blob response bytes")
    };
    assert!(response.len() <= 1768);
    bytes.clone()
}

fn commit(app: &mut TestApp, bytes: &[u8], auth: Option<(ClassicPinProtocol, &[u8; 32])>) {
    for (index, fragment) in bytes.chunks(MAX_FRAGMENT_LENGTH as usize).enumerate() {
        let offset = (index * MAX_FRAGMENT_LENGTH as usize) as u32;
        let request = write_request(offset, (offset == 0).then_some(bytes.len()), fragment, auth);
        assert!(request.len() <= 1768);
        assert_eq!(app.call(&request), [CTAP2_OK]);
    }
}

#[test]
fn initial_array_reads_include_end_and_zero_count() {
    assert_eq!(MAX_FRAGMENT_LENGTH, 1704);
    assert_eq!(MAX_SERIALIZED_LARGE_BLOB_ARRAY, 16384);
    let mut app = test_app([0x81; 16]);
    assert_eq!(read(&mut app, 0, 1704), INITIAL_LARGE_BLOB_ARRAY);
    assert_eq!(read(&mut app, 1, 1704), INITIAL_LARGE_BLOB_ARRAY[1..]);
    assert_eq!(read(&mut app, 17, 1704), []);
    assert_eq!(read(&mut app, 0, 0), []);
    assert_eq!(
        app.call(&request(vec![(int(1), int(1)), (int(3), int(18))])),
        [CTAP1_ERR_INVALID_PARAMETER]
    );
}

#[test]
fn common_and_get_checks_follow_spec_order() {
    let cases = [
        (vec![], CTAP1_ERR_INVALID_PARAMETER),
        (vec![(int(1), int(1))], CTAP1_ERR_INVALID_PARAMETER),
        (vec![(int(3), int(0))], CTAP1_ERR_INVALID_PARAMETER),
        (
            vec![
                (int(1), int(1)),
                (int(2), Value::Bytes(vec![])),
                (int(3), int(0)),
            ],
            CTAP1_ERR_INVALID_PARAMETER,
        ),
        (
            vec![
                (int(1), int(1705)),
                (int(3), int(18)),
                (int(4), Value::Null),
            ],
            CTAP1_ERR_INVALID_PARAMETER,
        ),
        (
            vec![
                (int(1), int(1705)),
                (int(3), int(18)),
                (int(5), Value::Null),
            ],
            CTAP1_ERR_INVALID_PARAMETER,
        ),
        (
            vec![(int(1), int(1705)), (int(3), int(18)), (int(6), int(0))],
            CTAP1_ERR_INVALID_PARAMETER,
        ),
        (
            vec![(int(1), int(1705)), (int(3), int(18))],
            CTAP1_ERR_INVALID_LENGTH,
        ),
        (
            vec![(int(1), int(1704)), (int(3), int(18))],
            CTAP1_ERR_INVALID_PARAMETER,
        ),
    ];
    for (entries, status) in cases {
        let mut app = test_app([0x81; 16]);
        assert_eq!(app.call(&request(entries)), [status]);
    }
}

#[test]
fn set_checks_follow_spec_order_and_bound_integer_arithmetic() {
    let mut app = test_app([0x81; 16]);
    app.pin_state.set_pin(pin_hash(b"1234"));
    let cases = [
        (
            write_request(0, None, &[0; 1705], None),
            CTAP1_ERR_INVALID_LENGTH,
        ),
        (
            write_request(0, None, &[], None),
            CTAP1_ERR_INVALID_PARAMETER,
        ),
        (
            write_request(0, Some(16), &[], None),
            CTAP1_ERR_INVALID_PARAMETER,
        ),
        (
            write_request(0, Some(16385), &[], None),
            CTAP2_ERR_LARGE_BLOB_STORAGE_FULL,
        ),
        (
            write_request(1, Some(17), &[], None),
            CTAP1_ERR_INVALID_PARAMETER,
        ),
        (write_request(1, None, &[], None), CTAP1_ERR_INVALID_SEQ),
        (
            write_request(0, Some(17), &[0; 18], None),
            CTAP2_ERR_PUAT_REQUIRED,
        ),
    ];
    for (request, status) in cases {
        assert_eq!(app.call(&request), [status]);
    }
    for key in [3, 4] {
        let mut entries = vec![(int(2), Value::Bytes(vec![])), (int(3), int(0))];
        if key == 3 {
            entries[1].1 = u64::MAX.into();
        } else {
            entries.push((int(4), u64::MAX.into()));
        }
        let status = if key == 3 {
            CTAP1_ERR_INVALID_SEQ
        } else {
            CTAP2_ERR_LARGE_BLOB_STORAGE_FULL
        };
        assert_eq!(app.call(&request(entries)), [status]);
    }
}

#[test]
fn malformed_parameters_do_not_panic_or_start_a_write() {
    for (key, status) in [
        (1, CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
        (2, CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
        (3, CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
        (4, CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    ] {
        let mut app = test_app([0x81; 16]);
        let mut entries = if key == 1 {
            vec![(int(1), Value::Null), (int(3), int(0))]
        } else {
            vec![
                (int(2), Value::Bytes(vec![])),
                (int(3), int(0)),
                (int(4), int(17)),
            ]
        };
        if key != 1 {
            entries
                .iter_mut()
                .find(|(candidate, _)| *candidate == int(key))
                .unwrap()
                .1 = Value::Null;
        }
        assert_eq!(app.call(&request(entries)), [status]);
    }
    for key in [1, 3, 4] {
        let mut app = test_app([0x81; 16]);
        let entries = if key == 1 {
            vec![(int(1), int(-1)), (int(3), int(0))]
        } else {
            vec![
                (int(2), Value::Bytes(vec![])),
                (int(3), int(if key == 3 { -1 } else { 0 })),
                (int(4), int(if key == 4 { -1 } else { 17 })),
            ]
        };
        assert_eq!(app.call(&request(entries)), [CTAP1_ERR_INVALID_PARAMETER]);
    }
    for parameters in [
        &[][..],
        &[0xa0, 0][..],
        &[0xbf, 0xff][..],
        &[0x80][..],
        &[0xa2, 3, 0, 3, 0][..],
    ] {
        let mut app = test_app([0x81; 16]);
        let mut request = vec![CTAP_CMD_LARGE_BLOBS];
        request.extend(parameters);
        assert_eq!(app.call(&request), [CTAP2_ERR_INVALID_CBOR]);
    }
}

#[test]
fn single_and_multiple_fragments_commit_only_the_complete_valid_array() {
    for length in [17, 1704, 1705, 3408, 4097, 16384] {
        let mut app = test_app([0x81; 16]);
        let bytes = array(length);
        commit(&mut app, &bytes, None);
        let mut actual = Vec::new();
        for offset in (0..length).step_by(1704) {
            actual.extend(read(&mut app, offset, 1704));
        }
        assert_eq!(actual, bytes);
    }
    let store = TestStore::new();
    let mut app = new_app(store.clone(), [0x81; 16]);
    let bytes = array(1705);
    assert_eq!(
        app.call(&write_request(0, Some(bytes.len()), &bytes[..1704], None)),
        [CTAP2_OK]
    );
    assert_eq!(store.large_blob_array().unwrap(), INITIAL_LARGE_BLOB_ARRAY);
    assert_eq!(
        app.call(&write_request(1704, None, &bytes[1704..], None)),
        [CTAP2_OK]
    );
    assert_eq!(store.large_blob_array().unwrap(), bytes);
}

#[test]
fn wrong_hash_and_fragments_past_the_expected_length_leave_old_bytes() {
    let mut app = test_app([0x81; 16]);
    let old = array(33);
    commit(&mut app, &old, None);
    assert_eq!(
        app.call(&write_request(0, Some(17), &[0; 18], None)),
        [CTAP1_ERR_INVALID_PARAMETER]
    );
    assert_eq!(
        app.call(&write_request(0, Some(17), &[0; 17], None)),
        [CTAP2_ERR_INTEGRITY_FAILURE]
    );
    assert_eq!(
        app.call(&write_request(17, None, &[], None)),
        [CTAP1_ERR_INVALID_SEQ]
    );
    assert_eq!(read(&mut app, 0, 1704), old);
    let bytes = array(20);
    assert_eq!(
        app.call(&write_request(0, Some(20), &bytes[..10], None)),
        [CTAP2_OK]
    );
    assert_eq!(
        app.call(&write_request(10, None, &[0; 11], None)),
        [CTAP1_ERR_INVALID_PARAMETER]
    );
    assert_eq!(
        app.call(&write_request(10, None, &bytes[10..], None)),
        [CTAP2_OK]
    );
    assert_eq!(read(&mut app, 0, 1704), bytes);
}

#[test]
fn continuation_length_order_and_empty_fragments_preserve_protocol_counters() {
    let mut app = test_app([0x81; 16]);
    let bytes = array(33);
    assert_eq!(app.call(&write_request(0, Some(33), &[], None)), [CTAP2_OK]);
    assert_eq!(
        app.call(&write_request(0, None, &bytes[..10], None)),
        [CTAP1_ERR_INVALID_PARAMETER]
    );
    assert_eq!(
        app.call(&write_request(0, Some(33), &bytes[..10], None)),
        [CTAP2_OK]
    );
    assert_eq!(
        app.call(&write_request(10, Some(33), &bytes[10..], None)),
        [CTAP1_ERR_INVALID_PARAMETER]
    );
    assert_eq!(app.call(&write_request(10, None, &[], None)), [CTAP2_OK]);
    assert_eq!(
        app.call(&write_request(10, None, &bytes[10..], None)),
        [CTAP2_OK]
    );
    assert_eq!(app.call(&write_request(33, None, &[], None)), [CTAP2_OK]);
    assert_eq!(read(&mut app, 0, 1704), bytes);
    assert_eq!(
        app.call(&write_request(0, Some(33), &bytes[..10], None)),
        [CTAP2_OK]
    );
    assert_eq!(
        app.call(&write_request(11, None, &bytes[11..], None)),
        [CTAP1_ERR_INVALID_SEQ]
    );
    assert_eq!(
        app.call(&write_request(10, None, &bytes[10..], None)),
        [CTAP1_ERR_INVALID_SEQ]
    );
    assert_eq!(read(&mut app, 0, 1704), bytes);
}

#[test]
fn protected_writes_require_authentication_and_lbw_for_both_protocols() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0x81; 16]);
        install_pin_uv_auth_token(
            &mut app,
            protocol,
            TOKEN,
            PIN_PERMISSION_LBW,
            Some("unrelated.example"),
        );
        let bytes = array(1705);
        let auth = Some((protocol, &TOKEN));
        let mut cases = Vec::new();
        cases.push((
            write_request(0, Some(17), &bytes[..17], None),
            CTAP2_ERR_PUAT_REQUIRED,
        ));
        cases.push((
            request(vec![
                (int(2), Value::Bytes(bytes[..17].to_vec())),
                (int(3), int(0)),
                (int(4), int(17)),
                (int(5), Value::Bytes(vec![])),
            ]),
            CTAP2_ERR_MISSING_PARAMETER,
        ));
        for (value, status) in [
            (int(3), CTAP1_ERR_INVALID_PARAMETER),
            (Value::Null, CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
        ] {
            cases.push((
                request(vec![
                    (int(2), Value::Bytes(bytes[..17].to_vec())),
                    (int(3), int(0)),
                    (int(4), int(17)),
                    (int(5), Value::Bytes(vec![])),
                    (int(6), value),
                ]),
                status,
            ));
        }
        cases.push((
            write_request(0, Some(17), &bytes[..17], Some((protocol, &[0; 32]))),
            CTAP2_ERR_PIN_AUTH_INVALID,
        ));
        for (request, status) in cases {
            assert_eq!(app.call(&request), [status]);
        }
        commit(&mut app, &bytes, auth);
        assert_eq!(read(&mut app, 0, 1704), bytes[..1704]);
        install_pin_uv_auth_token(&mut app, protocol, TOKEN, PIN_PERMISSION_MC, None);
        assert_eq!(
            app.call(&write_request(0, Some(17), &INITIAL_LARGE_BLOB_ARRAY, auth)),
            [CTAP2_ERR_PIN_AUTH_INVALID]
        );
    }
}

#[test]
fn always_uv_needs_authentication_even_without_a_pin() {
    let mut app = test_app([0x81; 16]);
    let mut persistent = app.pin_state.persistent().clone();
    persistent.always_uv = true;
    app.pin_state.adopt_persistent(persistent);
    assert!(!app.pin_state.is_set());
    assert_eq!(
        app.call(&write_request(0, Some(17), &INITIAL_LARGE_BLOB_ARRAY, None)),
        [CTAP2_ERR_PUAT_REQUIRED]
    );
    assert_eq!(
        app.call(&write_request(
            0,
            Some(17),
            &INITIAL_LARGE_BLOB_ARRAY,
            Some((ClassicPinProtocol::V2, &TOKEN))
        )),
        [CTAP2_ERR_PIN_AUTH_INVALID]
    );
}

#[test]
fn always_uv_with_a_pin_and_authentication_type_failures_follow_spec_order() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0x81; 16]);
        install_pin_uv_auth_token(&mut app, protocol, TOKEN, PIN_PERMISSION_LBW, None);
        let mut persistent = app.pin_state.persistent().clone();
        persistent.always_uv = true;
        app.pin_state.adopt_persistent(persistent);
        assert_eq!(
            app.call(&request(vec![
                (int(2), Value::Bytes(vec![0; 18])),
                (int(3), int(0)),
                (int(4), int(17)),
                (int(5), Value::Bool(true)),
                (int(6), int(protocol.identifier().into())),
            ])),
            [CTAP2_ERR_CBOR_UNEXPECTED_TYPE]
        );
        assert_eq!(
            app.call(&write_request(
                0,
                Some(17),
                &[0; 18],
                Some((protocol, &[0; 32]))
            )),
            [CTAP2_ERR_PIN_AUTH_INVALID]
        );
        assert_eq!(
            app.call(&write_request(
                0,
                Some(17),
                &[0; 18],
                Some((protocol, &TOKEN))
            )),
            [CTAP1_ERR_INVALID_PARAMETER]
        );
        commit(&mut app, &array(1705), Some((protocol, &TOKEN)));
    }
}

#[test]
fn rejected_initial_fragments_reset_counters_before_authentication() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0x81; 16]);
        install_pin_uv_auth_token(&mut app, protocol, TOKEN, PIN_PERMISSION_LBW, None);
        let old = array(33);
        commit(&mut app, &old, Some((protocol, &TOKEN)));
        let new = array(40);
        assert_eq!(
            app.call(&write_request(
                0,
                Some(40),
                &new[..10],
                Some((protocol, &TOKEN))
            )),
            [CTAP2_OK]
        );
        assert_eq!(
            app.call(&write_request(0, Some(17), &INITIAL_LARGE_BLOB_ARRAY, None)),
            [CTAP2_ERR_PUAT_REQUIRED]
        );
        assert_eq!(
            app.call(&write_request(
                10,
                None,
                &new[10..],
                Some((protocol, &TOKEN))
            )),
            [CTAP1_ERR_INVALID_SEQ]
        );
        assert_eq!(read(&mut app, 0, 1704), old);
    }
}

#[test]
fn lbw_tokens_are_granted_and_survive_user_presence() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0x81; 16]);
        app.pin_state.set_pin(pin_hash(b"1234"));
        let permissions = PIN_PERMISSION_MC | PIN_PERMISSION_LBW;
        let token = get_pin_uv_auth_token(
            &mut app,
            protocol,
            b"1234",
            permissions.into(),
            Some("example.com"),
        )
        .unwrap();
        assert_eq!(app.pin_state.pin_uv_auth_permissions(), permissions);
        let hash = [0x18; 32];
        app.handle_make_credential(&make_credential_request(
            &hash,
            "example.com",
            Some((protocol, token_pin_auth(protocol, &token, &hash))),
        ))
        .unwrap();
        assert_eq!(app.pin_state.pin_uv_auth_permissions(), PIN_PERMISSION_LBW);
        assert!(!app.pin_state.user_verified_flag());
        assert_eq!(
            app.call(&write_request(
                0,
                Some(17),
                &INITIAL_LARGE_BLOB_ARRAY,
                Some((protocol, &token))
            )),
            [CTAP2_OK]
        );
    }
}

#[test]
fn another_command_or_get_discards_the_pending_write() {
    let mut commands = vec![
        vec![],
        vec![CTAP_CMD_GET_INFO],
        vec![CTAP_CMD_SELECTION],
        vec![0xff],
        vec![CTAP_CMD_CLIENT_PIN, 0xa0],
        vec![CTAP_CMD_LARGE_BLOBS, 0x80],
    ];
    commands.push(request(vec![(int(1), int(1704)), (int(3), int(0))]));
    for command in commands {
        let mut app = test_app([0x81; 16]);
        let bytes = array(33);
        assert_eq!(
            app.call(&write_request(0, Some(33), &bytes[..10], None)),
            [CTAP2_OK]
        );
        app.call(&command);
        assert_eq!(
            app.call(&write_request(10, None, &bytes[10..], None)),
            [CTAP1_ERR_INVALID_SEQ]
        );
        assert_eq!(read(&mut app, 0, 1704), INITIAL_LARGE_BLOB_ARRAY);
    }
}

#[test]
fn idle_timeout_restarts_after_each_fragment_and_drops_at_thirty_seconds() {
    let mut app = test_app([0x81; 16]);
    let clock = ManualClock::default();
    app.set_clock(clock.clone());
    let bytes = array(33);
    assert_eq!(
        app.call(&write_request(0, Some(33), &bytes[..1], None)),
        [CTAP2_OK]
    );
    clock.advance(Duration::from_millis(29999));
    assert_eq!(
        app.call(&write_request(1, None, &bytes[1..2], None)),
        [CTAP2_OK]
    );
    clock.advance(Duration::from_millis(29999));
    assert_eq!(
        app.call(&write_request(2, None, &bytes[2..3], None)),
        [CTAP2_OK]
    );
    clock.advance(Duration::from_secs(30));
    assert_eq!(
        app.call(&write_request(3, None, &bytes[3..], None)),
        [CTAP1_ERR_INVALID_SEQ]
    );
    assert_eq!(read(&mut app, 0, 1704), INITIAL_LARGE_BLOB_ARRAY);
}

#[test]
fn token_expiry_and_replacement_drop_state_before_authentication() {
    for protocol in PROTOCOLS {
        let mut app = test_app([0x81; 16]);
        let clock = ManualClock::default();
        app.set_clock(clock.clone());
        install_pin_uv_auth_token(&mut app, protocol, TOKEN, PIN_PERMISSION_LBW, None);
        let bytes = array(100);
        for offset in 0..21 {
            if offset != 0 {
                clock.advance(Duration::from_secs(29));
            }
            assert_eq!(
                app.call(&write_request(
                    offset,
                    (offset == 0).then_some(100),
                    &bytes[offset as usize..offset as usize + 1],
                    Some((protocol, &TOKEN))
                )),
                [CTAP2_OK]
            );
        }
        clock.advance(Duration::from_secs(20));
        assert_eq!(
            app.call(&write_request(
                21,
                None,
                &bytes[21..],
                Some((protocol, &TOKEN))
            )),
            [CTAP1_ERR_INVALID_SEQ]
        );
        assert_eq!(read(&mut app, 0, 1704), INITIAL_LARGE_BLOB_ARRAY);
        install_pin_uv_auth_token(&mut app, protocol, TOKEN, PIN_PERMISSION_LBW, None);
        assert_eq!(
            app.call(&write_request(
                0,
                Some(100),
                &bytes[..10],
                Some((protocol, &TOKEN))
            )),
            [CTAP2_OK]
        );
        install_pin_uv_auth_token(&mut app, protocol, [0x87; 32], PIN_PERMISSION_LBW, None);
        assert_eq!(
            app.call(&write_request(
                10,
                None,
                &bytes[10..],
                Some((protocol, &[0x87; 32]))
            )),
            [CTAP1_ERR_INVALID_SEQ]
        );
        install_pin_uv_auth_token(&mut app, protocol, TOKEN, PIN_PERMISSION_LBW, None);
        assert_eq!(
            app.call(&write_request(
                0,
                Some(100),
                &bytes[..10],
                Some((protocol, &TOKEN))
            )),
            [CTAP2_OK]
        );
        app.pin_state.invalidate_pin_uv_auth_tokens();
        assert_eq!(
            app.call(&write_request(
                10,
                None,
                &bytes[10..],
                Some((protocol, &TOKEN))
            )),
            [CTAP1_ERR_INVALID_SEQ]
        );
    }
}

#[test]
fn read_and_write_failures_and_reset_preserve_their_contracts() {
    let store = TestStore::new();
    let mut app = new_app(store.clone(), [0x81; 16]);
    let bytes = array(33);
    commit(&mut app, &bytes, None);
    store.faults(|faults| faults.large_blob_array = true);
    assert_eq!(read(&mut app, 0, 1704), INITIAL_LARGE_BLOB_ARRAY);
    store.faults(|faults| {
        faults.large_blob_array = false;
        faults.set_large_blob_array = true;
    });
    assert_eq!(
        app.call(&write_request(0, Some(17), &INITIAL_LARGE_BLOB_ARRAY, None)),
        [CTAP2_ERR_PROCESSING]
    );
    assert_eq!(read(&mut app, 0, 1704), bytes);
    store.faults(|faults| faults.set_large_blob_array = false);
    let mut restarted = new_app(store.clone(), [0x81; 16]);
    assert_eq!(read(&mut restarted, 0, 1704), bytes);
    assert_eq!(
        restarted.call(&write_request(0, Some(33), &bytes[..1], None)),
        [CTAP2_OK]
    );
    assert_eq!(restarted.call(&[CTAP_CMD_RESET]), [CTAP2_OK]);
    assert_eq!(
        restarted.call(&write_request(1, None, &bytes[1..], None)),
        [CTAP1_ERR_INVALID_SEQ]
    );
    assert_eq!(read(&mut restarted, 0, 1704), INITIAL_LARGE_BLOB_ARRAY);
}

#[test]
fn request_logging_reads_the_large_blob_pin_protocol_without_secret_bytes() {
    let request = write_request(
        0,
        Some(17),
        &INITIAL_LARGE_BLOB_ARRAY,
        Some((ClassicPinProtocol::V2, &TOKEN)),
    );
    let log = CtapApp::request_log_line(&request, &[CTAP2_OK]);
    assert!(log.contains("sub=n/a pinProtocol=0x02"), "{log}");
}
