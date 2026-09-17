//! authenticatorGetInfo tests.

use super::support::{es256_credential, insert_owned, new_app, test_app, TestApp, TestStore};
use crate::ctap::cbor::canonical_map;
use crate::ctap::pin::protocol::{
    PIN_UV_AUTH_PROTOCOL_CLASSIC_V1, PIN_UV_AUTH_PROTOCOL_CLASSIC_V2,
};
use crate::ctap::pin::state::PinState;
use crate::CoseAlg;

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};

use crate::ctap::constants::*;

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn uint(value: u64) -> Value {
    Value::Integer(Integer::from(value))
}

/// The exact getInfo response for a PIN that is (`pin_set`) or is not set
/// and `remaining` free credential slots, in canonical CBOR.
fn assert_get_info_response(app: &mut TestApp, aaguid: [u8; 16], pin_set: bool, remaining: u64) {
    let response = app.handle_get_info().expect("getInfo succeeds");
    assert_eq!(response[0], CTAP2_OK);

    let options = canonical_map(vec![
        (text("rk"), Value::Bool(true)),
        (text("up"), Value::Bool(true)),
        (text("credMgmt"), Value::Bool(true)),
        (text("pinUvAuthToken"), Value::Bool(true)),
        (text("clientPin"), Value::Bool(pin_set)),
        (text("makeCredUvNotRqd"), Value::Bool(true)),
    ]);

    let extensions = Value::Array(vec![text("credProtect"), text("hmac-secret")]);

    let algorithms = Value::Array(
        [
            CoseAlg::ES256,
            CoseAlg::MLDSA44,
            CoseAlg::MLDSA65,
            CoseAlg::MLDSA87,
        ]
        .into_iter()
        .map(|alg| {
            canonical_map(vec![
                (text("type"), text("public-key")),
                (text("alg"), Value::Integer(Integer::from(alg as i32))),
            ])
        })
        .collect(),
    );

    let expected_map = canonical_map(vec![
        (
            uint(1),
            Value::Array(vec![text("FIDO_2_1"), text("FIDO_2_0")]),
        ),
        (uint(2), extensions),
        (uint(3), Value::Bytes(aaguid.to_vec())),
        (uint(4), options),
        (uint(5), uint(2048)),
        (
            uint(6),
            Value::Array(vec![
                Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC_V2)),
                Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC_V1)),
            ]),
        ),
        (uint(7), uint(8)),
        (uint(8), uint(128)),
        (uint(9), Value::Array(vec![text("usb")])),
        (uint(10), algorithms),
        (uint(13), uint(PinState::MIN_PIN_LENGTH as u64)),
        (uint(0x14), uint(remaining)),
    ]);

    let mut expected_bytes = Vec::new();
    into_writer(&expected_map, &mut expected_bytes).expect("encode expected getInfo map");
    assert_eq!(expected_bytes, &response[1..]);
}

fn options(app: &mut TestApp) -> Vec<(Value, Value)> {
    let response = app.handle_get_info().expect("getInfo succeeds");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode getInfo") else {
        panic!("getInfo must be a map");
    };
    map.into_iter()
        .find_map(|(key, value)| match value {
            Value::Map(options) if key == uint(4) => Some(options),
            _ => None,
        })
        .expect("options present")
}

#[test]
fn get_info_response_encoding_is_canonical_with_pin_unset() {
    let aaguid = [0xAB; 16];
    let mut app = new_app(TestStore::with_max_credentials(5), aaguid);

    assert_get_info_response(&mut app, aaguid, false, 5);
}

#[test]
fn get_info_response_encoding_is_canonical_with_pin_set() {
    let aaguid = [0xAB; 16];
    let mut app = new_app(TestStore::with_max_credentials(5), aaguid);
    app.pin_state.set_pin([0x11; 16]);
    insert_owned(&mut app, es256_credential("example.com", &[0x01]));

    assert_get_info_response(&mut app, aaguid, true, 4);
}

/// clientPin: "If present and set to false, it indicates that the device is
/// capable of accepting a PIN from the client and PIN has not been set yet."
/// (CTAP 2.3 §6.4)
#[test]
fn client_pin_option_reports_whether_a_pin_is_set() {
    let mut app = test_app([0xAC; 16]);
    assert!(options(&mut app).contains(&(text("clientPin"), Value::Bool(false))));
    app.pin_state.set_pin([0x11; 16]);
    assert!(options(&mut app).contains(&(text("clientPin"), Value::Bool(true))));
}

/// uv: "A device that can only do Client PIN will not return the "uv" option
/// id." (CTAP 2.3 §6.4)
#[test]
fn uv_option_is_absent_without_built_in_user_verification() {
    let mut app = test_app([0xAD; 16]);
    assert!(options(&mut app).iter().all(|(key, _)| *key != text("uv")));
}

/// A store that cannot be counted leaves remainingDiscoverableCredentials out
/// instead of failing getInfo.
#[test]
fn get_info_omits_remaining_credentials_when_the_store_cannot_count() {
    let store = TestStore::new();
    let mut app = new_app(store.clone(), [0xAE; 16]);
    store.faults(|faults| faults.list = true);
    let response = app.handle_get_info().expect("getInfo succeeds");
    let Value::Map(map) = from_reader(&response[1..]).expect("decode getInfo") else {
        panic!("getInfo must be a map");
    };
    assert!(map.iter().all(|(key, _)| *key != uint(0x14)));
}
