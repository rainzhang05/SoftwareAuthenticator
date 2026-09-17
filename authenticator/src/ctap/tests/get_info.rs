//! authenticatorGetInfo tests.

use super::support::{test_app, TestClient};
use crate::ctap::cbor::canonical_map;
use crate::ctap::pin::protocol::{
    PIN_UV_AUTH_PROTOCOL_CLASSIC_V1, PIN_UV_AUTH_PROTOCOL_CLASSIC_V2,
};
use crate::ctap::pin::state::PinState;
use crate::ctap::CtapApp;
use crate::CoseAlg;

use ciborium::{
    ser::into_writer,
    value::{Integer, Value},
};

use crate::ctap::constants::*;

fn assert_get_info_response(app: &mut CtapApp<TestClient>, aaguid: [u8; 16]) {
    let response = app.handle_get_info().expect("getInfo succeeds");
    assert_eq!(response[0], CTAP2_OK);

    let options = canonical_map(vec![
        (Value::Text("rk".into()), Value::Bool(true)),
        (Value::Text("up".into()), Value::Bool(true)),
        (Value::Text("uv".into()), Value::Bool(false)),
        (Value::Text("credMgmt".into()), Value::Bool(true)),
        (Value::Text("pinUvAuthToken".into()), Value::Bool(true)),
        (Value::Text("clientPin".into()), Value::Bool(true)),
    ]);

    let extensions = Value::Array(vec![
        Value::Text("credProtect".into()),
        Value::Text("hmac-secret".into()),
    ]);

    let algorithms = Value::Array(vec![
        canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (
                Value::Text("alg".into()),
                Value::Integer(Integer::from(CoseAlg::ES256 as i32)),
            ),
        ]),
        canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (
                Value::Text("alg".into()),
                Value::Integer(Integer::from(CoseAlg::MLDSA44 as i32)),
            ),
        ]),
        canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (
                Value::Text("alg".into()),
                Value::Integer(Integer::from(CoseAlg::MLDSA65 as i32)),
            ),
        ]),
        canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (
                Value::Text("alg".into()),
                Value::Integer(Integer::from(CoseAlg::MLDSA87 as i32)),
            ),
        ]),
    ]);

    let expected_map = canonical_map(vec![
        (
            Value::Integer(Integer::from(1)),
            Value::Array(vec![
                Value::Text("FIDO_2_1".into()),
                Value::Text("FIDO_2_0".into()),
            ]),
        ),
        (Value::Integer(Integer::from(2)), extensions),
        (
            Value::Integer(Integer::from(3)),
            Value::Bytes(aaguid.to_vec()),
        ),
        (Value::Integer(Integer::from(4)), options),
        (
            Value::Integer(Integer::from(5)),
            Value::Integer(Integer::from(2048)),
        ),
        (
            Value::Integer(Integer::from(6)),
            Value::Array(vec![
                Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC_V2)),
                Value::Integer(Integer::from(PIN_UV_AUTH_PROTOCOL_CLASSIC_V1)),
            ]),
        ),
        (
            Value::Integer(Integer::from(8)),
            Value::Integer(Integer::from(128)),
        ),
        (
            Value::Integer(Integer::from(9)),
            Value::Array(vec![Value::Text("usb".into())]),
        ),
        (Value::Integer(Integer::from(10)), algorithms),
        (
            Value::Integer(Integer::from(13)),
            Value::Integer(Integer::from(PinState::MIN_PIN_LENGTH as u64)),
        ),
    ]);

    let mut expected_bytes = Vec::new();
    into_writer(&expected_map, &mut expected_bytes).expect("encode expected getInfo map");
    assert_eq!(expected_bytes, &response[1..]);
}

#[test]
fn get_info_response_encoding_is_canonical_with_pin_unset() {
    let aaguid = [0xAB; 16];
    let mut app = test_app(aaguid);

    assert_get_info_response(&mut app, aaguid);
}

#[test]
fn get_info_response_encoding_is_canonical_with_pin_set() {
    let aaguid = [0xAB; 16];
    let mut app = test_app(aaguid);
    let pin_hash = [0x11; 16];
    app.pin_state.set_pin(pin_hash);

    assert_get_info_response(&mut app, aaguid);
}
