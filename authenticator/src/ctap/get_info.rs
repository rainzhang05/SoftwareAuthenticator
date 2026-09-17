//! The authenticatorGetInfo command.

use super::cbor::{canonical_map, canonical_sort};
use super::pin::state::PinState;
use super::CtapApp;
use crate::CoseAlg;

use ciborium::{
    ser::into_writer,
    value::{Integer, Value},
};

use crate::ctap::constants::*;

impl CtapApp<'_> {
    pub(super) fn handle_get_info(&mut self) -> Result<Vec<u8>, u8> {
        self.pending_assertion = None;
        let mut map = Vec::new();

        map.push((
            Value::Integer(Integer::from(1)),
            Value::Array(vec![
                Value::Text("FIDO_2_1".into()),
                Value::Text("FIDO_2_0".into()),
            ]),
        ));
        map.push((
            Value::Integer(Integer::from(3)),
            Value::Bytes(self.aaguid.to_vec()),
        ));

        map.push((
            Value::Integer(Integer::from(2)),
            Value::Array(vec![
                Value::Text("credProtect".into()),
                Value::Text("hmac-secret".into()),
            ]),
        ));

        let options = canonical_map(vec![
            (Value::Text("rk".into()), Value::Bool(true)),
            (Value::Text("up".into()), Value::Bool(true)),
            (Value::Text("uv".into()), Value::Bool(false)),
            (Value::Text("credMgmt".into()), Value::Bool(true)),
            (Value::Text("pinUvAuthToken".into()), Value::Bool(true)),
            (Value::Text("clientPin".into()), Value::Bool(true)),
        ]);
        map.push((Value::Integer(Integer::from(4)), options));

        map.push((
            Value::Integer(Integer::from(5)),
            Value::Integer(Integer::from(2048)),
        ));

        let protocols = self
            .supported_pin_uv_protocols()
            .iter()
            .map(|protocol| Value::Integer(Integer::from(*protocol)))
            .collect();
        map.push((Value::Integer(Integer::from(6)), Value::Array(protocols)));

        map.push((
            Value::Integer(Integer::from(8)),
            Value::Integer(Integer::from(128)),
        ));

        map.push((
            Value::Integer(Integer::from(13)),
            Value::Integer(Integer::from(PinState::MIN_PIN_LENGTH as u64)),
        ));

        let algorithms = [
            CoseAlg::ES256,
            CoseAlg::MLDSA44,
            CoseAlg::MLDSA65,
            CoseAlg::MLDSA87,
        ]
        .into_iter()
        .map(|alg| {
            canonical_map(vec![
                (Value::Text("type".into()), Value::Text("public-key".into())),
                (
                    Value::Text("alg".into()),
                    Value::Integer(Integer::from(alg as i32)),
                ),
            ])
        })
        .collect();
        map.push((Value::Integer(Integer::from(10)), Value::Array(algorithms)));

        let transports = Value::Array(vec![Value::Text("usb".into())]);
        map.push((Value::Integer(Integer::from(9)), transports));

        canonical_sort(&mut map);
        let mut encoded = Vec::new();
        into_writer(&Value::Map(map), &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }
}
