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

/// maxCredentialCountInList: how many credential descriptors an allowList or
/// excludeList may carry.  The engine looks up any number, so this only has
/// to keep a list of maxCredentialIdLength IDs within maxMsgSize.
pub(super) const MAX_CREDENTIAL_COUNT_IN_LIST: u64 = 8;

/// maxCredentialIdLength.  The engine's own credential IDs are much shorter;
/// longer IDs in a list can never name one of its credentials.
pub(super) const MAX_CREDENTIAL_ID_LENGTH: u64 = 128;

/// maxMsgSize: the largest request the engine accepts.
pub(super) const MAX_MSG_SIZE: u64 = 2048;

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn uint(value: u64) -> Value {
    Value::Integer(Integer::from(value))
}

impl CtapApp<'_> {
    pub(super) fn handle_get_info(&mut self) -> Result<Vec<u8>, u8> {
        self.pending_assertion = None;
        let mut map = Vec::new();

        // FIDO_2_3 carries the obligations of CTAP 2.3 §9, all of which hold:
        // hmac-secret and credProtect are supported, the rk option ID comes
        // with clientPin (true or false as a PIN is or is not set) and credMgmt
        // true, pinUvAuthToken is true, and pinUvAuthProtocols includes 2.
        // There is no minPinLength extension and no ep option ID.  "The
        // string "FIDO_2_2" was not defined for CTAP2.2 and MUST not be
        // present in versions member."
        map.push((
            uint(1),
            Value::Array(vec![text("FIDO_2_3"), text("FIDO_2_1"), text("FIDO_2_0")]),
        ));
        map.push((
            uint(2),
            Value::Array(vec![text("credProtect"), text("hmac-secret")]),
        ));
        map.push((uint(3), Value::Bytes(self.aaguid.to_vec())));

        // CTAP 2.3 §6.4 option IDs.  "uv" is absent: "A device that can only
        // do Client PIN will not return the "uv" option id."  "clientPin" is
        // "present and set to false" when the authenticator "is capable of
        // accepting a PIN from the client and PIN has not been set yet".
        let options = canonical_map(vec![
            (text("rk"), Value::Bool(true)),
            (text("up"), Value::Bool(true)),
            (text("credMgmt"), Value::Bool(true)),
            (text("pinUvAuthToken"), Value::Bool(true)),
            (text("clientPin"), Value::Bool(self.pin_state.is_set())),
            // "Authenticators SHOULD include this option with the value true."
            (text("makeCredUvNotRqd"), Value::Bool(true)),
        ]);
        map.push((uint(4), options));

        map.push((uint(5), uint(MAX_MSG_SIZE)));

        let protocols = self
            .supported_pin_uv_protocols()
            .iter()
            .map(|protocol| Value::Integer(Integer::from(*protocol)))
            .collect();
        map.push((uint(6), Value::Array(protocols)));

        map.push((uint(7), uint(MAX_CREDENTIAL_COUNT_IN_LIST)));
        map.push((uint(8), uint(MAX_CREDENTIAL_ID_LENGTH)));

        let transports = Value::Array(vec![text("usb")]);
        map.push((uint(9), transports));

        let algorithms = [
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
        .collect();
        map.push((uint(10), Value::Array(algorithms)));

        map.push((uint(13), uint(PinState::MIN_PIN_LENGTH as u64)));

        // remainingDiscoverableCredentials: every credential takes a slot in
        // the store, whether discoverable or not, and a record's size does not
        // matter to it.  Omitted rather than failing getInfo if the store
        // cannot be counted.
        if let Some(remaining) = self.remaining_credential_slots() {
            map.push((uint(0x14), uint(remaining as u64)));
        }

        // attestationFormats: "Support for "none" attestation is implied and
        // MUST be omitted."
        map.push((uint(0x16), Value::Array(vec![text("packed")])));

        canonical_sort(&mut map);
        let mut encoded = Vec::new();
        into_writer(&Value::Map(map), &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    /// How many more credentials the store accepts, or `None` if it cannot
    /// be counted.
    pub(super) fn remaining_credential_slots(&self) -> Option<usize> {
        match self.store.count() {
            Ok(count) => Some(self.store.max_credentials().saturating_sub(count)),
            Err(err) => {
                log::warn!("cannot count credentials: {err}");
                None
            }
        }
    }
}
