//! The authenticatorGetInfo command.

use super::cbor::{canonical_map, canonical_sort};
use super::{AttestationMode, CtapApp};
use crate::CoseAlg;
use crate::store::{MAX_CRED_BLOB_LENGTH, PinStateRecord};

use ciborium::{
    ser::into_writer,
    value::{Integer, Value},
};

use crate::ctap::constants::*;

/// maxCredentialCountInList: how many credential descriptors an allowList or
/// excludeList may carry.  The engine looks up any number, so this only has
/// to keep a list of maxCredentialIdLength IDs within maxMsgSize.
pub(super) const MAX_CREDENTIAL_COUNT_IN_LIST: u64 = 8;

/// maxCredentialIdLength.  The engine's own credential IDs are at most 107
/// bytes; longer IDs in a list can never name one of its credentials.
pub(super) const MAX_CREDENTIAL_ID_LENGTH: u64 = 128;

/// maxMsgSize: the largest request platforms should send.  "By default,
/// authenticators MUST support messages of at least 1024 bytes." (CTAP 2.3
/// §8)  It is advertised, not enforced: the engine takes
/// any request the transport delivers, and CTAPHID carries up to 7,609
/// bytes.
///
/// The value is what the daemon's transport is sure to deliver whole.  A
/// platform writes a request's packets as fast as it can, and a uhid device
/// has no flow control: the Linux kernel queues the output reports in a ring
/// of 32 events (UHID_BUFSIZE, one always free) and drops what does not fit
/// ("Output queue is full"), so a request of more packets than that can lose
/// some while the daemon is busy.  30 reports, keeping one slot spare for
/// another event, carry 57 + 29 × 59 = 1,768 bytes, room for an allowList of
/// maxCredentialCountInList IDs of maxCredentialIdLength bytes.
pub(super) const MAX_MSG_SIZE: u64 = 57 + 29 * 59;

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn uint(value: u64) -> Value {
    Value::Integer(Integer::from(value))
}

impl CtapApp<'_> {
    pub(super) fn handle_get_info(&mut self) -> Result<Vec<u8>, u8> {
        let mut map = Vec::new();

        // FIDO_2_3 carries the obligations of CTAP 2.3 §9, all of which hold:
        // the mandatory hmac-secret and credProtect are supported; rk comes
        // with clientPin (true or false as a PIN is or is not set) and credMgmt
        // true, pinUvAuthToken is true, and pinUvAuthProtocols includes 2.
        // minPinLength comes with setMinPINLength; there is no ep option ID.
        // "The
        // string "FIDO_2_2" was not defined for CTAP2.2 and MUST not be
        // present in versions member."
        map.push((
            uint(1),
            Value::Array(vec![text("FIDO_2_3"), text("FIDO_2_1"), text("FIDO_2_0")]),
        ));
        map.push((
            uint(2),
            Value::Array(vec![
                text("credBlob"),
                text("credProtect"),
                text("hmac-secret"),
                text("hmac-secret-mc"),
                text("minPinLength"),
            ]),
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
            (text("authnrCfg"), Value::Bool(true)),
            (
                text("alwaysUv"),
                Value::Bool(self.pin_state.persistent().always_uv),
            ),
            (text("setMinPINLength"), Value::Bool(true)),
            (
                text("makeCredUvNotRqd"),
                Value::Bool(!self.pin_state.persistent().always_uv),
            ),
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

        let algorithms = CoseAlg::ALL
            .into_iter()
            .map(|alg| {
                canonical_map(vec![
                    (text("type"), text("public-key")),
                    (text("alg"), Value::Integer(Integer::from(alg.identifier()))),
                ])
            })
            .collect();
        map.push((uint(10), Value::Array(algorithms)));

        map.push((
            uint(0x0C),
            Value::Bool(self.pin_state.persistent().force_pin_change),
        ));
        map.push((
            uint(0x0D),
            uint(u64::from(self.pin_state.persistent().min_pin_length)),
        ));
        map.push((
            uint(0x10),
            uint(PinStateRecord::MAX_MIN_PIN_LENGTH_RP_IDS as u64),
        ));
        map.push((uint(0x1F), Value::Array(vec![uint(2), uint(3)])));
        // maxCredBlobLength (CTAP 2.3 §6.4), required by §12.2.1.
        map.push((uint(0x0F), uint(MAX_CRED_BLOB_LENGTH as u64)));

        // remainingDiscoverableCredentials: the free slots of the store,
        // which holds the discoverable credentials (and non-discoverable ones
        // with RSA keys or made before sealing); a record's size does
        // not matter to it.  Omitted rather than failing getInfo if the store
        // cannot be counted.
        if let Some(remaining) = self.remaining_credential_slots() {
            map.push((uint(0x14), uint(remaining as u64)));
        }

        // attestationFormats: "List of supported attestation formats. [...]
        // The list MUST NOT include duplicate values nor be empty if present.
        // [...] Support for "none" attestation is implied and MUST be
        // omitted."  Self and basic attestation are both "packed"; with
        // AttestationMode::None makeCredential only ever returns "none", so
        // the list would be empty and is left out.
        match self.attestation_mode {
            AttestationMode::SelfAttestation | AttestationMode::Certificate => {
                map.push((uint(0x16), Value::Array(vec![text("packed")])));
            }
            AttestationMode::None => {}
        }

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
