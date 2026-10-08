//! Fragmented reads and writes of the serialized large-blob array (§6.10.2).

use super::CtapApp;
use super::cbor;
use super::get_info::MAX_MSG_SIZE;
use super::pin::permissions::PIN_PERMISSION_LBW;
use super::pin::protocol::parse_required_pin_uv_auth_protocol;
use super::storage::store_status;
use crate::store::{INITIAL_LARGE_BLOB_ARRAY, MAX_SERIALIZED_LARGE_BLOB_ARRAY};

use ciborium::{ser::into_writer, value::Value};
use core::time::Duration;
use sha2::{Digest, Sha256};

use crate::ctap::constants::*;

pub(super) const MAX_FRAGMENT_LENGTH: u64 = MAX_MSG_SIZE - 64;
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The protocol counters and staging buffer are volatile, including after a
/// completed transfer until a new write or another command discards them.
#[derive(Default)]
pub(super) struct LargeBlobState {
    expected_next_offset: u64,
    expected_length: u64,
    buffer: Vec<u8>,
    last_fragment: Option<Duration>,
    token: Option<u64>,
}

fn unsigned(value: &Value) -> Result<u64, u8> {
    match value {
        Value::Integer(number) => u64::try_from(*number).map_err(|_| CTAP1_ERR_INVALID_PARAMETER),
        _ => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

impl CtapApp<'_> {
    /// Observe state lifetime before any command, including malformed ones.
    pub(super) fn observe_large_blob_state(&mut self, command: Option<u8>) {
        let now = self.pin_state.now();
        let expired = self
            .large_blob_state
            .last_fragment
            .is_some_and(|last| now.saturating_sub(last) >= WRITE_TIMEOUT);
        let token_changed = self.large_blob_state.token.is_some()
            && self.large_blob_state.token != self.pin_state.pin_uv_auth_token_id();
        if command != Some(CTAP_CMD_LARGE_BLOBS) || expired || token_changed {
            self.large_blob_state = LargeBlobState::default();
        }
    }

    /// authenticatorLargeBlobs, in the order of CTAP 2.3 §6.10.2.
    pub(super) fn handle_large_blobs(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        self.observe_large_blob_state(Some(CTAP_CMD_LARGE_BLOBS));
        let map = match cbor::request_parameters(payload) {
            Ok(map) => map,
            Err(status) => {
                self.large_blob_state = LargeBlobState::default();
                return Err(status);
            }
        };
        let parameter = |key: i64| cbor::map_get(&map, key.into());
        let get = parameter(1);
        let set = parameter(2);
        // Only a set request can continue a write. In particular a get sees
        // the committed array and discards the staged replacement.
        if get.is_some() || set.is_none() || parameter(3).is_none() {
            self.large_blob_state = LargeBlobState::default();
        }
        let offset = match unsigned(parameter(3).ok_or(CTAP1_ERR_INVALID_PARAMETER)?) {
            Ok(offset) => offset,
            Err(status) => {
                self.large_blob_state = LargeBlobState::default();
                return Err(status);
            }
        };
        if get.is_none() && set.is_none() || get.is_some() && set.is_some() {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }
        if let Some(get) = get {
            if parameter(4).is_some() {
                return Err(CTAP1_ERR_INVALID_PARAMETER);
            }
            if parameter(5).is_some() || parameter(6).is_some() {
                return Err(CTAP1_ERR_INVALID_PARAMETER);
            }
            let get = unsigned(get)?;
            if get > MAX_FRAGMENT_LENGTH {
                return Err(CTAP1_ERR_INVALID_LENGTH);
            }
            let array = self.store.large_blob_array().unwrap_or_else(|err| {
                log::warn!("cannot read the large-blob array ({err}); using the initial array");
                INITIAL_LARGE_BLOB_ARRAY.to_vec()
            });
            if offset > array.len() as u64 {
                return Err(CTAP1_ERR_INVALID_PARAMETER);
            }
            let start = usize::try_from(offset).map_err(|_| CTAP1_ERR_INVALID_PARAMETER)?;
            let count = usize::try_from(get).map_err(|_| CTAP1_ERR_INVALID_LENGTH)?;
            let end = start.saturating_add(count).min(array.len());
            let mut response = vec![CTAP2_OK];
            into_writer(
                &Value::Map(vec![(1.into(), Value::Bytes(array[start..end].to_vec()))]),
                &mut response,
            )
            .map_err(|_| CTAP2_ERR_PROCESSING)?;
            return Ok(response);
        }
        let Some(Value::Bytes(fragment)) = set else {
            self.large_blob_state = LargeBlobState::default();
            return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        };
        if fragment.len() as u64 > MAX_FRAGMENT_LENGTH {
            return Err(CTAP1_ERR_INVALID_LENGTH);
        }
        if offset == 0 {
            let length = unsigned(parameter(4).ok_or(CTAP1_ERR_INVALID_PARAMETER)?)?;
            if length > MAX_SERIALIZED_LARGE_BLOB_ARRAY as u64 {
                return Err(CTAP2_ERR_LARGE_BLOB_STORAGE_FULL);
            }
            if length < 17 {
                return Err(CTAP1_ERR_INVALID_PARAMETER);
            }
            self.large_blob_state.expected_length = length;
            self.large_blob_state.expected_next_offset = 0;
        } else if parameter(4).is_some() {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }
        if offset != self.large_blob_state.expected_next_offset {
            self.large_blob_state = LargeBlobState::default();
            return Err(CTAP1_ERR_INVALID_SEQ);
        }
        let protected = self.pin_state.is_set() || self.pin_state.persistent().always_uv;
        if protected {
            let auth = parameter(5).ok_or(CTAP2_ERR_PUAT_REQUIRED)?;
            let protocol = parse_required_pin_uv_auth_protocol(parameter(6))?;
            let Value::Bytes(auth) = auth else {
                return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            };
            let offset = u32::try_from(offset).map_err(|_| CTAP1_ERR_INVALID_PARAMETER)?;
            let mut message = [0xff; 70];
            message[32..34].copy_from_slice(&[CTAP_CMD_LARGE_BLOBS, 0]);
            message[34..38].copy_from_slice(&offset.to_le_bytes());
            message[38..].copy_from_slice(&Sha256::digest(fragment));
            self.verify_pin_uv_auth_param(protocol, &message, auth)?;
            if !self.pin_state.has_permission(PIN_PERMISSION_LBW) {
                return Err(CTAP2_ERR_PIN_AUTH_INVALID);
            }
        }
        let end = offset
            .checked_add(fragment.len() as u64)
            .ok_or(CTAP1_ERR_INVALID_PARAMETER)?;
        if end > self.large_blob_state.expected_length {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }
        if offset == 0 {
            self.large_blob_state.buffer.clear();
            self.large_blob_state.token = protected
                .then(|| self.pin_state.pin_uv_auth_token_id())
                .flatten();
        }
        self.large_blob_state.buffer.extend_from_slice(fragment);
        self.large_blob_state.expected_next_offset = self.large_blob_state.buffer.len() as u64;
        self.large_blob_state.last_fragment = Some(self.pin_state.now());
        if self.large_blob_state.expected_next_offset == self.large_blob_state.expected_length {
            if crate::store::validate_large_blob_array(&self.large_blob_state.buffer).is_err() {
                self.large_blob_state = LargeBlobState::default();
                return Err(CTAP2_ERR_INTEGRITY_FAILURE);
            }
            self.store
                .set_large_blob_array(&self.large_blob_state.buffer)
                .map_err(|err| store_status("save the large-blob array", err))?;
        }
        Ok(vec![CTAP2_OK])
    }
}
