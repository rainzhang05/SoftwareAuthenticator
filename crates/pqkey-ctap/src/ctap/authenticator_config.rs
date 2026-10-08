//! authenticatorConfig and its persistent user-verification settings.

use super::CtapApp;
use super::cbor;
use super::pin::permissions::PIN_PERMISSION_ACFG;
use super::pin::protocol::parse_required_pin_uv_auth_protocol;
use crate::store::PinStateRecord;

use ciborium::value::{Integer, Value};

use crate::ctap::constants::*;

const TOGGLE_ALWAYS_UV: u8 = 0x02;
const SET_MIN_PIN_LENGTH: u8 = 0x03;

impl CtapApp<'_> {
    /// authenticatorConfig, in the order of CTAP 2.3 §6.11.
    pub(super) fn handle_authenticator_config(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        let map = cbor::request_parameters(payload)?;
        let parameter = |key: i64| cbor::map_get(&map, Value::Integer(Integer::from(key)));
        let subcommand = match parameter(1) {
            Some(Value::Integer(number)) => match i128::from(*number) {
                2 => TOGGLE_ALWAYS_UV,
                3 => SET_MIN_PIN_LENGTH,
                _ => return Err(CTAP1_ERR_INVALID_PARAMETER),
            },
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        // The exception lets a key without a PIN turn always-UV off again.
        let protected = self.pin_state.is_set();
        let always_uv = self.pin_state.persistent().always_uv;
        let toggle_exception = subcommand == TOGGLE_ALWAYS_UV && !protected && always_uv;
        if !toggle_exception && (protected || always_uv) {
            let auth = parameter(4).ok_or(CTAP2_ERR_PUAT_REQUIRED)?;
            let protocol = parse_required_pin_uv_auth_protocol(parameter(3))?;
            let Value::Bytes(auth) = auth else {
                return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            };
            let mut message = vec![0xff; 32];
            message.extend_from_slice(&[CTAP_CMD_AUTHENTICATOR_CONFIG, subcommand]);
            if let Some(raw_params) =
                cbor::raw_map_value(payload, 2).map_err(|()| CTAP2_ERR_INVALID_CBOR)?
            {
                message.extend_from_slice(raw_params);
            }
            self.verify_pin_uv_auth_param(protocol, &message, auth)?;
            if !self.pin_state.has_permission(PIN_PERMISSION_ACFG) {
                return Err(CTAP2_ERR_PIN_AUTH_INVALID);
            }
        }
        // Params are authenticated before their types and subcommand rules
        // are processed. toggleAlwaysUv ignores their contents (§6.11.2).
        let params = match parameter(2) {
            Some(Value::Map(params)) => Some(params.as_slice()),
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => None,
        };
        match subcommand {
            TOGGLE_ALWAYS_UV => {
                let mut persistent = self.pin_state.persistent().clone();
                persistent.always_uv = !always_uv;
                self.save_pin_state(&persistent)?;
                self.pin_state.adopt_persistent(persistent);
            }
            SET_MIN_PIN_LENGTH => self.set_min_pin_length(params.unwrap_or_default())?,
            _ => return Err(CTAP1_ERR_INVALID_PARAMETER),
        }
        Ok(vec![CTAP2_OK])
    }

    /// Validate every requested change before the single persistent write.
    fn set_min_pin_length(&mut self, params: &[(Value, Value)]) -> Result<(), u8> {
        let parameter = |key: i64| cbor::map_get(params, Value::Integer(Integer::from(key)));
        let mut persistent = self.pin_state.persistent().clone();
        let minimum = match parameter(1) {
            Some(Value::Integer(number)) => {
                u64::try_from(*number).map_err(|_| CTAP1_ERR_INVALID_PARAMETER)?
            }
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => u64::from(persistent.min_pin_length),
        };
        if minimum < u64::from(persistent.min_pin_length) {
            return Err(CTAP2_ERR_PIN_POLICY_VIOLATION);
        }
        if minimum > u64::from(PinStateRecord::MAX_PIN_LENGTH) {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }
        let bool_parameter = |key| match parameter(key) {
            Some(Value::Bool(value)) => Ok(*value),
            Some(_) => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => Ok(false),
        };
        if bool_parameter(3)? {
            if !self.pin_state.is_set() {
                return Err(CTAP2_ERR_PIN_NOT_SET);
            }
            persistent.force_pin_change = true;
        }
        // No complexity policy is implemented. The draft has no unsupported
        // policy branch; rejecting true avoids advertising an unenforced one.
        if bool_parameter(4)? {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }
        if self.pin_state.is_set() && u64::from(persistent.pin_code_point_length) < minimum {
            persistent.force_pin_change = true;
        }
        if let Some(rp_ids) = parameter(2) {
            let Value::Array(rp_ids) = rp_ids else {
                return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            };
            let rp_ids = rp_ids
                .iter()
                .map(|value| match value {
                    Value::Text(rp_id) => Ok(rp_id.clone()),
                    _ => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
                })
                .collect::<Result<Vec<_>, _>>()?;
            if rp_ids.len() > PinStateRecord::MAX_MIN_PIN_LENGTH_RP_IDS
                || rp_ids
                    .iter()
                    .any(|rp| rp.len() > PinStateRecord::MAX_RP_ID_LENGTH)
            {
                return Err(CTAP2_ERR_KEY_STORE_FULL);
            }
            // §6.11.4 step 8 only replaces a list containing a string.
            if !rp_ids.is_empty() {
                persistent.min_pin_length_rp_ids = rp_ids;
            }
        }
        persistent.min_pin_length = minimum as u8;
        self.save_pin_state(&persistent)?;
        if persistent.force_pin_change {
            self.pin_state.invalidate_pin_uv_auth_tokens();
        }
        self.pin_state.adopt_persistent(persistent);
        Ok(())
    }
}
