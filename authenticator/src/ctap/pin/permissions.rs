//! pinUvAuthToken permission bits and the checks that bind a token to an RP.

use crate::ctap::cbor;
use crate::ctap::CtapApp;

use ciborium::value::{Integer, Value};
use trussed::client::{Client as TrussedClient, CryptoClient, FilesystemClient};

use transport_core::ctap::constants::*;

pub(crate) const PIN_PERMISSION_MC: u8 = 0x01;
pub(crate) const PIN_PERMISSION_GA: u8 = 0x02;
pub(crate) const PIN_PERMISSION_CM: u8 = 0x04;

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    pub(crate) fn ensure_pin_token_permission_for_rp(
        &mut self,
        permission: u8,
        rp_id: &str,
    ) -> Result<(), u8> {
        if !self.pin_state.has_permission(permission) {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if !self.pin_state.should_bind_pin_token_to_rp() {
            return Ok(());
        }
        match self.pin_state.permissions_rp_id() {
            Some(existing) => {
                if existing != rp_id {
                    return Err(CTAP2_ERR_PIN_AUTH_INVALID);
                }
            }
            None => self.pin_state.set_permissions_rp_id(rp_id),
        }
        Ok(())
    }

    pub(crate) fn ensure_pin_token_permission_for_cm(
        &mut self,
        subcommand: u8,
        params: Option<&[(Value, Value)]>,
    ) -> Result<(), u8> {
        if !self.pin_state.has_permission(PIN_PERMISSION_CM) {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        let Some(binding) = self
            .pin_state
            .permissions_rp_id()
            .map(|value| value.to_string())
        else {
            return Ok(());
        };
        match subcommand {
            0x01 | 0x02 | 0x03 => Err(CTAP2_ERR_PIN_AUTH_INVALID),
            0x04 => {
                let params = params.ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
                let rp_hash = match cbor::map_get(params, Value::Integer(Integer::from(1))) {
                    Some(Value::Bytes(bytes)) => bytes,
                    _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
                };
                if Self::cm_hash_rp_id(&binding) == *rp_hash {
                    Ok(())
                } else {
                    Err(CTAP2_ERR_PIN_AUTH_INVALID)
                }
            }
            0x05 => match self.cred_mgmt_state.current_rp.as_deref() {
                Some(current) if current == binding => Ok(()),
                _ => Err(CTAP2_ERR_PIN_AUTH_INVALID),
            },
            0x06 | 0x07 => {
                let params = params.ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
                let descriptor = match cbor::map_get(params, Value::Integer(Integer::from(2))) {
                    Some(Value::Map(map)) => map,
                    _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
                };
                let Some(Value::Bytes(id)) = cbor::map_get(descriptor, Value::Text("id".into()))
                else {
                    return Err(CTAP2_ERR_MISSING_PARAMETER);
                };
                let credentials = self.load_credentials()?;
                let Some(credential) = credentials.iter().find(|cred| cred.credential_id == *id)
                else {
                    return Err(CTAP2_ERR_NO_CREDENTIALS);
                };
                if credential.rp_id == binding {
                    Ok(())
                } else {
                    Err(CTAP2_ERR_PIN_AUTH_INVALID)
                }
            }
            _ => Ok(()),
        }
    }
}
