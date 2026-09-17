//! pinUvAuthToken permission bits and the checks that bind a token to an RP.

use crate::ctap::CtapApp;
use crate::ctap::cbor;

use ciborium::value::{Integer, Value};

use crate::ctap::constants::*;

pub(crate) const PIN_PERMISSION_MC: u8 = 0x01;
pub(crate) const PIN_PERMISSION_GA: u8 = 0x02;
pub(crate) const PIN_PERMISSION_CM: u8 = 0x04;

/// Every pinUvAuthToken permission CTAP 2.3 §6.5.5.7 defines: mc (0x01),
/// ga (0x02), cm (0x04), be (0x08), lbw (0x10), acfg (0x20) and pcmr (0x40).
const DEFINED_PIN_PERMISSIONS: u8 = 0x7F;

/// The permissions this authenticator can grant.  The others need a feature
/// its authenticatorGetInfo does not advertise (bioEnroll, largeBlobs,
/// authnrCfg, perCredMgmtRO), and credMgmt is true, so cm is authorized.
const SUPPORTED_PIN_PERMISSIONS: u8 = PIN_PERMISSION_MC | PIN_PERMISSION_GA | PIN_PERMISSION_CM;

/// The permissions to assign for a getPinUvAuthTokenUsingPinWithPermissions
/// permissions parameter (already checked to be non-zero), per CTAP 2.3
/// §6.5.5.7.2: "For each pinUvAuthToken permission present in the permissions
/// parameter, if the statement corresponding to the permission is currently
/// true, terminate these steps and return CTAP2_ERR_UNAUTHORIZED_PERMISSION.
/// Undefined permissions present in the permissions parameter are ignored."
pub(crate) fn requested_pin_permissions(permissions: i128) -> Result<u8, u8> {
    let defined = (permissions & i128::from(DEFINED_PIN_PERMISSIONS)) as u8;
    if defined & !SUPPORTED_PIN_PERMISSIONS != 0 {
        return Err(CTAP2_ERR_UNAUTHORIZED_PERMISSION);
    }
    Ok(defined)
}

impl CtapApp<'_> {
    pub(crate) fn ensure_pin_token_permission_for_rp(
        &mut self,
        permission: u8,
        rp_id: &str,
    ) -> Result<(), u8> {
        self.pin_state.authorize_rp_operation(permission, rp_id)
    }

    /// The pinUvAuthToken permission check of authenticatorCredentialManagement
    /// (CTAP 2.3 §6.8).  A token without a permissions RP ID may do anything.
    /// A token scoped to an RP (cm requested together with an rpId):
    ///
    /// * getCredsMetadata and enumerateRPs: refused, they need "the cm
    ///   permission and no associated permissions RP ID" (§6.8.2, §6.8.3).
    /// * deleteCredential and updateUserInformation: only for a credential of
    ///   that RP, "the pinUvAuthToken permissions RP ID matches the RP ID of
    ///   the credential" (§6.8.5, §6.8.6).
    /// * enumerateCredentials: only for that RP.  CTAP 2.1 §6.8.4 allows this
    ///   ("matches the RP ID of this request") and CTAP 2.3 §6.8 still describes
    ///   it for fetching a credential's public key, although 2.3's step text
    ///   asks for no RP ID; libfido2 and OpenSSH request exactly this token.
    pub(crate) fn ensure_pin_token_permission_for_cm(
        &mut self,
        subcommand: u8,
        params: Option<&[(Value, Value)]>,
    ) -> Result<(), u8> {
        if !self.pin_state.has_permission(PIN_PERMISSION_CM) {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        let Some(binding) = self.pin_state.permissions_rp_id() else {
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
                let Some(credential) = self.stored_credential(id)? else {
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
