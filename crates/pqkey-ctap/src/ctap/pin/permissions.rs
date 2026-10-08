//! pinUvAuthToken permission bits and the checks that bind a token to an RP.

use crate::ctap::CtapApp;
use crate::ctap::cbor::{required_bytes, required_map};
use crate::ctap::request;

use ciborium::value::Value;

use crate::ctap::constants::*;

pub(crate) const PIN_PERMISSION_MC: u8 = 0x01;
pub(crate) const PIN_PERMISSION_GA: u8 = 0x02;
pub(crate) const PIN_PERMISSION_CM: u8 = 0x04;
pub(crate) const PIN_PERMISSION_LBW: u8 = 0x10;
pub(crate) const PIN_PERMISSION_ACFG: u8 = 0x20;

/// Every pinUvAuthToken permission CTAP 2.3 §6.5.5.7 defines: mc (0x01),
/// ga (0x02), cm (0x04), be (0x08), lbw (0x10), acfg (0x20) and pcmr (0x40).
const DEFINED_PIN_PERMISSIONS: u8 = 0x7F;

/// The permissions this authenticator can grant.  The others need a feature
/// its authenticatorGetInfo does not advertise (bioEnroll, perCredMgmtRO);
/// credMgmt, largeBlobs and authnrCfg are true.
const SUPPORTED_PIN_PERMISSIONS: u8 = PIN_PERMISSION_MC
    | PIN_PERMISSION_GA
    | PIN_PERMISSION_CM
    | PIN_PERMISSION_LBW
    | PIN_PERMISSION_ACFG;

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
    /// * enumerateCredentialsBegin: only for that RP.  This follows CTAP 2.1,
    ///   not the step text of CTAP 2.3, which contradicts the rest of 2.3:
    ///   - CTAP 2.3 §6.8.4 step 3: "The authenticator verifies that the
    ///     pinUvAuthToken has the cm permission and no associated permissions
    ///     RP ID. If not, return CTAP2_ERR_PIN_AUTH_INVALID."
    ///   - CTAP 2.1 (Proposed Standard, errata 2022-06-21) §6.8.4: "The
    ///     authenticator verifies that the pinUvAuthToken has the cm
    ///     permission and that the pinUvAuthToken does not have an permissions
    ///     RP ID associated or that the pinUvAuthToken permissions RP ID
    ///     matches the RP ID of this request."
    ///   - CTAP 2.3 §6.5.5.7, the cm permission: "The rpId parameter is
    ///     optional, if it is present, the pinUvAuthToken can only be used for
    ///     Credential Management operations on Credentials associated with
    ///     that RP ID."
    ///   - CTAP 2.3 §6.8: "When making the authenticatorGetAssertion request,
    ///     a permissions RP ID is present [...] but now the cm permission will
    ///     only allow you to retrieve credentials related to that
    ///     authenticatorGetAssertion request."
    ///
    ///   This authenticator reports FIDO_2_1 as well as FIDO_2_3, and libfido2
    ///   (1.16 `fido_credman_get_dev_rk`, which OpenSSH's `ssh-keygen -K`
    ///   uses) asks for a token bound to the RP before
    ///   enumerateCredentialsBegin, so refusing it would break CTAP 2.1
    ///   platforms for no gain: such a token reveals no more than the
    ///   deleteCredential and updateUserInformation steps already allow it.
    ///
    /// enumerateRPsGetNextRP and enumerateCredentialsGetNextCredential carry
    /// no pinUvAuthParam and never come here: their begin subcommand did.
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
            0x01 | 0x02 => Err(CTAP2_ERR_PIN_AUTH_INVALID),
            // The same parsing, and so the same status codes, as the
            // subcommands themselves use once a token without an RP ID passes.
            0x04 => {
                let rp_hash = required_bytes(params.ok_or(CTAP2_ERR_MISSING_PARAMETER)?, 1)?;
                if Self::cm_hash_rp_id(&binding) == rp_hash {
                    Ok(())
                } else {
                    Err(CTAP2_ERR_PIN_AUTH_INVALID)
                }
            }
            0x06 | 0x07 => {
                let descriptor = required_map(params.ok_or(CTAP2_ERR_MISSING_PARAMETER)?, 2)?;
                let Some(id) = request::public_key_credential_id(descriptor)? else {
                    return Err(CTAP2_ERR_NO_CREDENTIALS);
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
            _ => Err(CTAP2_ERR_PIN_AUTH_INVALID),
        }
    }
}
