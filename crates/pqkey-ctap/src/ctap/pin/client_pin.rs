//! The authenticatorClientPIN command and its subcommands.

use super::permissions::{PIN_PERMISSION_GA, PIN_PERMISSION_MC, requested_pin_permissions};
use super::protocol::{PinProtocol, decrypt, parse_required_pin_uv_auth_protocol, verify};
use super::state::{MAX_PIN_RETRIES, PersistentPinState, PinState};
use crate::PinUvSessionKeys;
use crate::ctap::CtapApp;
use crate::ctap::cbor::{self, canonical_map, required_bytes, required_map};

use ciborium::{
    ser::into_writer,
    value::{Integer, Value},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ctap::constants::*;

/// The authenticatorClientPIN subcommands this authenticator implements
/// (CTAP 2.3 §6.5.5).  getPinUvAuthTokenUsingUvWithPermissions (0x06) and
/// getUVRetries (0x07) need a built-in user verification method, which it
/// does not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientPinSubcommand {
    GetPinRetries,
    GetKeyAgreement,
    SetPin,
    ChangePin,
    GetPinToken,
    GetPinUvAuthTokenUsingPinWithPermissions,
}

impl ClientPinSubcommand {
    /// Parse subCommand (0x02).  "If the authenticator implements a command
    /// code having subcommands, but does not implement an invoked subcommand,
    /// it MUST return CTAP2_ERR_INVALID_SUBCOMMAND." (CTAP 2.3 §8.1)
    fn parse(value: Option<&Value>) -> Result<Self, u8> {
        let number = match value {
            Some(Value::Integer(number)) => i128::from(*number),
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        match number {
            0x01 => Ok(Self::GetPinRetries),
            0x02 => Ok(Self::GetKeyAgreement),
            0x03 => Ok(Self::SetPin),
            0x04 => Ok(Self::ChangePin),
            0x05 => Ok(Self::GetPinToken),
            0x09 => Ok(Self::GetPinUvAuthTokenUsingPinWithPermissions),
            _ => Err(CTAP2_ERR_INVALID_SUBCOMMAND),
        }
    }
}

/// Length of paddedPin: newPin "padded on the right with 0x00 bytes to make
/// it 64 bytes long" (CTAP 2.3 §6.5.5.5).
const PADDED_PIN_LENGTH: usize = 64;

/// "Maximum PIN Length: 63 bytes" (CTAP 2.3 §6.5.1).
const MAX_PIN_BYTES: usize = 63;

/// Recover newPin from the decrypted newPinEnc, as setPIN (CTAP 2.3 §6.5.5.5)
/// and changePIN (§6.5.5.6) specify:
///
/// > If paddedNewPin is NOT 64 bytes long, it returns
/// > CTAP1_ERR_INVALID_PARAMETER. The authenticator drops all trailing 0x00
/// > bytes from paddedNewPin to produce newPin. The authenticator checks the
/// > length of newPin against the current minimum PIN length, returning
/// > CTAP2_ERR_PIN_POLICY_VIOLATION if it is too short.
///
/// The minimum is counted in Unicode code points and the maximum is 63 bytes
/// (§6.5.1: "Minimum PIN Length: 4 code points", "Maximum PIN Length: 63
/// bytes").  A newPin that is not UTF-8 has no length in code points, so it is
/// refused too ("An authenticator MAY impose arbitrary, additional constraints
/// on PINs").
fn decode_new_pin(padded_new_pin: &[u8]) -> Result<Zeroizing<Vec<u8>>, u8> {
    if padded_new_pin.len() != PADDED_PIN_LENGTH {
        return Err(CTAP1_ERR_INVALID_PARAMETER);
    }
    let length = padded_new_pin
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |last| last + 1);
    let new_pin = &padded_new_pin[..length];
    if new_pin.len() > MAX_PIN_BYTES {
        return Err(CTAP2_ERR_PIN_POLICY_VIOLATION);
    }
    let code_points = core::str::from_utf8(new_pin)
        .map_err(|_| CTAP2_ERR_PIN_POLICY_VIOLATION)?
        .chars()
        .count();
    if code_points < PinState::MIN_PIN_LENGTH {
        return Err(CTAP2_ERR_PIN_POLICY_VIOLATION);
    }
    Ok(Zeroizing::new(new_pin.to_vec()))
}

/// CurrentStoredPIN for `pin`: `LEFT(SHA-256(pin), 16)`.
fn hash_pin(pin: &[u8]) -> Zeroizing<[u8; 16]> {
    let digest = Zeroizing::new(Sha256::digest(pin));
    let mut hash = Zeroizing::new([0u8; 16]);
    hash.copy_from_slice(&digest[..16]);
    hash
}

impl CtapApp<'_> {
    /// Decrypt newPinEnc and turn it into the PIN hash to store:
    /// "calls decrypt(shared secret, newPinEnc) to produce paddedNewPin. If an
    /// error results, it returns CTAP2_ERR_PIN_AUTH_INVALID." (CTAP 2.3
    /// §6.5.5.5, §6.5.5.6)
    fn new_pin_hash(
        protocol: PinProtocol,
        keys: &PinUvSessionKeys,
        new_pin_enc: &[u8],
    ) -> Result<Zeroizing<[u8; 16]>, u8> {
        let padded_new_pin =
            decrypt(protocol, keys, new_pin_enc).ok_or(CTAP2_ERR_PIN_AUTH_INVALID)?;
        let new_pin = decode_new_pin(&padded_new_pin)?;
        Ok(hash_pin(&new_pin))
    }

    /// The PIN check of changePIN (CTAP 2.3 §6.5.5.6), getPinToken
    /// (§6.5.5.7.1) and getPinUvAuthTokenUsingPinWithPermissions (§6.5.5.7.2):
    ///
    /// > The authenticator decrements the pinRetries counter by 1.
    /// >
    /// > The authenticator decrypts pinHashEnc using decrypt and verifies
    /// > against its internally stored CurrentStoredPIN.
    ///
    /// The decremented counter is persisted before pinHashEnc is decrypted, so
    /// cutting power part-way through the check still costs a retry.  A
    /// pinHashEnc that fails to decrypt counts as a mismatch ("If an error
    /// results, or a mismatch is detected").
    fn verify_pin_hash_enc(
        &mut self,
        protocol: PinProtocol,
        keys: &PinUvSessionKeys,
        pin_hash_enc: &[u8],
    ) -> Result<(), u8> {
        let attempt = self.pin_state.begin_pin_attempt()?;
        self.save_persistent_pin_state()?;
        let candidate = decrypt(protocol, keys, pin_hash_enc);
        let result = self
            .pin_state
            .finish_pin_attempt(attempt, candidate.as_ref().map(|hash| hash.as_slice()));
        if result.is_err() {
            // "If an error results, or a mismatch is detected, the
            // authenticator performs the following operations: Calls
            // regenerate for the selected pinUvAuthProtocol."
            self.pin_state.key_agreement.regenerate(protocol);
        }
        self.save_persistent_pin_state()?;
        result
    }

    /// getKeyAgreement (CTAP 2.3 §6.5.5.4): "keyAgreement: the result of
    /// calling getPublicKey for the selected pinUvAuthProtocol."  The key is
    /// not regenerated.
    fn client_pin_get_key_agreement(&mut self, protocol: PinProtocol) -> Result<Vec<u8>, u8> {
        let key_map = self.key_agreement_key(protocol)?.cose_key();
        let response = canonical_map(vec![(Value::Integer(Integer::from(1)), key_map)]);
        let mut encoded = Vec::new();
        into_writer(&response, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    /// setPIN (CTAP 2.3 §6.5.5.5).
    fn client_pin_set_pin(&mut self, map: &[(Value, Value)]) -> Result<Vec<u8>, u8> {
        // "If the authenticator does not receive mandatory parameters for this
        // command, it returns CTAP2_ERR_MISSING_PARAMETER error. If
        // pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
        // If a PIN has already been set, authenticator returns
        // CTAP2_ERR_PIN_AUTH_INVALID error."
        let protocol = cbor::map_get(map, Value::Integer(Integer::from(1)));
        let key_agreement = required_map(map, 3)?;
        let pin_auth_param = required_bytes(map, 4)?;
        let new_pin_enc = required_bytes(map, 5)?;
        let protocol = parse_required_pin_uv_auth_protocol(protocol)?;
        if self.pin_state.is_set() {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }

        let keys = self.decapsulate(protocol, key_agreement)?;
        verify(protocol, &keys.auth_key, new_pin_enc, pin_auth_param)?;
        let hash = Self::new_pin_hash(protocol, &keys, new_pin_enc)?;
        self.store_new_pin(&hash)?;
        Ok(vec![CTAP2_OK])
    }

    /// "stores LEFT(SHA-256(newPin), 16) internally as CurrentStoredPIN, sets
    /// the pinRetries counter to maximum count" (CTAP 2.3 §6.5.5.5,
    /// §6.5.5.6).  The new PIN is written first and only then used, so a
    /// failed write leaves the old PIN in force, in memory as on disk.
    fn store_new_pin(&mut self, hash: &[u8; 16]) -> Result<(), u8> {
        self.save_pin_state(&PersistentPinState {
            pin_hash: Some(*hash),
            pin_retries: MAX_PIN_RETRIES,
        })?;
        self.pin_state.set_pin(*hash);
        Ok(())
    }

    /// changePIN (CTAP 2.3 §6.5.5.6).
    fn client_pin_change_pin(&mut self, map: &[(Value, Value)]) -> Result<Vec<u8>, u8> {
        // "If the authenticator does not receive mandatory parameters for this
        // command, it returns CTAP2_ERR_MISSING_PARAMETER error. If
        // pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
        // If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error."
        let protocol = cbor::map_get(map, Value::Integer(Integer::from(1)));
        let key_agreement = required_map(map, 3)?;
        let pin_auth_param = required_bytes(map, 4)?;
        let new_pin_enc = required_bytes(map, 5)?;
        let pin_hash_enc = required_bytes(map, 6)?;
        let protocol = parse_required_pin_uv_auth_protocol(protocol)?;
        self.pin_state.check_pin_attempt_allowed()?;

        let keys = self.decapsulate(protocol, key_agreement)?;
        let mut auth_data = Vec::with_capacity(new_pin_enc.len() + pin_hash_enc.len());
        auth_data.extend_from_slice(new_pin_enc);
        auth_data.extend_from_slice(pin_hash_enc);
        verify(protocol, &keys.auth_key, &auth_data, pin_auth_param)?;
        self.verify_pin_hash_enc(protocol, &keys, pin_hash_enc)?;

        let hash = Self::new_pin_hash(protocol, &keys, new_pin_enc)?;
        self.store_new_pin(&hash)?;
        Ok(vec![CTAP2_OK])
    }

    /// The shared tail of getPinToken and
    /// getPinUvAuthTokenUsingPinWithPermissions, once their parameters have
    /// been validated.  Neither takes a pinUvAuthParam (CTAP 2.3 §6.5.5.7.1 and
    /// §6.5.5.7.2): proof of the PIN is pinHashEnc itself, so a pinUvAuthParam
    /// sent anyway is ignored rather than verified.
    fn client_pin_get_token_common(
        &mut self,
        protocol: PinProtocol,
        key_agreement: &[(Value, Value)],
        pin_hash_enc: &[u8],
        permissions: u8,
        rp_id: Option<String>,
    ) -> Result<Vec<u8>, u8> {
        // "If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error."
        self.pin_state.check_pin_attempt_allowed()?;
        let keys = self.decapsulate(protocol, key_agreement)?;
        self.verify_pin_hash_enc(protocol, &keys, pin_hash_enc)?;

        let token = Zeroizing::new(self.random_array::<32>());
        let encrypted = self.encrypt_for_platform(protocol, &keys, &token[..])?;
        self.pin_state
            .issue_pin_uv_auth_token(protocol, *token, permissions, rp_id);
        // "The authenticator returns the encrypted pinUvAuthToken for the
        // specified pinUvAuthProtocol" (CTAP 2.3 §6.5.5.7.1, §6.5.5.7.2), and
        // nothing else.
        let response = canonical_map(vec![(
            Value::Integer(Integer::from(2)),
            Value::Bytes(encrypted),
        )]);
        let mut encoded = Vec::new();
        into_writer(&response, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    /// getPinToken (CTAP 2.3 §6.5.5.7.1).
    fn client_pin_get_token_legacy(&mut self, map: &[(Value, Value)]) -> Result<Vec<u8>, u8> {
        // "If the authenticator does not receive mandatory parameters for this
        // command, it returns CTAP2_ERR_MISSING_PARAMETER error. If
        // pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
        // If authenticatorClientPIN's permissions parameter is present in the
        // getPinToken (0x05) subcommand, return CTAP1_ERR_INVALID_PARAMETER."
        // (And likewise for rpId.)
        let protocol = cbor::map_get(map, Value::Integer(Integer::from(1)));
        let key_agreement = required_map(map, 3)?;
        let pin_hash_enc = required_bytes(map, 6)?;
        let protocol = parse_required_pin_uv_auth_protocol(protocol)?;
        if cbor::map_get(map, Value::Integer(Integer::from(9))).is_some()
            || cbor::map_get(map, Value::Integer(Integer::from(10))).is_some()
        {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }
        let permissions = PIN_PERMISSION_MC | PIN_PERMISSION_GA;
        self.client_pin_get_token_common(protocol, key_agreement, pin_hash_enc, permissions, None)
    }

    /// getPinUvAuthTokenUsingPinWithPermissions (CTAP 2.3 §6.5.5.7.2).
    fn client_pin_get_token_with_permissions(
        &mut self,
        map: &[(Value, Value)],
    ) -> Result<Vec<u8>, u8> {
        let protocol = cbor::map_get(map, Value::Integer(Integer::from(1)));
        let key_agreement = required_map(map, 3)?;
        let pin_hash_enc = required_bytes(map, 6)?;
        let permissions = match cbor::map_get(map, Value::Integer(Integer::from(9))) {
            Some(Value::Integer(permissions)) => i128::from(*permissions),
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let rp_id = match cbor::map_get(map, Value::Integer(Integer::from(10))) {
            Some(Value::Text(rp_id)) => Some(rp_id.clone()),
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => None,
        };
        // The mc and ga permissions have "RP ID: Required" (CTAP 2.3 §6.5.5.7);
        // cm's is optional and scopes the token to that RP's credentials.
        let rp_scoped = i128::from(PIN_PERMISSION_MC | PIN_PERMISSION_GA);
        if permissions > 0 && permissions & rp_scoped != 0 && rp_id.is_none() {
            return Err(CTAP2_ERR_MISSING_PARAMETER);
        }
        let protocol = parse_required_pin_uv_auth_protocol(protocol)?;
        // "If the authenticator receives a permissions parameter with value 0,
        // return CTAP1_ERR_INVALID_PARAMETER."  permissions is an unsigned
        // integer, so a negative value is invalid too.
        if permissions <= 0 {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }
        let permissions = requested_pin_permissions(permissions)?;
        self.client_pin_get_token_common(protocol, key_agreement, pin_hash_enc, permissions, rp_id)
    }

    pub(crate) fn handle_client_pin(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        let map = cbor::request_parameters(payload)?;
        let subcommand =
            ClientPinSubcommand::parse(cbor::map_get(&map, Value::Integer(Integer::from(2))))?;
        match subcommand {
            // getPINRetries takes no pinUvAuthProtocol (CTAP 2.3 §6.5.5.2).
            ClientPinSubcommand::GetPinRetries => self.client_pin_get_retries(),
            ClientPinSubcommand::GetKeyAgreement => {
                // "If the authenticator does not receive mandatory parameters for
                // this subcommand, end the operation by returning
                // CTAP2_ERR_MISSING_PARAMETER. If the authenticator does not
                // support the selected pinUvAuthProtocol, it returns
                // CTAP1_ERR_INVALID_PARAMETER." (CTAP 2.3 §6.5.5.4)
                let protocol = parse_required_pin_uv_auth_protocol(cbor::map_get(
                    &map,
                    Value::Integer(Integer::from(1)),
                ))?;
                self.client_pin_get_key_agreement(protocol)
            }
            ClientPinSubcommand::SetPin => self.client_pin_set_pin(&map),
            ClientPinSubcommand::ChangePin => self.client_pin_change_pin(&map),
            ClientPinSubcommand::GetPinToken => self.client_pin_get_token_legacy(&map),
            ClientPinSubcommand::GetPinUvAuthTokenUsingPinWithPermissions => {
                self.client_pin_get_token_with_permissions(&map)
            }
        }
    }

    fn client_pin_get_retries(&mut self) -> Result<Vec<u8>, u8> {
        let mut entries = vec![(
            Value::Integer(Integer::from(0x03)),
            Value::Integer(Integer::from(u64::from(self.pin_state.retries()))),
        )];

        if self.pin_state.needs_power_cycle() {
            entries.push((Value::Integer(Integer::from(0x04)), Value::Bool(true)));
        }

        let response = canonical_map(entries);
        let mut encoded = Vec::new();
        into_writer(&response, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }
}
