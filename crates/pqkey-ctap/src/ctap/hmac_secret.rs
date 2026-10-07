//! Shared hmac-secret processing for authenticatorGetAssertion (§12.7) and
//! authenticatorMakeCredential's hmac-secret-mc extension (§12.8), CTAP 2.3.

use super::CtapApp;
use super::cbor;
use super::pin::protocol::{HmacSha256, PinProtocol, decrypt, parse_pin_uv_auth_protocol, verify};
use crate::ctap::constants::*;
use crate::{ClassicPinProtocol, PinUvSessionKeys};

use ciborium::value::{Integer, Value};
use hmac::{KeyInit, Mac};
use zeroize::Zeroizing;

pub(super) struct PendingHmacSecret {
    protocol: PinProtocol,
    keys: PinUvSessionKeys,
    salt_plaintext: Zeroizing<Vec<u8>>,
}

impl PendingHmacSecret {
    /// `output1 [|| output2]` with `outputN = HMAC-SHA-256(CredRandom, saltN)`
    /// (CTAP 2.3 §12.7).
    fn outputs_for(&self, cred_random: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, u8> {
        let mut outputs = Zeroizing::new(Vec::with_capacity(self.salt_plaintext.len()));
        for salt in self.salt_plaintext.chunks(32) {
            let mut hmac =
                HmacSha256::new_from_slice(cred_random).map_err(|_| CTAP2_ERR_PROCESSING)?;
            hmac.update(salt);
            let output = Zeroizing::new(hmac.finalize().into_bytes());
            outputs.extend_from_slice(&output[..]);
        }
        Ok(outputs)
    }
}

pub(super) struct HmacSecretRequest {
    key_agreement: Vec<(Value, Value)>,
    salt_enc: Vec<u8>,
    salt_auth: Vec<u8>,
    protocol: PinProtocol,
}

impl CtapApp<'_> {
    pub(super) fn process_hmac_secret(
        &mut self,
        request: &HmacSecretRequest,
        cred_random_with_uv: &[u8; 32],
        cred_random_without_uv: &[u8; 32],
        user_verified: bool,
    ) -> Result<(Vec<u8>, PendingHmacSecret), u8> {
        // "The authenticator calls decapsulate on the provided platform
        // key-agreement key to obtain a shared secret." (CTAP 2.3 §12.7)
        let keys = self.decapsulate(request.protocol, &request.key_agreement)?;

        // CTAP 2.3 §12.7: "The authenticator calls verify(shared secret,
        // saltEnc, saltAuth). If the verification fails, return
        // CTAP2_ERR_PIN_AUTH_INVALID."
        verify(
            request.protocol,
            &keys.auth_key,
            &request.salt_enc,
            &request.salt_auth,
        )?;

        // "The authenticator obtains salt1 and salt2 by calling decrypt(shared
        // secret, saltEnc). If the decryption fails, or if the result is not 32
        // or 64 bytes long, return CTAP1_ERR_INVALID_PARAMETER."
        let salt_plaintext = decrypt(request.protocol, &keys, &request.salt_enc)
            .filter(|salts| salts.len() == 32 || salts.len() == 64)
            .ok_or(CTAP1_ERR_INVALID_PARAMETER)?;

        let cred_random = if user_verified {
            cred_random_with_uv
        } else {
            cred_random_without_uv
        };

        let pending = PendingHmacSecret {
            protocol: request.protocol,
            keys,
            salt_plaintext,
        };
        let encrypted = self.encrypt_hmac_secret_outputs(&pending, cred_random)?;
        Ok((encrypted, pending))
    }

    /// `encrypt(shared secret, output1 [|| output2])` with the protocol the
    /// platform selected for hmac-secret (CTAP 2.3 §12.7).
    pub(super) fn encrypt_hmac_secret_outputs(
        &mut self,
        pending: &PendingHmacSecret,
        cred_random: &[u8; 32],
    ) -> Result<Vec<u8>, u8> {
        let outputs = pending.outputs_for(cred_random)?;
        self.encrypt_for_platform(pending.protocol, &pending.keys, &outputs)
    }
}

/// Parse the hmac-secret getAssertion input (CTAP 2.3 §12.7): a missing
/// member is CTAP2_ERR_MISSING_PARAMETER, a wrongly typed input or member
/// CTAP2_ERR_CBOR_UNEXPECTED_TYPE (§8).
pub(super) fn parse_hmac_secret_request(value: &Value) -> Result<HmacSecretRequest, u8> {
    let Value::Map(params) = value else {
        return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
    };
    let key_agreement = cbor::required_map(params, 1)?.to_vec();
    let salt_enc = cbor::required_bytes(params, 2)?.to_vec();
    let salt_auth = cbor::required_bytes(params, 3)?.to_vec();
    // "If pinUvAuthProtocol is absent and a pinUvAuthProtocol value of 1 is
    // supported by the authenticator, let the value of pinUvAuthProtocol be 1"
    // (CTAP 2.3 §12.7).
    let protocol = match cbor::map_get(params, Value::Integer(Integer::from(4))) {
        Some(value) => parse_pin_uv_auth_protocol(value)?,
        None => ClassicPinProtocol::V1,
    };
    Ok(HmacSecretRequest {
        key_agreement,
        salt_enc,
        salt_auth,
        protocol,
    })
}
