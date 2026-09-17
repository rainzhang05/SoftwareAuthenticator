//! PIN/UV auth protocol plumbing: protocol selection, the key-agreement
//! session, shared-secret encryption and pinUvAuthParam verification.

use crate::ctap::cbor::canonical_map;
use crate::ctap::CtapApp;
use crate::{
    decrypt_classic_pin_block, derive_classic_pin_uv_session_keys, encrypt_classic_pin_block,
    ClassicPinProtocol, PinUvSessionKeys,
};

use ciborium::value::{Integer, Value};
use hmac::{Hmac, KeyInit, Mac};
use p256::{
    ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point, PublicKey as P256PublicKey, Sec1Point,
    SecretKey as P256SecretKey,
};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::ctap::constants::*;

/// `decrypt(shared secret, ciphertext)` for the given PIN/UV auth protocol:
/// AES-256-CBC with an all-zero IV for protocol one (CTAP 2.3 §6.5.6), and with
/// the IV taken from the first 16 bytes of the ciphertext for protocol two
/// (§6.5.7).  `None` is the spec's "error"; each caller maps it to the status
/// code its own algorithm prescribes.
pub(crate) fn decrypt(
    protocol: PinProtocol,
    keys: &PinUvSessionKeys,
    ciphertext: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    decrypt_classic_pin_block(protocol, keys, ciphertext)
        .ok()
        .map(Zeroizing::new)
}

pub(crate) type HmacSha256 = Hmac<Sha256>;

pub(crate) const PIN_UV_AUTH_PROTOCOL_CLASSIC_V1: i32 = 1;
pub(crate) const PIN_UV_AUTH_PROTOCOL_CLASSIC_V2: i32 = 2;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const PIN_UV_AUTH_PROTOCOL_CLASSIC: i32 = PIN_UV_AUTH_PROTOCOL_CLASSIC_V2;
const PIN_UV_PROTOCOLS_SUPPORTED: [i32; 2] = [
    PIN_UV_AUTH_PROTOCOL_CLASSIC_V2,
    PIN_UV_AUTH_PROTOCOL_CLASSIC_V1,
];

pub(crate) type PinProtocol = ClassicPinProtocol;

/// Length of a protocol one MAC: `authenticate` returns "the first 16 bytes of
/// the result of computing HMAC-SHA-256" (CTAP 2.3 §6.5.6).
const PROTOCOL_ONE_MAC_LEN: usize = 16;

/// `authenticate(key, message)` for the given PIN/UV auth protocol.
///
/// * Protocol one (CTAP 2.3 §6.5.6): "Return the first 16 bytes of the result
///   of computing HMAC-SHA-256 with the given key and message."
/// * Protocol two (CTAP 2.3 §6.5.7): "Return the result of computing
///   HMAC-SHA-256 on key and message", i.e. all 32 bytes.
///
/// `key` is either the HMAC half of a shared secret or a pinUvAuthToken; both
/// are exactly 32 bytes, so protocol two's "discard the excess" step is a no-op.
pub(crate) fn authenticate(
    protocol: PinProtocol,
    key: &[u8; 32],
    message: &[u8],
) -> Result<Zeroizing<Vec<u8>>, u8> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| CTAP2_ERR_PROCESSING)?;
    mac.update(message);
    let tag = Zeroizing::new(mac.finalize().into_bytes());
    let len = match protocol {
        ClassicPinProtocol::V1 => PROTOCOL_ONE_MAC_LEN,
        ClassicPinProtocol::V2 => tag.len(),
    };
    Ok(Zeroizing::new(tag[..len].to_vec()))
}

/// `verify(key, message, signature)` for the given PIN/UV auth protocol.
///
/// * Protocol one (CTAP 2.3 §6.5.6): "Return success if signature is 16 bytes
///   and is equal to the first 16 bytes of the result, otherwise return error."
/// * Protocol two (CTAP 2.3 §6.5.7): "Return success if the signature is equal
///   to the result, otherwise return an error." (the full 32 bytes).
///
/// A signature of the other protocol's length is rejected, so a protocol two
/// request can never be satisfied by a truncated 16-byte MAC.  The comparison
/// is constant time; only the (public) length can short-circuit it.
///
/// This is the single place every pinUvAuthParam and hmac-secret saltAuth is
/// checked.  The additional "is the pinUvAuthToken in use" rule of `verify`
/// belongs to the token state and is applied by the callers that pass a token.
pub(crate) fn verify(
    protocol: PinProtocol,
    key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), u8> {
    let expected = authenticate(protocol, key, message)?;
    if bool::from(expected.as_slice().ct_eq(signature)) {
        Ok(())
    } else {
        Err(CTAP2_ERR_PIN_AUTH_INVALID)
    }
}

/// Parse a pinUvAuthProtocol value.  "If pinUvAuthProtocol is not supported,
/// return CTAP1_ERR_INVALID_PARAMETER." (CTAP 2.3 §6.5.5.4 to §6.5.5.7.2,
/// §6.1.2 step 2, §6.2.2 step 2, §6.8.2 to §6.8.6)
pub(crate) fn parse_pin_uv_auth_protocol(value: &Value) -> Result<PinProtocol, u8> {
    let Value::Integer(identifier) = value else {
        return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
    };
    match i128::from(*identifier) {
        id if id == i128::from(PIN_UV_AUTH_PROTOCOL_CLASSIC_V1) => Ok(ClassicPinProtocol::V1),
        id if id == i128::from(PIN_UV_AUTH_PROTOCOL_CLASSIC_V2) => Ok(ClassicPinProtocol::V2),
        _ => Err(CTAP1_ERR_INVALID_PARAMETER),
    }
}

/// Parse a pinUvAuthProtocol that the command requires: absent is "If the
/// authenticator does not receive mandatory parameters for this command, it
/// returns CTAP2_ERR_MISSING_PARAMETER error."
pub(crate) fn parse_required_pin_uv_auth_protocol(
    value: Option<&Value>,
) -> Result<PinProtocol, u8> {
    parse_pin_uv_auth_protocol(value.ok_or(CTAP2_ERR_MISSING_PARAMETER)?)
}

/// Parse the pinUvAuthParam and pinUvAuthProtocol parameters of
/// authenticatorMakeCredential, authenticatorGetAssertion and
/// authenticatorCredentialManagement.  `None` when pinUvAuthParam is absent,
/// whatever pinUvAuthProtocol says.  Otherwise, per CTAP 2.3 §6.1.2 step 2 and
/// §6.2.2 step 2: "If the pinUvAuthProtocol parameter's value is not
/// supported, return CTAP1_ERR_INVALID_PARAMETER error. If the
/// pinUvAuthProtocol parameter is absent, return CTAP2_ERR_MISSING_PARAMETER
/// error."
pub(crate) fn parse_pin_uv_auth_param(
    pin_uv_auth_param: Option<&Value>,
    pin_uv_auth_protocol: Option<&Value>,
) -> Result<Option<(PinProtocol, Vec<u8>)>, u8> {
    let param = match pin_uv_auth_param {
        None => return Ok(None),
        Some(Value::Bytes(param)) => param.clone(),
        Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    };
    let protocol = parse_required_pin_uv_auth_protocol(pin_uv_auth_protocol)?;
    Ok(Some((protocol, param)))
}

/// A PIN/UV auth protocol's key agreement key: "a P-256 private key, x, and
/// the associated public point xB" (CTAP 2.3 §6.5.6; protocol two inherits
/// it, §6.5.7).
pub(crate) struct KeyAgreementKey {
    secret_key: P256SecretKey,
    public_key: Sec1Point,
}

impl KeyAgreementKey {
    pub(crate) fn new(secret_key: P256SecretKey) -> Self {
        let public_key = secret_key.public_key().to_sec1_point(false);
        Self {
            secret_key,
            public_key,
        }
    }

    /// `getPublicKey()`: a COSE_Key with "1 (kty) = 2 (EC2)", "3 (alg) = -25",
    /// "-1 (crv) = 1 (P-256)" and the x and y coordinates (CTAP 2.3 §6.5.6).
    pub(crate) fn cose_key(&self) -> Value {
        let (x, y) = match (self.public_key.x(), self.public_key.y()) {
            (Some(x_bytes), Some(y_bytes)) => (x_bytes.to_vec(), y_bytes.to_vec()),
            _ => (Vec::new(), Vec::new()),
        };
        canonical_map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(2)),
            ),
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(-25)),
            ),
            (
                Value::Integer(Integer::from(-1)),
                Value::Integer(Integer::from(1)),
            ),
            (Value::Integer(Integer::from(-2)), Value::Bytes(x)),
            (Value::Integer(Integer::from(-3)), Value::Bytes(y)),
        ])
    }

    /// `decapsulate(peerCoseKey)`: ECDH with the platform key-agreement key,
    /// then `kdf(Z)` of `protocol` (CTAP 2.3 §6.5.6, §6.5.7).  Parse errors
    /// and points not on the curve are CTAP1_ERR_INVALID_PARAMETER.
    pub(crate) fn decapsulate(
        &self,
        protocol: PinProtocol,
        platform_key: &[(Value, Value)],
    ) -> Result<PinUvSessionKeys, u8> {
        let Some(peer_x) = platform_key
            .iter()
            .find(|(k, _)| *k == Value::Integer(Integer::from(-2)))
            .and_then(|(_, v)| match v {
                Value::Bytes(bytes) => Some(bytes.clone()),
                _ => None,
            })
        else {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        };
        let Some(peer_y) = platform_key
            .iter()
            .find(|(k, _)| *k == Value::Integer(Integer::from(-3)))
            .and_then(|(_, v)| match v {
                Value::Bytes(bytes) => Some(bytes.clone()),
                _ => None,
            })
        else {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        };
        if peer_x.len() != 32 || peer_y.len() != 32 {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }

        let mut peer_encoded = [0u8; 65];
        peer_encoded[0] = 0x04;
        peer_encoded[1..33].copy_from_slice(&peer_x);
        peer_encoded[33..65].copy_from_slice(&peer_y);

        let peer_public = P256PublicKey::from_sec1_bytes(&peer_encoded)
            .map_err(|_| CTAP1_ERR_INVALID_PARAMETER)?;
        let shared = diffie_hellman(self.secret_key.to_nonzero_scalar(), peer_public.as_affine());

        let shared_bytes = shared.raw_secret_bytes();
        Ok(derive_classic_pin_uv_session_keys(
            protocol,
            shared_bytes.as_ref(),
        ))
    }
}

/// The key agreement key of each supported PIN/UV auth protocol: "Each PIN/UV
/// auth protocol [...] maintains its own" state (CTAP 2.3 §6.5).
///
/// A key lives from power-up, when "the authenticator calls initialize for
/// each pinUvAuthProtocol that it supports" (§6.5.5.1), until that protocol's
/// `regenerate()` after a PIN mismatch.  getKeyAgreement only returns it, so a
/// platform can use one key for several commands.  Here a key is drawn from
/// the RNG when first needed, which a platform cannot tell apart from drawing
/// it at power-up: nothing reveals or uses it before then.
#[derive(Default)]
pub(crate) struct KeyAgreementKeys {
    protocol_one: Option<KeyAgreementKey>,
    protocol_two: Option<KeyAgreementKey>,
}

impl KeyAgreementKeys {
    fn slot(&mut self, protocol: PinProtocol) -> &mut Option<KeyAgreementKey> {
        match protocol {
            ClassicPinProtocol::V1 => &mut self.protocol_one,
            ClassicPinProtocol::V2 => &mut self.protocol_two,
        }
    }

    /// `regenerate()`: "Generates a fresh public key."  The new key is drawn
    /// when it is next needed.
    pub(crate) fn regenerate(&mut self, protocol: PinProtocol) {
        *self.slot(protocol) = None;
    }
}

/// Attempts at drawing a P-256 private key from the RNG before giving up.  A
/// uniformly random 32-byte string is out of range with probability below
/// 2^-32, so exhausting these means the RNG is broken.
const KEY_AGREEMENT_KEY_ATTEMPTS: usize = 8;

impl CtapApp<'_> {
    pub(crate) fn supported_pin_uv_protocols(&self) -> &'static [i32] {
        &PIN_UV_PROTOCOLS_SUPPORTED
    }

    /// `encrypt(shared secret, plaintext)` for the given PIN/UV auth protocol.
    ///
    /// Protocol one uses an all-zero IV (CTAP 2.3 §6.5.6).  Protocol two: "Let
    /// iv be a 16-byte, random bytestring. [...] Return iv || ct." (§6.5.7).
    pub(crate) fn encrypt_for_platform(
        &mut self,
        protocol: PinProtocol,
        keys: &PinUvSessionKeys,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, u8> {
        let iv = match protocol {
            ClassicPinProtocol::V1 => None,
            ClassicPinProtocol::V2 => Some(self.random_array::<16>()),
        };
        encrypt_classic_pin_block(protocol, keys, iv.as_ref(), plaintext)
            .map_err(|_| CTAP2_ERR_PROCESSING)
    }
    /// `verify(pinUvAuthToken, message, pinUvAuthParam)` as used by
    /// authenticatorMakeCredential (CTAP 2.3 §6.1.2 step 11.1.1),
    /// authenticatorGetAssertion (§6.2.2 step 6.1.1) and
    /// authenticatorCredentialManagement (§6.8.2 to §6.8.6): any failure,
    /// including the absence of a pinUvAuthToken, is
    /// `CTAP2_ERR_PIN_AUTH_INVALID`.
    pub(crate) fn verify_pin_uv_auth_param(
        &mut self,
        protocol: PinProtocol,
        message: &[u8],
        pin_uv_auth_param: &[u8],
    ) -> Result<(), u8> {
        self.pin_state
            .verify_pin_uv_auth_token(protocol, message, pin_uv_auth_param)
    }

    /// The key agreement key of `protocol`, drawn from the RNG if it has not
    /// been yet (see [`KeyAgreementKeys`]).
    pub(crate) fn key_agreement_key(
        &mut self,
        protocol: PinProtocol,
    ) -> Result<&KeyAgreementKey, u8> {
        if self.pin_state.key_agreement.slot(protocol).is_none() {
            let secret_key = (0..KEY_AGREEMENT_KEY_ATTEMPTS)
                .find_map(|_| {
                    let mut bytes = self.random_array::<32>();
                    let secret_key = P256SecretKey::from_slice(&bytes).ok();
                    bytes.zeroize();
                    secret_key
                })
                .ok_or(CTAP2_ERR_PROCESSING)?;
            *self.pin_state.key_agreement.slot(protocol) = Some(KeyAgreementKey::new(secret_key));
        }
        self.pin_state
            .key_agreement
            .slot(protocol)
            .as_ref()
            .ok_or(CTAP2_ERR_PROCESSING)
    }

    /// `decapsulate(peerCoseKey)` with `protocol`'s key agreement key.
    pub(crate) fn decapsulate(
        &mut self,
        protocol: PinProtocol,
        platform_key: &[(Value, Value)],
    ) -> Result<PinUvSessionKeys, u8> {
        self.key_agreement_key(protocol)?
            .decapsulate(protocol, platform_key)
    }
}
