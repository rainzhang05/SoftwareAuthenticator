//! The platform's side of PIN/UV auth protocols one and two (CTAP 2.3 §6.5),
//! so the stateful target can send requests that authenticate.

use ciborium::value::Value;
use hmac::{Hmac, KeyInit, Mac};
use p256::{PublicKey, SecretKey, ecdh::diffie_hellman, elliptic_curve::sec1::ToSec1Point};
use pqkey_ctap::{
    ClassicPinProtocol, PinUvSessionKeys, decrypt_classic_pin_block,
    derive_classic_pin_uv_session_keys, encrypt_classic_pin_block,
};
use sha2::{Digest, Sha256};

use crate::cbor::{bytes, get_int, int};

/// `authenticate(key, message)`: HMAC-SHA-256, the first 16 bytes for
/// protocol one (§6.5.6) and all 32 for protocol two (§6.5.7).
pub fn authenticate(protocol: ClassicPinProtocol, key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC takes any key");
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    match protocol {
        ClassicPinProtocol::V1 => tag[..16].to_vec(),
        ClassicPinProtocol::V2 => tag.to_vec(),
    }
}

/// `LEFT(SHA-256(pin), 16)`.
pub fn pin_hash(pin: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(pin);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&digest[..16]);
    hash
}

/// A shared secret with the authenticator, from getKeyAgreement.
pub struct Session {
    pub protocol: ClassicPinProtocol,
    pub keys: PinUvSessionKeys,
    /// The platform's COSE key, for keyAgreement (0x03).
    pub key_agreement: Value,
}

impl Session {
    /// Encapsulate against the authenticator key agreement key in the
    /// getKeyAgreement response `response` (status byte included), with the
    /// platform secret scalar `secret`.  `None` if the response carries no
    /// usable key.
    pub fn establish(
        protocol: ClassicPinProtocol,
        response: &[u8],
        secret: [u8; 32],
    ) -> Option<Self> {
        let entries = crate::cbor::decode_map(response.get(1..)?)?;
        let Value::Map(key) = get_int(&entries, 1)? else {
            return None;
        };
        let coordinate = |label| match get_int(key, label) {
            Some(Value::Bytes(value)) if value.len() == 32 => Some(value.clone()),
            _ => None,
        };
        let mut encoded = vec![0x04];
        encoded.extend(coordinate(-2)?);
        encoded.extend(coordinate(-3)?);
        let authenticator_key = PublicKey::from_sec1_bytes(&encoded).ok()?;

        let secret = SecretKey::from_slice(&secret).ok()?;
        let shared = diffie_hellman(secret.to_nonzero_scalar(), authenticator_key.as_affine());
        let keys = derive_classic_pin_uv_session_keys(protocol, shared.raw_secret_bytes().as_ref());
        let point = secret.public_key().to_sec1_point(false);
        let key_agreement = Value::Map(vec![
            (int(1), int(2)),
            (int(3), int(-25)),
            (int(-1), int(1)),
            (int(-2), bytes(point.x()?.as_ref())),
            (int(-3), bytes(point.y()?.as_ref())),
        ]);
        Some(Self {
            protocol,
            keys,
            key_agreement,
        })
    }

    /// `encrypt(shared secret, plaintext)`, `plaintext` a multiple of 16 bytes.
    pub fn encrypt(&self, plaintext: &[u8], iv: [u8; 16]) -> Vec<u8> {
        encrypt_classic_pin_block(self.protocol, &self.keys, Some(&iv), plaintext)
            .expect("the plaintext is a whole number of blocks")
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        decrypt_classic_pin_block(self.protocol, &self.keys, ciphertext).ok()
    }

    /// `authenticate(shared secret, message)`.
    pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        authenticate(self.protocol, &self.keys.auth_key, message)
    }
}

/// The pinUvAuthProtocol identifier of `protocol`.
pub fn protocol_value(protocol: ClassicPinProtocol) -> Value {
    int(protocol.identifier().into())
}
