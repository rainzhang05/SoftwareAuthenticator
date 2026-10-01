//! The platform's side of PIN/UV auth protocols one and two (CTAP 2.3 §6.5),
//! so the stateful target can send requests that authenticate.

use ciborium::value::Value;
use pqkey_ctap::ClassicPinProtocol;
use pqkey_ctap::platform::{self, PlatformKeyAgreement};

use crate::cbor::{bytes, get_int, int};

/// `authenticate(key, message)`: HMAC-SHA-256, the first 16 bytes for
/// protocol one (§6.5.6) and all 32 for protocol two (§6.5.7).
pub fn authenticate(protocol: ClassicPinProtocol, key: &[u8], message: &[u8]) -> Vec<u8> {
    platform::authenticate(protocol, key, message)
}

/// `LEFT(SHA-256(pin), 16)`.
pub fn pin_hash(pin: &[u8]) -> [u8; 16] {
    *platform::pin_hash(pin)
}

/// A shared secret with the authenticator, from getKeyAgreement.
pub struct Session {
    shared: PlatformKeyAgreement,
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
            Some(Value::Bytes(value)) => <[u8; 32]>::try_from(value.as_slice()).ok(),
            _ => None,
        };
        let shared =
            PlatformKeyAgreement::new(protocol, &coordinate(-2)?, &coordinate(-3)?, &secret)
                .ok()?;
        let (x, y) = shared.public_key();
        let key_agreement = Value::Map(vec![
            (int(1), int(2)),
            (int(3), int(-25)),
            (int(-1), int(1)),
            (int(-2), bytes(&x)),
            (int(-3), bytes(&y)),
        ]);
        Some(Self {
            shared,
            key_agreement,
        })
    }

    /// `encrypt(shared secret, plaintext)`, `plaintext` a multiple of 16 bytes.
    pub fn encrypt(&self, plaintext: &[u8], iv: [u8; 16]) -> Vec<u8> {
        self.shared
            .encrypt(plaintext, iv)
            .expect("the plaintext is a whole number of blocks")
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        self.shared
            .decrypt(ciphertext)
            .ok()
            .map(|plaintext| plaintext.to_vec())
    }

    /// `authenticate(shared secret, message)`.
    pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        self.shared.authenticate(message)
    }
}

/// The pinUvAuthProtocol identifier of `protocol`.
pub fn protocol_value(protocol: ClassicPinProtocol) -> Value {
    int(protocol.identifier().into())
}
