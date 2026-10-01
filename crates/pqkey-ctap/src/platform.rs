//! The platform's side of the PIN/UV auth protocols (CTAP 2.3 §6.5.6, §6.5.7),
//! for clients that talk to an authenticator: getting a shared secret with
//! the authenticator's key agreement key, encrypting a PIN or its hash for it,
//! decrypting the pinUvAuthToken it returns, and authenticating requests with
//! that token.
//!
//! The authenticator's side is the engine's own and stays inside the crate;
//! this is what the `pqkey` command line uses to manage a running key, the way
//! a security key's management application does.
//!
//! ```
//! use pqkey_ctap::ClassicPinProtocol;
//! use pqkey_ctap::platform::PlatformKeyAgreement;
//!
//! // Two parties derive the same shared secret from each other's public keys,
//! // which is what the platform and the authenticator do in `decapsulate`.
//! let alice = PlatformKeyAgreement::generate_key()?;
//! let bob = PlatformKeyAgreement::generate_key()?;
//! let protocol = ClassicPinProtocol::V2;
//! let (bob_x, bob_y) = PlatformKeyAgreement::public_coordinates(&bob)?;
//! let (alice_x, alice_y) = PlatformKeyAgreement::public_coordinates(&alice)?;
//! let to_bob = PlatformKeyAgreement::new(protocol, &bob_x, &bob_y, &alice)?;
//! let to_alice = PlatformKeyAgreement::new(protocol, &alice_x, &alice_y, &bob)?;
//! assert_eq!(to_bob.authenticate(b"message"), to_alice.authenticate(b"message"));
//!
//! let ciphertext = to_bob.encrypt(&[0x55; 32], [7; 16])?;
//! assert_eq!(&to_alice.decrypt(&ciphertext)?[..], &[0x55; 32]);
//! # Ok::<(), pqkey_ctap::CryptoError>(())
//! ```

use hmac::{Hmac, KeyInit, Mac};
use p256::{
    PublicKey as P256PublicKey, SecretKey as P256SecretKey, ecdh::diffie_hellman,
    elliptic_curve::sec1::ToSec1Point,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    ClassicPinProtocol, CryptoError, PinUvSessionKeys, decrypt_classic_pin_block,
    derive_classic_pin_uv_session_keys, encrypt_classic_pin_block, with_scrubbed_stack,
};

/// The secret of a platform key agreement key: a P-256 scalar, zeroized on
/// drop.
pub type PlatformSecret = Zeroizing<[u8; 32]>;

/// A shared secret with an authenticator: the platform's half of
/// `encapsulate(peerCoseKey)` (CTAP 2.3 §6.5.6), for one PIN/UV auth protocol.
pub struct PlatformKeyAgreement {
    protocol: ClassicPinProtocol,
    keys: PinUvSessionKeys,
    public_x: [u8; 32],
    public_y: [u8; 32],
}

impl PlatformKeyAgreement {
    /// A fresh platform key agreement secret from the operating system's
    /// random number generator: "generate an ephemeral ECDH P-256 key pair"
    /// (§6.5.6, encapsulate).
    pub fn generate_key() -> Result<PlatformSecret, CryptoError> {
        let mut secret = Zeroizing::new([0u8; 32]);
        loop {
            getrandom::fill(&mut secret[..]).map_err(|_| CryptoError::Randomness)?;
            if P256SecretKey::from_slice(&secret[..]).is_ok() {
                return Ok(secret);
            }
        }
    }

    /// The x and y coordinates of the public key of `secret`, for the
    /// keyAgreement parameter (a COSE_Key with kty 2, alg -25, crv 1, -2 x,
    /// -3 y).
    pub fn public_coordinates(secret: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), CryptoError> {
        let secret = P256SecretKey::from_slice(&secret[..]).map_err(|_| CryptoError::InvalidKey)?;
        coordinates(&secret.public_key())
    }

    /// The shared secret of the platform key `secret` and the authenticator
    /// key agreement key with coordinates `x` and `y`, from getKeyAgreement:
    /// ECDH, then `kdf(Z)` of `protocol`.  An invalid point is
    /// [`CryptoError::InvalidPublicKey`].
    pub fn new(
        protocol: ClassicPinProtocol,
        x: &[u8; 32],
        y: &[u8; 32],
        secret: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        let mut encoded = [0u8; 65];
        encoded[0] = 0x04;
        encoded[1..33].copy_from_slice(x);
        encoded[33..].copy_from_slice(y);
        let peer =
            P256PublicKey::from_sec1_bytes(&encoded).map_err(|_| CryptoError::InvalidPublicKey)?;
        let secret = P256SecretKey::from_slice(&secret[..]).map_err(|_| CryptoError::InvalidKey)?;
        let shared =
            with_scrubbed_stack(|| diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine()));
        let keys = derive_classic_pin_uv_session_keys(protocol, shared.raw_secret_bytes().as_ref());
        let (public_x, public_y) = coordinates(&secret.public_key())?;
        Ok(Self {
            protocol,
            keys,
            public_x,
            public_y,
        })
    }

    /// The PIN/UV auth protocol of this shared secret.
    pub fn protocol(&self) -> ClassicPinProtocol {
        self.protocol
    }

    /// The platform's public key, the keyAgreement parameter's x and y.
    pub fn public_key(&self) -> ([u8; 32], [u8; 32]) {
        (self.public_x, self.public_y)
    }

    /// `encrypt(shared secret, plaintext)`: AES-256-CBC without padding, so
    /// `plaintext` is a whole number of 16-byte blocks.  Protocol two puts
    /// `iv` in front of the ciphertext; protocol one uses a zero IV and
    /// ignores it.
    pub fn encrypt(&self, plaintext: &[u8], iv: [u8; 16]) -> Result<Vec<u8>, CryptoError> {
        encrypt_classic_pin_block(self.protocol, &self.keys, Some(&iv), plaintext)
    }

    /// `decrypt(shared secret, ciphertext)`, the inverse of
    /// [`Self::encrypt`].
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        decrypt_classic_pin_block(self.protocol, &self.keys, ciphertext).map(Zeroizing::new)
    }

    /// `authenticate(shared secret, message)`, as for setPIN and changePIN.
    pub fn authenticate(&self, message: &[u8]) -> Vec<u8> {
        authenticate(self.protocol, &self.keys.auth_key, message)
    }
}

/// `authenticate(key, message)` of `protocol`: HMAC-SHA-256, cut to its first
/// 16 bytes for protocol one (§6.5.6) and whole for protocol two (§6.5.7).
/// With a pinUvAuthToken as the key this is a request's pinUvAuthParam.
pub fn authenticate(protocol: ClassicPinProtocol, key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key");
    mac.update(message);
    let tag = mac.finalize().into_bytes();
    match protocol {
        ClassicPinProtocol::V1 => tag[..16].to_vec(),
        ClassicPinProtocol::V2 => tag.to_vec(),
    }
}

/// `LEFT(SHA-256(pin), 16)`, what getPinToken and changePIN send encrypted.
pub fn pin_hash(pin: &[u8]) -> Zeroizing<[u8; 16]> {
    let digest = Zeroizing::new(Sha256::digest(pin));
    let mut hash = Zeroizing::new([0u8; 16]);
    hash.copy_from_slice(&digest[..16]);
    hash
}

/// `newPin` padded on the right with zeros to 64 bytes, the plaintext of
/// newPinEnc (§6.5.5.5, §6.5.5.6).  `None` for a PIN longer than 63 bytes,
/// which no authenticator accepts.
pub fn padded_pin(pin: &[u8]) -> Option<Zeroizing<[u8; 64]>> {
    if pin.len() > 63 {
        return None;
    }
    let mut padded = Zeroizing::new([0u8; 64]);
    padded[..pin.len()].copy_from_slice(pin);
    Some(padded)
}

fn coordinates(public: &P256PublicKey) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let point = public.to_sec1_point(false);
    let (Some(x), Some(y)) = (point.x(), point.y()) else {
        return Err(CryptoError::InvalidPublicKey);
    };
    let mut coordinates = ([0u8; 32], [0u8; 32]);
    coordinates.0.copy_from_slice(x);
    coordinates.1.copy_from_slice(y);
    Ok(coordinates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_pins_are_padded_and_long_ones_refused() {
        let padded = padded_pin(b"1234").unwrap();
        assert_eq!(&padded[..4], b"1234");
        assert!(padded[4..].iter().all(|byte| *byte == 0));
        assert!(padded_pin(&[b'1'; 63]).is_some());
        assert!(padded_pin(&[b'1'; 64]).is_none());
    }

    #[test]
    fn protocol_one_tags_are_16_bytes_and_protocol_two_tags_32() {
        assert_eq!(
            authenticate(ClassicPinProtocol::V1, &[1; 32], b"m").len(),
            16
        );
        assert_eq!(
            authenticate(ClassicPinProtocol::V2, &[1; 32], b"m").len(),
            32
        );
    }

    #[test]
    fn a_point_off_the_curve_is_refused() {
        let secret = PlatformKeyAgreement::generate_key().unwrap();
        assert!(matches!(
            PlatformKeyAgreement::new(ClassicPinProtocol::V2, &[1; 32], &[2; 32], &secret),
            Err(CryptoError::InvalidPublicKey)
        ));
    }
}
