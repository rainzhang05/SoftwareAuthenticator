//! EdDSA on Ed448 ([`EdwardsCurve::Ed448`], RFC 8032 §5.2) with an empty
//! context, the scheme of Ed448: keys kept as a seed the 57-byte private key
//! is derived from ([`private_key`]).

use ed448_goldilocks::{SecretKey, SigningKey};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use zeroize::Zeroizing;

use super::CryptoError;
use super::alg::CoseAlg;
use super::credential_key::Seed;
use super::eddsa::{EdwardsCurve, try_cose_key};
use super::scrub::with_scrubbed_stack;

/// What the derivation's input starts with, before the seed.
const DERIVATION_CONTEXT: &[u8] = b"pqkey/v1/eddsa-key/Ed448";

/// The RFC 8032 private key that `seed` derives: the first 57 bytes of
/// SHAKE256("pqkey/v1/eddsa-key/Ed448" ‖ `seed`).
///
/// "The private key is 57 octets (456 bits, corresponding to b) of
/// cryptographically secure random data." (RFC 8032 §5.2.5)  SHAKE256
/// expands the credential's 32 random bytes into them, so that stored
/// records and sealed credential IDs hold 32 bytes of key for Ed448 as for
/// every other algorithm.  The sponge and the key are zeroized; what RFC
/// 8032 derives from the key is computed on a scrubbed stack, as is this.
pub(super) fn private_key(seed: &Seed) -> Zeroizing<SecretKey> {
    let mut private_key = Zeroizing::new(SecretKey::default());
    let mut shake = Shake256::default();
    shake.update(DERIVATION_CONTEXT);
    shake.update(seed.as_bytes());
    shake.finalize_xof().read(&mut private_key[..]);
    private_key
}

/// The signing key whose RFC 8032 private key is `private_key`.  It hashes
/// the private key into the secret scalar and prefix, and computes the
/// public key, so it runs on a scrubbed stack.
fn signing_key(private_key: &SecretKey) -> SigningKey {
    SigningKey::from(private_key)
}

/// The 57-byte RFC 8032 encoding of the public key of `private_key`.  It
/// runs on a scrubbed stack.
pub(super) fn public_key(private_key: &SecretKey) -> [u8; 57] {
    signing_key(private_key).verifying_key().to_bytes()
}

/// Sign `message` with pure Ed448 and an empty context under `private_key`,
/// returned as the 114-byte signature R ‖ S that RFC 8032 §5.2.6 encodes.
/// Signing hashes the private key again and draws the nonce r from its
/// prefix and the message, so it runs on a scrubbed stack.
///
/// Returns [`CryptoError::SigningFailed`] if signing fails.
pub(super) fn sign_with(private_key: &SecretKey, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let signature = signing_key(private_key)
        .sign_ctx(&[], message)
        .map_err(|_| CryptoError::SigningFailed)?;
    Ok(signature.to_bytes().to_vec())
}

/// The CBOR COSE_Key of the public key that `seed` derives, for `alg`.
pub(super) fn cose_public_key(alg: CoseAlg, seed: &Seed) -> Result<Vec<u8>, CryptoError> {
    let x = with_scrubbed_stack(|| public_key(&private_key(seed)));
    try_cose_key(alg, EdwardsCurve::Ed448, &x)
}

/// Sign `message` with pure Ed448 and an empty context under the private
/// key that `seed` derives ([`sign_with`]).
pub(super) fn sign(seed: &Seed, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    with_scrubbed_stack(|| sign_with(&private_key(seed), message))
}
