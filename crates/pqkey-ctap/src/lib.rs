//! The CTAP2 authenticator: the protocol engine in [`ctap`], the encrypted
//! credential store in [`store`], the platform half of the PIN/UV auth
//! protocols in [`platform`], and the cryptography they share, re-exported
//! here: the signature algorithms ([`CoseAlg`]), credential keys and
//! signing, and the PIN/UV auth protocols' key derivation and encryption.

// Everything here is safe Rust; memory wiping and kernel operations that
// need `unsafe` live in the pqkey crate.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod cbor;
mod credential_id;
mod crypto;
pub mod ctap;
pub mod platform;
/// Fixed RSA known answers shared by tests and fuzz harnesses.
#[cfg(any(test, feature = "test-support"))]
#[path = "../tests/vectors/rsa2048.rs"]
pub mod rsa_fixture;
pub mod store;

pub use crypto::CryptoError;
pub use crypto::alg::{CoseAlg, KeyKind, UnsupportedCoseAlg};
pub use crypto::credential_key::{
    CredentialSecretKey, Seed, try_cose_public_key, try_credential_secret_from_bytes,
    try_sign_challenge,
};
pub use crypto::pin_uv::{
    ClassicPinProtocol, PinUvSessionKeys, decrypt_classic_pin_block,
    derive_classic_pin_uv_session_keys, encrypt_classic_pin_block,
    try_derive_classic_pin_uv_session_keys,
};
#[cfg(feature = "test-support")]
pub use crypto::verify::{VerificationError, verify_signature};
