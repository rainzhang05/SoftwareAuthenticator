//! The CTAP2 authenticator: the protocol engine in [`ctap`], the encrypted
//! credential store in [`store`], the platform half of the PIN/UV auth
//! protocols in [`platform`], and the cryptography they share, re-exported
//! here: the signature algorithms ([`CoseAlg`]), credential keys and
//! signing, and the PIN/UV auth protocols' key derivation and encryption.

// Everything here is safe Rust; the one place that needs `unsafe` (the uhid
// device) lives in the pqkey crate.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod crypto;
pub mod ctap;
pub mod platform;
pub mod store;

pub use crypto::CryptoError;
pub use crypto::alg::{CoseAlg, UnsupportedCoseAlg};
pub use crypto::credential_key::{
    CredentialSecretKey, try_create_credential, try_credential_secret_from_bytes,
    try_sign_challenge,
};
pub use crypto::mldsa::{MlDsaSeed, mldsa_paramset_from_alg};
pub use crypto::pin_uv::{
    ClassicPinProtocol, PinUvSessionKeys, decrypt_classic_pin_block,
    derive_classic_pin_uv_session_keys, encrypt_classic_pin_block,
    try_derive_classic_pin_uv_session_keys,
};
