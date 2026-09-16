//! Persistent storage for credentials, PIN state, and attestation material.

mod record;

pub use record::{AttestationRecord, CredentialRecord, PinStateRecord, PrivateKeyMaterial};
