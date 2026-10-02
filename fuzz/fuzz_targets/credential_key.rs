//! Stored credential key material: `try_credential_secret_from_bytes`,
//! `try_sign_challenge` and `try_cose_public_key` with arbitrary key bytes for
//! every algorithm.
//!
//! The bytes come from the credential store, which the engine treats as
//! untrusted: "a corrupted or truncated record must produce an error, never a
//! panic".  Invariants: no panic, and a signature verifies under the public
//! key of the key that made it (which for ES256 includes that it is DER
//! encoded).
//!
//! Input layout: the algorithm the key is read for (byte 0) and the algorithm
//! it signs with (byte 1, as a record whose alg disagrees with its key
//! would), each an index into `CoseAlg::ALL`; the authenticator data length
//! (byte 2), a 32-byte client data hash, the authenticator data, and the key
//! bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pqkey_ctap::{
    CoseAlg, try_cose_public_key, try_credential_secret_from_bytes, try_sign_challenge,
    verify_signature,
};

fuzz_target!(|data: &[u8]| {
    let [alg, sign_with, auth_data_len, rest @ ..] = data else {
        return;
    };
    let Some((client_data_hash, rest)) = rest.split_at_checked(32) else {
        return;
    };
    let Some((auth_data, key)) = rest.split_at_checked(usize::from(*auth_data_len)) else {
        return;
    };
    let alg = CoseAlg::ALL[usize::from(*alg) % CoseAlg::ALL.len()];
    let Ok(key) = try_credential_secret_from_bytes(alg, key) else {
        return;
    };
    let sign_alg = CoseAlg::ALL[usize::from(*sign_with) % CoseAlg::ALL.len()];
    if let Ok(signature) = try_sign_challenge(sign_alg, &key, auth_data, client_data_hash) {
        let public_key =
            try_cose_public_key(sign_alg, &key).expect("a key that signs has a public key");
        let message = [auth_data, client_data_hash].concat();
        verify_signature(sign_alg, &public_key, &message, &signature)
            .expect("the signature verifies under the key's public key");
    }
});
