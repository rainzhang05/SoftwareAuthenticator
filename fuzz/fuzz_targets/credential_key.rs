//! Stored credential key material: `try_credential_secret_from_bytes` and
//! `try_sign_challenge` with arbitrary key bytes for every algorithm.
//!
//! The bytes come from the credential store, which the engine treats as
//! untrusted: "a corrupted or truncated record must produce an error, never a
//! panic".  Invariants: no panic, and an ES256 signature is DER encoded.
//!
//! Input layout: the algorithm the key is read for (byte 0), the algorithm
//! it signs with (byte 1, as a record whose alg disagrees with its key
//! would), the authenticator data length (byte 2), a 32-byte client data
//! hash, the authenticator data, and the key bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use pqkey_ctap::{CoseAlg, try_credential_secret_from_bytes, try_sign_challenge};

const ALGORITHMS: [CoseAlg; 4] = [
    CoseAlg::ES256,
    CoseAlg::MLDSA44,
    CoseAlg::MLDSA65,
    CoseAlg::MLDSA87,
];

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
    let alg = ALGORITHMS[usize::from(*alg) % 4];
    let Ok(key) = try_credential_secret_from_bytes(alg, key) else {
        return;
    };
    let sign_alg = ALGORITHMS[usize::from(*sign_with) % 4];
    if let Ok(signature) = try_sign_challenge(sign_alg, &key, auth_data, client_data_hash) {
        if sign_alg == CoseAlg::ES256 {
            p256::ecdsa::Signature::from_der(&signature).expect("a DER ECDSA signature");
        }
    }
});
