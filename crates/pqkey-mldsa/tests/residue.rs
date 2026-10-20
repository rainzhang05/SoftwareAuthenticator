//! Secrets left behind in the stack after signing and key derivation.
//!
//! FIPS 204 §3.6.3: "implementations of ML-DSA shall ensure that any
//! potentially sensitive intermediate data is destroyed as soon as it is no
//! longer needed."  ρ′ = SHAKE256(ξ ‖ k ‖ ℓ)[32..96] alone regenerates the
//! secret vectors s1 and s2, and K = [96..128] is the signing key's PRF key.
//! After each entry point returns, this test scans the dead stack below its
//! caller for both 32-byte halves of ρ′, K, and a control nobody computed.
//! Fixtures precede the wipe; verification follows the scans. Linux also
//! repeats the operations in a child whose OS RNG is forced to fail.
//!
//! It is its own program (`harness = false`), single-threaded on the main
//! thread, because it reads stack memory that other functions left behind:
//! `wipe` and `scan` look at the same region below `main`'s frame through
//! buffers of their own.  Reading those bytes is outside what Rust defines,
//! so a clean result proves less than a dirty one; it found the residue
//! before the stack was scrubbed.

use core::mem::MaybeUninit;

use pqkey_mldsa::{
    MAX_CONTEXT_LEN, MlDsaError, ParamSet, PublicKey, SecretKey, try_keypair_from_seed,
    try_public_key, try_public_key_from_seed, try_sign, try_sign_deterministic, try_sign_from_seed,
    try_sign_from_seed_with_context, try_sign_with_context, verify_with_context,
};
use shake::Shake256;
use shake::digest::{ExtendableOutput, Update, XofReader};

#[cfg(target_os = "linux")]
#[path = "support/rng_failure.rs"]
mod rng_failure;

#[cfg(target_os = "linux")]
use pqkey_mldsa::try_keypair;

enum Output {
    Signature(Vec<u8>),
    PublicKey(PublicKey),
    Keypair(PublicKey, SecretKey),
}

type Operation<'a> = (
    &'static str,
    &'a [u8],
    &'a dyn Fn() -> Result<Output, MlDsaError>,
    Option<MlDsaError>,
);

/// How far below `main` the scan reaches, more than signing ever uses.
const SCAN: usize = 2 * 1024 * 1024;

/// Overwrite the region below the caller with zeros.
#[inline(never)]
fn wipe() {
    let mut buffer: MaybeUninit<[u8; SCAN]> = MaybeUninit::uninit();
    let start = buffer.as_mut_ptr().cast::<u8>();
    for offset in 0..SCAN {
        // SAFETY: `start + offset` is inside `buffer`, which this frame owns.
        unsafe { core::ptr::write_volatile(start.add(offset), 0) };
    }
    core::hint::black_box(&buffer);
}

/// How often `needle` occurs in the region below the caller.
#[inline(never)]
fn scan(needle: &[u8]) -> usize {
    let buffer: MaybeUninit<[u8; SCAN]> = MaybeUninit::uninit();
    let start = buffer.as_ptr().cast::<u8>();
    let mut hits = 0;
    for offset in 0..=SCAN - needle.len() {
        // SAFETY: every byte read is inside `buffer`, which this frame owns.
        // The bytes are uninitialised as far as Rust is concerned: they hold
        // whatever earlier calls left there, which is what this test is after,
        // and they are only compared, never used as values of another type.
        let found = (0..needle.len()).all(
            |index| unsafe { core::ptr::read_volatile(start.add(offset + index)) } == needle[index],
        );
        if found {
            hits += 1;
        }
    }
    core::hint::black_box(&buffer);
    hits
}

/// ρ′ and K of the key generated from `seed` with parameters (k, ℓ).
fn rho_prime_and_key(seed: &[u8; 32], k: u8, l: u8) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut out = [0u8; 128];
    let mut shake = Shake256::default();
    shake.update(seed);
    shake.update(&[k, l]);
    shake.finalize_xof().read(&mut out);
    (
        out[32..64].try_into().expect("32 bytes"),
        out[96..128].try_into().expect("32 bytes"),
        out[64..96].try_into().expect("32 bytes"),
    )
}

fn main() {
    #[cfg(target_os = "linux")]
    let rng_failed = rng_failure::is_child();
    #[cfg(not(target_os = "linux"))]
    let rng_failed = false;

    let seed = [0x5A; 32];
    let mut control = [0u8; 32];
    let mut shake = Shake256::default();
    shake.update(b"never computed by the signer");
    shake.finalize_xof().read(&mut control);

    let mut failures = Vec::new();
    for (ps, k, l) in [
        (ParamSet::MLDSA44, 4, 4),
        (ParamSet::MLDSA65, 6, 5),
        (ParamSet::MLDSA87, 8, 7),
    ] {
        if !ps.is_enabled() {
            continue;
        }
        let (rho_prime, key, rho_prime_tail) = rho_prime_and_key(&seed, k, l);
        let (pk, sk) = try_keypair_from_seed(ps, &seed).expect("fixture");
        let mut malformed = sk.as_bytes().to_vec();
        malformed[128] = 0xff; // out-of-range first s1 coefficient
        let malformed = SecretKey::new(malformed);
        let maximum = [0xaa; MAX_CONTEXT_LEN];
        let overlong = [0xaa; MAX_CONTEXT_LEN + 1];
        let rnd = [0; 32];
        let message = b"message";
        let signing_error = rng_failed.then_some(MlDsaError::SigningFailed);
        let operations: [Operation<'_>; 15] = [
            (
                "try_sign_from_seed",
                &[],
                &|| try_sign_from_seed(ps, &seed, message).map(Output::Signature),
                signing_error,
            ),
            (
                "try_public_key_from_seed",
                &[],
                &|| try_public_key_from_seed(ps, &seed).map(Output::PublicKey),
                None,
            ),
            (
                "seed context",
                b"ctx",
                &|| {
                    try_sign_from_seed_with_context(ps, &seed, message, b"ctx")
                        .map(Output::Signature)
                },
                signing_error,
            ),
            (
                "seed maximum context",
                &maximum,
                &|| {
                    try_sign_from_seed_with_context(ps, &seed, message, &maximum)
                        .map(Output::Signature)
                },
                signing_error,
            ),
            (
                "try_keypair_from_seed",
                &[],
                &|| try_keypair_from_seed(ps, &seed).map(|(pk, sk)| Output::Keypair(pk, sk)),
                None,
            ),
            (
                "try_public_key",
                &[],
                &|| try_public_key(ps, &sk).map(Output::PublicKey),
                None,
            ),
            (
                "try_sign",
                &[],
                &|| try_sign(ps, &sk, message).map(Output::Signature),
                signing_error,
            ),
            (
                "expanded context",
                b"ctx",
                &|| try_sign_with_context(ps, &sk, message, b"ctx").map(Output::Signature),
                signing_error,
            ),
            (
                "deterministic signing",
                &[],
                &|| try_sign_deterministic(ps, &sk, message, &[], &rnd).map(Output::Signature),
                None,
            ),
            (
                "deterministic maximum context",
                &maximum,
                &|| try_sign_deterministic(ps, &sk, message, &maximum, &rnd).map(Output::Signature),
                None,
            ),
            (
                "seed overlong context",
                &overlong,
                &|| {
                    try_sign_from_seed_with_context(ps, &seed, message, &overlong)
                        .map(Output::Signature)
                },
                Some(MlDsaError::SigningFailed),
            ),
            (
                "expanded overlong context",
                &overlong,
                &|| try_sign_with_context(ps, &sk, message, &overlong).map(Output::Signature),
                Some(MlDsaError::SigningFailed),
            ),
            (
                "malformed expanded signing",
                &[],
                &|| try_sign(ps, &malformed, message).map(Output::Signature),
                Some(MlDsaError::InvalidKeyLength),
            ),
            (
                "malformed public key",
                &[],
                &|| try_public_key(ps, &malformed).map(Output::PublicKey),
                Some(MlDsaError::InvalidKeyLength),
            ),
            (
                "malformed deterministic signing",
                &[],
                &|| {
                    try_sign_deterministic(ps, &malformed, message, &[], &rnd)
                        .map(Output::Signature)
                },
                Some(MlDsaError::InvalidKeyLength),
            ),
        ];
        #[cfg(target_os = "linux")]
        if rng_failed
            && ps
                == ParamSet::ALL
                    .into_iter()
                    .find(|ps| ps.is_enabled())
                    .expect("enabled set")
        {
            rng_failure::block_getrandom();
            assert_eq!(try_keypair(ps).err(), Some(MlDsaError::KeyGenFailed));
        }
        for (name, context, operation, expected_error) in operations {
            wipe();
            let result = core::hint::black_box(operation());
            let found = (
                scan(&rho_prime),
                scan(&key),
                scan(&control),
                scan(&rho_prime_tail),
            );
            println!(
                "{ps} {name} (RNG failure: {rng_failed}): rho' {}x/{}x, K {}x, control {}x",
                found.0, found.3, found.1, found.2
            );
            if found != (0, 0, 0, 0) {
                failures.push(format!("{ps} {name}"));
            }
            match (result, expected_error) {
                (Err(actual), Some(expected)) => assert_eq!(actual, expected, "{ps} {name}"),
                (Ok(Output::Signature(signature)), None) => assert!(
                    verify_with_context(ps, &pk, message, &signature, context),
                    "{ps} {name}"
                ),
                (Ok(Output::PublicKey(actual)), None) => assert_eq!(actual, pk, "{ps} {name}"),
                (Ok(Output::Keypair(actual_pk, actual_sk)), None) => {
                    assert_eq!(actual_pk, pk, "{ps} {name}");
                    assert_eq!(actual_sk.as_bytes(), sk.as_bytes(), "{ps} {name}");
                }
                _ => panic!("unexpected result: {ps} {name}"),
            }
        }
    }
    assert!(
        failures.is_empty(),
        "secrets left in the stack after {failures:?}"
    );
    println!("no ML-DSA secrets left in the stack");
    #[cfg(target_os = "linux")]
    if !rng_failed {
        rng_failure::run_child();
    }
}
