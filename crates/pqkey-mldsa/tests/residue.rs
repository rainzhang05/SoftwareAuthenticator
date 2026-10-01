//! Secrets left behind in the stack after signing and key derivation.
//!
//! FIPS 204 §3.6.3: "implementations of ML-DSA shall ensure that any
//! potentially sensitive intermediate data is destroyed as soon as it is no
//! longer needed."  ρ′ = SHAKE256(ξ ‖ k ‖ ℓ)[32..64] alone regenerates the
//! secret vectors s1 and s2, and K = [96..128] is the signing key's PRF key.
//! After each entry point returns, this test scans the dead stack below its
//! caller for both, and for a control value nobody computed.
//!
//! It is its own program (`harness = false`), single-threaded on the main
//! thread, because it reads stack memory that other functions left behind:
//! `wipe` and `scan` look at the same region below `main`'s frame through
//! buffers of their own.  Reading those bytes is outside what Rust defines,
//! so a clean result proves less than a dirty one; it found the residue
//! before the stack was scrubbed.

use core::mem::MaybeUninit;

use pqkey_mldsa::{ParamSet, try_public_key_from_seed, try_sign_from_seed};
use shake::Shake256;
use shake::digest::{ExtendableOutput, Update, XofReader};

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
fn rho_prime_and_key(seed: &[u8; 32], k: u8, l: u8) -> ([u8; 32], [u8; 32]) {
    let mut out = [0u8; 128];
    let mut shake = Shake256::default();
    shake.update(seed);
    shake.update(&[k, l]);
    shake.finalize_xof().read(&mut out);
    (
        out[32..64].try_into().expect("32 bytes"),
        out[96..128].try_into().expect("32 bytes"),
    )
}

fn main() {
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
        let (rho_prime, key) = rho_prime_and_key(&seed, k, l);
        let operations: [(&str, &dyn Fn()); 2] = [
            ("try_sign_from_seed", &|| {
                core::hint::black_box(try_sign_from_seed(ps, &seed, b"message").expect("sign"));
            }),
            ("try_public_key_from_seed", &|| {
                core::hint::black_box(try_public_key_from_seed(ps, &seed).expect("public key"));
            }),
        ];
        for (name, operation) in operations {
            wipe();
            operation();
            let found = (scan(&rho_prime), scan(&key), scan(&control));
            println!(
                "{ps} {name}: rho' {}x, K {}x, control {}x",
                found.0, found.1, found.2
            );
            if found != (0, 0, 0) {
                failures.push(format!("{ps} {name}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "secrets left in the stack after {failures:?}"
    );
    println!("no ML-DSA secrets left in the stack");
}
