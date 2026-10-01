//! ES256 secrets left behind in the stack after signing and key generation.
//!
//! An ECDSA signature together with its nonce `k` reveals the private key, so
//! `k` must not outlive the signature any more than the key does.  RustCrypto's
//! `ecdsa` leaves the RFC 6979 nonce in plain locals.  This test recomputes `k`
//! independently (RFC 6979 §3.2 with HMAC-SHA-256), signs through the
//! engine's public entry point, and scans the dead stack below the caller for
//! `k`, for the private scalar, and for a control value nobody computed.
//!
//! It does not look for a newly generated private key: a key returned by
//! value can leave copies in the frames it passes through on its way to the
//! caller, because Rust moves are copies.  That is a limit of the language
//! the store's record types document, not an intermediate value.
//!
//! As in `pqkey-mldsa`'s residue test, it reads stack memory other functions
//! left behind, through buffers of its own, so it is a single-threaded
//! program of its own (`harness = false`).

use core::mem::MaybeUninit;

use hmac::{Hmac, KeyInit, Mac};
use pqkey_ctap::{CoseAlg, try_credential_secret_from_bytes, try_sign_challenge};
use sha2::{Digest, Sha256};

const SCAN: usize = 2 * 1024 * 1024;

/// The order of the P-256 group, big-endian.
const ORDER: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

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

#[inline(never)]
fn scan(needle: &[u8]) -> usize {
    let buffer: MaybeUninit<[u8; SCAN]> = MaybeUninit::uninit();
    let start = buffer.as_ptr().cast::<u8>();
    let mut hits = 0;
    for offset in 0..=SCAN - needle.len() {
        // SAFETY: every byte read is inside `buffer`, which this frame owns;
        // they hold whatever earlier calls left there, which is what this test
        // is after, and are only compared.
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

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// The RFC 6979 §3.2 nonce for private key `d` and SHA-256 digest `h`, both
/// already below the group order (true for the values used here).
fn rfc6979_k(d: &[u8; 32], h: &[u8; 32]) -> [u8; 32] {
    let (mut v, mut k) = ([0x01u8; 32], [0x00u8; 32]);
    k = hmac(&k, &[&v, &[0x00], d, h]);
    v = hmac(&k, &[&v]);
    k = hmac(&k, &[&v, &[0x01], d, h]);
    v = hmac(&k, &[&v]);
    loop {
        v = hmac(&k, &[&v]);
        if v != [0; 32] && v < ORDER {
            return v;
        }
        k = hmac(&k, &[&v, &[0x00]]);
        v = hmac(&k, &[&v]);
    }
}

fn main() {
    let d: [u8; 32] = core::array::from_fn(|i| {
        if i == 0 {
            0x3C
        } else {
            ((i * 29) as u8) ^ 0xA7
        }
    });
    let (auth_data, client_data_hash) = ([0x11u8; 37], [0x22u8; 32]);
    let mut message = auth_data.to_vec();
    message.extend_from_slice(&client_data_hash);
    let digest: [u8; 32] = Sha256::digest(&message).into();
    let k = rfc6979_k(&d, &digest);
    let control: [u8; 32] = Sha256::digest(b"never computed by the signer").into();

    wipe();
    {
        let key = try_credential_secret_from_bytes(CoseAlg::ES256, &d).expect("key");
        core::hint::black_box(
            try_sign_challenge(CoseAlg::ES256, &key, &auth_data, &client_data_hash).expect("sign"),
        );
    }
    let found = (scan(&k), scan(&d), scan(&control));
    println!(
        "try_sign_challenge: k {}x, d {}x, control {}x",
        found.0, found.1, found.2
    );
    assert_eq!(
        found,
        (0, 0, 0),
        "ES256 secrets left in the stack after signing"
    );
    println!("no ES256 secrets left in the stack");
}
