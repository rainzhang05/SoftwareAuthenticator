//! ECDSA secrets left behind in the stack after reading a key and signing.
//!
//! An ECDSA signature together with its nonce `k` reveals the private key, so
//! `k` must not outlive the signature any more than the key does.  RustCrypto's
//! `ecdsa` leaves the RFC 6979 nonce in plain locals.  For each curve, this
//! test recomputes `k` independently (RFC 6979 §3.2 with HMAC over the curve's
//! hash), and for a key kept as a seed it derives the private scalar `d` and
//! the SHAKE256 output it came from (FIPS 186-5 Appendix A.2.1, as
//! pqkey-ctap's `ecdsa::derive_scalar` documents).  It checks that `k`·G
//! gives the signature's r, and that `d`·G is the public key, so that it
//! looks for the real secrets.  It reads the key, derives its public key and
//! signs through the engine's public entry points, then scans the dead stack
//! below the caller for `k`, for the HMAC blocks RFC 6979 drew `k` from (on
//! P-521, `k` is their leftmost 521 bits), for `d`, for the SHAKE256 output,
//! and for a control value nobody computed: each as big-endian bytes and
//! reversed, the order of crypto-bigint's little-endian limbs.
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

use ciborium::value::Value;
use hmac::{EagerHash, Hmac, KeyInit, Mac};
use p256::elliptic_curve::bigint::{NonZero, U640};
use p256::elliptic_curve::sec1::ToSec1Point;
use pqkey_ctap::{
    CoseAlg, try_cose_public_key, try_credential_secret_from_bytes, try_sign_challenge,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use shake::{ExtendableOutput, Shake256, Update, XofReader};

const SCAN: usize = 2 * 1024 * 1024;

/// A point's affine x and y, big-endian.
type Point = (Vec<u8>, Vec<u8>);

/// What the test states itself about a curve the engine signs on.
struct Case {
    /// An algorithm on the curve.
    alg: CoseAlg,
    /// The order n of the curve's group, big-endian, in as many bytes as the
    /// curve's scalars.
    order: &'static str,
    /// The curve's hash.
    digest: fn(&[u8]) -> Vec<u8>,
    /// HMAC over the curve's hash, keyed with the first argument, over the
    /// parts of the second.
    hmac: fn(&[u8], &[&[u8]]) -> Vec<u8>,
    /// The affine x and y of the given scalar times the base point, from the
    /// curve's crate.
    multiply: fn(&[u8]) -> Point,
    /// What the credential keeps.
    kept: Kept,
    /// The key the credential keeps.
    key: [u8; 32],
}

/// The form a credential keeps its key in.
enum Kept {
    /// The private scalar.
    Scalar,
    /// A seed the scalar is derived from, on the curve of this name.
    Seed(&'static str),
}

const CASES: [Case; 4] = [
    Case {
        alg: CoseAlg::ES256,
        order: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        digest: digest::<Sha256>,
        hmac: hmac::<Sha256>,
        multiply: |scalar| {
            let secret = p256::SecretKey::from_slice(scalar).expect("a scalar below n");
            coordinates(secret.public_key().to_sec1_point(false).as_bytes())
        },
        kept: Kept::Scalar,
        key: [
            0x3C, 0xBA, 0x9D, 0xF0, 0xD3, 0x36, 0x09, 0x6C, 0x4F, 0xA2, 0x85, 0x98, 0xFB, 0xDE,
            0x31, 0x14, 0x77, 0x4A, 0xAD, 0x80, 0xE3, 0xC6, 0xD9, 0x3C, 0x1F, 0x72, 0x55, 0xA8,
            0x8B, 0xEE, 0xC1, 0x24,
        ],
    },
    Case {
        alg: CoseAlg::ES384,
        order: concat!(
            "ffffffffffffffffffffffffffffffffffffffffffffffff",
            "c7634d81f4372ddf581a0db248b0a77aecec196accc52973"
        ),
        digest: digest::<Sha384>,
        hmac: hmac::<Sha384>,
        multiply: |scalar| {
            let secret = p384::SecretKey::from_slice(scalar).expect("a scalar below n");
            coordinates(secret.public_key().to_sec1_point(false).as_bytes())
        },
        kept: Kept::Seed("P-384"),
        key: [0x5A; 32],
    },
    Case {
        alg: CoseAlg::ES512,
        order: concat!(
            "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "fa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409"
        ),
        digest: digest::<Sha512>,
        hmac: hmac::<Sha512>,
        multiply: |scalar| {
            let secret = p521::SecretKey::from_slice(scalar).expect("a scalar below n");
            coordinates(secret.public_key().to_sec1_point(false).as_bytes())
        },
        kept: Kept::Seed("P-521"),
        key: [0xA5; 32],
    },
    Case {
        alg: CoseAlg::ES256K,
        order: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        digest: digest::<Sha256>,
        hmac: hmac::<Sha256>,
        multiply: |scalar| {
            let secret = k256::SecretKey::from_slice(scalar).expect("a scalar below n");
            coordinates(secret.public_key().to_sec1_point(false).as_bytes())
        },
        kept: Kept::Seed("secp256k1"),
        key: [0xC3; 32],
    },
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

fn digest<D: Digest>(message: &[u8]) -> Vec<u8> {
    D::digest(message).to_vec()
}

fn hmac<D: EagerHash>(key: &[u8], parts: &[&[u8]]) -> Vec<u8>
where
    Hmac<D>: KeyInit + Mac,
{
    let mut mac = <Hmac<D> as KeyInit>::new_from_slice(key).expect("any key length");
    for part in parts {
        Mac::update(&mut mac, part);
    }
    mac.finalize().into_bytes().to_vec()
}

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

/// The x and y of an uncompressed SEC1 point.
fn coordinates(point: &[u8]) -> Point {
    let (x, y) = point[1..].split_at((point.len() - 1) / 2);
    (x.to_vec(), y.to_vec())
}

/// `bytes` without leading zeros.
fn strip(bytes: &[u8]) -> &[u8] {
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    &bytes[zeros..]
}

/// The big-endian `bytes` as an integer.
fn integer(bytes: &[u8]) -> U640 {
    let mut padded = [0u8; U640::BYTES];
    padded[U640::BYTES - bytes.len()..].copy_from_slice(bytes);
    U640::from_be_slice(&padded)
}

/// `value` mod `modulus`.
fn modulo(value: &U640, modulus: &U640) -> U640 {
    value.rem_vartime(&NonZero::new(*modulus).expect("a modulus is not zero"))
}

/// `x` mod `n`, both big-endian, without leading zeros.
fn reduce(x: &[u8], n: &[u8]) -> Vec<u8> {
    strip(&modulo(&integer(x), &integer(n)).to_be_bytes()).to_vec()
}

/// The private scalar d of `case`'s key on a curve of order `n`, as long as
/// `n`, and for a key kept as a seed the SHAKE256 output d was derived from:
/// the first ⌈(N + 64) / 8⌉ bytes of SHAKE256("pqkey/v1/ecdsa-key/" ‖ curve
/// ‖ seed), N the bit length of `n`, read as an integer c, and
/// d = (c mod (n − 1)) + 1.
fn private_scalar(case: &Case, n: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
    let Kept::Seed(curve) = case.kept else {
        return (case.key.to_vec(), None);
    };
    let bits = n.len() * 8 - n[0].leading_zeros() as usize;
    let mut returned_bits = vec![0; (bits + 64).div_ceil(8)];
    let mut shake = Shake256::default();
    shake.update(b"pqkey/v1/ecdsa-key/");
    shake.update(curve.as_bytes());
    shake.update(&case.key);
    shake.finalize_xof().read(&mut returned_bits);
    let n_minus_one = integer(n).wrapping_sub(&U640::ONE);
    let d = modulo(&integer(&returned_bits), &n_minus_one).wrapping_add(&U640::ONE);
    let d = d.to_be_bytes().as_ref()[U640::BYTES - n.len()..].to_vec();
    (d, Some(returned_bits))
}

/// The r of the DER `Ecdsa-Sig-Value` `signature`, without leading zeros.
fn der_r(signature: &[u8]) -> &[u8] {
    assert_eq!(signature[0], 0x30, "a SEQUENCE");
    // The SEQUENCE's length takes one byte, or more after a long-form byte.
    let r = match signature[1] {
        length if length < 0x80 => 2,
        long => 2 + usize::from(long & 0x7f),
    };
    assert_eq!(signature[r], 0x02, "an INTEGER");
    let length = usize::from(signature[r + 1]);
    strip(&signature[r + 2..r + 2 + length])
}

/// The x and y of the COSE_Key `cose_key`.
fn cose_coordinates(cose_key: &[u8]) -> Point {
    let Value::Map(entries) = ciborium::de::from_reader(cose_key).expect("a COSE_Key") else {
        panic!("a COSE_Key is a map");
    };
    let label = |wanted: i128| {
        entries
            .iter()
            .find_map(|(label, value)| match (label, value) {
                (Value::Integer(label), Value::Bytes(bytes)) if i128::from(*label) == wanted => {
                    Some(bytes.clone())
                }
                _ => None,
            })
            .expect("a coordinate")
    };
    (label(-2), label(-3))
}

/// The RFC 6979 §3.2 nonce for private key `x` and message digest `h1` on a
/// curve of order `q`, with the case's HMAC, and the HMAC blocks T it was
/// drawn from.  `h1` is no longer than `q` and below it, true of the curves
/// and values used here, so bits2octets(`h1`) is `h1` itself, padded to the
/// length of `q`.
fn rfc6979_k(case: &Case, q: &[u8], x: &[u8], h1: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut h = vec![0; q.len() - h1.len()];
    h.extend_from_slice(h1);
    assert!(
        h.as_slice() < q,
        "{:?}: the digest is not below n",
        case.alg
    );
    // qlen, the bit length of q, and the bits bits2int drops from rlen bits.
    let excess = q[0].leading_zeros() as usize;
    let qlen = q.len() * 8 - excess;
    let (mut v, mut k) = (vec![0x01; h1.len()], vec![0x00; h1.len()]);
    k = (case.hmac)(&k, &[&v, &[0x00], x, &h]);
    v = (case.hmac)(&k, &[&v]);
    k = (case.hmac)(&k, &[&v, &[0x01], x, &h]);
    v = (case.hmac)(&k, &[&v]);
    loop {
        let mut blocks = Vec::new();
        while blocks.len() * h1.len() * 8 < qlen {
            v = (case.hmac)(&k, &[&v]);
            blocks.push(v.clone());
        }
        let t = blocks.concat();
        // bits2int: the leftmost qlen bits of T.
        let candidate: Vec<u8> = (0..q.len())
            .map(|i| match (excess, i) {
                (0, _) => t[i],
                (_, 0) => t[0] >> excess,
                _ => (t[i] >> excess) | (t[i - 1] << (8 - excess)),
            })
            .collect();
        if candidate.iter().any(|byte| *byte != 0) && candidate.as_slice() < q {
            return (candidate, blocks);
        }
        k = (case.hmac)(&k, &[&v, &[0x00]]);
        v = (case.hmac)(&k, &[&v]);
    }
}

/// Run `case` through the engine and return what it left in the stack.
#[inline(never)]
fn check(case: &Case) -> Vec<String> {
    let alg = case.alg;
    let order = unhex(case.order);
    let (d, returned_bits) = private_scalar(case, &order);
    let (auth_data, client_data_hash) = ([0x11u8; 37], [0x22u8; 32]);
    let message = [&auth_data[..], &client_data_hash[..]].concat();
    let (k, blocks) = rfc6979_k(case, &order, &d, &(case.digest)(&message));
    let public_key = (case.multiply)(&d);
    let r = reduce(&(case.multiply)(&k).0, &order);
    let control = Sha256::digest(b"never computed by the signer").to_vec();
    // Every needle is made before the engine runs, so that making one leaves
    // nothing behind that a scan would find.
    // The blocks are k itself unless qlen is not a whole number of them.
    let blocks: Vec<(String, Vec<u8>)> = blocks
        .into_iter()
        .filter(|block| *block != k)
        .enumerate()
        .map(|(i, block)| (format!("T block {}", i + 1), block))
        .collect();
    let needles: Vec<(String, Vec<u8>, Vec<u8>)> = [("k", k), ("d", d), ("control", control)]
        .into_iter()
        .chain(returned_bits.map(|bytes| ("SHAKE256 output", bytes)))
        .map(|(name, bytes)| (name.to_owned(), bytes))
        .chain(blocks)
        .map(|(name, bytes)| (name, bytes.iter().rev().copied().collect(), bytes))
        .collect();

    wipe();
    let (cose_key, signature) = {
        let key = try_credential_secret_from_bytes(alg, &case.key).expect("key");
        let cose_key = try_cose_public_key(alg, &key).expect("public key");
        let signature = try_sign_challenge(alg, &key, &auth_data, &client_data_hash).expect("sign");
        (cose_key, signature)
    };
    let found: Vec<(&str, usize, usize)> = needles
        .iter()
        .map(|(name, reversed, bytes)| (name.as_str(), scan(bytes), scan(reversed)))
        .collect();

    let report: Vec<String> = found
        .iter()
        .map(|(name, hits, reversed)| format!("{name} {hits}x/{reversed}x"))
        .collect();
    println!("{alg:?}: {} (big-endian/reversed)", report.join(", "));
    assert_eq!(
        cose_coordinates(&cose_key),
        public_key,
        "{alg:?}: d·G is not the engine's public key"
    );
    assert_eq!(
        der_r(&signature),
        r.as_slice(),
        "{alg:?}: k·G does not give the signature's r"
    );
    found
        .into_iter()
        .filter(|(_, hits, reversed)| hits + reversed > 0)
        .map(|(name, hits, reversed)| format!("{alg:?}: {name} {hits}x/{reversed}x"))
        .collect()
}

fn main() {
    let failures: Vec<String> = CASES.iter().flat_map(check).collect();
    assert!(
        failures.is_empty(),
        "ECDSA secrets left in the stack after signing: {failures:?}"
    );
    println!("no ECDSA secrets left in the stack");
}
