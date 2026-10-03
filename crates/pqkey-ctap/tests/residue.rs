//! ECDSA and EdDSA secrets left behind in the stack after reading a key and
//! signing.
//!
//! An ECDSA signature together with its nonce `k` reveals the private key, and
//! so does an EdDSA signature together with its nonce `r`, so neither nonce
//! may outlive the signature any more than the key does.  RustCrypto's `ecdsa`
//! leaves the RFC 6979 nonce in plain locals, and ed25519-dalek leaves `r` and
//! the hash of the private key in its own.
//!
//! For each ECDSA curve, this test recomputes `k` independently (RFC 6979
//! §3.2 with HMAC over the curve's hash), and for a key kept as a seed it
//! derives the private scalar `d` and the SHAKE256 output it came from (FIPS
//! 186-5 Appendix A.2.1, as pqkey-ctap's `ecdsa::derive_scalar` documents).
//! It checks that `k`·G gives the signature's r, and that `d`·G is the public
//! key, so that it looks for the real secrets.  It reads the key, derives its
//! public key and signs through the engine's public entry points, then scans
//! the dead stack below the caller for `k`, for the HMAC blocks RFC 6979 drew
//! `k` from (on P-521, `k` is their leftmost 521 bits), for `d`, for the
//! SHAKE256 output, and for a control value nobody computed: each as
//! big-endian bytes and reversed, the order of crypto-bigint's little-endian
//! limbs.
//!
//! For each EdDSA curve, it follows RFC 8032 (§5.1.5 and §5.1.6): it hashes
//! the private key with SHA-512, prunes the first half of the hash into the
//! secret scalar `s` and keeps the second half as the prefix, and hashes the
//! prefix and the message into `r`.  It checks that `s`·B is the public key
//! and that `r`·B is the signature's R, then scans for the private key, both
//! halves of its hash, `s` and `s` mod L (the scalar the signer computes
//! with), `r` and the hash it was reduced from, and the control value: each
//! as little-endian bytes, the order of RFC 8032's integers, and reversed.
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
use core::ops::{Add, Mul};

use ciborium::value::Value;
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use hmac::{EagerHash, Hmac, KeyInit, Mac};
use p256::elliptic_curve::bigint::{NonZero, U1024};
use p256::elliptic_curve::sec1::ToSec1Point;
use pqkey_ctap::{
    CoseAlg, try_cose_public_key, try_credential_secret_from_bytes, try_sign_challenge,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use shake::{ExtendableOutput, Shake256, Update, XofReader};

const SCAN: usize = 2 * 1024 * 1024;

/// A point's affine x and y, big-endian.
type Point = (Vec<u8>, Vec<u8>);

/// What the test states itself about a curve the engine signs ECDSA on.
struct EcdsaCase {
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

const ECDSA_CASES: [EcdsaCase; 4] = [
    EcdsaCase {
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
    EcdsaCase {
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
    EcdsaCase {
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
    EcdsaCase {
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

/// What the test states itself about a curve the engine signs EdDSA on.
struct EdDsaCase {
    /// An algorithm on the curve.
    alg: CoseAlg,
    /// The order L of the base point B, big-endian, without leading zeros.
    order: &'static str,
    /// The length of the curve's private keys and encoded points, b/8 in RFC
    /// 8032.
    length: usize,
    /// The curve's hash H, over the parts given: 2·b/8 bytes of output.
    hash: fn(&[&[u8]]) -> Vec<u8>,
    /// Prune the first half of the hash of the private key into the secret
    /// scalar, little-endian.
    prune: fn(&mut [u8]),
    /// The encoding of the given little-endian scalar times B, from the
    /// curve's crate.
    multiply: fn(&[u8]) -> Vec<u8>,
    /// The key the credential keeps.
    key: [u8; 32],
}

const EDDSA_CASES: [EdDsaCase; 1] = [EdDsaCase {
    alg: CoseAlg::EdDSA,
    order: "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
    length: 32,
    hash: |parts| Sha512::digest(parts.concat()).to_vec(),
    // "The lowest three bits of the first octet are cleared, the highest bit
    // of the last octet is cleared, and the second highest bit of the last
    // octet is set." (RFC 8032 §5.1.5)
    prune: |buffer| {
        buffer[0] &= 0xf8;
        buffer[31] &= 0x7f;
        buffer[31] |= 0x40;
    },
    // ed25519-dalek multiplies B only by the scalar of an expanded secret
    // key, which it reduces mod L.
    multiply: |scalar| {
        let mut expanded = ExpandedSecretKey::from_bytes(&[0; 64]);
        expanded.scalar = scalar_like(&expanded.scalar, scalar);
        VerifyingKey::from(&expanded).to_bytes().to_vec()
    },
    key: [0x3E; 32],
}];

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
fn integer(bytes: &[u8]) -> U1024 {
    let mut padded = [0u8; U1024::BYTES];
    padded[U1024::BYTES - bytes.len()..].copy_from_slice(bytes);
    U1024::from_be_slice(&padded)
}

/// `value` mod `modulus`.
fn modulo(value: &U1024, modulus: &U1024) -> U1024 {
    value.rem_vartime(&NonZero::new(*modulus).expect("a modulus is not zero"))
}

/// `x` mod `n`, both big-endian, without leading zeros.
fn reduce(x: &[u8], n: &[u8]) -> Vec<u8> {
    strip(&modulo(&integer(x), &integer(n)).to_be_bytes()).to_vec()
}

/// The little-endian `x` mod `n`, which is big-endian, as little-endian bytes
/// as long as `n`.
fn reduce_le(x: &[u8], n: &[u8]) -> Vec<u8> {
    let x: Vec<u8> = x.iter().rev().copied().collect();
    let remainder = modulo(&integer(&x), &integer(n)).to_be_bytes();
    remainder.as_ref()[U1024::BYTES - n.len()..]
        .iter()
        .rev()
        .copied()
        .collect()
}

/// The little-endian `bytes` as a scalar of `like`'s type, built from `u128`
/// halves by the type's own arithmetic: ed25519-dalek's expanded secret key
/// holds a scalar of curve25519-dalek's, a type it does not name.
fn scalar_like<S>(_like: &S, bytes: &[u8]) -> S
where
    S: From<u128> + Add<Output = S> + Mul<Output = S>,
{
    let two_to_the_64 = || S::from(1u128 << 64);
    bytes.chunks(16).rev().fold(S::from(0u128), |high, chunk| {
        let mut low = [0; 16];
        low[..chunk.len()].copy_from_slice(chunk);
        high * two_to_the_64() * two_to_the_64() + S::from(u128::from_le_bytes(low))
    })
}

/// The private scalar d of `case`'s key on a curve of order `n`, as long as
/// `n`, and for a key kept as a seed the SHAKE256 output d was derived from:
/// the first ⌈(N + 64) / 8⌉ bytes of SHAKE256("pqkey/v1/ecdsa-key/" ‖ curve
/// ‖ seed), N the bit length of `n`, read as an integer c, and
/// d = (c mod (n − 1)) + 1.
fn private_scalar(case: &EcdsaCase, n: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
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
    let n_minus_one = integer(n).wrapping_sub(&U1024::ONE);
    let d = modulo(&integer(&returned_bits), &n_minus_one).wrapping_add(&U1024::ONE);
    let d = d.to_be_bytes().as_ref()[U1024::BYTES - n.len()..].to_vec();
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

/// The byte string under label `wanted` in the COSE_Key `cose_key`.
fn cose_bytes(cose_key: &[u8], wanted: i128) -> Vec<u8> {
    let Value::Map(entries) = ciborium::de::from_reader(cose_key).expect("a COSE_Key") else {
        panic!("a COSE_Key is a map");
    };
    entries
        .into_iter()
        .find_map(|(label, value)| match (label, value) {
            (Value::Integer(label), Value::Bytes(bytes)) if i128::from(label) == wanted => {
                Some(bytes)
            }
            _ => None,
        })
        .expect("a byte string")
}

/// The RFC 6979 §3.2 nonce for private key `x` and message digest `h1` on a
/// curve of order `q`, with the case's HMAC, and the HMAC blocks T it was
/// drawn from.  `h1` is no longer than `q` and below it, true of the curves
/// and values used here, so bits2octets(`h1`) is `h1` itself, padded to the
/// length of `q`.
fn rfc6979_k(case: &EcdsaCase, q: &[u8], x: &[u8], h1: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
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

/// The authenticator data every case signs.
const AUTH_DATA: [u8; 37] = [0x11; 37];
/// The client data hash every case signs.
const CLIENT_DATA_HASH: [u8; 32] = [0x22; 32];

/// The secrets of `case`'s key and signature, checked to be the real ones
/// and looked for in the stack the engine left: what [`run`] found.
fn check_ecdsa(case: &EcdsaCase) -> Vec<String> {
    let alg = case.alg;
    let order = unhex(case.order);
    let (d, returned_bits) = private_scalar(case, &order);
    let message = [&AUTH_DATA[..], &CLIENT_DATA_HASH[..]].concat();
    let (k, blocks) = rfc6979_k(case, &order, &d, &(case.digest)(&message));
    let public_key = (case.multiply)(&d);
    let r = reduce(&(case.multiply)(&k).0, &order);
    // The blocks are k itself unless qlen is not a whole number of them.
    let blocks: Vec<(String, Vec<u8>)> = blocks
        .into_iter()
        .filter(|block| *block != k)
        .enumerate()
        .map(|(i, block)| (format!("T block {}", i + 1), block))
        .collect();
    let needles: Vec<(String, Vec<u8>)> = [("k", k), ("d", d)]
        .into_iter()
        .chain(returned_bits.map(|bytes| ("SHAKE256 output", bytes)))
        .map(|(name, bytes)| (name.to_owned(), bytes))
        .chain(blocks)
        .collect();

    let (cose_key, signature, found) = run(alg, &case.key, needles);
    assert_eq!(
        (cose_bytes(&cose_key, -2), cose_bytes(&cose_key, -3)),
        public_key,
        "{alg:?}: d·G is not the engine's public key"
    );
    assert_eq!(
        der_r(&signature),
        r.as_slice(),
        "{alg:?}: k·G does not give the signature's r"
    );
    found
}

/// The secrets of `case`'s key and signature, checked to be the real ones
/// and looked for in the stack the engine left: what [`run`] found.
fn check_eddsa(case: &EdDsaCase) -> Vec<String> {
    let alg = case.alg;
    let order = unhex(case.order);
    let private_key = case.key.to_vec();
    let hash = (case.hash)(&[&private_key]);
    let (first_half, prefix) = hash.split_at(case.length);
    let mut s = first_half.to_vec();
    (case.prune)(&mut s);
    // Pruning clears every bit of s that L's bytes do not hold.
    s.truncate(order.len());
    let s_mod_l = reduce_le(&s, &order);
    let message = [&AUTH_DATA[..], &CLIENT_DATA_HASH[..]].concat();
    let r_hash = (case.hash)(&[prefix, &message]);
    let r = reduce_le(&r_hash, &order);
    let public_key = (case.multiply)(&s);
    let big_r = (case.multiply)(&r);
    let needles: Vec<(String, Vec<u8>)> = [
        ("private key", private_key),
        ("hash, first half", first_half.to_vec()),
        ("prefix", prefix.to_vec()),
        ("s", s),
        ("s mod L", s_mod_l),
        ("r", r),
        ("r's hash", r_hash),
    ]
    .into_iter()
    .map(|(name, bytes)| (name.to_owned(), bytes))
    .collect();

    let (cose_key, signature, found) = run(alg, &case.key, needles);
    assert_eq!(
        cose_bytes(&cose_key, -2),
        public_key,
        "{alg:?}: s·B is not the engine's public key"
    );
    assert_eq!(signature.len(), 2 * case.length, "{alg:?}: R ‖ S");
    assert_eq!(
        signature[..case.length],
        big_r,
        "{alg:?}: r·B is not the signature's R"
    );
    found
}

/// Read `key` as `alg`, derive its public key and sign
/// [`AUTH_DATA`] ‖ [`CLIENT_DATA_HASH`] through the engine's public entry
/// points, then scan the dead stack below for each of `needles` and for a
/// control value nobody computed, each as given and reversed.  Returns the
/// COSE_Key, the signature, and a line for each value found.
///
/// Every needle is made before the engine runs, so that making one leaves
/// nothing behind that a scan would find.
#[inline(never)]
fn run(
    alg: CoseAlg,
    key: &[u8; 32],
    needles: Vec<(String, Vec<u8>)>,
) -> (Vec<u8>, Vec<u8>, Vec<String>) {
    let control = Sha256::digest(b"never computed by the signer").to_vec();
    let needles: Vec<(String, Vec<u8>, Vec<u8>)> = needles
        .into_iter()
        .chain([("control".to_owned(), control)])
        .map(|(name, bytes)| (name, bytes.iter().rev().copied().collect(), bytes))
        .collect();

    wipe();
    let (cose_key, signature) = {
        let key = try_credential_secret_from_bytes(alg, key).expect("key");
        let cose_key = try_cose_public_key(alg, &key).expect("public key");
        let signature = try_sign_challenge(alg, &key, &AUTH_DATA, &CLIENT_DATA_HASH).expect("sign");
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
    println!("{alg:?}: {} (as given/reversed)", report.join(", "));
    let found = found
        .into_iter()
        .filter(|(_, hits, reversed)| hits + reversed > 0)
        .map(|(name, hits, reversed)| format!("{alg:?}: {name} {hits}x/{reversed}x"))
        .collect();
    (cose_key, signature, found)
}

fn main() {
    let failures: Vec<String> = ECDSA_CASES
        .iter()
        .flat_map(check_ecdsa)
        .chain(EDDSA_CASES.iter().flat_map(check_eddsa))
        .collect();
    assert!(
        failures.is_empty(),
        "secrets left in the stack after signing: {failures:?}"
    );
    println!("no ECDSA or EdDSA secrets left in the stack");
}
