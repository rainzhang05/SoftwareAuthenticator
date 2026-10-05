//! Independent private RSA values for the stack and heap residue tests.

use core::fmt;

use p256::elliptic_curve::bigint::{
    NonZero, Odd, U1024, U2048,
    modular::{FixedMontyForm, MontyParams},
};
use zeroize::Zeroizing;

use crate::CryptoError;

/// A named byte pattern, wiped on drop and redacted in debug output.
pub struct PrivateValue {
    /// The private component's name, never its value.
    pub name: &'static str,
    /// Its big-endian encoding.
    pub bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for PrivateValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateValue")
            .field("name", &self.name)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// The modulus and private values independently derived from p || q.
#[derive(Debug)]
pub struct PrivateValues {
    /// The public modulus.
    pub modulus: [u8; 256],
    /// Private components in both key generation and reconstruction.
    pub secrets: Vec<PrivateValue>,
}

/// Derive RSA-2048's private components with fixed-width arithmetic.
///
/// Key generation uses Euler's totient; reconstruction uses Carmichael's
/// function. Include both exponents and the CRT inverse's Montgomery form.
/// Invalid prime material returns an error rather than panicking.
pub fn private_values(primes: &[u8; 256]) -> Result<PrivateValues, CryptoError> {
    let invalid = || CryptoError::InvalidKey;
    let p = Zeroizing::new(U1024::from_be_slice(&primes[..128]));
    let q = Zeroizing::new(U1024::from_be_slice(&primes[128..]));
    let n: U2048 = p.concatenating_mul(&q);
    let p1 = Zeroizing::new(p.wrapping_sub(&U1024::ONE));
    let q1 = Zeroizing::new(q.wrapping_sub(&U1024::ONE));
    let gcd = Zeroizing::new(p1.gcd(&q1));
    let divisor = NonZero::new(*gcd).into_option().ok_or_else(invalid)?;
    let quotient = Zeroizing::new(*p1 / divisor);
    let lambda = Zeroizing::new(quotient.concatenating_mul::<_, { U2048::LIMBS }>(&q1));
    let phi = Zeroizing::new(p1.concatenating_mul::<_, { U2048::LIMBS }>(&q1));
    let exponent = U2048::from(65537u64);
    let invert = |modulus: U2048| {
        exponent
            .invert_mod(&NonZero::new(modulus).into_option().ok_or_else(invalid)?)
            .into_option()
            .map(Zeroizing::new)
            .ok_or_else(invalid)
    };
    let d = invert(*lambda)?;
    let d_euler = invert(*phi)?;
    let dp = Zeroizing::new(
        d.rem(
            &NonZero::new(p1.resize::<{ U2048::LIMBS }>())
                .into_option()
                .ok_or_else(invalid)?,
        ),
    );
    let dq = Zeroizing::new(
        d.rem(
            &NonZero::new(q1.resize::<{ U2048::LIMBS }>())
                .into_option()
                .ok_or_else(invalid)?,
        ),
    );
    let qinv = Zeroizing::new(
        q.invert_mod(&NonZero::new(*p).into_option().ok_or_else(invalid)?)
            .into_option()
            .ok_or_else(invalid)?,
    );
    let params = MontyParams::new(Odd::new(*p).into_option().ok_or_else(invalid)?);
    let montgomery = Zeroizing::new(FixedMontyForm::new(&qinv, &params).to_montgomery());
    let mut secrets = Vec::new();
    for (name, bytes) in [
        ("p", Zeroizing::new(p.to_be_bytes().to_vec())),
        ("q", Zeroizing::new(q.to_be_bytes().to_vec())),
        ("d", Zeroizing::new(d.to_be_bytes().to_vec())),
        ("d-euler", Zeroizing::new(d_euler.to_be_bytes().to_vec())),
        ("dp", Zeroizing::new(dp.to_be_bytes()[128..].to_vec())),
        ("dq", Zeroizing::new(dq.to_be_bytes()[128..].to_vec())),
        ("qinv", Zeroizing::new(qinv.to_be_bytes().to_vec())),
        (
            "qinv-montgomery",
            Zeroizing::new(montgomery.to_be_bytes().to_vec()),
        ),
    ] {
        secrets.push(PrivateValue { name, bytes });
    }
    Ok(PrivateValues {
        modulus: n.to_be_bytes().into(),
        secrets,
    })
}
