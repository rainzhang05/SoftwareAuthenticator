//! Provisioning the attestation key and its certificate.
//!
//! The certificate is self-signed by the attestation key, with the product
//! named in the subject. The signature is made with the `p256` crate the CTAP
//! engine already uses, so rcgen is built without a crypto backend.

use std::io;

use p256::ecdsa::{signature::Signer, DerSignature, SigningKey as EcdsaSigningKey};
use p256::elliptic_curve::Generate;
use rcgen::{
    CertificateParams, DnType, IsCa, KeyIdMethod, PublicKeyData, SanType, SerialNumber,
    SignatureAlgorithm, SigningKey, PKCS_ECDSA_P256_SHA256,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Who the attestation certificate names.
#[derive(Clone, Copy)]
pub struct IdentityConfig<'a> {
    pub manufacturer: &'a str,
    pub product: &'a str,
    pub serial: &'a str,
}

/// A P-256 key that rcgen signs certificates with.
struct P256Key {
    signing_key: EcdsaSigningKey,
    /// The uncompressed SEC1 public key.
    public_key: Vec<u8>,
}

impl P256Key {
    fn new(signing_key: EcdsaSigningKey) -> Self {
        let public_key = signing_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        Self {
            signing_key,
            public_key,
        }
    }
}

impl PublicKeyData for P256Key {
    fn der_bytes(&self) -> &[u8] {
        &self.public_key
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for P256Key {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature: DerSignature = self.signing_key.sign(msg);
        Ok(signature.as_bytes().to_vec())
    }
}

/// The officially assigned ISO 3166-1 alpha-2 country codes, in order.
///
/// WebAuthn Level 3 §8.2.1 wants Subject-C to be the "ISO 3166 code
/// specifying the country where the Authenticator vendor is incorporated".
/// User-assigned codes (AA, QM to QZ, XA to XZ, ZZ), and so XK, are not
/// countries and are left out.
const ISO_3166_ALPHA_2: &str = "\
    AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ \
    BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM \
    DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS \
    GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN \
    KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ \
    MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM \
    PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV \
    SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI \
    VN VU WF WS YE YT ZA ZM ZW";

/// Parse the country named in the attestation certificate's subject: an ISO
/// 3166-1 alpha-2 code, in either case. Returns it in upper case.
pub fn parse_country(input: &str) -> Result<String, String> {
    let code = input.to_ascii_uppercase();
    let is_assigned = code.len() == 2
        && code.bytes().all(|byte| byte.is_ascii_uppercase())
        && ISO_3166_ALPHA_2.split_ascii_whitespace().any(|c| c == code);
    if is_assigned {
        Ok(code)
    } else {
        Err(format!(
            "{input:?} is not an ISO 3166-1 alpha-2 country code, such as US or CN"
        ))
    }
}

fn certificate_error(err: rcgen::Error) -> io::Error {
    io::Error::other(format!(
        "cannot generate the attestation certificate: {err}"
    ))
}

/// Generate a P-256 attestation key and a self-signed certificate for it.
/// Returns the 32-byte private scalar and the DER certificate.
pub fn generate_attestation_certificate(
    identity: &IdentityConfig<'_>,
) -> io::Result<(Zeroizing<[u8; 32]>, Vec<u8>)> {
    let key = P256Key::new(EcdsaSigningKey::generate());
    let private_key = Zeroizing::new(key.signing_key.to_bytes().into());

    let mut params =
        CertificateParams::new(vec![identity.product.to_string()]).map_err(certificate_error)?;
    params
        .distinguished_name
        .push(DnType::OrganizationName, identity.manufacturer);
    params
        .distinguished_name
        .push(DnType::CommonName, identity.product);
    params.subject_alt_names.push(SanType::DnsName(
        identity.product.try_into().map_err(certificate_error)?,
    ));
    params.serial_number = Some(SerialNumber::from(identity.serial.as_bytes().to_vec()));
    params.is_ca = IsCa::ExplicitNoCa;
    // The subject key identifier rcgen computes with a crypto backend: the
    // first 20 bytes of SHA-256 over the subjectPublicKeyInfo.
    params.key_identifier_method =
        KeyIdMethod::PreSpecified(Sha256::digest(key.subject_public_key_info())[..20].to_vec());

    let certificate = params.self_signed(&key).map_err(certificate_error)?;
    Ok((private_key, certificate.der().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    /// One DER element: its tag, its contents, and the whole encoding.
    struct Tlv<'a> {
        tag: u8,
        contents: &'a [u8],
        encoding: &'a [u8],
    }

    /// Split the first DER element off `input`.
    fn next_tlv<'a>(input: &mut &'a [u8]) -> Tlv<'a> {
        let tag = input[0];
        let (length, header) = match input[1] {
            short if short < 0x80 => (short as usize, 2),
            long => {
                let count = (long & 0x7f) as usize;
                let length = input[2..2 + count]
                    .iter()
                    .fold(0usize, |acc, byte| (acc << 8) | *byte as usize);
                (length, 2 + count)
            }
        };
        let encoding = &input[..header + length];
        let contents = &encoding[header..];
        *input = &input[header + length..];
        Tlv {
            tag,
            contents,
            encoding,
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    const IDENTITY: IdentityConfig<'static> = IdentityConfig {
        manufacturer: "Feitian Technologies Co., Ltd.",
        product: "Feitian FIDO2 Software Authenticator (ML-DSA)",
        serial: "FEITIAN-PQC-001",
    };

    #[test]
    fn certificate_is_self_signed_by_the_returned_key() {
        let (private_key, der) = generate_attestation_certificate(&IDENTITY).unwrap();
        let verifying_key = *EcdsaSigningKey::from_bytes(&(*private_key).into())
            .unwrap()
            .verifying_key();

        let mut input = der.as_slice();
        let certificate = next_tlv(&mut input);
        assert_eq!(certificate.tag, 0x30);
        assert!(input.is_empty());
        let mut fields = certificate.contents;
        let tbs = next_tlv(&mut fields);
        let algorithm = next_tlv(&mut fields);
        let signature = next_tlv(&mut fields);
        assert!(fields.is_empty());

        // ecdsa-with-SHA256
        let ecdsa_with_sha256 = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        assert_eq!(algorithm.contents, ecdsa_with_sha256);
        assert_eq!(signature.tag, 0x03);
        assert_eq!(signature.contents[0], 0, "no unused bits");
        let signature = DerSignature::from_bytes(&signature.contents[1..]).unwrap();
        verifying_key
            .verify(tbs.encoding, &signature)
            .expect("the signature verifies with the attestation key");

        let tbs = tbs.contents;
        let public_key = verifying_key.to_sec1_point(false);
        assert!(contains(tbs, public_key.as_bytes()));
        assert!(contains(tbs, IDENTITY.manufacturer.as_bytes()));
        assert!(contains(tbs, IDENTITY.product.as_bytes()));
        // The serial number is the serial string's bytes.
        let mut serial = vec![0x02, IDENTITY.serial.len() as u8];
        serial.extend_from_slice(IDENTITY.serial.as_bytes());
        assert!(contains(tbs, &serial));
        // Basic constraints, critical, CA:FALSE (the default, so an empty
        // sequence in DER).
        let basic_constraints = [
            0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00,
        ];
        assert!(contains(tbs, &basic_constraints));
        // Subject key identifier: SHA-256 of the subjectPublicKeyInfo, 20 bytes.
        let spki = P256Key::new(EcdsaSigningKey::from_bytes(&(*private_key).into()).unwrap())
            .subject_public_key_info();
        assert!(contains(tbs, &spki));
        assert!(contains(tbs, &Sha256::digest(&spki)[..20]));
    }

    #[test]
    fn countries_are_assigned_iso_3166_alpha_2_codes() {
        let codes: Vec<&str> = ISO_3166_ALPHA_2.split_ascii_whitespace().collect();
        assert_eq!(codes.len(), 249);
        assert!(codes.windows(2).all(|pair| pair[0] < pair[1]), "sorted");

        assert_eq!(parse_country("CN").unwrap(), "CN");
        assert_eq!(parse_country("us").unwrap(), "US");
        assert_eq!(parse_country("Gb").unwrap(), "GB");
        for rejected in [
            "", "U", "USA", "U1", "12", "ÜS", "UK", "EU", "XK", "AA", "QZ", "ZZ", " US",
        ] {
            assert!(parse_country(rejected).is_err(), "{rejected:?}");
        }
    }

    #[test]
    fn every_certificate_has_a_new_key() {
        let (first, _) = generate_attestation_certificate(&IDENTITY).unwrap();
        let (second, _) = generate_attestation_certificate(&IDENTITY).unwrap();
        assert_ne!(*first, *second);
    }
}
