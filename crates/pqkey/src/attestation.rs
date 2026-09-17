//! Provisioning the attestation key and its certificate.
//!
//! The certificate is self-signed by the attestation key and meets the
//! requirements WebAuthn Level 3 §8.2.1 sets for the attestation certificate
//! of a packed attestation statement:
//!
//! * version 3;
//! * subject C (PrintableString), O, OU "Authenticator Attestation" and CN
//!   (UTF8String);
//! * the id-fido-gen-ce-aaguid extension, not critical, holding the AAGUID
//!   as an OCTET STRING inside the extension's OCTET STRING, so a relying
//!   party can check it against the AAGUID in authenticatorData;
//! * basic constraints with cA false.
//!
//! The serial number is 20 random octets made positive (RFC 5280 §4.1.2.2).
//! The certificate is meant to last as long as the installation, so it has no
//! well-defined expiration date (RFC 5280 §4.1.2.5). It has no subject
//! alternative name: the subject names it, and a product name is not a DNS
//! name. It rides in every makeCredential response with attestation, so it is
//! kept to what is needed.
//!
//! The signature is ECDSA P-256 with SHA-256, made with the `p256` crate the
//! CTAP engine already uses, so rcgen is built without a crypto backend.

use std::{
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use p256::ecdsa::{signature::Signer, DerSignature, SigningKey as EcdsaSigningKey};
use p256::elliptic_curve::Generate;
use rcgen::{
    date_time_ymd, string::PrintableString, CertificateParams, CustomExtension, DistinguishedName,
    DnType, DnValue, IsCa, KeyIdMethod, PublicKeyData, SerialNumber, SignatureAlgorithm,
    SigningKey, PKCS_ECDSA_P256_SHA256,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// id-fido-gen-ce-aaguid (WebAuthn Level 3 §8.2.1).
pub const ID_FIDO_GEN_CE_AAGUID: &[u64] = &[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4];

/// The subject organizational unit WebAuthn Level 3 §8.2.1 prescribes.
pub const ORGANIZATIONAL_UNIT: &str = "Authenticator Attestation";

/// Who the attestation certificate names, and the AAGUID it carries.
#[derive(Clone, Copy)]
pub struct IdentityConfig<'a> {
    /// Subject O: the legal name of the authenticator vendor.
    pub manufacturer: &'a str,
    /// Subject CN.
    pub product: &'a str,
    /// Subject C: where the vendor is incorporated, an ISO 3166-1 alpha-2
    /// code (see [`parse_country`]).
    pub country: &'a str,
    /// The AAGUID the authenticator reports in authenticatorData.
    pub aaguid: [u8; 16],
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

/// The contents octets of id-fido-gen-ce-aaguid's DER encoding.
const ID_FIDO_GEN_CE_AAGUID_DER: [u8; 11] = [
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe5, 0x1c, 0x01, 0x01, 0x04,
];

const TAG_BOOLEAN: u8 = 0x01;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
/// `[0] EXPLICIT`, the TBSCertificate version.
const TAG_VERSION: u8 = 0xa0;
/// `[3] EXPLICIT`, the TBSCertificate extensions.
const TAG_EXTENSIONS: u8 = 0xa3;

/// Split the first DER element off `input`: its tag and contents. `None` if
/// `input` does not start with a complete element.
fn next_element<'a>(input: &mut &'a [u8]) -> Option<(u8, &'a [u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let length = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let (octets, tail) = rest.split_at(count);
        rest = tail;
        octets
            .iter()
            .fold(0usize, |length, octet| (length << 8) | usize::from(*octet))
    };
    if rest.len() < length {
        return None;
    }
    let (contents, tail) = rest.split_at(length);
    *input = tail;
    Some((tag, contents))
}

/// The contents of the next DER element if it has tag `tag`.
fn expect_element<'a>(input: &mut &'a [u8], tag: u8) -> Option<&'a [u8]> {
    match next_element(input)? {
        (found, contents) if found == tag => Some(contents),
        _ => None,
    }
}

/// The AAGUID in a certificate's id-fido-gen-ce-aaguid extension, if it has
/// that extension, not critical and encoded as WebAuthn Level 3 §8.2.1
/// requires. `None` for anything else, including a certificate that cannot
/// be parsed.
///
/// This is not a certificate validator: it walks only as much of the DER as
/// it takes to find the extension.
pub fn certificate_aaguid(certificate: &[u8]) -> Option<[u8; 16]> {
    let mut input = certificate;
    let mut certificate = expect_element(&mut input, TAG_SEQUENCE)?;
    let mut tbs = expect_element(&mut certificate, TAG_SEQUENCE)?;
    if tbs.first() == Some(&TAG_VERSION) {
        next_element(&mut tbs)?;
    }
    // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    for _ in 0..6 {
        next_element(&mut tbs)?;
    }
    // issuerUniqueID and subjectUniqueID may come before the extensions.
    let mut extensions = loop {
        match next_element(&mut tbs)? {
            (TAG_EXTENSIONS, mut wrapper) => break expect_element(&mut wrapper, TAG_SEQUENCE)?,
            _ => continue,
        }
    };
    while !extensions.is_empty() {
        let mut extension = expect_element(&mut extensions, TAG_SEQUENCE)?;
        if expect_element(&mut extension, TAG_OID)? != ID_FIDO_GEN_CE_AAGUID_DER {
            continue;
        }
        if extension.first() == Some(&TAG_BOOLEAN) {
            let critical = expect_element(&mut extension, TAG_BOOLEAN)?;
            if critical != [0x00] {
                return None;
            }
        }
        let mut value = expect_element(&mut extension, TAG_OCTET_STRING)?;
        let aaguid = expect_element(&mut value, TAG_OCTET_STRING)?;
        return if value.is_empty() && extension.is_empty() {
            aaguid.try_into().ok()
        } else {
            None
        };
    }
    None
}

/// A random serial number: 20 octets (the most RFC 5280 §4.1.2.2 allows),
/// with the top bit clear so the INTEGER is positive and the next bit set so
/// it keeps all 20 octets. 158 random bits make it unique.
fn random_serial_number() -> io::Result<SerialNumber> {
    let mut serial = [0u8; 20];
    getrandom::fill(&mut serial).map_err(|err| {
        io::Error::other(format!(
            "cannot generate a certificate serial number: {err}"
        ))
    })?;
    serial[0] = (serial[0] & 0x7f) | 0x40;
    Ok(SerialNumber::from_slice(&serial))
}

/// Generate a P-256 attestation key and a self-signed certificate for it.
/// Returns the 32-byte private scalar and the DER certificate.
pub fn generate_attestation_certificate(
    identity: &IdentityConfig<'_>,
) -> io::Result<(Zeroizing<[u8; 32]>, Vec<u8>)> {
    let country = parse_country(identity.country)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let key = P256Key::new(EcdsaSigningKey::generate());
    let private_key = Zeroizing::new(key.signing_key.to_bytes().into());

    let mut params = CertificateParams::default();
    let mut subject = DistinguishedName::new();
    subject.push(
        DnType::CountryName,
        DnValue::PrintableString(PrintableString::try_from(country).map_err(certificate_error)?),
    );
    subject.push(DnType::OrganizationName, identity.manufacturer);
    subject.push(DnType::OrganizationalUnitName, ORGANIZATIONAL_UNIT);
    subject.push(DnType::CommonName, identity.product);
    params.distinguished_name = subject;
    params.serial_number = Some(random_serial_number()?);

    // Valid from the start of the day before it is made, so a relying party
    // whose clock is somewhat behind still accepts it, without recording
    // when it was made more precisely than that. There is no well-defined
    // expiration date: RFC 5280 §4.1.2.5 "the notAfter SHOULD be assigned the
    // GeneralizedTime value of 99991231235959Z".
    const DAY: u64 = 24 * 60 * 60;
    let today = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() / DAY);
    params.not_before =
        date_time_ymd(1970, 1, 1) + Duration::from_secs(today.saturating_sub(1) * DAY);
    params.not_after = date_time_ymd(9999, 12, 31) + Duration::from_secs(DAY - 1);

    // AAGUID OCTET STRING; rcgen wraps it in the extension's OCTET STRING.
    let mut aaguid = vec![0x04, 16];
    aaguid.extend_from_slice(&identity.aaguid);
    let mut aaguid_extension = CustomExtension::from_oid_content(ID_FIDO_GEN_CE_AAGUID, aaguid);
    aaguid_extension.set_criticality(false);
    params.custom_extensions.push(aaguid_extension);

    // Writes basic constraints (critical, cA false) and a subject key
    // identifier, which RFC 5280 §4.2.1.2 says SHOULD be in every end entity
    // certificate: here the first 20 bytes of SHA-256 over the
    // subjectPublicKeyInfo, as rcgen computes it with a crypto backend.
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_identifier_method =
        KeyIdMethod::PreSpecified(Sha256::digest(key.subject_public_key_info())[..20].to_vec());

    let certificate = params.self_signed(&key).map_err(certificate_error)?;
    Ok((private_key, certificate.der().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use x509_parser::{
        certificate::X509Certificate, der_parser::asn1_rs::Tag, oid_registry, prelude::FromDer,
    };

    const IDENTITY: IdentityConfig<'static> = IdentityConfig {
        manufacturer: "Feitian Technologies Co., Ltd.",
        product: "Feitian FIDO2 Software Authenticator (ML-DSA)",
        country: "CN",
        aaguid: [
            0x46, 0x45, 0x49, 0x54, 0x49, 0x41, 0x4e, 0x98, 0x06, 0x16, 0x52, 0x5a, 0x30, 0x31,
            0x00, 0x00,
        ],
    };

    fn parse(der: &[u8]) -> X509Certificate<'_> {
        let (rest, certificate) = X509Certificate::from_der(der).expect("a valid certificate");
        assert!(rest.is_empty(), "trailing bytes after the certificate");
        certificate
    }

    /// Every field and extension WebAuthn Level 3 §8.2.1 requires, read back
    /// with x509-parser, and the signature checked with the attestation key.
    #[test]
    fn certificate_meets_the_packed_attestation_requirements() {
        let (private_key, der) = generate_attestation_certificate(&IDENTITY).unwrap();
        let signing_key = EcdsaSigningKey::from_bytes(&(*private_key).into()).unwrap();
        let verifying_key = *signing_key.verifying_key();
        let certificate = parse(&der);
        let tbs = &certificate.tbs_certificate;

        // "Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER
        // with value 2)."
        assert_eq!(tbs.version.0, 2);

        // Subject C, O, OU and CN, in that order, with the string types
        // §8.2.1 names; and self-issued.
        let subject: Vec<_> = tbs
            .subject
            .iter_attributes()
            .map(|attribute| {
                (
                    attribute.attr_type().clone(),
                    attribute.attr_value().tag(),
                    attribute.as_str().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            subject,
            [
                (
                    oid_registry::OID_X509_COUNTRY_NAME,
                    Tag::PrintableString,
                    "CN"
                ),
                (
                    oid_registry::OID_X509_ORGANIZATION_NAME,
                    Tag::Utf8String,
                    IDENTITY.manufacturer
                ),
                (
                    oid_registry::OID_X509_ORGANIZATIONAL_UNIT,
                    Tag::Utf8String,
                    "Authenticator Attestation"
                ),
                (
                    oid_registry::OID_X509_COMMON_NAME,
                    Tag::Utf8String,
                    IDENTITY.product
                ),
            ]
        );
        assert_eq!(tbs.issuer.as_raw(), tbs.subject.as_raw());

        // Exactly these extensions: nothing else, in particular no subject
        // alternative name.
        let extensions: Vec<_> = tbs
            .extensions()
            .iter()
            .map(|extension| (extension.oid.to_id_string(), extension.critical))
            .collect();
        assert_eq!(
            extensions,
            [
                ("2.5.29.14".to_owned(), false),
                ("2.5.29.19".to_owned(), true),
                ("1.3.6.1.4.1.45724.1.1.4".to_owned(), false),
            ]
        );

        // The AAGUID: "The extension MUST NOT be marked as critical" and "the
        // AAGUID MUST be wrapped in two OCTET STRINGS".
        let aaguid = tbs
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == "1.3.6.1.4.1.45724.1.1.4")
            .unwrap();
        let mut expected = vec![0x04, 0x10];
        expected.extend_from_slice(&IDENTITY.aaguid);
        assert_eq!(aaguid.value, expected);
        // The whole extension as the example in §8.2.1 lays it out: SEQUENCE,
        // the OID, no critical flag, the extension's OCTET STRING and the
        // AAGUID's OCTET STRING inside it.
        let mut extension = vec![
            0x30, 0x21, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe5, 0x1c, 0x01, 0x01,
            0x04, 0x04, 0x12,
        ];
        extension.extend_from_slice(&expected);
        assert!(der
            .windows(extension.len())
            .any(|window| window == extension));

        // "The Basic Constraints extension MUST have the CA component set to
        // false."
        let basic_constraints = tbs.basic_constraints().unwrap().unwrap();
        assert!(basic_constraints.critical);
        assert!(!basic_constraints.value.ca);
        assert!(!certificate.is_ca());

        // Subject key identifier: SHA-256 of the subjectPublicKeyInfo, 20 bytes.
        let spki = P256Key::new(signing_key).subject_public_key_info();
        assert_eq!(tbs.subject_pki.raw, spki);
        let ski = tbs
            .extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == "2.5.29.14")
            .unwrap();
        let mut expected = vec![0x04, 20];
        expected.extend_from_slice(&Sha256::digest(&spki)[..20]);
        assert_eq!(ski.value, expected);

        // A positive serial number of 20 octets (RFC 5280 §4.1.2.2).
        let serial = tbs.raw_serial();
        assert_eq!(serial.len(), 20);
        assert_eq!(
            serial[0] & 0xc0,
            0x40,
            "positive, and no leading zero octet"
        );

        // From the start of the day before, to 99991231235959Z.
        let validity = &tbs.validity;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let not_before = validity.not_before.timestamp();
        assert_eq!(not_before % 86_400, 0);
        assert!((now - 2 * 86_400..=now - 86_400).contains(&not_before));
        assert!(validity.not_before.is_utctime());
        assert!(validity.not_after.is_generalizedtime());
        assert_eq!(validity.not_after.timestamp(), 253_402_300_799);

        // ecdsa-with-SHA256 over the TBS certificate, with the attestation
        // key.
        assert_eq!(
            certificate.signature_algorithm.algorithm,
            oid_registry::OID_SIG_ECDSA_WITH_SHA256
        );
        assert_eq!(
            tbs.subject_pki.algorithm.algorithm,
            oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY
        );
        assert_eq!(certificate.signature_value.unused_bits, 0);
        let signature = DerSignature::from_bytes(&certificate.signature_value.data).unwrap();
        verifying_key
            .verify(tbs.as_ref(), &signature)
            .expect("the signature verifies with the attestation key");
    }

    #[test]
    fn the_aaguid_is_read_back_from_a_generated_certificate() {
        let (_, der) = generate_attestation_certificate(&IDENTITY).unwrap();
        assert_eq!(certificate_aaguid(&der), Some(IDENTITY.aaguid));
        // Any truncation is refused rather than read past.
        for length in 0..der.len() {
            assert_eq!(certificate_aaguid(&der[..length]), None, "{length} bytes");
        }
    }

    /// A certificate from the generator this one replaced: subject O and CN,
    /// a DNS name, the serial string as serial number, and no AAGUID.
    #[test]
    fn a_certificate_without_the_extension_has_no_aaguid() {
        let key = P256Key::new(EcdsaSigningKey::generate());
        let mut params = CertificateParams::new(vec!["example".to_owned()]).unwrap();
        params.serial_number = Some(SerialNumber::from(b"FEITIAN-PQC-001".to_vec()));
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_identifier_method = KeyIdMethod::PreSpecified(vec![1; 20]);
        let der = params.self_signed(&key).unwrap().der().to_vec();
        assert!(parse(&der).tbs_certificate.extensions().len() == 3);
        assert_eq!(certificate_aaguid(&der), None);
    }

    /// The extension counts only as §8.2.1 has it: not critical, and the
    /// AAGUID in an OCTET STRING of 16 bytes inside the extension value.
    #[test]
    fn a_malformed_or_critical_extension_has_no_aaguid() {
        let certificate = |critical: bool, content: Vec<u8>| {
            let key = P256Key::new(EcdsaSigningKey::generate());
            let mut params = CertificateParams::default();
            params.serial_number = Some(SerialNumber::from(1));
            let mut extension = CustomExtension::from_oid_content(ID_FIDO_GEN_CE_AAGUID, content);
            extension.set_criticality(critical);
            params.custom_extensions.push(extension);
            params.self_signed(&key).unwrap().der().to_vec()
        };
        let mut wrapped = vec![0x04, 0x10];
        wrapped.extend_from_slice(&[7; 16]);
        assert_eq!(
            certificate_aaguid(&certificate(false, wrapped.clone())),
            Some([7; 16])
        );
        assert_eq!(
            certificate_aaguid(&certificate(true, wrapped.clone())),
            None
        );
        assert_eq!(certificate_aaguid(&certificate(false, vec![7; 16])), None);
        assert_eq!(
            certificate_aaguid(&certificate(false, wrapped[..17].to_vec())),
            None
        );
        let mut trailing = wrapped;
        trailing.push(0);
        assert_eq!(certificate_aaguid(&certificate(false, trailing)), None);
    }

    #[test]
    fn every_certificate_has_a_new_key_and_serial_number() {
        let (first_key, first) = generate_attestation_certificate(&IDENTITY).unwrap();
        let (second_key, second) = generate_attestation_certificate(&IDENTITY).unwrap();
        assert_ne!(*first_key, *second_key);
        assert_ne!(
            parse(&first).tbs_certificate.raw_serial(),
            parse(&second).tbs_certificate.raw_serial()
        );
    }

    #[test]
    fn the_configured_aaguid_and_country_are_used() {
        let identity = IdentityConfig {
            country: "us",
            aaguid: [0xa5; 16],
            ..IDENTITY
        };
        let (_, der) = generate_attestation_certificate(&identity).unwrap();
        let certificate = parse(&der);
        let tbs = &certificate.tbs_certificate;
        let country = tbs.subject.iter_country().next().unwrap();
        assert_eq!(country.as_str().unwrap(), "US");
        let mut expected = vec![0x04, 0x10];
        expected.extend_from_slice(&[0xa5; 16]);
        assert!(tbs
            .extensions()
            .iter()
            .any(|extension| extension.value == expected));
    }

    #[test]
    fn an_invalid_country_is_refused() {
        let identity = IdentityConfig {
            country: "China",
            ..IDENTITY
        };
        let err = generate_attestation_certificate(&identity).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// The certificate is sent in every makeCredential response with basic
    /// attestation, so its size matters. Run with `--nocapture` to see it.
    #[test]
    fn certificate_is_compact() {
        let (_, der) = generate_attestation_certificate(&IDENTITY).unwrap();
        println!("attestation certificate: {} bytes", der.len());
        assert!(der.len() <= 700, "{} bytes", der.len());
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
}
