use std::io;

use p256::{pkcs8::EncodePrivateKey, SecretKey};
use rand_core::OsRng;
use rcgen::{
    Certificate, CertificateParams, DnType, IsCa, KeyPair, SanType, SerialNumber,
    PKCS_ECDSA_P256_SHA256,
};

#[derive(Clone, Copy)]
pub struct IdentityConfig<'a> {
    pub aaguid: [u8; 16],
    pub manufacturer: &'a str,
    pub product: &'a str,
    pub serial: &'a str,
}

/// Generate a P-256 attestation key and a self-signed certificate for it.
/// Returns the 32-byte private scalar and the DER certificate.
pub fn generate_attestation_certificate(
    identity: &IdentityConfig<'_>,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut rng = OsRng;
    let secret = SecretKey::random(&mut rng);
    let private_key = secret.to_bytes().to_vec();
    let pkcs8 = secret
        .to_pkcs8_der()
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("pkcs8 error: {err}")))?;
    let key_pair = KeyPair::from_der(pkcs8.as_bytes())
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("key pair error: {err}")))?;

    let mut params = CertificateParams::new(vec![identity.product.to_string()]);
    params.alg = &PKCS_ECDSA_P256_SHA256;
    params
        .distinguished_name
        .push(DnType::OrganizationName, identity.manufacturer);
    params
        .distinguished_name
        .push(DnType::CommonName, identity.product);
    params
        .subject_alt_names
        .push(SanType::DnsName(identity.product.to_string()));
    params.serial_number = Some(SerialNumber::from(identity.serial.as_bytes().to_vec()));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_pair = Some(key_pair);

    let certificate = Certificate::from_params(params)
        .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("certificate error: {err}")))?;
    let der = certificate.serialize_der().map_err(|err| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("certificate encode error: {err}"),
        )
    })?;

    Ok((private_key, der))
}
