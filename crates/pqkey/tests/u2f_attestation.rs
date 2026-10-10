//! Independent parsing and verification of U2F registration certificates.

use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use pqkey::attestation::{IdentityConfig, generate_attestation_certificate};
use pqkey_ctap::ctap::u2f::{SW_INTERNAL_ERROR, SW_NO_ERROR};
use pqkey_ctap::ctap::{AttestationMode, CtapApp, InterruptFlag, presence::AutoApprove};
use pqkey_ctap::store::{AttestationRecord, CredentialStore, MemoryStore};
use x509_parser::{certificate::X509Certificate, prelude::FromDer};

static INTERRUPT: InterruptFlag = InterruptFlag::new();
const CHALLENGE: [u8; 32] = [0x42; 32];
const APPLICATION: [u8; 32] = [0x43; 32];

fn app(mode: AttestationMode, store: MemoryStore) -> CtapApp<'static> {
    let mut app = CtapApp::new(
        store,
        rand_core::UnwrapErr(getrandom::SysRng),
        AutoApprove,
        &INTERRUPT,
        [0x44; 16],
    );
    app.set_attestation_mode(mode);
    app
}

fn register(app: &mut CtapApp<'_>) -> Vec<u8> {
    let mut request = vec![0, 1, 0, 0, 0, 0, 64];
    request.extend_from_slice(&CHALLENGE);
    request.extend_from_slice(&APPLICATION);
    app.call_u2f(&request)
}

fn verify(response: &[u8]) -> X509Certificate<'_> {
    assert_eq!(&response[response.len() - 2..], SW_NO_ERROR.to_be_bytes());
    let response = &response[..response.len() - 2];
    assert_eq!(response[0], 5);
    let end = 67 + usize::from(response[66]);
    let (signature, certificate) = X509Certificate::from_der(&response[end..]).unwrap();
    let public = &certificate
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data;
    let key = VerifyingKey::from_sec1_bytes(public).unwrap();
    let base = [
        vec![0],
        APPLICATION.to_vec(),
        CHALLENGE.to_vec(),
        response[67..end].to_vec(),
        response[1..66].to_vec(),
    ]
    .concat();
    key.verify(&base, &Signature::from_der(signature).unwrap())
        .unwrap();
    certificate
}

#[test]
fn self_and_none_use_unlinkable_credential_certificates() {
    for mode in [AttestationMode::SelfAttestation, AttestationMode::None] {
        let mut app = app(mode, MemoryStore::new());
        let first = register(&mut app);
        let second = register(&mut app);
        let first_cert = verify(&first);
        let second_cert = verify(&second);
        for (response, cert) in [(&first, &first_cert), (&second, &second_cert)] {
            assert_eq!(cert.version().0, 2);
            assert!(cert.extensions().is_empty());
            assert_eq!(cert.subject(), cert.issuer());
            assert_eq!(
                &*cert.public_key().subject_public_key.data,
                &response[1..66]
            );
            assert_eq!(cert.subject().to_string(), "CN=U2F credential");
            VerifyingKey::from_sec1_bytes(&cert.public_key().subject_public_key.data)
                .unwrap()
                .verify(
                    cert.tbs_certificate.as_ref(),
                    &Signature::from_der(&cert.signature_value.data).unwrap(),
                )
                .unwrap();
        }
        assert_ne!(first_cert.raw_serial(), second_cert.raw_serial());
        assert_ne!(
            first_cert.public_key().subject_public_key.data,
            second_cert.public_key().subject_public_key.data
        );
        assert_eq!(first_cert.validity(), second_cert.validity());
    }
}

#[test]
fn certificate_mode_returns_only_the_provisioned_leaf_and_uses_its_key() {
    let identity = IdentityConfig {
        manufacturer: "Example",
        product: "Test key",
        country: "US",
        aaguid: [0x44; 16],
    };
    let (key, certificate) = generate_attestation_certificate(&identity).unwrap();
    let mut store = MemoryStore::new();
    store
        .set_attestation(&AttestationRecord {
            private_key: *key,
            certificate_chain: vec![certificate.clone(), vec![1; 20]],
        })
        .unwrap();
    let response = register(&mut app(AttestationMode::Certificate, store));
    let parsed = verify(&response);
    assert_ne!(
        &*parsed.public_key().subject_public_key.data,
        &response[1..66]
    );
    assert_eq!(&response[174..174 + certificate.len()], certificate);
}

#[test]
fn missing_attestation_falls_back_and_an_oversized_leaf_fails() {
    verify(&register(&mut app(
        AttestationMode::Certificate,
        MemoryStore::new(),
    )));
    let mut store = MemoryStore::new();
    store
        .set_attestation(&AttestationRecord {
            private_key: [1; 32],
            certificate_chain: vec![vec![1; 7609]],
        })
        .unwrap();
    assert_eq!(
        register(&mut app(AttestationMode::Certificate, store)),
        SW_INTERNAL_ERROR.to_be_bytes()
    );
}
