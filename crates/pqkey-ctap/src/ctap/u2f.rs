//! CTAP1/U2F APDUs over CTAPHID_MSG (CTAP 2.3 §10).
//!
//! The engine blocks for presence as it does for CTAP2. The HID transport
//! supplies U2F polling, retaining one answer for an identical repeat.
//! Short APDUs and a zero Lc followed by Le are accepted for compatibility.
//! Le is checked for correct framing, but HID always returns the complete
//! response; it neither truncates signatures nor implements GET RESPONSE.

use super::credential_id::is_discoverable;
use super::presence::{PresenceOperation, PresenceOutcome, PresenceRequest};
use super::{AttestationMode, CtapApp};
use crate::store::CredentialRecord;
use crate::{CoseAlg, CredentialSecretKey, try_sign_challenge};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, PKCS_ECDSA_P256_SHA256, PublicKeyData,
    SerialNumber, SignatureAlgorithm, SigningKey, date_time_ymd,
};

/// The operation completed successfully.
pub const SW_NO_ERROR: u16 = 0x9000;
/// Presence is required, or a check-only handle is valid.
pub const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985;
/// U2F is disabled by alwaysUv (CTAP 2.3 §7.2.4).
pub const SW_COMMAND_NOT_ALLOWED: u16 = 0x6986;
/// The key handle is invalid or cannot be used over U2F.
pub const SW_WRONG_DATA: u16 = 0x6a80;
/// A length field or command's data length is invalid.
pub const SW_WRONG_LENGTH: u16 = 0x6700;
/// The APDU class is not supported.
pub const SW_CLA_NOT_SUPPORTED: u16 = 0x6e00;
/// The APDU instruction is not supported.
pub const SW_INS_NOT_SUPPORTED: u16 = 0x6d00;
/// P1 or P2 is invalid; an additional ISO7816 status word.
pub const SW_WRONG_PARAMETERS: u16 = 0x6a86;
/// An internal operation failed; an additional ISO7816 status word.
pub const SW_INTERNAL_ERROR: u16 = 0x6f00;

enum Request<'a> {
    Version,
    Register {
        challenge: &'a [u8],
        application: &'a [u8; 32],
    },
    Authenticate {
        control: u8,
        challenge: &'a [u8],
        application: &'a [u8; 32],
        handle: &'a [u8],
    },
}

/// Whether a well-formed APDU could require presence. Handle validation and
/// alwaysUv are still the engine's responsibility; this never authorizes it.
pub fn requests_presence(apdu: &[u8]) -> bool {
    matches!(
        decode(apdu, false),
        Ok(Request::Register { .. } | Request::Authenticate { control: 3, .. })
    )
}

fn decode(apdu: &[u8], disabled: bool) -> Result<Request<'_>, u16> {
    let header = apdu.get(..4).ok_or(SW_WRONG_LENGTH)?;
    if header[0] != 0 {
        return Err(SW_CLA_NOT_SUPPORTED);
    }
    let ins = header[1];
    if !matches!(ins, 1..=3) {
        return Err(SW_INS_NOT_SUPPORTED);
    }
    if disabled && matches!(ins, 1 | 2) {
        return Err(SW_COMMAND_NOT_ALLOWED);
    }
    if header[3] != 0
        || (ins != 2 && header[2] != 0)
        || (ins == 2 && !matches!(header[2], 3 | 7 | 8))
    {
        return Err(SW_WRONG_PARAMETERS);
    }
    let data = match apdu.len() {
        4 | 5 => &[][..],
        _ if apdu[4] == 0 => {
            let length = apdu.get(5..7).ok_or(SW_WRONG_LENGTH)?;
            let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
            if apdu.len() == 7 || (length == 0 && apdu.len() == 9) {
                &[][..]
            } else {
                let end = 7 + length;
                let data = apdu.get(7..end).ok_or(SW_WRONG_LENGTH)?;
                if !matches!(apdu.len().saturating_sub(end), 0 | 2) {
                    return Err(SW_WRONG_LENGTH);
                }
                data
            }
        }
        _ => {
            let end = 5 + usize::from(apdu[4]);
            let data = apdu.get(5..end).ok_or(SW_WRONG_LENGTH)?;
            if !matches!(apdu.len().saturating_sub(end), 0 | 1) {
                return Err(SW_WRONG_LENGTH);
            }
            data
        }
    };
    match ins {
        3 if data.is_empty() => Ok(Request::Version),
        1 if data.len() == 64 => Ok(Request::Register {
            challenge: &data[..32],
            application: data[32..64].try_into().map_err(|_| SW_WRONG_LENGTH)?,
        }),
        2 if data.len() >= 65 && data.len() == 65 + usize::from(data[64]) => {
            Ok(Request::Authenticate {
                control: header[2],
                challenge: &data[..32],
                application: data[32..64].try_into().map_err(|_| SW_WRONG_LENGTH)?,
                handle: &data[65..],
            })
        }
        _ => Err(SW_WRONG_LENGTH),
    }
}

impl CtapApp<'_> {
    /// Whether U2F registration and authentication are enabled by policy.
    pub fn u2f_enabled(&self) -> bool {
        !self.pin_state.persistent().always_uv
    }

    /// Answer one U2F command APDU with data followed by its status word.
    /// Presence blocks here; the HID transport implements client polling.
    pub fn call_u2f(&mut self, apdu: &[u8]) -> Vec<u8> {
        self.pending_assertion = None;
        self.observe_large_blob_state(None);
        let result =
            decode(apdu, self.pin_state.persistent().always_uv).and_then(|request| match request {
                Request::Version => Ok(b"U2F_V2".to_vec()),
                Request::Register {
                    challenge,
                    application,
                } => self.u2f_register(challenge, application),
                Request::Authenticate {
                    control,
                    challenge,
                    application,
                    handle,
                } => self.u2f_authenticate(control, challenge, application, handle),
            });
        let (mut response, status) = match result {
            Ok(data) if data.len() <= super::constants::MAX_RESPONSE_SIZE - 2 => {
                (data, SW_NO_ERROR)
            }
            Ok(_) => (Vec::new(), SW_INTERNAL_ERROR),
            Err(status) => (Vec::new(), status),
        };
        response.extend_from_slice(&status.to_be_bytes());
        log::info!(
            "U2F ins={} status=0x{status:04x} req_bcnt={} resp_bcnt={}",
            super::HexOption(apdu.get(1).copied()),
            apdu.len(),
            response.len()
        );
        response
    }

    fn u2f_presence(&mut self, operation: PresenceOperation) -> Result<(), u16> {
        let request = PresenceRequest::new(operation, self.presence_timeout);
        if self.ask_user(&request) == PresenceOutcome::Approved {
            Ok(())
        } else {
            Err(SW_CONDITIONS_NOT_SATISFIED)
        }
    }

    fn u2f_register(&mut self, challenge: &[u8], application: &[u8; 32]) -> Result<Vec<u8>, u16> {
        self.u2f_presence(PresenceOperation::U2fRegister)?;
        let private_key = (self.generate_key)(CoseAlg::ES256).map_err(internal_error)?;
        let mut record = CredentialRecord {
            credential_id: Vec::new(),
            rp_id: String::new(),
            user_id: Vec::new(),
            user_name: None,
            user_display_name: None,
            alg: CoseAlg::ES256,
            private_key,
            cred_random_with_uv: [0; 32],
            cred_random_without_uv: [0; 32],
            cred_blob: None,
            large_blob_key: None,
            cred_protect: 1,
            sign_count: 0,
            created_at: 0,
        };
        let material = record.private_key.sealable().ok_or(SW_INTERNAL_ERROR)?;
        record.credential_id = self
            .seal_credential(&mut record, &material, application)
            .map_err(|_| SW_INTERNAL_ERROR)?;
        let key = record.secret_key().map_err(internal_error)?;
        let public = public_key(&key)?;
        let attestation = (self.attestation_mode == AttestationMode::Certificate)
            .then(|| self.attestation_record())
            .flatten();
        let attestation_key;
        let (certificate, signer) = if let Some(attestation) = &attestation {
            attestation_key = attestation.signing_key().map_err(internal_error)?;
            (
                attestation
                    .certificate_chain
                    .first()
                    .ok_or(SW_INTERNAL_ERROR)?
                    .clone(),
                &attestation_key,
            )
        } else {
            let mut serial = self.random_array::<16>();
            serial[0] = (serial[0] & 0x7f) | 1;
            (self_certificate(&key, &public, serial)?, &key)
        };
        let mut base = vec![0];
        base.extend_from_slice(application);
        base.extend_from_slice(challenge);
        base.extend_from_slice(&record.credential_id);
        base.extend_from_slice(&public);
        let signature =
            try_sign_challenge(CoseAlg::ES256, signer, &base, &[]).map_err(internal_error)?;
        let mut response = vec![5];
        response.extend_from_slice(&public);
        response.push(u8::try_from(record.credential_id.len()).map_err(|_| SW_INTERNAL_ERROR)?);
        response.extend_from_slice(&record.credential_id);
        response.extend_from_slice(&certificate);
        response.extend_from_slice(&signature);
        Ok(response)
    }

    fn u2f_authenticate(
        &mut self,
        control: u8,
        challenge: &[u8],
        application: &[u8; 32],
        handle: &[u8],
    ) -> Result<Vec<u8>, u16> {
        let mut record = self
            .credential_for_hash(handle, application)
            .map_err(|_| SW_INTERNAL_ERROR)?
            .filter(|record| {
                record.alg == CoseAlg::ES256
                    && !is_discoverable(&record.credential_id)
                    && record.cred_protect != 3
            })
            .ok_or(SW_WRONG_DATA)?;
        if control == 7 {
            return Err(SW_CONDITIONS_NOT_SATISFIED);
        }
        if control == 3 {
            self.u2f_presence(PresenceOperation::U2fAuthenticate)?;
        }
        let key = record.secret_key().map_err(internal_error)?;
        self.advance_signature_counter(&mut record)
            .map_err(|_| SW_INTERNAL_ERROR)?;
        let mut response = vec![u8::from(control == 3)];
        response.extend_from_slice(&record.sign_count.to_be_bytes());
        let mut base = application.to_vec();
        base.extend_from_slice(&response);
        let signature =
            try_sign_challenge(CoseAlg::ES256, &key, &base, challenge).map_err(internal_error)?;
        response.extend_from_slice(&signature);
        Ok(response)
    }
}

fn internal_error(error: impl core::fmt::Display) -> u16 {
    log::error!("U2F operation failed: {error}");
    SW_INTERNAL_ERROR
}

fn public_key(key: &CredentialSecretKey) -> Result<Vec<u8>, u16> {
    match key {
        CredentialSecretKey::P256(key) => {
            Ok(key.verifying_key().to_sec1_point(false).as_bytes().to_vec())
        }
        _ => Err(SW_INTERNAL_ERROR),
    }
}

struct CertificateKey<'a> {
    key: &'a CredentialSecretKey,
    public: &'a [u8],
}

impl PublicKeyData for CertificateKey<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.public
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for CertificateKey<'_> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        try_sign_challenge(CoseAlg::ES256, self.key, message, &[])
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

fn self_certificate(
    key: &CredentialSecretKey,
    public: &[u8],
    serial: [u8; 16],
) -> Result<Vec<u8>, u16> {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "U2F credential");
    let mut params = CertificateParams::default();
    params.distinguished_name = name;
    params.serial_number = Some(SerialNumber::from(serial.to_vec()));
    params.not_before = date_time_ymd(1970, 1, 1);
    params.not_after = date_time_ymd(9999, 12, 31);
    params
        .self_signed(&CertificateKey { key, public })
        .map(|cert| cert.der().to_vec())
        .map_err(internal_error)
}
