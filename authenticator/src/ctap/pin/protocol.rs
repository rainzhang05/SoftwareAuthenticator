//! PIN/UV auth protocol plumbing: protocol selection, the key-agreement
//! session, shared-secret encryption and pinUvAuthParam verification.

use crate::ctap::cbor::{self, canonical_map};
use crate::ctap::CtapApp;
use crate::{
    decrypt_classic_pin_block, derive_classic_pin_uv_session_keys, ClassicPinProtocol,
    PinUvSessionKeys,
};

use aes::Aes256;
use cbc::{
    cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit},
    Decryptor, Encryptor,
};
use ciborium::value::{Integer, Value};
use hmac::{Hmac, Mac};
use p256::{
    ecdh::diffie_hellman, EncodedPoint, PublicKey as P256PublicKey, SecretKey as P256SecretKey,
};
use sha2::{Digest, Sha256};
use trussed::client::{Client as TrussedClient, CryptoClient, FilesystemClient};

use transport_core::ctap::constants::*;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub(crate) fn encrypt_shared_secret(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, u8> {
    if plaintext.len() % 16 != 0 {
        return Err(CTAP1_ERR_INVALID_PARAMETER);
    }
    let cipher =
        Aes256CbcEnc::new_from_slices(key, &[0u8; 16]).map_err(|_| CTAP2_ERR_PROCESSING)?;
    Ok(cipher.encrypt_padded_vec_mut::<NoPadding>(plaintext))
}

pub(crate) fn decrypt_shared_secret(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, u8> {
    if ciphertext.len() % 16 != 0 {
        return Err(CTAP1_ERR_INVALID_PARAMETER);
    }
    let mut buffer = ciphertext.to_vec();
    let cipher =
        Aes256CbcDec::new_from_slices(key, &[0u8; 16]).map_err(|_| CTAP2_ERR_PROCESSING)?;
    let plaintext = cipher
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|_| CTAP1_ERR_INVALID_PARAMETER)?;
    Ok(plaintext.to_vec())
}

pub(crate) type HmacSha256 = Hmac<Sha256>;

pub(crate) const PIN_UV_AUTH_PROTOCOL_CLASSIC_V1: i32 = 1;
pub(crate) const PIN_UV_AUTH_PROTOCOL_CLASSIC_V2: i32 = 2;
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const PIN_UV_AUTH_PROTOCOL_CLASSIC: i32 = PIN_UV_AUTH_PROTOCOL_CLASSIC_V2;
const PIN_UV_PROTOCOLS_SUPPORTED: [i32; 2] = [
    PIN_UV_AUTH_PROTOCOL_CLASSIC_V2,
    PIN_UV_AUTH_PROTOCOL_CLASSIC_V1,
];

pub(crate) type PinProtocol = ClassicPinProtocol;

pub(crate) fn pin_protocol_from_identifier(value: i128) -> Result<PinProtocol, u8> {
    if value == i128::from(PIN_UV_AUTH_PROTOCOL_CLASSIC_V1) {
        Ok(ClassicPinProtocol::V1)
    } else if value == i128::from(PIN_UV_AUTH_PROTOCOL_CLASSIC_V2) {
        Ok(ClassicPinProtocol::V2)
    } else {
        Err(CTAP2_ERR_PIN_AUTH_INVALID)
    }
}

pub(crate) struct PinProtocolSession {
    pub(crate) protocol: ClassicPinProtocol,
    pub(crate) public_key: EncodedPoint,
    pub(crate) secret_key: P256SecretKey,
}

impl PinProtocolSession {
    fn protocol(&self) -> PinProtocol {
        self.protocol
    }

    pub(crate) fn key_agreement_value(&self) -> Value {
        let (x, y) = match (self.public_key.x(), self.public_key.y()) {
            (Some(x_bytes), Some(y_bytes)) => (x_bytes.to_vec(), y_bytes.to_vec()),
            _ => (Vec::new(), Vec::new()),
        };
        canonical_map(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(2)),
            ),
            (
                Value::Integer(Integer::from(3)),
                Value::Integer(Integer::from(-25)),
            ),
            (
                Value::Integer(Integer::from(-1)),
                Value::Integer(Integer::from(1)),
            ),
            (Value::Integer(Integer::from(-2)), Value::Bytes(x)),
            (Value::Integer(Integer::from(-3)), Value::Bytes(y)),
        ])
    }

    pub(crate) fn derive_session_keys(
        self,
        platform_key: &[(Value, Value)],
    ) -> Result<(PinUvSessionKeys, Vec<u8>), u8> {
        let Some(peer_x) = platform_key
            .iter()
            .find(|(k, _)| *k == Value::Integer(Integer::from(-2)))
            .and_then(|(_, v)| match v {
                Value::Bytes(bytes) => Some(bytes.clone()),
                _ => None,
            })
        else {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        };
        let Some(peer_y) = platform_key
            .iter()
            .find(|(k, _)| *k == Value::Integer(Integer::from(-3)))
            .and_then(|(_, v)| match v {
                Value::Bytes(bytes) => Some(bytes.clone()),
                _ => None,
            })
        else {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        };
        if peer_x.len() != 32 || peer_y.len() != 32 {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }

        let mut peer_encoded = [0u8; 65];
        peer_encoded[0] = 0x04;
        peer_encoded[1..33].copy_from_slice(&peer_x);
        peer_encoded[33..65].copy_from_slice(&peer_y);

        let peer_public = P256PublicKey::from_sec1_bytes(&peer_encoded)
            .map_err(|_| CTAP1_ERR_INVALID_PARAMETER)?;
        let shared = diffie_hellman(self.secret_key.to_nonzero_scalar(), peer_public.as_affine());

        let auth_public_bytes = self.public_key.as_bytes();
        let mut hasher = Sha256::new();
        hasher.update(auth_public_bytes);
        hasher.update(&peer_encoded);
        let transcript_hash = hasher.finalize().to_vec();

        let shared_bytes = shared.raw_secret_bytes();
        let keys = derive_classic_pin_uv_session_keys(self.protocol, shared_bytes.as_ref());
        Ok((keys, transcript_hash))
    }
}

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    pub(crate) fn supported_pin_uv_protocols(&self) -> &'static [i32] {
        &PIN_UV_PROTOCOLS_SUPPORTED
    }
    pub(super) fn verify_pin_auth(
        _protocol: PinProtocol,
        keys: &PinUvSessionKeys,
        data: &[u8],
        provided: &[u8],
    ) -> Result<(), u8> {
        let mut mac =
            HmacSha256::new_from_slice(&keys.auth_key).map_err(|_| CTAP2_ERR_PROCESSING)?;
        mac.update(data);
        let result = mac.finalize().into_bytes();
        if provided.len() != 16 {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        if result[..16] == provided[..16] {
            Ok(())
        } else {
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        }
    }

    pub(super) fn decrypt_pin_block_checked(
        protocol: PinProtocol,
        keys: &PinUvSessionKeys,
        _transcript_hash: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, u8> {
        decrypt_classic_pin_block(protocol, keys, ciphertext)
            .map_err(|_| CTAP2_ERR_PIN_AUTH_INVALID)
    }

    pub(crate) fn ensure_supported_pin_uv_protocol(&self, protocol: i128) -> Result<(), u8> {
        if protocol < i32::MIN as i128 || protocol > i32::MAX as i128 {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }
        let protocol_i32 = protocol as i32;
        if self.supported_pin_uv_protocols().contains(&protocol_i32) {
            Ok(())
        } else {
            Err(CTAP2_ERR_PIN_AUTH_INVALID)
        }
    }

    pub(super) fn requested_pin_protocol(
        &mut self,
        map: &[(Value, Value)],
    ) -> Result<PinProtocol, u8> {
        if let Some(Value::Integer(int)) = cbor::map_get(map, Value::Integer(Integer::from(1))) {
            let value: i128 = int.clone().into();
            match value {
                v if v == i128::from(PIN_UV_AUTH_PROTOCOL_CLASSIC_V2) => Ok(ClassicPinProtocol::V2),
                v if v == i128::from(PIN_UV_AUTH_PROTOCOL_CLASSIC_V1) => Ok(ClassicPinProtocol::V1),
                _ => Err(CTAP1_ERR_INVALID_PARAMETER),
            }
        } else {
            Ok(ClassicPinProtocol::V2)
        }
    }

    pub(crate) fn take_session(&mut self, protocol: PinProtocol) -> Result<PinProtocolSession, u8> {
        match self.pin_protocol_session.take() {
            Some(session) if session.protocol() == protocol => Ok(session),
            Some(session) => {
                self.pin_protocol_session = Some(session);
                Err(CTAP2_ERR_PIN_AUTH_INVALID)
            }
            None => Err(CTAP2_ERR_PIN_AUTH_INVALID),
        }
    }
}
