//! The authenticatorGetAssertion and authenticatorGetNextAssertion commands,
//! including hmac-secret extension processing.

use super::cbor::{self, canonical_map, canonical_sort};
use super::pin::permissions::PIN_PERMISSION_GA;
use super::pin::protocol::{
    decrypt, pin_protocol_from_identifier, verify, HmacSha256, PinProtocol,
};
use super::storage::StoredCredential;
use super::CtapApp;
use crate::{
    credential_secret_from_bytes, sign_challenge, ClassicPinProtocol, CoseAlg, PinUvSessionKeys,
};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use hmac::Mac;
use sha2::{Digest, Sha256};
use trussed::client::{Client as TrussedClient, CryptoClient, FilesystemClient};
use zeroize::{Zeroize, Zeroizing};

use transport_core::ctap::constants::*;

use std::collections::VecDeque;

struct PendingHmacSecret {
    protocol: PinProtocol,
    keys: PinUvSessionKeys,
    salt_plaintext: Zeroizing<Vec<u8>>,
}

impl PendingHmacSecret {
    /// `output1 [|| output2]` with `outputN = HMAC-SHA-256(CredRandom, saltN)`,
    /// or `None` when the credential has no CredRandom (CTAP 2.3 §12.7).
    fn outputs_for(&self, cred_random: Option<&Vec<u8>>) -> Result<Option<Zeroizing<Vec<u8>>>, u8> {
        let Some(random) = cred_random else {
            return Ok(None);
        };
        let mut outputs = Zeroizing::new(Vec::with_capacity(self.salt_plaintext.len()));
        for salt in self.salt_plaintext.chunks(32) {
            let mut hmac = HmacSha256::new_from_slice(random).map_err(|_| CTAP2_ERR_PROCESSING)?;
            hmac.update(salt);
            outputs.extend_from_slice(&hmac.finalize().into_bytes());
        }
        Ok(Some(outputs))
    }
}

pub(super) struct PendingAssertion {
    rp_id: String,
    client_hash: Vec<u8>,
    user_present: bool,
    user_verified: bool,
    remaining_credentials: VecDeque<Vec<u8>>,
    hmac_secret: Option<PendingHmacSecret>,
}

impl Drop for PendingAssertion {
    fn drop(&mut self) {
        self.client_hash.zeroize();
    }
}

struct HmacSecretRequest {
    key_agreement: Vec<(Value, Value)>,
    salt_enc: Vec<u8>,
    salt_auth: Vec<u8>,
    protocol: PinProtocol,
}

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    fn credential_allows(
        credential: &StoredCredential,
        user_verified: bool,
        allow_list_provided: bool,
    ) -> bool {
        match credential.cred_protect.unwrap_or(1) {
            3 => user_verified,
            2 => user_verified || allow_list_provided,
            _ => true,
        }
    }

    fn process_hmac_secret_for_assertion(
        &mut self,
        request: &HmacSecretRequest,
        cred_random_with_uv: Option<&Vec<u8>>,
        cred_random_without_uv: Option<&Vec<u8>>,
        user_verified: bool,
    ) -> Result<(Option<Vec<u8>>, PendingHmacSecret), u8> {
        let session = self.take_session(request.protocol)?;
        let (keys, _) = session.derive_session_keys(&request.key_agreement)?;

        // CTAP 2.3 §12.7: "The authenticator calls verify(shared secret,
        // saltEnc, saltAuth). If the verification fails, return
        // CTAP2_ERR_PIN_AUTH_INVALID."
        verify(
            request.protocol,
            &keys.auth_key,
            &request.salt_enc,
            &request.salt_auth,
        )?;

        // "The authenticator obtains salt1 and salt2 by calling decrypt(shared
        // secret, saltEnc). If the decryption fails, or if the result is not 32
        // or 64 bytes long, return CTAP1_ERR_INVALID_PARAMETER."
        let salt_plaintext = decrypt(request.protocol, &keys, &request.salt_enc)
            .filter(|salts| salts.len() == 32 || salts.len() == 64)
            .ok_or(CTAP1_ERR_INVALID_PARAMETER)?;

        let cred_random = if user_verified {
            cred_random_with_uv
        } else {
            cred_random_without_uv
        };

        let pending = PendingHmacSecret {
            protocol: request.protocol,
            keys,
            salt_plaintext,
        };
        let encrypted = self.encrypt_hmac_secret_outputs(&pending, cred_random)?;
        Ok((encrypted, pending))
    }

    /// `encrypt(shared secret, output1 [|| output2])` with the protocol the
    /// platform selected for hmac-secret (CTAP 2.3 §12.7).
    fn encrypt_hmac_secret_outputs(
        &mut self,
        pending: &PendingHmacSecret,
        cred_random: Option<&Vec<u8>>,
    ) -> Result<Option<Vec<u8>>, u8> {
        match pending.outputs_for(cred_random)? {
            Some(outputs) => self
                .encrypt_for_platform(pending.protocol, &pending.keys, &outputs)
                .map(Some),
            None => Ok(None),
        }
    }

    fn assertion_auth_data(
        &self,
        rp_id: &str,
        sign_count: u32,
        user_present: bool,
        user_verified: bool,
        extensions: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        let rp_hash = hasher.finalize();

        let mut auth_data = Vec::with_capacity(32 + 1 + 4);
        auth_data.extend_from_slice(&rp_hash);
        let mut flags = 0u8;
        if user_present {
            flags |= 0x01;
        }
        if user_verified {
            flags |= 0x04;
        }
        if extensions.is_some() {
            flags |= 0x80;
        }
        auth_data.push(flags);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        if let Some(ext) = extensions {
            auth_data.extend_from_slice(ext);
        }
        auth_data
    }

    pub(super) fn handle_get_assertion(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        self.pending_assertion = None;
        let request: Value = from_reader(payload).map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
        let map = match request {
            Value::Map(map) => map,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };

        let rp_id = match cbor::map_get(&map, Value::Integer(Integer::from(1))) {
            Some(Value::Text(text)) => text.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let client_hash = match cbor::map_get(&map, Value::Integer(Integer::from(2))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let allow_list = match cbor::map_get(&map, Value::Integer(Integer::from(3))) {
            Some(Value::Array(list)) => Some(list.clone()),
            _ => None,
        };

        let mut hmac_secret_request: Option<HmacSecretRequest> = None;
        if let Some(value) = cbor::map_get(&map, Value::Integer(Integer::from(4))) {
            let Value::Map(extension_map) = value else {
                return Err(CTAP2_ERR_INVALID_CBOR);
            };
            for (key, value) in extension_map.iter() {
                if let Value::Text(text) = key {
                    if text == "hmac-secret" {
                        let Value::Map(params) = value else {
                            return Err(CTAP2_ERR_INVALID_CBOR);
                        };
                        let key_agreement =
                            match cbor::map_get(params, Value::Integer(Integer::from(1))) {
                                Some(Value::Map(entries)) => entries.clone(),
                                _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
                            };
                        let salt_enc = match cbor::map_get(params, Value::Integer(Integer::from(2)))
                        {
                            Some(Value::Bytes(bytes)) => bytes.clone(),
                            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
                        };
                        let salt_auth =
                            match cbor::map_get(params, Value::Integer(Integer::from(3))) {
                                Some(Value::Bytes(bytes)) => bytes.clone(),
                                _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
                            };
                        let protocol = match cbor::map_get(params, Value::Integer(Integer::from(4)))
                        {
                            Some(Value::Integer(int)) => {
                                let value: i128 = int.clone().into();
                                pin_protocol_from_identifier(value)?
                            }
                            Some(_) => return Err(CTAP2_ERR_PIN_AUTH_INVALID),
                            None => ClassicPinProtocol::V2,
                        };
                        hmac_secret_request = Some(HmacSecretRequest {
                            key_agreement,
                            salt_enc,
                            salt_auth,
                            protocol,
                        });
                    }
                }
            }
        }

        let mut uv_requested = false;
        if let Some(Value::Map(options)) = cbor::map_get(&map, Value::Integer(Integer::from(5))) {
            if let Some(Value::Bool(false)) = cbor::map_get(options, Value::Text("up".into())) {
                return Err(CTAP2_ERR_INVALID_OPTION);
            }
            if let Some(Value::Bool(uv)) = cbor::map_get(options, Value::Text("uv".into())) {
                uv_requested = *uv;
            }
        }

        let pin_uv_auth_param = match cbor::map_get(&map, Value::Integer(Integer::from(6))) {
            Some(Value::Bytes(bytes)) => Some(bytes.clone()),
            Some(_) => return Err(CTAP2_ERR_PIN_AUTH_INVALID),
            None => None,
        };

        let pin_uv_auth_protocol = match cbor::map_get(&map, Value::Integer(Integer::from(7))) {
            Some(Value::Integer(int)) => Some(int.clone().into()),
            Some(_) => return Err(CTAP2_ERR_PIN_AUTH_INVALID),
            None => None,
        };

        let mut user_verified = false;
        match (pin_uv_auth_param.as_ref(), pin_uv_auth_protocol) {
            (Some(param), Some(protocol)) => {
                let protocol = pin_protocol_from_identifier(protocol)?;
                self.verify_pin_uv_auth_param(protocol, &client_hash, param)?;
                user_verified = true;
            }
            (None, None) => {
                if uv_requested {
                    return Err(CTAP2_ERR_INVALID_OPTION);
                }
            }
            _ => {
                return Err(CTAP2_ERR_MISSING_PARAMETER);
            }
        }

        if user_verified {
            self.ensure_pin_token_permission_for_rp(PIN_PERMISSION_GA, &rp_id)?;
        }

        let mut credentials = self.load_credentials()?;

        let mut matching_indices: Vec<usize> = Vec::new();
        if let Some(list) = allow_list.as_ref() {
            for descriptor in list {
                let Value::Map(desc_map) = descriptor else {
                    continue;
                };
                let Some(Value::Bytes(id)) = cbor::map_get(desc_map, Value::Text("id".into()))
                else {
                    continue;
                };
                if let Some(pos) = credentials.iter().position(|cred| {
                    cred.credential_id == *id
                        && cred.rp_id == rp_id
                        && Self::credential_allows(cred, user_verified, true)
                }) {
                    if !matching_indices.contains(&pos) {
                        matching_indices.push(pos);
                    }
                }
            }
            if matching_indices.is_empty() {
                return Err(CTAP2_ERR_NO_CREDENTIALS);
            }
        } else {
            for (index, cred) in credentials.iter().enumerate() {
                if cred.rp_id == rp_id && Self::credential_allows(cred, user_verified, false) {
                    matching_indices.push(index);
                }
            }
            if matching_indices.is_empty() {
                return Err(CTAP2_ERR_NO_CREDENTIALS);
            }
        }

        let user_present = self.await_user_presence()?;

        let chosen_index = matching_indices[0];
        let remaining_credentials: VecDeque<Vec<u8>> = matching_indices
            .iter()
            .skip(1)
            .map(|idx| credentials[*idx].credential_id.clone())
            .collect();
        let remaining_count = remaining_credentials.len();

        let (
            credential_id,
            user_id,
            user_name,
            user_display_name,
            secret_key_bytes,
            sign_count,
            alg,
            cred_random_with_uv,
            cred_random_without_uv,
        ) = {
            let credential = &mut credentials[chosen_index];
            let alg =
                CoseAlg::try_from(credential.alg).map_err(|_| CTAP2_ERR_UNSUPPORTED_ALGORITHM)?;
            let secret_key_bytes = credential.secret_key.clone();
            credential.sign_count = credential.sign_count.saturating_add(1);
            let sign_count = credential.sign_count;
            (
                credential.credential_id.clone(),
                credential.user_id.clone(),
                credential.user_name.clone(),
                credential.user_display_name.clone(),
                secret_key_bytes,
                sign_count,
                alg,
                credential.cred_random_with_uv.clone(),
                credential.cred_random_without_uv.clone(),
            )
        };

        let signing_key = credential_secret_from_bytes(alg, &secret_key_bytes)
            .map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut extension_entries = Vec::new();
        let mut pending_hmac_secret = None;
        if let Some(ref request) = hmac_secret_request {
            let (maybe_encrypted, pending_state) = self.process_hmac_secret_for_assertion(
                request,
                cred_random_with_uv.as_ref(),
                cred_random_without_uv.as_ref(),
                user_verified,
            )?;
            if let Some(encrypted) = maybe_encrypted {
                extension_entries
                    .push((Value::Text("hmac-secret".into()), Value::Bytes(encrypted)));
            }
            pending_hmac_secret = Some(pending_state);
        }

        let extension_bytes = if extension_entries.is_empty() {
            None
        } else {
            let map = canonical_map(extension_entries);
            let mut encoded = Vec::new();
            into_writer(&map, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
            Some(encoded)
        };

        let auth_data = self.assertion_auth_data(
            &rp_id,
            sign_count,
            user_present,
            user_verified,
            extension_bytes.as_deref(),
        );
        let signature = sign_challenge(alg, &signing_key, &auth_data, &client_hash);
        self.save_credentials(&credentials)?;

        if remaining_count != 0 {
            self.pending_assertion = Some(PendingAssertion {
                rp_id: rp_id.clone(),
                client_hash: client_hash.clone(),
                user_present,
                user_verified,
                remaining_credentials,
                hmac_secret: pending_hmac_secret,
            });
        }

        let credential_map = canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (
                Value::Text("id".into()),
                Value::Bytes(credential_id.clone()),
            ),
        ]);

        let mut user_entries = vec![(Value::Text("id".into()), Value::Bytes(user_id))];
        if let Some(name) = user_name {
            user_entries.push((Value::Text("name".into()), Value::Text(name)));
        }
        if let Some(display) = user_display_name {
            user_entries.push((Value::Text("displayName".into()), Value::Text(display)));
        }
        let user_map = canonical_map(user_entries);

        let mut response = vec![
            (Value::Integer(Integer::from(1)), credential_map),
            (Value::Integer(Integer::from(2)), Value::Bytes(auth_data)),
            (Value::Integer(Integer::from(3)), Value::Bytes(signature)),
            (Value::Integer(Integer::from(4)), user_map),
        ];

        if remaining_count != 0 {
            let total_count = 1 + remaining_count;
            response.push((
                Value::Integer(Integer::from(5)),
                Value::Integer(Integer::from(total_count as u64)),
            ));
        }

        canonical_sort(&mut response);
        let mut encoded = Vec::new();
        into_writer(&Value::Map(response), &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }

    pub(super) fn handle_get_next_assertion(&mut self) -> Result<Vec<u8>, u8> {
        let mut pending = self.pending_assertion.take().ok_or(CTAP2_ERR_NOT_ALLOWED)?;
        let credential_id = pending
            .remaining_credentials
            .pop_front()
            .ok_or(CTAP2_ERR_NOT_ALLOWED)?;

        let mut credentials = self.load_credentials()?;
        let credential = credentials
            .iter_mut()
            .find(|cred| cred.rp_id == pending.rp_id && cred.credential_id == credential_id)
            .ok_or(CTAP2_ERR_NO_CREDENTIALS)?;

        let alg = CoseAlg::try_from(credential.alg).map_err(|_| CTAP2_ERR_UNSUPPORTED_ALGORITHM)?;
        let secret_key_bytes = credential.secret_key.clone();
        credential.sign_count = credential.sign_count.saturating_add(1);
        let sign_count = credential.sign_count;
        let user_id = credential.user_id.clone();
        let user_name = credential.user_name.clone();
        let user_display_name = credential.user_display_name.clone();
        let cred_random_with_uv = credential.cred_random_with_uv.clone();
        let cred_random_without_uv = credential.cred_random_without_uv.clone();

        let signing_key = credential_secret_from_bytes(alg, &secret_key_bytes)
            .map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut extension_entries = Vec::new();
        if let Some(ref hmac_state) = pending.hmac_secret {
            let cred_random = if pending.user_verified {
                cred_random_with_uv.as_ref()
            } else {
                cred_random_without_uv.as_ref()
            };
            if let Some(encrypted) = self.encrypt_hmac_secret_outputs(hmac_state, cred_random)? {
                extension_entries
                    .push((Value::Text("hmac-secret".into()), Value::Bytes(encrypted)));
            }
        }

        let extension_bytes = if extension_entries.is_empty() {
            None
        } else {
            let map = canonical_map(extension_entries);
            let mut encoded = Vec::new();
            into_writer(&map, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
            Some(encoded)
        };

        let auth_data = self.assertion_auth_data(
            &pending.rp_id,
            sign_count,
            pending.user_present,
            pending.user_verified,
            extension_bytes.as_deref(),
        );
        let signature = sign_challenge(
            alg,
            &signing_key,
            &auth_data,
            pending.client_hash.as_slice(),
        );
        self.save_credentials(&credentials)?;

        if !pending.remaining_credentials.is_empty() {
            self.pending_assertion = Some(pending);
        }

        let credential_map = canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (Value::Text("id".into()), Value::Bytes(credential_id)),
        ]);

        let mut user_entries = vec![(Value::Text("id".into()), Value::Bytes(user_id))];
        if let Some(name) = user_name {
            user_entries.push((Value::Text("name".into()), Value::Text(name)));
        }
        if let Some(display) = user_display_name {
            user_entries.push((Value::Text("displayName".into()), Value::Text(display)));
        }
        let user_map = canonical_map(user_entries);

        let mut response = vec![
            (Value::Integer(Integer::from(1)), credential_map),
            (Value::Integer(Integer::from(2)), Value::Bytes(auth_data)),
            (Value::Integer(Integer::from(3)), Value::Bytes(signature)),
            (Value::Integer(Integer::from(4)), user_map),
        ];

        canonical_sort(&mut response);
        let mut encoded = Vec::new();
        into_writer(&Value::Map(response), &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }
}
