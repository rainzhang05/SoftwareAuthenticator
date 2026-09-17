//! The authenticatorMakeCredential command.

use super::cbor::{self, canonical_map, canonical_sort};
use super::pin::permissions::PIN_PERMISSION_MC;
use super::pin::protocol::parse_pin_uv_auth_param;
use super::presence::{PresenceOperation, PresenceRequest};
use super::request;
use super::storage::{is_discoverable, store_status};
use super::CtapApp;
use crate::store::{CredentialRecord, PrivateKeyMaterial, StoreError};
use crate::try_sign_challenge;

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use p256::ecdsa::{signature::Signer, Signature as P256EcdsaSignature};
use sha2::{Digest, Sha256};

use crate::ctap::constants::*;

pub(super) const COSE_ALG_ES256: i32 = -7;

impl CtapApp<'_> {
    fn attested_auth_data(
        &self,
        rp_id: &str,
        credential_id: &[u8],
        cose_key: &[u8],
        user_present: bool,
        uv: bool,
        sign_count: u32,
        extensions: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        let rp_hash = hasher.finalize();

        let mut auth_data =
            Vec::with_capacity(32 + 1 + 4 + 16 + 2 + credential_id.len() + cose_key.len());
        auth_data.extend_from_slice(&rp_hash);
        let mut flags = 0x40; // AT
        if user_present {
            flags |= 0x01;
        }
        if uv {
            flags |= 0x04;
        }
        if extensions.is_some() {
            flags |= 0x80;
        }
        auth_data.push(flags);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());
        auth_data.extend_from_slice(&self.aaguid);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(cose_key);
        if let Some(ext) = extensions {
            auth_data.extend_from_slice(ext);
        }
        auth_data
    }

    pub(super) fn handle_make_credential(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        self.pending_assertion = None;
        let request: Value = from_reader(payload).map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
        let map = match request {
            Value::Map(map) => map,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };

        let client_hash = match cbor::map_get(&map, Value::Integer(Integer::from(1))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };

        let rp = match cbor::map_get(&map, Value::Integer(Integer::from(2))) {
            Some(Value::Map(rp)) => rp,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };
        let rp_id = match cbor::map_get(rp, Value::Text("id".into())) {
            Some(Value::Text(text)) => text.clone(),
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };

        let user = match cbor::map_get(&map, Value::Integer(Integer::from(3))) {
            Some(Value::Map(user)) => user,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };
        let user_id = match cbor::map_get(user, Value::Text("id".into())) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };
        let user_name = cbor::map_get(user, Value::Text("name".into())).and_then(|v| match v {
            Value::Text(text) => Some(text.clone()),
            _ => None,
        });
        let user_display_name =
            cbor::map_get(user, Value::Text("displayName".into())).and_then(|v| match v {
                Value::Text(text) => Some(text.clone()),
                _ => None,
            });

        let alg = match cbor::map_get(&map, Value::Integer(Integer::from(4))) {
            Some(Value::Array(params)) => request::chosen_algorithm(params)?,
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let exclude_list = cbor::map_get(&map, Value::Integer(Integer::from(5)))
            .map(request::credential_ids)
            .transpose()?
            .unwrap_or_default();
        for id in &exclude_list {
            // CTAP 2.3 §6.1.2 step 12: a credential "bound to the specified
            // rp.id".
            if self
                .stored_credential(id)?
                .is_some_and(|credential| credential.rp_id == rp_id)
            {
                return Err(CTAP2_ERR_CREDENTIAL_EXCLUDED);
            }
        }

        let mut hmac_secret_requested = false;
        let mut cred_protect_requested: Option<u8> = None;

        if let Some(value) = cbor::map_get(&map, Value::Integer(Integer::from(6))) {
            let Value::Map(extension_map) = value else {
                return Err(CTAP2_ERR_INVALID_CBOR);
            };
            for (key, value) in extension_map.iter() {
                match key {
                    Value::Text(text) if text == "hmac-secret" => match value {
                        Value::Bool(flag) => {
                            hmac_secret_requested = *flag;
                        }
                        _ => return Err(CTAP2_ERR_INVALID_CBOR),
                    },
                    Value::Text(text) if text == "credProtect" => {
                        let policy_value = match value {
                            Value::Integer(int) => {
                                let int_value: i128 = int.clone().into();
                                if int_value < 0 || int_value > u8::MAX as i128 {
                                    return Err(CTAP2_ERR_INVALID_OPTION);
                                }
                                int_value as u8
                            }
                            _ => return Err(CTAP2_ERR_INVALID_CBOR),
                        };
                        match policy_value {
                            1 | 2 | 3 => cred_protect_requested = Some(policy_value),
                            _ => return Err(CTAP2_ERR_INVALID_OPTION),
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut uv_requested = false;
        let mut rk_requested = false;
        if let Some(Value::Map(options)) = cbor::map_get(&map, Value::Integer(Integer::from(7))) {
            if let Some(Value::Bool(rk)) = cbor::map_get(options, Value::Text("rk".into())) {
                rk_requested = *rk;
            }
            if let Some(Value::Bool(false)) = cbor::map_get(options, Value::Text("up".into())) {
                return Err(CTAP2_ERR_INVALID_OPTION);
            }
            if let Some(Value::Bool(uv)) = cbor::map_get(options, Value::Text("uv".into())) {
                if *uv {
                    uv_requested = true;
                }
            }
        }

        let pin_uv_auth = parse_pin_uv_auth_param(
            cbor::map_get(&map, Value::Integer(Integer::from(8))),
            cbor::map_get(&map, Value::Integer(Integer::from(9))),
        )?;

        if uv_requested && pin_uv_auth.is_some() {
            return Err(CTAP2_ERR_INVALID_OPTION);
        }

        let mut uv_verified = false;

        if let Some((protocol, pin_uv_auth_param)) = pin_uv_auth.as_ref() {
            self.verify_pin_uv_auth_param(*protocol, &client_hash, pin_uv_auth_param)?;
            uv_verified = true;
        }

        if uv_verified {
            self.ensure_pin_token_permission_for_rp(PIN_PERMISSION_MC, &rp_id)?;
        }

        let cred_protect_value = cred_protect_requested.unwrap_or(1);

        let timeout = self.presence_timeout;
        self.confirm_user_presence(PresenceRequest {
            rp_id: Some(&rp_id),
            user_name: user_name.as_deref(),
            user_display_name: user_display_name.as_deref(),
            ..PresenceRequest::new(PresenceOperation::Register, timeout)
        })?;
        let user_present = true;
        self.pin_state
            .consume_pin_uv_auth_token_after_user_presence();

        // ML-DSA keys are stored as their 32-byte seed (RFC 9964 §4).
        let record = CredentialRecord {
            credential_id: self.new_credential_id(rk_requested),
            rp_id,
            user_id,
            user_name,
            user_display_name,
            alg,
            private_key: PrivateKeyMaterial::generate(alg),
            cred_random_with_uv: self.random_array(),
            cred_random_without_uv: self.random_array(),
            cred_protect: cred_protect_value,
            sign_count: 0,
            created_at: 0,
        };
        // One key expansion yields both the signing key and the public key.
        let (secret_key, cose_key) = record.keypair().map_err(|err| {
            log::error!("cannot use a newly generated {alg:?} key: {err}");
            CTAP2_ERR_PROCESSING
        })?;

        let mut extension_entries = Vec::new();
        if hmac_secret_requested {
            extension_entries.push((Value::Text("hmac-secret".into()), Value::Bool(true)));
        }
        if cred_protect_requested.is_some() {
            extension_entries.push((
                Value::Text("credProtect".into()),
                Value::Integer(Integer::from(cred_protect_value as u64)),
            ));
        }
        let extension_bytes = if extension_entries.is_empty() {
            None
        } else {
            let map = canonical_map(extension_entries);
            let mut encoded = Vec::new();
            into_writer(&map, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
            Some(encoded)
        };

        let auth_data = self.attested_auth_data(
            &record.rp_id,
            &record.credential_id,
            &cose_key,
            user_present,
            uv_verified,
            record.sign_count,
            extension_bytes.as_deref(),
        );
        let (attestation_format, att_stmt) = if self.suppress_attestation {
            (Value::Text("none".into()), Value::Map(Vec::new()))
        } else {
            let att_stmt = match self.attestation_record() {
                // Packed attestation with the attestation key and certificate
                // chain (WebAuthn §8.2).
                Some(attestation) => {
                    let signing_key = attestation.signing_key().map_err(|err| {
                        log::error!("the attestation key is unusable: {err}");
                        CTAP2_ERR_PROCESSING
                    })?;
                    let mut message = Vec::with_capacity(auth_data.len() + client_hash.len());
                    message.extend_from_slice(&auth_data);
                    message.extend_from_slice(&client_hash);
                    let signature: P256EcdsaSignature = signing_key.sign(&message);
                    canonical_map(vec![
                        (
                            Value::Text("alg".into()),
                            Value::Integer(Integer::from(COSE_ALG_ES256)),
                        ),
                        (
                            Value::Text("sig".into()),
                            Value::Bytes(signature.to_der().as_bytes().to_vec()),
                        ),
                        (
                            Value::Text("x5c".into()),
                            Value::Array(
                                attestation
                                    .certificate_chain
                                    .iter()
                                    .cloned()
                                    .map(Value::Bytes)
                                    .collect(),
                            ),
                        ),
                    ])
                }
                // Self attestation with the credential key.
                None => {
                    let signature = try_sign_challenge(alg, &secret_key, &auth_data, &client_hash)
                        .map_err(|err| {
                            log::error!("self attestation with {alg:?} failed: {err}");
                            CTAP2_ERR_PROCESSING
                        })?;
                    canonical_map(vec![
                        (
                            Value::Text("alg".into()),
                            Value::Integer(Integer::from(alg as i32)),
                        ),
                        (Value::Text("sig".into()), Value::Bytes(signature)),
                    ])
                }
            };
            (Value::Text("packed".into()), att_stmt)
        };

        let mut response_map = vec![
            (Value::Integer(Integer::from(1)), attestation_format),
            (Value::Integer(Integer::from(2)), Value::Bytes(auth_data)),
            (Value::Integer(Integer::from(3)), att_stmt),
        ];

        canonical_sort(&mut response_map);
        let mut encoded = Vec::new();
        into_writer(&Value::Map(response_map), &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);

        // Stored only once the response is complete, so a request that fails
        // leaves no credential behind that the platform never learned about.
        self.store_new_credential(&record, rk_requested)?;
        Ok(out)
    }

    /// Persist a newly created credential.
    ///
    /// CTAP 2.3 §6.1.2 step 17.2: when a discoverable credential is created
    /// ("rk" true) and "a credential for the same rp.id and account ID already
    /// exists on the authenticator", the authenticator must "Overwrite that
    /// credential".  Only discoverable credentials are replaced: a
    /// non-discoverable credential for the same account is the relying
    /// party's to keep or drop.  The replaced credentials are deleted, which
    /// also stops their IDs from working (§6.1.3).
    ///
    /// The new credential is written first and the old ones deleted after, so
    /// a failure can leave a duplicate but never loses the account.  Only when
    /// the store is full is the replaced credential deleted first, because the
    /// overwrite needs no extra space (step 17.4 is checked after step 17.2).
    fn store_new_credential(
        &mut self,
        record: &CredentialRecord,
        discoverable: bool,
    ) -> Result<(), u8> {
        let replaced: Vec<Vec<u8>> = if discoverable {
            self.stored_credentials()?
                .iter()
                .filter(|existing| {
                    existing.rp_id == record.rp_id
                        && existing.user_id == record.user_id
                        && is_discoverable(&existing.credential_id)
                })
                .map(|existing| existing.credential_id.clone())
                .collect()
        } else {
            Vec::new()
        };
        // `put` replaces a credential with the same ID; a random 32-byte ID
        // only collides if the random number generator is broken.
        if self.stored_credential(&record.credential_id)?.is_some() {
            log::error!("refusing to overwrite a credential with a duplicate random ID");
            return Err(CTAP2_ERR_PROCESSING);
        }
        match self.store.put(record) {
            Ok(()) => {}
            Err(StoreError::Full { .. }) if !replaced.is_empty() => {
                self.store
                    .delete(&replaced[0])
                    .map_err(|err| store_status("delete a replaced credential", err))?;
                self.store
                    .put(record)
                    .map_err(|err| store_status("store a credential", err))?;
            }
            Err(err) => return Err(store_status("store a credential", err)),
        }
        for credential_id in &replaced {
            if let Err(err) = self.store.delete(credential_id) {
                // The new credential is stored and about to be registered by
                // the relying party; failing now would orphan it.
                log::warn!("could not delete a credential replaced by a new registration: {err}");
            }
        }
        Ok(())
    }
}
