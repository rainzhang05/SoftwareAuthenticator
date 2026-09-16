//! The authenticatorMakeCredential command.

use super::cbor::{self, canonical_map, canonical_sort};
use super::pin::permissions::PIN_PERMISSION_MC;
use super::pin::protocol::parse_pin_uv_auth_param;
use super::storage::StoredCredential;
use super::CtapApp;
use crate::{create_credential, sign_challenge, CoseAlg};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use sha2::{Digest, Sha256};
use trussed::client::{Client as TrussedClient, CryptoClient, FilesystemClient};
use trussed::syscall;

use transport_core::ctap::constants::*;

pub(super) const COSE_ALG_ES256: i32 = -7;

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
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

        let params = match cbor::map_get(&map, Value::Integer(Integer::from(4))) {
            Some(Value::Array(params)) => params,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };

        let mut selected_alg = None;
        for entry in params {
            let Value::Map(param_map) = entry else {
                return Err(CTAP2_ERR_INVALID_CBOR);
            };
            let Some(Value::Integer(alg_value)) =
                cbor::map_get(param_map, Value::Text("alg".into()))
            else {
                continue;
            };
            let alg_i128: i128 = alg_value.clone().into();
            if let Ok(alg) = CoseAlg::try_from(alg_i128 as i32) {
                selected_alg = Some(alg);
                break;
            }
        }
        let alg = selected_alg.ok_or(CTAP2_ERR_UNSUPPORTED_ALGORITHM)?;

        if let Some(Value::Array(exclude)) = cbor::map_get(&map, Value::Integer(Integer::from(5))) {
            let credentials = self.load_credentials()?;
            for descriptor in exclude {
                let Value::Map(descriptor_map) = descriptor else {
                    continue;
                };
                let Some(Value::Bytes(id)) =
                    cbor::map_get(descriptor_map, Value::Text("id".into()))
                else {
                    continue;
                };
                if credentials.iter().any(|c| c.credential_id == *id) {
                    return Err(CTAP2_ERR_CREDENTIAL_EXCLUDED);
                }
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
        if let Some(Value::Map(options)) = cbor::map_get(&map, Value::Integer(Integer::from(7))) {
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

        let user_present = self.await_user_presence()?;

        let (cose_key, secret_key) = create_credential(alg);
        let secret_key_bytes = secret_key.to_bytes();
        let credential_id_bytes = syscall!(self.client.random_bytes(32)).bytes;
        let credential_id = credential_id_bytes.to_vec();

        let cred_random_with_uv_bytes = syscall!(self.client.random_bytes(32)).bytes;
        if cred_random_with_uv_bytes.len() != 32 {
            return Err(CTAP2_ERR_PROCESSING);
        }
        let cred_random_without_uv_bytes = syscall!(self.client.random_bytes(32)).bytes;
        if cred_random_without_uv_bytes.len() != 32 {
            return Err(CTAP2_ERR_PROCESSING);
        }

        let cred_random_with_uv = cred_random_with_uv_bytes.to_vec();
        let cred_random_without_uv = cred_random_without_uv_bytes.to_vec();

        let mut credentials = self.load_credentials()?;
        let initial_sign_count = 0;
        credentials.push(StoredCredential {
            rp_id: rp_id.clone(),
            user_id: user_id.clone(),
            user_name,
            user_display_name,
            alg: alg as i32,
            credential_id: credential_id.clone(),
            public_key: cose_key.clone(),
            secret_key: secret_key_bytes.clone(),
            cred_random_with_uv: Some(cred_random_with_uv.clone()),
            cred_random_without_uv: Some(cred_random_without_uv.clone()),
            cred_protect: Some(cred_protect_value),
            sign_count: initial_sign_count,
        });
        self.save_credentials(&credentials)?;

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
            &rp_id,
            &credential_id,
            &cose_key,
            user_present,
            uv_verified,
            initial_sign_count,
            extension_bytes.as_deref(),
        );
        let (attestation_format, att_stmt) = if self.suppress_attestation {
            (Value::Text("none".into()), Value::Map(Vec::new()))
        } else {
            let attestation_result = self.attestation_signature(&auth_data, &client_hash)?;
            let att_stmt = if let Some((signature, certificate_chain)) = attestation_result {
                let entries = vec![
                    (
                        Value::Text("alg".into()),
                        Value::Integer(Integer::from(COSE_ALG_ES256)),
                    ),
                    (Value::Text("sig".into()), Value::Bytes(signature)),
                    (
                        Value::Text("x5c".into()),
                        Value::Array(certificate_chain.into_iter().map(Value::Bytes).collect()),
                    ),
                ];
                canonical_map(entries)
            } else {
                let signature = sign_challenge(alg, &secret_key, &auth_data, &client_hash);
                canonical_map(vec![
                    (
                        Value::Text("alg".into()),
                        Value::Integer(Integer::from(alg as i32)),
                    ),
                    (Value::Text("sig".into()), Value::Bytes(signature)),
                ])
            };
            (Value::Text("packed".into()), att_stmt)
        };

        let mut response_map = vec![
            (Value::Integer(Integer::from(1)), attestation_format),
            (
                Value::Integer(Integer::from(2)),
                Value::Bytes(auth_data.clone()),
            ),
            (Value::Integer(Integer::from(3)), att_stmt),
        ];

        canonical_sort(&mut response_map);
        let mut encoded = Vec::new();
        into_writer(&Value::Map(response_map), &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
        let mut out = Vec::with_capacity(1 + encoded.len());
        out.push(CTAP2_OK);
        out.extend_from_slice(&encoded);
        Ok(out)
    }
}
