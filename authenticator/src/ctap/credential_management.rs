//! The authenticatorCredentialManagement command and its subcommands.

use super::cbor::{self, canonical_map, canonical_sort};
use super::pin::protocol::pin_protocol_from_identifier;
use super::storage::StoredCredential;
use super::CtapApp;

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use sha2::{Digest, Sha256};
use trussed::client::{Client as TrussedClient, CryptoClient, FilesystemClient};

use transport_core::ctap::constants::*;

pub(super) struct CredentialManagementState {
    rp_list: Vec<String>,
    rp_index: usize,
    credential_list: Vec<usize>,
    credential_index: usize,
    pub(super) current_rp: Option<String>,
}

impl CredentialManagementState {
    pub(super) fn new() -> Self {
        Self {
            rp_list: Vec::new(),
            rp_index: 0,
            credential_list: Vec::new(),
            credential_index: 0,
            current_rp: None,
        }
    }

    fn reset_credentials(&mut self) {
        self.credential_list.clear();
        self.credential_index = 0;
        self.current_rp = None;
    }
}

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    pub(super) fn cm_hash_rp_id(rp_id: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        hasher.finalize().to_vec()
    }

    fn cm_get_metadata(&mut self) -> Result<Vec<(Value, Value)>, u8> {
        let credentials = self.load_credentials()?;
        let existing = credentials.len() as u64;
        let remaining = 2048u64.saturating_sub(existing);
        Ok(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(existing)),
            ),
            (
                Value::Integer(Integer::from(2)),
                Value::Integer(Integer::from(remaining)),
            ),
        ])
    }

    fn cm_enumerate_rps_begin(&mut self) -> Result<Vec<(Value, Value)>, u8> {
        let credentials = self.load_credentials()?;
        let mut rp_ids: Vec<String> = credentials.iter().map(|cred| cred.rp_id.clone()).collect();
        rp_ids.sort();
        rp_ids.dedup();
        if rp_ids.is_empty() {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        }

        let total = rp_ids.len() as u64;
        let first = rp_ids[0].clone();
        self.cred_mgmt_state.rp_list = rp_ids;
        self.cred_mgmt_state.rp_index = 1;
        self.cred_mgmt_state.reset_credentials();

        let rp_entry = canonical_map(vec![(Value::Text("id".into()), Value::Text(first.clone()))]);
        let hash = Self::cm_hash_rp_id(&first);
        Ok(vec![
            (Value::Integer(Integer::from(3)), rp_entry),
            (Value::Integer(Integer::from(4)), Value::Bytes(hash)),
            (
                Value::Integer(Integer::from(5)),
                Value::Integer(Integer::from(total)),
            ),
        ])
    }

    fn cm_enumerate_rps_next(&mut self) -> Result<Vec<(Value, Value)>, u8> {
        if self.cred_mgmt_state.rp_index >= self.cred_mgmt_state.rp_list.len() {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        }
        let rp_id = self.cred_mgmt_state.rp_list[self.cred_mgmt_state.rp_index].clone();
        self.cred_mgmt_state.rp_index += 1;
        let rp_entry = canonical_map(vec![(Value::Text("id".into()), Value::Text(rp_id.clone()))]);
        let hash = Self::cm_hash_rp_id(&rp_id);
        Ok(vec![
            (Value::Integer(Integer::from(3)), rp_entry),
            (Value::Integer(Integer::from(4)), Value::Bytes(hash)),
        ])
    }

    fn cm_find_rp_indices(&self, credentials: &[StoredCredential], rp_hash: &[u8]) -> Vec<usize> {
        credentials
            .iter()
            .enumerate()
            .filter_map(|(idx, cred)| {
                let hash = Self::cm_hash_rp_id(&cred.rp_id);
                if hash == rp_hash {
                    Some(idx)
                } else {
                    None
                }
            })
            .collect()
    }

    fn cm_credential_response(
        credential: &StoredCredential,
        total: usize,
    ) -> Result<Vec<(Value, Value)>, u8> {
        let mut user_entries = vec![(
            Value::Text("id".into()),
            Value::Bytes(credential.user_id.clone()),
        )];
        if let Some(name) = &credential.user_name {
            user_entries.push((Value::Text("name".into()), Value::Text(name.clone())));
        }
        if let Some(display) = &credential.user_display_name {
            user_entries.push((
                Value::Text("displayName".into()),
                Value::Text(display.clone()),
            ));
        }
        let user_map = canonical_map(user_entries);

        let credential_descriptor = canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (
                Value::Text("id".into()),
                Value::Bytes(credential.credential_id.clone()),
            ),
        ]);

        let public_key_value: Value = from_reader::<Value, _>(&credential.public_key[..])
            .map_err(|_| CTAP2_ERR_PROCESSING)?;

        Ok(vec![
            (Value::Integer(Integer::from(6)), user_map),
            (Value::Integer(Integer::from(7)), credential_descriptor),
            (Value::Integer(Integer::from(8)), public_key_value),
            (
                Value::Integer(Integer::from(9)),
                Value::Integer(Integer::from(total as u64)),
            ),
            (
                Value::Integer(Integer::from(10)),
                Value::Integer(Integer::from(credential.cred_protect.unwrap_or(1) as u64)),
            ),
        ])
    }

    fn cm_enumerate_credentials_begin(
        &mut self,
        params: &[(Value, Value)],
    ) -> Result<Vec<(Value, Value)>, u8> {
        let rp_hash = match cbor::map_get(params, Value::Integer(Integer::from(1))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let credentials = self.load_credentials()?;
        let indices = self.cm_find_rp_indices(&credentials, &rp_hash);
        if indices.is_empty() {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        }

        let first_idx = indices[0];
        let response = Self::cm_credential_response(&credentials[first_idx], indices.len())?;

        self.cred_mgmt_state.current_rp = Some(credentials[first_idx].rp_id.clone());
        self.cred_mgmt_state.credential_list = indices;
        self.cred_mgmt_state.credential_index = 1;

        Ok(response)
    }

    fn cm_enumerate_credentials_next(&mut self) -> Result<Vec<(Value, Value)>, u8> {
        if self.cred_mgmt_state.credential_index >= self.cred_mgmt_state.credential_list.len() {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        }
        let credentials = self.load_credentials()?;
        let idx = self.cred_mgmt_state.credential_list[self.cred_mgmt_state.credential_index];
        self.cred_mgmt_state.credential_index += 1;
        Self::cm_credential_response(
            &credentials[idx],
            self.cred_mgmt_state.credential_list.len(),
        )
    }

    fn cm_delete_credential(&mut self, params: &[(Value, Value)]) -> Result<(), u8> {
        let descriptor = match cbor::map_get(params, Value::Integer(Integer::from(2))) {
            Some(Value::Map(map)) => map,
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let Some(Value::Bytes(id)) = cbor::map_get(descriptor, Value::Text("id".into())) else {
            return Err(CTAP2_ERR_MISSING_PARAMETER);
        };
        let mut credentials = self.load_credentials()?;
        let Some(pos) = credentials
            .iter()
            .position(|cred| cred.credential_id == *id)
        else {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        };
        credentials.remove(pos);
        self.save_credentials(&credentials)?;
        self.cred_mgmt_state.rp_list.clear();
        self.cred_mgmt_state.rp_index = 0;
        self.cred_mgmt_state.reset_credentials();
        Ok(())
    }

    fn cm_update_user_information(&mut self, params: &[(Value, Value)]) -> Result<(), u8> {
        let descriptor = match cbor::map_get(params, Value::Integer(Integer::from(2))) {
            Some(Value::Map(map)) => map,
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let Some(Value::Bytes(id)) = cbor::map_get(descriptor, Value::Text("id".into())) else {
            return Err(CTAP2_ERR_MISSING_PARAMETER);
        };

        let user_map = match cbor::map_get(params, Value::Integer(Integer::from(3))) {
            Some(Value::Map(map)) => map,
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let Some(Value::Bytes(user_id)) = cbor::map_get(user_map, Value::Text("id".into())) else {
            return Err(CTAP2_ERR_MISSING_PARAMETER);
        };

        let mut credentials = self.load_credentials()?;
        let Some(credential) = credentials
            .iter_mut()
            .find(|cred| cred.credential_id == *id)
        else {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        };
        if credential.user_id != *user_id {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }

        credential.user_name = cbor::map_get(user_map, Value::Text("name".into())).and_then(|v| {
            if let Value::Text(text) = v {
                if text.is_empty() {
                    None
                } else {
                    Some(text.clone())
                }
            } else {
                None
            }
        });
        credential.user_display_name = cbor::map_get(user_map, Value::Text("displayName".into()))
            .and_then(|v| {
                if let Value::Text(text) = v {
                    if text.is_empty() {
                        None
                    } else {
                        Some(text.clone())
                    }
                } else {
                    None
                }
            });

        self.save_credentials(&credentials)
    }

    pub(super) fn handle_credential_management(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        self.pending_assertion = None;
        let request: Value = from_reader(payload).map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
        let map = match request {
            Value::Map(map) => map,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };

        let subcommand = match cbor::map_get(&map, Value::Integer(Integer::from(1))) {
            Some(Value::Integer(int)) => {
                let value: i128 = int.clone().into();
                if value < 0 || value > u8::MAX as i128 {
                    return Err(CTAP1_ERR_INVALID_PARAMETER);
                }
                value as u8
            }
            _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let subcommand_params = match cbor::map_get(&map, Value::Integer(Integer::from(2))) {
            Some(Value::Map(entries)) => Some(entries.clone()),
            Some(_) => return Err(CTAP2_ERR_INVALID_CBOR),
            None => None,
        };

        let protocol_value = match cbor::map_get(&map, Value::Integer(Integer::from(3))) {
            Some(Value::Integer(int)) => int.clone().into(),
            _ => return Err(CTAP2_ERR_PIN_AUTH_INVALID),
        };
        let protocol = pin_protocol_from_identifier(protocol_value)?;

        let pin_auth_param = match cbor::map_get(&map, Value::Integer(Integer::from(4))) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            Some(_) => return Err(CTAP2_ERR_PUAT_REQUIRED),
            None => return Err(CTAP2_ERR_PUAT_REQUIRED),
        };

        let mut message = vec![subcommand];
        if let Some(params) = subcommand_params.as_ref() {
            let map_value = canonical_map(params.clone());
            let mut encoded = Vec::new();
            into_writer(&map_value, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
            message.extend_from_slice(&encoded);
        }
        self.verify_pin_uv_auth_param(protocol, &message, &pin_auth_param)?;

        self.ensure_pin_token_permission_for_cm(
            subcommand,
            subcommand_params.as_ref().map(|params| params.as_slice()),
        )?;

        let response_entries = match subcommand {
            0x01 => Some(self.cm_get_metadata()?),
            0x02 => Some(self.cm_enumerate_rps_begin()?),
            0x03 => Some(self.cm_enumerate_rps_next()?),
            0x04 => {
                let params = subcommand_params
                    .as_ref()
                    .ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
                Some(self.cm_enumerate_credentials_begin(params)?)
            }
            0x05 => Some(self.cm_enumerate_credentials_next()?),
            0x06 => {
                let params = subcommand_params
                    .as_ref()
                    .ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
                self.cm_delete_credential(params)?;
                None
            }
            0x07 => {
                let params = subcommand_params
                    .as_ref()
                    .ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
                self.cm_update_user_information(params)?;
                None
            }
            _ => return Err(CTAP1_ERR_INVALID_PARAMETER),
        };

        if let Some(mut entries) = response_entries {
            canonical_sort(&mut entries);
            let value = Value::Map(entries);
            let mut encoded = Vec::new();
            into_writer(&value, &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
            let mut out = Vec::with_capacity(1 + encoded.len());
            out.push(CTAP2_OK);
            out.extend_from_slice(&encoded);
            Ok(out)
        } else {
            Ok(vec![CTAP2_OK])
        }
    }
}
