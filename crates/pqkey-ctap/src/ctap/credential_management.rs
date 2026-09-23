//! The authenticatorCredentialManagement command and its subcommands.

use super::CtapApp;
use super::cbor::{self, canonical_map, canonical_sort, required_bytes, required_map};
use super::pin::protocol::parse_pin_uv_auth_param;
use super::request::{self, truncate_utf8};
use super::storage::{is_discoverable, store_status};
use crate::store::CredentialRecord;

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use sha2::{Digest, Sha256};

use crate::ctap::constants::*;

const GET_CREDS_METADATA: u8 = 0x01;
const ENUMERATE_RPS_BEGIN: u8 = 0x02;
const ENUMERATE_RPS_GET_NEXT_RP: u8 = 0x03;
const ENUMERATE_CREDENTIALS_BEGIN: u8 = 0x04;
const ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL: u8 = 0x05;
const DELETE_CREDENTIAL: u8 = 0x06;
const UPDATE_USER_INFORMATION: u8 = 0x07;

/// "#define MAX_STORED_RPID_LENGTH 32  /* MUST be >= 32 */" (CTAP 2.3 §6.8.7)
const MAX_RETURNED_RP_ID_LENGTH: usize = 32;

/// The PublicKeyCredentialRpEntity returned by enumerateRPsBegin and
/// enumerateRPsGetNextRP, its id truncated as CTAP 2.3 §6.8.7 describes:
/// "authenticators MAY truncate them using a procedure that produces the same
/// results as the code included below", which keeps a protocol prefix up to
/// the first colon and the end of the identifier, joined by U+2026.  Only the
/// returned entity is truncated; "authenticators MUST NOT use truncated
/// relying party identifiers for comparisons at any time".  The truncation
/// keeps a response with an RP ID of any length within the transport's
/// message size.
fn rp_entity(rp_id: &str) -> Value {
    canonical_map(vec![(
        Value::Text("id".into()),
        Value::Text(truncated_rp_id(rp_id)),
    )])
}

/// `maybe_truncate_rpid` of CTAP 2.3 §6.8.7.  The byte-oriented procedure can
/// split a multi-byte character of a non-ASCII identifier; such a split is
/// replaced by U+FFFD so the result stays a CBOR text string.
pub(super) fn truncated_rp_id(rp_id: &str) -> String {
    let rpid = rp_id.as_bytes();
    if rpid.len() <= MAX_RETURNED_RP_ID_LENGTH {
        return rp_id.to_string();
    }
    let mut stored = Vec::with_capacity(MAX_RETURNED_RP_ID_LENGTH);
    if let Some(colon) = rpid.iter().position(|byte| *byte == b':') {
        let protocol_len = colon + 1;
        stored.extend_from_slice(&rpid[..protocol_len.min(MAX_RETURNED_RP_ID_LENGTH)]);
    }
    if MAX_RETURNED_RP_ID_LENGTH - stored.len() >= 3 {
        stored.extend_from_slice("\u{2026}".as_bytes());
        let to_copy = MAX_RETURNED_RP_ID_LENGTH - stored.len();
        stored.extend_from_slice(&rpid[rpid.len() - to_copy..]);
    }
    String::from_utf8_lossy(&stored).into_owned()
}

/// The state of the two stateful subcommands, enumerateRPsGetNextRP and
/// enumerateCredentialsGetNextCredential (CTAP 2.3 §6).
///
/// Each enumeration remembers the pinUvAuthToken that authenticated its
/// begin subcommand, because the get-next subcommands carry no
/// pinUvAuthParam of their own and "An authenticator MUST discard the state
/// for a stateful command command if the pinUvAuthToken that authenticated
/// the state initializing command expires".
pub(super) struct CredentialManagementState {
    rp_list: Vec<String>,
    rp_index: usize,
    rp_token: Option<u64>,
    /// The IDs of the credentials being enumerated, looked up again for each
    /// enumerateCredentialsGetNextCredential so no private key is kept.
    credential_list: Vec<Vec<u8>>,
    credential_index: usize,
    credential_token: Option<u64>,
}

impl CredentialManagementState {
    pub(super) fn new() -> Self {
        Self {
            rp_list: Vec::new(),
            rp_index: 0,
            rp_token: None,
            credential_list: Vec::new(),
            credential_index: 0,
            credential_token: None,
        }
    }

    fn reset_rps(&mut self) {
        self.rp_list.clear();
        self.rp_index = 0;
        self.rp_token = None;
    }

    fn reset_credentials(&mut self) {
        self.credential_list.clear();
        self.credential_index = 0;
        self.credential_token = None;
    }
}

impl CtapApp<'_> {
    pub(super) fn cm_hash_rp_id(rp_id: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        hasher.finalize().to_vec()
    }

    /// Every discoverable credential, most recently created first: the
    /// credentials this command manages ("This command is used by the
    /// platform to manage discoverable credentials on the authenticator.",
    /// CTAP 2.3 §6.8).
    fn discoverable_credentials(&self) -> Result<Vec<CredentialRecord>, u8> {
        let mut credentials = self.stored_credentials()?;
        credentials.retain(|credential| is_discoverable(&credential.credential_id));
        Ok(credentials)
    }

    /// existingResidentCredentialsCount counts discoverable credentials.
    /// maxPossibleRemainingResidentCredentialsCount is the free space of the
    /// store, which non-discoverable credentials made before they were sealed
    /// into their IDs take up too.
    fn cm_get_metadata(&mut self) -> Result<Vec<(Value, Value)>, u8> {
        let existing = self.discoverable_credentials()?.len();
        let stored = self
            .store
            .count()
            .map_err(|err| store_status("count credentials", err))?;
        let remaining = self.store.max_credentials().saturating_sub(stored);
        Ok(vec![
            (
                Value::Integer(Integer::from(1)),
                Value::Integer(Integer::from(existing as u64)),
            ),
            (
                Value::Integer(Integer::from(2)),
                Value::Integer(Integer::from(remaining as u64)),
            ),
        ])
    }

    fn cm_enumerate_rps_begin(&mut self) -> Result<Vec<(Value, Value)>, u8> {
        let credentials = self.discoverable_credentials()?;
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
        self.cred_mgmt_state.rp_token = self.pin_state.pin_uv_auth_token_id();

        let rp_entry = rp_entity(&first);
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

    /// enumerateRPsGetNextRP.  CTAP2_ERR_NOT_ALLOWED without an enumeration
    /// to continue: none was begun, it has returned every RP, or the
    /// pinUvAuthToken that authenticated enumerateRPsBegin has expired
    /// (CTAP 2.3 §6).
    fn cm_enumerate_rps_next(&mut self) -> Result<Vec<(Value, Value)>, u8> {
        let token = self.pin_state.pin_uv_auth_token_id();
        let state = &mut self.cred_mgmt_state;
        if state.rp_token.is_none() || state.rp_token != token {
            state.reset_rps();
            return Err(CTAP2_ERR_NOT_ALLOWED);
        }
        let Some(rp_id) = state.rp_list.get(state.rp_index).cloned() else {
            state.reset_rps();
            return Err(CTAP2_ERR_NOT_ALLOWED);
        };
        state.rp_index += 1;
        let rp_entry = rp_entity(&rp_id);
        let hash = Self::cm_hash_rp_id(&rp_id);
        Ok(vec![
            (Value::Integer(Integer::from(3)), rp_entry),
            (Value::Integer(Integer::from(4)), Value::Bytes(hash)),
        ])
    }

    /// One credential of an enumeration.  `total` is totalCredentials, which
    /// only enumerateCredentialsBegin reports: the enumerateCredentialsGetNext
    /// response is user, credentialID, publicKey and credProtect (CTAP 2.3
    /// §6.8.4).
    fn cm_credential_response(
        credential: &CredentialRecord,
        total: Option<usize>,
    ) -> Result<Vec<(Value, Value)>, u8> {
        let mut user_entries = vec![(
            Value::Text("id".into()),
            Value::Bytes(credential.user_id.clone()),
        )];
        let bounded =
            |text: &str| Value::Text(truncate_utf8(text, request::MAX_USER_STRING_LENGTH));
        if let Some(name) = &credential.user_name {
            user_entries.push((Value::Text("name".into()), bounded(name)));
        }
        if let Some(display) = &credential.user_display_name {
            user_entries.push((Value::Text("displayName".into()), bounded(display)));
        }
        let user_map = canonical_map(user_entries);

        let credential_descriptor = canonical_map(vec![
            (Value::Text("type".into()), Value::Text("public-key".into())),
            (
                Value::Text("id".into()),
                Value::Bytes(credential.credential_id.clone()),
            ),
        ]);

        let public_key = credential.cose_public_key().map_err(|err| {
            log::error!("cannot derive a stored credential's public key: {err}");
            CTAP2_ERR_PROCESSING
        })?;
        let public_key_value: Value =
            from_reader::<Value, _>(&public_key[..]).map_err(|_| CTAP2_ERR_PROCESSING)?;

        let mut entries = vec![
            (Value::Integer(Integer::from(6)), user_map),
            (Value::Integer(Integer::from(7)), credential_descriptor),
            (Value::Integer(Integer::from(8)), public_key_value),
            (
                Value::Integer(Integer::from(10)),
                Value::Integer(Integer::from(u64::from(credential.cred_protect))),
            ),
        ];
        if let Some(total) = total {
            entries.push((
                Value::Integer(Integer::from(9)),
                Value::Integer(Integer::from(total as u64)),
            ));
        }
        Ok(entries)
    }

    fn cm_enumerate_credentials_begin(
        &mut self,
        params: &[(Value, Value)],
    ) -> Result<Vec<(Value, Value)>, u8> {
        let rp_hash = required_bytes(params, 1)?;

        let credentials: Vec<CredentialRecord> = self
            .discoverable_credentials()?
            .into_iter()
            .filter(|credential| Self::cm_hash_rp_id(&credential.rp_id) == rp_hash)
            .collect();
        let Some(first) = credentials.first() else {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        };

        let response = Self::cm_credential_response(first, Some(credentials.len()))?;
        self.cred_mgmt_state.credential_list = credentials
            .iter()
            .map(|credential| credential.credential_id.clone())
            .collect();
        self.cred_mgmt_state.credential_index = 1;
        self.cred_mgmt_state.credential_token = self.pin_state.pin_uv_auth_token_id();

        Ok(response)
    }

    /// enumerateCredentialsGetNextCredential.  CTAP2_ERR_NOT_ALLOWED without
    /// an enumeration to continue, as for [`Self::cm_enumerate_rps_next`].  A
    /// credential deleted since enumerateCredentialsBegin is skipped.
    fn cm_enumerate_credentials_next(&mut self) -> Result<Vec<(Value, Value)>, u8> {
        let token = self.pin_state.pin_uv_auth_token_id();
        let state = &self.cred_mgmt_state;
        if state.credential_token.is_none() || state.credential_token != token {
            self.cred_mgmt_state.reset_credentials();
            return Err(CTAP2_ERR_NOT_ALLOWED);
        }
        loop {
            let index = self.cred_mgmt_state.credential_index;
            let Some(credential_id) = self.cred_mgmt_state.credential_list.get(index).cloned()
            else {
                self.cred_mgmt_state.reset_credentials();
                return Err(CTAP2_ERR_NOT_ALLOWED);
            };
            self.cred_mgmt_state.credential_index += 1;
            if let Some(credential) = self.stored_credential(&credential_id)? {
                return Self::cm_credential_response(&credential, None);
            }
        }
    }

    fn cm_delete_credential(&mut self, params: &[(Value, Value)]) -> Result<(), u8> {
        let id = required_bytes(required_map(params, 2)?, "id")?;
        let deleted = self
            .store
            .delete(id)
            .map_err(|err| store_status("delete a credential", err))?;
        if !deleted {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        }
        self.cred_mgmt_state.reset_rps();
        self.cred_mgmt_state.reset_credentials();
        Ok(())
    }

    fn cm_update_user_information(&mut self, params: &[(Value, Value)]) -> Result<(), u8> {
        let id = required_bytes(required_map(params, 2)?, "id")?;
        let user_map = required_map(params, 3)?;
        let user_id = required_bytes(user_map, "id")?;

        let Some(mut credential) = self.stored_credential(id)? else {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        };
        if credential.user_id != user_id {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }

        // Kept to the same bounds as makeCredential stores.
        let non_empty_text = |key: &str| match cbor::map_get(user_map, Value::Text(key.into())) {
            Some(Value::Text(text)) if !text.is_empty() => {
                Some(truncate_utf8(text, request::MAX_USER_STRING_LENGTH))
            }
            _ => None,
        };
        credential.user_name = non_empty_text("name");
        credential.user_display_name = non_empty_text("displayName");

        self.store
            .put(&credential)
            .map_err(|err| store_status("update a credential", err))
    }

    /// The subCommandParams members a subcommand cannot do without:
    /// rpIDHash for enumerateCredentialsBegin (CTAP 2.3 §6.8.4), credentialId
    /// for deleteCredential (§6.8.5), and credentialId and user for
    /// updateUserInformation (§6.8.6).  Any of them missing is
    /// CTAP2_ERR_MISSING_PARAMETER.
    fn cm_check_mandatory_parameters(
        subcommand: u8,
        params: Option<&[(Value, Value)]>,
    ) -> Result<(), u8> {
        let required: &[i64] = match subcommand {
            ENUMERATE_CREDENTIALS_BEGIN => &[1],
            DELETE_CREDENTIAL => &[2],
            UPDATE_USER_INFORMATION => &[2, 3],
            _ => &[],
        };
        let missing = |key: &i64| {
            params.is_none_or(|params| {
                cbor::map_get(params, Value::Integer(Integer::from(*key))).is_none()
            })
        };
        if required.iter().any(missing) {
            Err(CTAP2_ERR_MISSING_PARAMETER)
        } else {
            Ok(())
        }
    }

    pub(super) fn handle_credential_management(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        let map = cbor::request_parameters(payload)?;

        let subcommand = match cbor::map_get(&map, Value::Integer(Integer::from(1))) {
            // "If the authenticator implements a command code having
            // subcommands, but does not implement an invoked subcommand, it
            // MUST return CTAP2_ERR_INVALID_SUBCOMMAND." (CTAP 2.3 §8.1)
            Some(Value::Integer(int)) => u8::try_from(i128::from(*int))
                .ok()
                .filter(|sub| (GET_CREDS_METADATA..=UPDATE_USER_INFORMATION).contains(sub))
                .ok_or(CTAP2_ERR_INVALID_SUBCOMMAND)?,
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let subcommand_params = match cbor::map_get(&map, Value::Integer(Integer::from(2))) {
            Some(Value::Map(entries)) => Some(entries.clone()),
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => None,
        };

        // enumerateRPsGetNextRP and enumerateCredentialsGetNextCredential
        // carry no pinUvAuthParam (CTAP 2.3 §6.8.3, §6.8.4): the platform
        // sends only the subCommand, and the enumeration's begin subcommand
        // was authenticated instead.
        let response_entries = match subcommand {
            ENUMERATE_RPS_GET_NEXT_RP => Some(self.cm_enumerate_rps_next()?),
            ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL => {
                Some(self.cm_enumerate_credentials_next()?)
            }
            _ => {
                // "If pinUvAuthParam is missing from the input map, end the
                // operation by returning CTAP2_ERR_PUAT_REQUIRED. If the
                // authenticator does not receive mandatory parameters for this
                // subcommand, end the operation by returning
                // CTAP2_ERR_MISSING_PARAMETER. If pinUvAuthProtocol is not
                // supported, return CTAP1_ERR_INVALID_PARAMETER." (CTAP 2.3
                // §6.8.2 to §6.8.6), in that order, and all before the
                // pinUvAuthParam is verified.
                let pin_auth_param = cbor::map_get(&map, Value::Integer(Integer::from(4)))
                    .ok_or(CTAP2_ERR_PUAT_REQUIRED)?;
                Self::cm_check_mandatory_parameters(subcommand, subcommand_params.as_deref())?;
                let (protocol, pin_auth_param) = parse_pin_uv_auth_param(
                    Some(pin_auth_param),
                    cbor::map_get(&map, Value::Integer(Integer::from(3))),
                )?
                .ok_or(CTAP2_ERR_PUAT_REQUIRED)?;

                // "verify(pinUvAuthToken, enumerateCredentialsBegin (0x04) ||
                // subCommandParams, pinUvAuthParam)": subCommandParams as the
                // platform encoded them, not as this engine would re-encode
                // them.
                let mut message = vec![subcommand];
                if let Some(raw_params) =
                    cbor::raw_map_value(payload, 2).map_err(|()| CTAP2_ERR_INVALID_CBOR)?
                {
                    message.extend_from_slice(raw_params);
                }
                self.verify_pin_uv_auth_param(protocol, &message, &pin_auth_param)?;

                self.ensure_pin_token_permission_for_cm(subcommand, subcommand_params.as_deref())?;

                let params = subcommand_params
                    .as_ref()
                    .ok_or(CTAP2_ERR_MISSING_PARAMETER);
                match subcommand {
                    GET_CREDS_METADATA => Some(self.cm_get_metadata()?),
                    ENUMERATE_RPS_BEGIN => Some(self.cm_enumerate_rps_begin()?),
                    ENUMERATE_CREDENTIALS_BEGIN => {
                        Some(self.cm_enumerate_credentials_begin(params?)?)
                    }
                    DELETE_CREDENTIAL => {
                        self.cm_delete_credential(params?)?;
                        None
                    }
                    _ => {
                        self.cm_update_user_information(params?)?;
                        None
                    }
                }
            }
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
