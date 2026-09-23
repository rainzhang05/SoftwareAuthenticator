//! The authenticatorMakeCredential command.

use super::cbor::{self, canonical_map, canonical_sort};
use super::pin::permissions::PIN_PERMISSION_MC;
use super::pin::protocol::parse_pin_uv_auth_param;
use super::presence::{PresenceOperation, PresenceRequest};
use super::request;
use super::storage::{is_discoverable, store_status};
use super::{AttestationMode, CtapApp};
use crate::store::{AttestationRecord, CredentialRecord, PrivateKeyMaterial, StoreError};
use crate::try_sign_challenge;

use ciborium::{
    ser::into_writer,
    value::{Integer, Value},
};
use p256::ecdsa::{Signature as P256EcdsaSignature, signature::Signer};
use sha2::{Digest, Sha256};

use crate::ctap::constants::*;

pub(super) const COSE_ALG_ES256: i32 = -7;

/// The attestation statements makeCredential can return, in order of
/// preference.
enum Attestation {
    /// "packed" basic attestation with the provisioned attestation key.
    Basic(AttestationRecord),
    /// "packed" self attestation with the credential key.
    SelfSigned,
    /// "none".
    None,
}

impl Attestation {
    fn name(&self) -> &'static str {
        match self {
            Attestation::Basic(_) => "basic",
            Attestation::SelfSigned => "self",
            Attestation::None => "no",
        }
    }
}

impl CtapApp<'_> {
    /// The authenticator data for the new credential `record`, with its
    /// attested credential data.
    fn attested_auth_data(
        &self,
        record: &CredentialRecord,
        cose_key: &[u8],
        user_present: bool,
        uv: bool,
        extensions: Option<&[u8]>,
    ) -> Vec<u8> {
        let credential_id = &record.credential_id;
        let mut hasher = Sha256::new();
        hasher.update(record.rp_id.as_bytes());
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
        auth_data.extend_from_slice(&record.sign_count.to_be_bytes());
        auth_data.extend_from_slice(&self.aaguid);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(credential_id);
        auth_data.extend_from_slice(cose_key);
        if let Some(ext) = extensions {
            auth_data.extend_from_slice(ext);
        }
        auth_data
    }

    /// authenticatorMakeCredential, following the steps of CTAP 2.3 §6.1.2.
    ///
    /// This authenticator supports clientPin and pinUvAuthToken but no
    /// built-in user verification, alwaysUv, noMcGaPermissionsWithClientPin or
    /// enterprise attestation, and advertises makeCredUvNotRqd.  It "is
    /// protected by some form of user verification" exactly when a PIN is
    /// set.
    pub(super) fn handle_make_credential(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        let map = cbor::request_parameters(payload)?;
        let parameter = |key: i64| cbor::map_get(&map, Value::Integer(Integer::from(key)));

        // Step 1: a zero length pinUvAuthParam asks the user to select this
        // authenticator.
        if request::is_zero_length(parameter(8)) {
            return Err(self.select_for_pin_uv_auth());
        }

        // Step 2.
        let pin_uv_auth = parse_pin_uv_auth_param(parameter(8), parameter(9))?;

        let client_hash = match parameter(1) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let rp = match parameter(2) {
            Some(Value::Map(rp)) => rp,
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let rp_id = match cbor::map_get(rp, Value::Text("id".into())) {
            Some(Value::Text(text)) => text.clone(),
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let user = match parameter(3) {
            Some(Value::Map(user)) => user,
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let user_id = match cbor::map_get(user, Value::Text("id".into())) {
            Some(Value::Bytes(bytes)) if bytes.len() <= request::MAX_USER_ID_LENGTH => {
                bytes.clone()
            }
            Some(Value::Bytes(_)) => return Err(CTAP1_ERR_INVALID_LENGTH),
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };
        let user_string = |name: &str| match cbor::map_get(user, Value::Text(name.into())) {
            None => Ok(None),
            Some(Value::Text(text)) => Ok(Some(request::truncate_utf8(
                text,
                request::MAX_USER_STRING_LENGTH,
            ))),
            Some(_) => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
        };
        let user_name = user_string("name")?;
        let user_display_name = user_string("displayName")?;

        // Step 3.
        let alg = match parameter(4) {
            Some(Value::Array(params)) => request::chosen_algorithm(params)?,
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let exclude_list = parameter(5)
            .map(request::credential_ids)
            .transpose()?
            .unwrap_or_default();

        // Step 5.  "If the pinUvAuthParam is present, let the "uv" option be
        // treated as being present with the value false." (pinUvAuthParam
        // takes precedence.)  "If the "uv" option is true then: If the
        // authenticator does not support a built-in user verification method
        // end the operation by returning CTAP2_ERR_INVALID_OPTION."
        let options = request::options(parameter(7))?;
        let uv = pin_uv_auth.is_none() && options.uv.unwrap_or(false);
        if uv {
            return Err(CTAP2_ERR_INVALID_OPTION);
        }
        // The rk option ID is in authenticatorGetInfo, so "rk" is supported.
        let rk = options.rk.unwrap_or(false);
        if options.up == Some(false) {
            return Err(CTAP2_ERR_INVALID_OPTION);
        }

        // Step 7, with makeCredUvNotRqd true: "If the following statements are
        // all true: The authenticator is protected by some form of user
        // verification. The "uv" option is set to false. The pinUvAuthParam
        // parameter is not present. The "rk" option is present and set to
        // true. Then: If ClientPin option ID is true and the
        // noMcGaPermissionsWithClientPin option ID is absent or false, end the
        // operation by returning CTAP2_ERR_PUAT_REQUIRED."  A non-discoverable
        // credential needs no user verification (step 10).
        let protected = self.pin_state.is_set();
        if protected && pin_uv_auth.is_none() && rk {
            return Err(CTAP2_ERR_PUAT_REQUIRED);
        }

        // Step 8: "If the authenticator is not enterprise attestation capable
        // [...] end the operation by returning CTAP1_ERR_INVALID_PARAMETER."
        if parameter(0x0A).is_some() {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }

        // attestationFormatsPreference (0x0B): "Clients may request omission
        // of attestation by including a single element with the string value
        // "none"." (CTAP 2.3 §6.1)
        let none_requested = match parameter(0x0B) {
            None => false,
            Some(Value::Array(formats)) => {
                if formats
                    .iter()
                    .any(|format| !matches!(format, Value::Text(_)))
                {
                    return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
                }
                matches!(formats.as_slice(), [Value::Text(format)] if format == "none")
            }
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
        };

        let mut hmac_secret_requested = false;
        let mut cred_protect_requested: Option<u8> = None;

        // A wrongly typed extensions map or extension input is
        // CTAP2_ERR_CBOR_UNEXPECTED_TYPE (CTAP 2.3 §8).
        if let Some(value) = parameter(6) {
            let Value::Map(extension_map) = value else {
                return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
            };
            for (key, value) in extension_map.iter() {
                match key {
                    Value::Text(text) if text == "hmac-secret" => match value {
                        Value::Bool(flag) => {
                            hmac_secret_requested = *flag;
                        }
                        _ => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
                    },
                    Value::Text(text) if text == "credProtect" => {
                        let policy_value = match value {
                            Value::Integer(int) => u8::try_from(i128::from(*int))
                                .map_err(|_| CTAP2_ERR_INVALID_OPTION)?,
                            _ => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
                        };
                        match policy_value {
                            1..=3 => cred_protect_requested = Some(policy_value),
                            _ => return Err(CTAP2_ERR_INVALID_OPTION),
                        }
                    }
                    _ => {}
                }
            }
        }

        // Steps 10 and 11.  Without a PIN the authenticator is not protected,
        // step 11 is skipped and a pinUvAuthParam is not verified: the "uv"
        // bit stays false.  (No pinUvAuthToken can be in use then, since only
        // a PIN issues one.)
        let mut uv_bit = false;
        if protected && let Some((protocol, pin_uv_auth_param)) = pin_uv_auth.as_ref() {
            self.verify_pin_uv_auth_param(*protocol, &client_hash, pin_uv_auth_param)?;
            self.ensure_pin_token_permission_for_rp(PIN_PERMISSION_MC, &rp_id)?;
            uv_bit = true;
        }

        let cred_protect_value = cred_protect_requested.unwrap_or(1);
        let timeout = self.presence_timeout;
        let register_request = |timeout| PresenceRequest {
            rp_id: Some(&rp_id),
            user_name: user_name.as_deref(),
            user_display_name: user_display_name.as_deref(),
            ..PresenceRequest::new(PresenceOperation::Register, timeout)
        };

        // Step 12.
        for id in &exclude_list {
            let Some(excluded) = self.stored_credential(id)? else {
                continue;
            };
            if excluded.rp_id != rp_id {
                continue;
            }
            // "Else (implying the credential's credProtect value is
            // userVerificationRequired): [...] Else (implying user
            // verification was not collected in Step 11), remove the
            // credential from the excludeList and continue parsing the rest
            // of the list."
            if excluded.cred_protect == 3 && !uv_bit {
                continue;
            }
            // "If the pinUvAuthParam parameter is present then let
            // userPresentFlagValue be the result of calling
            // getUserPresentFlagValue(). [...] If userPresentFlagValue is
            // false, then: Wait for user presence. Regardless of whether user
            // presence is obtained or the authenticator times out, terminate
            // this procedure and return CTAP2_ERR_CREDENTIAL_EXCLUDED."  A
            // request the platform cancels ends as cancelled.
            let user_present = pin_uv_auth.is_some() && self.pin_state.user_present_flag();
            if !user_present {
                let outcome = self.confirm_user_presence(register_request(timeout));
                if outcome == Err(CTAP2_ERR_KEEPALIVE_CANCEL) {
                    return Err(CTAP2_ERR_KEEPALIVE_CANCEL);
                }
            }
            return Err(CTAP2_ERR_CREDENTIAL_EXCLUDED);
        }

        // Step 14: collect user presence unless a pinUvAuthParam brought a
        // pinUvAuthToken whose userPresent flag is set, then "Call
        // clearUserPresentFlag(), clearUserVerifiedFlag(), and
        // clearPinUvAuthTokenPermissionsExceptLbw()."
        let user_present = pin_uv_auth.is_some() && self.pin_state.user_present_flag();
        if !user_present {
            self.confirm_user_presence(register_request(timeout))?;
        }
        let up_bit = true;
        self.pin_state
            .consume_pin_uv_auth_token_after_user_presence();

        // ML-DSA keys are stored as their 32-byte seed (RFC 9964 §4).
        let record = CredentialRecord {
            credential_id: self.new_credential_id(rk),
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
            &record,
            &cose_key,
            up_bit,
            uv_bit,
            extension_bytes.as_deref(),
        );
        // Steps 18 and 19.  "If attestationFormatsPreference is present and
        // contains only one entry with the value "none", omit attestation from
        // the output."  Otherwise this authenticator, whose only format besides
        // "none" is "packed", generates the statement its attestation mode
        // asks for: self attestation, or with AttestationMode::Certificate
        // basic attestation with the provisioned attestation key if there is
        // one, else self attestation.  A response the transport cannot carry
        // is no response, so an attestation statement that would make it
        // longer than MAX_RESPONSE_SIZE gives way to the next one in that
        // order and finally to "none".  (Only an unusually large certificate
        // chain, or one combined with ML-DSA-87 self attestation, comes near
        // the limit.)
        let mut kinds = Vec::with_capacity(3);
        if !none_requested {
            match self.attestation_mode {
                AttestationMode::Certificate => {
                    if let Some(attestation) = self.attestation_record() {
                        kinds.push(Attestation::Basic(attestation));
                    }
                    kinds.push(Attestation::SelfSigned);
                }
                AttestationMode::SelfAttestation => kinds.push(Attestation::SelfSigned),
                AttestationMode::None => {}
            }
        }
        kinds.push(Attestation::None);

        for kind in kinds {
            let (attestation_format, att_stmt) = match &kind {
                // Packed attestation with the attestation key and certificate
                // chain (WebAuthn §8.2).
                Attestation::Basic(attestation) => {
                    let signing_key = attestation.signing_key().map_err(|err| {
                        log::error!("the attestation key is unusable: {err}");
                        CTAP2_ERR_PROCESSING
                    })?;
                    let mut message = Vec::with_capacity(auth_data.len() + client_hash.len());
                    message.extend_from_slice(&auth_data);
                    message.extend_from_slice(&client_hash);
                    let signature: P256EcdsaSignature = signing_key.sign(&message);
                    let statement = canonical_map(vec![
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
                    ]);
                    ("packed", statement)
                }
                // Self attestation with the credential key.
                Attestation::SelfSigned => {
                    let signature = try_sign_challenge(alg, &secret_key, &auth_data, &client_hash)
                        .map_err(|err| {
                            log::error!("self attestation with {alg:?} failed: {err}");
                            CTAP2_ERR_PROCESSING
                        })?;
                    let statement = canonical_map(vec![
                        (
                            Value::Text("alg".into()),
                            Value::Integer(Integer::from(alg as i32)),
                        ),
                        (Value::Text("sig".into()), Value::Bytes(signature)),
                    ]);
                    ("packed", statement)
                }
                Attestation::None => ("none", Value::Map(Vec::new())),
            };

            let mut response_map = vec![
                (
                    Value::Integer(Integer::from(1)),
                    Value::Text(attestation_format.into()),
                ),
                (
                    Value::Integer(Integer::from(2)),
                    Value::Bytes(auth_data.clone()),
                ),
                (Value::Integer(Integer::from(3)), att_stmt),
            ];
            canonical_sort(&mut response_map);
            let mut encoded = Vec::new();
            into_writer(&Value::Map(response_map), &mut encoded)
                .map_err(|_| CTAP2_ERR_PROCESSING)?;
            let mut out = Vec::with_capacity(1 + encoded.len());
            out.push(CTAP2_OK);
            out.extend_from_slice(&encoded);

            if out.len() > MAX_RESPONSE_SIZE {
                log::warn!(
                    "{} attestation would make the makeCredential response {} bytes, more than \
                     the {MAX_RESPONSE_SIZE} a response can have",
                    kind.name(),
                    out.len()
                );
                continue;
            }

            // Stored only once the response is complete, so a request that
            // fails leaves no credential behind that the platform never
            // learned about.
            self.store_new_credential(&record, rk)?;
            return Ok(out);
        }
        log::error!("the makeCredential response does not fit even without attestation");
        Err(CTAP2_ERR_PROCESSING)
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
