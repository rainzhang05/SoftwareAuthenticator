//! The authenticatorGetAssertion and authenticatorGetNextAssertion commands,
//! including hmac-secret extension processing.

use super::cbor::{self, canonical_map, canonical_sort};
use super::pin::permissions::PIN_PERMISSION_GA;
use super::pin::protocol::{
    decrypt, parse_pin_uv_auth_param, parse_pin_uv_auth_protocol, verify, HmacSha256, PinProtocol,
};
use super::presence::{PresenceOperation, PresenceRequest};
use super::request;
use super::storage::{is_discoverable, store_status};
use super::CtapApp;
use crate::store::{sort_newest_first, CredentialRecord};
use crate::{try_sign_challenge, ClassicPinProtocol, PinUvSessionKeys};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use core::time::Duration;
use hmac::{KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::ctap::constants::*;

use std::collections::VecDeque;

/// "If timer since the last call to authenticatorGetAssertion/
/// authenticatorGetNextAssertion is greater than 30 seconds, discard the
/// current authenticatorGetAssertion state and return CTAP2_ERR_NOT_ALLOWED."
/// (CTAP 2.3 §6.3)
const GET_NEXT_ASSERTION_TIMEOUT: Duration = Duration::from_secs(30);

struct PendingHmacSecret {
    protocol: PinProtocol,
    keys: PinUvSessionKeys,
    salt_plaintext: Zeroizing<Vec<u8>>,
}

impl PendingHmacSecret {
    /// `output1 [|| output2]` with `outputN = HMAC-SHA-256(CredRandom, saltN)`
    /// (CTAP 2.3 §12.7).
    fn outputs_for(&self, cred_random: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, u8> {
        let mut outputs = Zeroizing::new(Vec::with_capacity(self.salt_plaintext.len()));
        for salt in self.salt_plaintext.chunks(32) {
            let mut hmac =
                HmacSha256::new_from_slice(cred_random).map_err(|_| CTAP2_ERR_PROCESSING)?;
            hmac.update(salt);
            outputs.extend_from_slice(&hmac.finalize().into_bytes());
        }
        Ok(outputs)
    }
}

/// The authenticatorGetAssertion parameters remembered for
/// authenticatorGetNextAssertion (CTAP 2.3 §6.2.2 step 11.2.2.1.1).
pub(super) struct PendingAssertion {
    rp_id: String,
    client_hash: Vec<u8>,
    user_present: bool,
    user_verified: bool,
    remaining_credentials: VecDeque<Vec<u8>>,
    hmac_secret: Option<PendingHmacSecret>,
    /// When authenticatorGetAssertion or the last
    /// authenticatorGetNextAssertion was answered.
    timer_started: Duration,
    /// The pinUvAuthToken that authenticated authenticatorGetAssertion, if
    /// one did: "An authenticator MUST discard the state for a stateful
    /// command command if the pinUvAuthToken that authenticated the state
    /// initializing command expires" (CTAP 2.3 §6).
    token: Option<u64>,
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

impl CtapApp<'_> {
    fn credential_allows(
        credential: &CredentialRecord,
        user_verified: bool,
        allow_list_provided: bool,
    ) -> bool {
        match credential.cred_protect {
            3 => user_verified,
            2 => user_verified || allow_list_provided,
            _ => true,
        }
    }

    fn process_hmac_secret_for_assertion(
        &mut self,
        request: &HmacSecretRequest,
        cred_random_with_uv: &[u8; 32],
        cred_random_without_uv: &[u8; 32],
        user_verified: bool,
    ) -> Result<(Vec<u8>, PendingHmacSecret), u8> {
        // "The authenticator calls decapsulate on the provided platform
        // key-agreement key to obtain a shared secret." (CTAP 2.3 §12.7)
        let keys = self.decapsulate(request.protocol, &request.key_agreement)?;

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
        cred_random: &[u8; 32],
    ) -> Result<Vec<u8>, u8> {
        let outputs = pending.outputs_for(cred_random)?;
        self.encrypt_for_platform(pending.protocol, &pending.keys, &outputs)
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

    /// authenticatorGetAssertion, following the steps of CTAP 2.3 §6.2.2 for
    /// an authenticator with clientPin and pinUvAuthToken, no built-in user
    /// verification, no alwaysUv and no display.  It "is protected by some
    /// form of user verification" exactly when a PIN is set.
    pub(super) fn handle_get_assertion(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
        self.pending_assertion = None;
        let request: Value = from_reader(payload).map_err(|_| CTAP2_ERR_INVALID_CBOR)?;
        let map = match request {
            Value::Map(map) => map,
            _ => return Err(CTAP2_ERR_INVALID_CBOR),
        };
        let parameter = |key: i64| cbor::map_get(&map, Value::Integer(Integer::from(key)));

        // Step 1: a zero length pinUvAuthParam asks the user to select this
        // authenticator.
        if request::is_zero_length(parameter(6)) {
            return Err(self.select_for_pin_uv_auth(PresenceOperation::Authenticate));
        }

        // Step 2.
        let pin_uv_auth = parse_pin_uv_auth_param(parameter(6), parameter(7))?;

        let rp_id = match parameter(1) {
            Some(Value::Text(text)) => text.clone(),
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let client_hash = match parameter(2) {
            Some(Value::Bytes(bytes)) => bytes.clone(),
            Some(_) => return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
            None => return Err(CTAP2_ERR_MISSING_PARAMETER),
        };

        let allow_list = parameter(3).map(request::credential_ids).transpose()?;

        let mut hmac_secret_request: Option<HmacSecretRequest> = None;
        if let Some(value) = parameter(4) {
            let Value::Map(extension_map) = value else {
                return Err(CTAP2_ERR_INVALID_CBOR);
            };
            for (key, value) in extension_map.iter() {
                if let Value::Text(text) = key {
                    if text == "hmac-secret" {
                        hmac_secret_request = Some(parse_hmac_secret_request(value)?);
                    }
                }
            }
        }

        // Step 4.  "If the pinUvAuthParam is present, let the "uv" option be
        // treated as being present with the value false."  "If the "uv"
        // option is present and true then: If the authenticator does not
        // support a built-in user verification method end the operation by
        // returning CTAP2_ERR_INVALID_OPTION."  "If the "rk" option is present
        // then: Return CTAP2_ERR_UNSUPPORTED_OPTION."
        let options = request::options(parameter(5))?;
        if pin_uv_auth.is_none() && options.uv == Some(true) {
            return Err(CTAP2_ERR_INVALID_OPTION);
        }
        if options.rk.is_some() {
            return Err(CTAP2_ERR_UNSUPPORTED_OPTION);
        }
        let up_option = options.up.unwrap_or(true);

        // Step 6.  Without a PIN the step is skipped, so a pinUvAuthParam is
        // not verified and the "uv" bit stays false.
        let mut user_verified = false;
        let mut token = None;
        if self.pin_state.is_set() {
            if let Some((protocol, param)) = pin_uv_auth.as_ref() {
                self.verify_pin_uv_auth_param(*protocol, &client_hash, param)?;
                self.ensure_pin_token_permission_for_rp(PIN_PERMISSION_GA, &rp_id)?;
                user_verified = true;
                token = self.pin_state.pin_uv_auth_token_id();
            }
        }

        // Step 7: locate the applicable credentials.
        let mut applicable: Vec<CredentialRecord> = Vec::new();
        if let Some(list) = allow_list.as_ref() {
            // "If the allowList parameter is present and is non-empty, locate
            // all denoted credentials created by this authenticator and bound
            // to the specified rpId."
            for id in list {
                if applicable.iter().any(|cred| cred.credential_id == *id) {
                    continue;
                }
                if let Some(cred) = self.stored_credential(id)? {
                    if cred.rp_id == rp_id && Self::credential_allows(&cred, user_verified, true) {
                        applicable.push(cred);
                    }
                }
            }
            sort_newest_first(&mut applicable);
        } else {
            // "If an allowList is not present, locate all discoverable
            // credentials that are created by this authenticator and bound to
            // the specified rpId." (CTAP 2.3 §6.2.2 step 7.2)
            applicable = self
                .stored_credentials()?
                .into_iter()
                .filter(|cred| {
                    cred.rp_id == rp_id
                        && is_discoverable(&cred.credential_id)
                        && Self::credential_allows(cred, user_verified, false)
                })
                .collect();
        }
        if applicable.is_empty() {
            return Err(CTAP2_ERR_NO_CREDENTIALS);
        }

        // Step 9: "If the "up" option is set to true or not present", collect
        // user presence unless a pinUvAuthToken with its userPresent flag set
        // authenticated the request, then "Call clearUserPresentFlag(),
        // clearUserVerifiedFlag(), and clearPinUvAuthTokenPermissionsExceptLbw()."
        // With "up" false the assertion is silent and the "up" bit false.
        let mut user_present = false;
        if up_option {
            if !(pin_uv_auth.is_some() && self.pin_state.user_present_flag()) {
                let timeout = self.presence_timeout;
                self.confirm_user_presence(PresenceRequest {
                    rp_id: Some(&rp_id),
                    ..PresenceRequest::new(PresenceOperation::Authenticate, timeout)
                })?;
            }
            user_present = true;
            self.pin_state
                .consume_pin_uv_auth_token_after_user_presence();
        } else if hmac_secret_request.is_some() {
            // hmac-secret: "If "up" is set to false, the authenticator returns
            // CTAP2_ERR_UNSUPPORTED_OPTION." (CTAP 2.3 §12.7)
            return Err(CTAP2_ERR_UNSUPPORTED_OPTION);
        }

        // Step 11.  With an allowList: "Select any credential from the
        // applicable credentials list. Delete the numberOfCredentials member."
        // Without one, the most recently created credential, and when there
        // are several the authenticator (which has no display) remembers the
        // request for authenticatorGetNextAssertion and reports
        // numberOfCredentials.
        let mut applicable = applicable.into_iter();
        let credential = applicable.next().ok_or(CTAP2_ERR_NO_CREDENTIALS)?;
        let remaining_credentials: VecDeque<Vec<u8>> = if allow_list.is_some() {
            VecDeque::new()
        } else {
            applicable.map(|cred| cred.credential_id.clone()).collect()
        };
        let remaining_count = remaining_credentials.len();

        let mut extension_entries = Vec::new();
        let mut pending_hmac_secret = None;
        if let Some(ref request) = hmac_secret_request {
            let (encrypted, pending_state) = self.process_hmac_secret_for_assertion(
                request,
                &credential.cred_random_with_uv,
                &credential.cred_random_without_uv,
                user_verified,
            )?;
            extension_entries.push((Value::Text("hmac-secret".into()), Value::Bytes(encrypted)));
            pending_hmac_secret = Some(pending_state);
        }
        let extension_bytes = encode_extensions(extension_entries)?;

        let (credential, auth_data, signature) = self.sign_assertion(
            credential,
            &rp_id,
            &client_hash,
            user_present,
            user_verified,
            extension_bytes.as_deref(),
        )?;

        if remaining_count != 0 {
            self.pending_assertion = Some(PendingAssertion {
                rp_id: rp_id.clone(),
                client_hash: client_hash.clone(),
                user_present,
                user_verified,
                remaining_credentials,
                hmac_secret: pending_hmac_secret,
                timer_started: self.pin_state.now(),
                token,
            });
        }

        let number_of_credentials = (remaining_count != 0).then_some(1 + remaining_count);
        assertion_response(
            &credential,
            auth_data,
            signature,
            user_verified,
            number_of_credentials,
        )
    }

    /// authenticatorGetNextAssertion (CTAP 2.3 §6.3).
    pub(super) fn handle_get_next_assertion(&mut self) -> Result<Vec<u8>, u8> {
        // "If the authenticator does not remember any authenticatorGetAssertion
        // parameters, return CTAP2_ERR_NOT_ALLOWED."  Taking the state
        // discards it on every error below.
        let mut pending = self.pending_assertion.take().ok_or(CTAP2_ERR_NOT_ALLOWED)?;

        // "If timer since the last call to authenticatorGetAssertion/
        // authenticatorGetNextAssertion is greater than 30 seconds, discard
        // the current authenticatorGetAssertion state and return
        // CTAP2_ERR_NOT_ALLOWED."
        let now = self.pin_state.now();
        if now.saturating_sub(pending.timer_started) > GET_NEXT_ASSERTION_TIMEOUT {
            return Err(CTAP2_ERR_NOT_ALLOWED);
        }
        if pending.token.is_some() && pending.token != self.pin_state.pin_uv_auth_token_id() {
            return Err(CTAP2_ERR_NOT_ALLOWED);
        }

        // "If the credentialCounter is equal to or greater than
        // numberOfCredentials, return CTAP2_ERR_NOT_ALLOWED."  A credential
        // deleted since authenticatorGetAssertion is skipped.
        let credential = loop {
            let credential_id = pending
                .remaining_credentials
                .pop_front()
                .ok_or(CTAP2_ERR_NOT_ALLOWED)?;
            if let Some(credential) = self
                .stored_credential(&credential_id)?
                .filter(|cred| cred.rp_id == pending.rp_id)
            {
                break credential;
            }
        };

        let mut extension_entries = Vec::new();
        if let Some(ref hmac_state) = pending.hmac_secret {
            let cred_random = if pending.user_verified {
                &credential.cred_random_with_uv
            } else {
                &credential.cred_random_without_uv
            };
            let encrypted = self.encrypt_hmac_secret_outputs(hmac_state, cred_random)?;
            extension_entries.push((Value::Text("hmac-secret".into()), Value::Bytes(encrypted)));
        }
        let extension_bytes = encode_extensions(extension_entries)?;

        let (credential, auth_data, signature) = self.sign_assertion(
            credential,
            &pending.rp_id,
            &pending.client_hash,
            pending.user_present,
            pending.user_verified,
            extension_bytes.as_deref(),
        )?;

        // "User identifiable information [...] MUST NOT be returned if user
        // verification was not done by the authenticator in the original
        // authenticatorGetAssertion call."
        let user_verified = pending.user_verified;

        // "Reset the timer."
        if !pending.remaining_credentials.is_empty() {
            pending.timer_started = self.pin_state.now();
            self.pending_assertion = Some(pending);
        }

        assertion_response(&credential, auth_data, signature, user_verified, None)
    }

    /// Increment `credential`'s signature counter, persist it, and sign
    /// `authData || clientDataHash` with the new count.
    ///
    /// The counter is written before the signature is made, and a failed
    /// write fails the command: a signature is never returned for a counter
    /// that was not saved, so the counter a relying party sees can never go
    /// backwards after a restart (WebAuthn Level 3 §6.1.1, "SHOULD ensure
    /// that the signature counter value does not accidentally decrease").
    /// The signing key is materialised once, which for ML-DSA is one key
    /// expansion from the stored seed.
    fn sign_assertion(
        &mut self,
        mut credential: CredentialRecord,
        rp_id: &str,
        client_hash: &[u8],
        user_present: bool,
        user_verified: bool,
        extensions: Option<&[u8]>,
    ) -> Result<(CredentialRecord, Vec<u8>, Vec<u8>), u8> {
        let secret_key = credential.secret_key().map_err(|err| {
            log::error!("cannot use a stored credential's key: {err}");
            CTAP2_ERR_PROCESSING
        })?;
        credential.sign_count = credential.sign_count.saturating_add(1);
        self.store
            .put(&credential)
            .map_err(|err| store_status("save the signature counter", err))?;

        let auth_data = self.assertion_auth_data(
            rp_id,
            credential.sign_count,
            user_present,
            user_verified,
            extensions,
        );
        let signature = try_sign_challenge(credential.alg, &secret_key, &auth_data, client_hash)
            .map_err(|err| {
                log::error!(
                    "assertion signature with {:?} failed: {err}",
                    credential.alg
                );
                CTAP2_ERR_PROCESSING
            })?;
        Ok((credential, auth_data, signature))
    }
}

/// Parse the hmac-secret getAssertion input (CTAP 2.3 §12.7).
fn parse_hmac_secret_request(value: &Value) -> Result<HmacSecretRequest, u8> {
    let Value::Map(params) = value else {
        return Err(CTAP2_ERR_INVALID_CBOR);
    };
    let key_agreement = match cbor::map_get(params, Value::Integer(Integer::from(1))) {
        Some(Value::Map(entries)) => entries.clone(),
        _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
    };
    let salt_enc = match cbor::map_get(params, Value::Integer(Integer::from(2))) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
    };
    let salt_auth = match cbor::map_get(params, Value::Integer(Integer::from(3))) {
        Some(Value::Bytes(bytes)) => bytes.clone(),
        _ => return Err(CTAP2_ERR_MISSING_PARAMETER),
    };
    // "If pinUvAuthProtocol is absent and a pinUvAuthProtocol value of 1 is
    // supported by the authenticator, let the value of pinUvAuthProtocol be 1"
    // (CTAP 2.3 §12.7).
    let protocol = match cbor::map_get(params, Value::Integer(Integer::from(4))) {
        Some(value) => parse_pin_uv_auth_protocol(value)?,
        None => ClassicPinProtocol::V1,
    };
    Ok(HmacSecretRequest {
        key_agreement,
        salt_enc,
        salt_auth,
        protocol,
    })
}

/// The CBOR extension outputs for authenticator data, or `None` if empty.
fn encode_extensions(entries: Vec<(Value, Value)>) -> Result<Option<Vec<u8>>, u8> {
    if entries.is_empty() {
        return Ok(None);
    }
    let mut encoded = Vec::new();
    into_writer(&canonical_map(entries), &mut encoded).map_err(|_| CTAP2_ERR_PROCESSING)?;
    Ok(Some(encoded))
}

/// The authenticatorGetAssertion response, with `numberOfCredentials` only
/// when given (it is omitted from authenticatorGetNextAssertion responses).
///
/// The user member (CTAP 2.3 §6.2.2 step 12, §6.3): "User identifiable
/// information (name, DisplayName, icon) inside the
/// publicKeyCredentialUserEntity MUST NOT be returned if user verification is
/// not done by the authenticator", so name and displayName only accompany
/// `user_verified`.  "For discoverable credentials on FIDO devices, at least
/// user "id" is mandatory", while for server-side credentials the member "is
/// OPTIONAL as server-side credentials behave the same as U2F credentials
/// where they are discovered given the user information on the RP"; this
/// authenticator omits it for them, as for U2F credentials.
fn assertion_response(
    credential: &CredentialRecord,
    auth_data: Vec<u8>,
    signature: Vec<u8>,
    user_verified: bool,
    number_of_credentials: Option<usize>,
) -> Result<Vec<u8>, u8> {
    let credential_map = canonical_map(vec![
        (Value::Text("type".into()), Value::Text("public-key".into())),
        (
            Value::Text("id".into()),
            Value::Bytes(credential.credential_id.clone()),
        ),
    ]);

    let mut response = vec![
        (Value::Integer(Integer::from(1)), credential_map),
        (Value::Integer(Integer::from(2)), Value::Bytes(auth_data)),
        (Value::Integer(Integer::from(3)), Value::Bytes(signature)),
    ];

    if is_discoverable(&credential.credential_id) {
        let mut user_entries = vec![(
            Value::Text("id".into()),
            Value::Bytes(credential.user_id.clone()),
        )];
        if user_verified {
            let bounded = |text: &str| {
                Value::Text(request::truncate_utf8(
                    text,
                    request::MAX_USER_STRING_LENGTH,
                ))
            };
            if let Some(name) = &credential.user_name {
                user_entries.push((Value::Text("name".into()), bounded(name)));
            }
            if let Some(display) = &credential.user_display_name {
                user_entries.push((Value::Text("displayName".into()), bounded(display)));
            }
        }
        response.push((
            Value::Integer(Integer::from(4)),
            canonical_map(user_entries),
        ));
    }

    if let Some(total) = number_of_credentials {
        response.push((
            Value::Integer(Integer::from(5)),
            Value::Integer(Integer::from(total as u64)),
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
