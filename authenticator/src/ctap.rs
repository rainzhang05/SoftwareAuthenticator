mod cbor;
mod credential_management;
mod get_info;
mod pin;
mod presence;
mod storage;

use self::cbor::{canonical_map, canonical_sort};
use self::credential_management::CredentialManagementState;
use self::pin::permissions::{PIN_PERMISSION_GA, PIN_PERMISSION_MC};
use self::pin::protocol::{
    decrypt_shared_secret, encrypt_shared_secret, pin_protocol_from_identifier, HmacSha256,
    PinProtocol, PinProtocolSession,
};
use self::pin::state::PinState;
use self::presence::noop_keepalive;
// The tests still address these through `super::`.
#[cfg(test)]
use self::presence::{take_waiting_log, USER_PRESENCE_MAX_WAIT_MS, USER_PRESENCE_POLL_TIMEOUT_MS};
use self::storage::StoredCredential;
use crate::{
    create_credential, credential_secret_from_bytes, sign_challenge, ClassicPinProtocol, CoseAlg,
    PinUvSessionKeys,
};

use ciborium::{
    de::from_reader,
    ser::into_writer,
    value::{Integer, Value},
};
use ctaphid_app::{App, Command, Error};
use hmac::Mac;
use log::info;
use sha2::{Digest, Sha256};
use trussed::client::{Client as TrussedClient, CryptoClient, FilesystemClient};
use trussed::interrupt::InterruptFlag;
use trussed::syscall;
use zeroize::Zeroize;

use transport_core::{ctap::constants::*, logging::HexOption};

use std::collections::VecDeque;

const COSE_ALG_ES256: i32 = -7;

struct PendingHmacSecret {
    keys: PinUvSessionKeys,
    salt_plaintext: Vec<u8>,
}

impl PendingHmacSecret {
    fn new(keys: PinUvSessionKeys, salt_plaintext: Vec<u8>) -> Self {
        Self {
            keys,
            salt_plaintext,
        }
    }

    fn encrypt_output_for(&self, cred_random: Option<&Vec<u8>>) -> Result<Option<Vec<u8>>, u8> {
        if let Some(random) = cred_random {
            let mut outputs = Vec::new();
            let mut hmac = HmacSha256::new_from_slice(random).map_err(|_| CTAP2_ERR_PROCESSING)?;
            hmac.update(&self.salt_plaintext[..32]);
            outputs.extend_from_slice(&hmac.finalize().into_bytes());
            if self.salt_plaintext.len() == 64 {
                let mut hmac =
                    HmacSha256::new_from_slice(random).map_err(|_| CTAP2_ERR_PROCESSING)?;
                hmac.update(&self.salt_plaintext[32..]);
                outputs.extend_from_slice(&hmac.finalize().into_bytes());
            }
            let encrypted = encrypt_shared_secret(&self.keys.encryption_key, &outputs)?;
            Ok(Some(encrypted))
        } else {
            Ok(None)
        }
    }
}

impl Drop for PendingHmacSecret {
    fn drop(&mut self) {
        self.salt_plaintext.zeroize();
    }
}

struct PendingAssertion {
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

#[cfg(test)]
mod tests;

pub struct CtapApp<C> {
    client: C,
    aaguid: [u8; 16],
    pin_state: PinState,
    pin_protocol_session: Option<PinProtocolSession>,
    suppress_attestation: bool,
    cred_mgmt_state: CredentialManagementState,
    pending_assertion: Option<PendingAssertion>,
    attestation_private_key: Option<Vec<u8>>,
    attestation_certificate_chain: Option<Vec<Vec<u8>>>,
    attestation_material_initialized: bool,
    keepalive_callback: fn(bool),
    interrupt_flag: &'static InterruptFlag,
    auto_user_presence: bool,
    #[cfg(test)]
    stored_credentials: Vec<StoredCredential>,
}

impl<C> CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    pub fn new(client: C, aaguid: [u8; 16]) -> Self {
        let mut app = Self {
            client,
            aaguid,
            pin_state: PinState::new(),
            pin_protocol_session: None,
            suppress_attestation: false,
            cred_mgmt_state: CredentialManagementState::new(),
            pending_assertion: None,
            attestation_private_key: None,
            attestation_certificate_chain: None,
            attestation_material_initialized: false,
            keepalive_callback: noop_keepalive,
            interrupt_flag: Box::leak(Box::new(InterruptFlag::new())),
            auto_user_presence: false,
            #[cfg(test)]
            stored_credentials: Vec::new(),
        };
        app.load_persistent_pin_state();
        app
    }

    pub fn set_keepalive_callback(&mut self, callback: fn(bool)) {
        self.keepalive_callback = callback;
    }

    pub fn set_auto_user_presence(&mut self, enabled: bool) {
        self.auto_user_presence = enabled;
    }

    pub fn suppress_attestation(&mut self, suppress: bool) {
        self.suppress_attestation = suppress;
    }

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

    fn handle_bio_enrollment(&mut self, _payload: &[u8]) -> Result<Vec<u8>, u8> {
        Err(CTAP1_ERR_INVALID_COMMAND)
    }

    /// CTAP2 `authenticatorReset` (command 0x07).  Wipes credentials and
    /// PIN state after collecting user presence.  The standard 10-second
    /// "since power-up" window from the FIDO spec is intentionally not
    /// enforced; a software authenticator on a multi-user desktop already
    /// requires explicit user consent via the presence prompt.
    fn handle_reset(&mut self) -> Result<Vec<u8>, u8> {
        let _present = self.await_user_presence()?;
        self.clear_credentials()?;
        self.pin_state = PinState::new();
        self.save_persistent_pin_state();
        self.cred_mgmt_state = CredentialManagementState::new();
        self.pending_assertion = None;
        Ok(vec![CTAP2_OK])
    }

    fn extract_subcommand_and_pin_protocol_for_logging(payload: &[u8]) -> (Option<u8>, Option<u8>) {
        use std::io::Cursor;

        let mut sub_command = None;
        let mut pin_protocol = None;

        if payload.is_empty() {
            return (sub_command, pin_protocol);
        }

        if let Ok(Value::Map(entries)) = from_reader(Cursor::new(payload)) {
            for (key, value) in entries {
                if let Value::Integer(key_int) = key {
                    let key_val: i128 = key_int.into();
                    match key_val {
                        1 => {
                            if let Value::Integer(sub_int) = value {
                                let value: i128 = sub_int.into();
                                if (0..=u8::MAX as i128).contains(&value) {
                                    sub_command = Some(value as u8);
                                }
                            }
                        }
                        2 => {
                            if let Value::Integer(pin_int) = value {
                                let value: i128 = pin_int.into();
                                if (0..=u8::MAX as i128).contains(&value) {
                                    pin_protocol = Some(value as u8);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        (sub_command, pin_protocol)
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

        let mut mac =
            HmacSha256::new_from_slice(&keys.auth_key).map_err(|_| CTAP2_ERR_PROCESSING)?;
        mac.update(&request.salt_enc);
        let computed = mac.finalize().into_bytes();
        if computed[..16] != request.salt_auth[..] {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }

        let plaintext = decrypt_shared_secret(&keys.encryption_key, &request.salt_enc)?;
        if plaintext.len() != 32 && plaintext.len() != 64 {
            return Err(CTAP1_ERR_INVALID_PARAMETER);
        }

        let cred_random = if user_verified {
            cred_random_with_uv
        } else {
            cred_random_without_uv
        };

        let pending = PendingHmacSecret::new(keys, plaintext);
        let encrypted = pending.encrypt_output_for(cred_random)?;
        Ok((encrypted, pending))
    }

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

    fn handle_make_credential(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
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

        let pin_uv_auth_param = match cbor::map_get(&map, Value::Integer(Integer::from(8))) {
            Some(Value::Bytes(bytes)) => Some(bytes.clone()),
            Some(_) => return Err(CTAP2_ERR_INVALID_CBOR),
            None => None,
        };

        let pin_uv_auth_protocol = match cbor::map_get(&map, Value::Integer(Integer::from(9))) {
            Some(Value::Integer(int)) => Some(int.clone()),
            Some(_) => return Err(CTAP2_ERR_INVALID_CBOR),
            None => None,
        };

        if pin_uv_auth_param.is_some() != pin_uv_auth_protocol.is_some() {
            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
        }

        if uv_requested && pin_uv_auth_param.is_some() {
            return Err(CTAP2_ERR_INVALID_OPTION);
        }

        let mut uv_verified = false;

        if let (Some(pin_uv_auth_param), Some(protocol)) =
            (pin_uv_auth_param.as_ref(), pin_uv_auth_protocol)
        {
            let value: i128 = protocol.into();
            self.ensure_supported_pin_uv_protocol(value)?;
            if pin_uv_auth_param.len() != 16 && pin_uv_auth_param.len() != 32 {
                return Err(CTAP2_ERR_PIN_AUTH_INVALID);
            }

            let mut token = self
                .pin_state
                .pin_uv_auth_token()
                .ok_or(CTAP2_ERR_PIN_AUTH_INVALID)?;
            let mut mac = HmacSha256::new_from_slice(&token).map_err(|_| CTAP2_ERR_PROCESSING)?;
            mac.update(&client_hash);
            let computed = mac.finalize().into_bytes();
            uv_verified = match pin_uv_auth_param.len() {
                16 => computed[..16] == pin_uv_auth_param[..],
                32 => computed[..32] == pin_uv_auth_param[..],
                _ => false,
            };
            token.zeroize();
            if !uv_verified {
                return Err(CTAP2_ERR_PIN_AUTH_INVALID);
            }
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

    fn handle_get_assertion(&mut self, payload: &[u8]) -> Result<Vec<u8>, u8> {
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
                        if salt_auth.len() != 16 {
                            return Err(CTAP2_ERR_PIN_AUTH_INVALID);
                        }
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
                self.ensure_supported_pin_uv_protocol(protocol)?;
                if param.len() != 16 && param.len() != 32 {
                    return Err(CTAP2_ERR_PIN_AUTH_INVALID);
                }
                let mut token = self
                    .pin_state
                    .pin_uv_auth_token()
                    .ok_or(CTAP2_ERR_PIN_AUTH_INVALID)?;
                let mut mac =
                    HmacSha256::new_from_slice(&token).map_err(|_| CTAP2_ERR_PROCESSING)?;
                mac.update(&client_hash);
                let computed = mac.finalize().into_bytes();
                let uv_verified = match param.len() {
                    16 => computed[..16] == param[..],
                    32 => computed[..32] == param[..],
                    _ => false,
                };
                token.zeroize();
                if !uv_verified {
                    return Err(CTAP2_ERR_PIN_AUTH_INVALID);
                }
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

    fn handle_get_next_assertion(&mut self) -> Result<Vec<u8>, u8> {
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
            if let Some(encrypted) = hmac_state.encrypt_output_for(cred_random)? {
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

impl<'interrupt, C, const N: usize> App<'interrupt, N> for CtapApp<C>
where
    C: TrussedClient + FilesystemClient + CryptoClient,
{
    fn interrupt(&self) -> Option<&'interrupt InterruptFlag> {
        Some(self.interrupt_flag)
    }

    fn commands(&self) -> &'static [Command] {
        &[Command::Cbor]
    }

    fn call(
        &mut self,
        command: Command,
        request: &[u8],
        response: &mut heapless_bytes::Bytes<N>,
    ) -> Result<(), Error> {
        match command {
            Command::Cbor => {
                if request.is_empty() {
                    return Err(Error::InvalidLength);
                }
                let ctap_cmd = request[0];
                let payload = &request[1..];
                let result = match ctap_cmd {
                    CTAP_CMD_GET_INFO => self.handle_get_info(),
                    CTAP_CMD_MAKE_CREDENTIAL => self.handle_make_credential(payload),
                    CTAP_CMD_GET_ASSERTION => self.handle_get_assertion(payload),
                    CTAP_CMD_GET_NEXT_ASSERTION => self.handle_get_next_assertion(),
                    CTAP_CMD_CLIENT_PIN => self.handle_client_pin(payload),
                    CTAP_CMD_RESET => self.handle_reset(),
                    CTAP_CMD_CREDENTIAL_MANAGEMENT => self.handle_credential_management(payload),
                    CTAP_CMD_BIO_ENROLLMENT => self.handle_bio_enrollment(payload),
                    _ => Err(CTAP1_ERR_INVALID_COMMAND),
                };

                let (message, status) = match result {
                    Ok(bytes) => {
                        let status = bytes.first().copied().unwrap_or(CTAP2_OK);
                        (bytes, status)
                    }
                    Err(status) => (vec![status], status),
                };

                let (sub_command, pin_protocol) = match ctap_cmd {
                    CTAP_CMD_CLIENT_PIN | CTAP_CMD_BIO_ENROLLMENT => {
                        Self::extract_subcommand_and_pin_protocol_for_logging(payload)
                    }
                    _ => (None, None),
                };

                info!(
                    "CTAP2 cmd=0x{ctap_cmd:02x} status=0x{:02x} sub={} pinProtocol={} req_bcnt={} resp_bcnt={} resp_payload_len={}",
                    status,
                    HexOption(sub_command),
                    HexOption(pin_protocol),
                    request.len(),
                    message.len(),
                    message.len(),
                );

                response.clear();
                response
                    .extend_from_slice(&message)
                    .map_err(|_| Error::InvalidLength)
            }
            _ => Err(Error::InvalidCommand),
        }
    }
}
