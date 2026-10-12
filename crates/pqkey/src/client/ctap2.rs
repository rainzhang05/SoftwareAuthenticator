//! The CTAP2 requests a security key's management application sends: what
//! `pqkey pin`, `pqkey config`, `pqkey passkeys`, `pqkey reset` and
//! `pqkey status` do with the running key, through the same commands a
//! browser uses.

use std::sync::{Arc, atomic::AtomicBool};

use ciborium::value::{Integer, Value};
use pqkey_ctap::ClassicPinProtocol;
use pqkey_ctap::CryptoError;
use pqkey_ctap::platform::{PlatformKeyAgreement, authenticate, padded_pin, pin_hash};
use zeroize::Zeroizing;

use super::ctaphid::{CtapHid, HidError, MAX_PAYLOAD, ReportLink};

/// Message limit when getInfo omits maxMsgSize (CTAP 2.3 §8).
const DEFAULT_MAX_MSG_SIZE: u64 = 1024;

const GET_INFO: u8 = 0x04;
const CLIENT_PIN: u8 = 0x06;
const RESET: u8 = 0x07;
const CREDENTIAL_MANAGEMENT: u8 = 0x0A;
const AUTHENTICATOR_CONFIG: u8 = 0x0D;

/// The PIN/UV auth protocol `pqkey` uses: two, the one every CTAP 2.1 key
/// supports.
const PROTOCOL: ClassicPinProtocol = ClassicPinProtocol::V2;
/// The cm permission of a pinUvAuthToken (CTAP 2.3 §6.5.5.7).
const PERMISSION_CM: u8 = 0x04;
/// The acfg permission of a pinUvAuthToken (§6.11).
const PERMISSION_ACFG: u8 = 0x20;

/// CTAP2_ERR_NO_CREDENTIALS.
pub const NO_CREDENTIALS: u8 = 0x2E;

/// What went wrong.
#[derive(Debug)]
pub enum ClientError {
    /// Rejected locally, before sending any part of this command.
    RequestTooLarge { encoded_bytes: usize, limit: usize },
    /// The CTAPHID transport.
    Hid(HidError),
    /// The key answered with this CTAP status.
    Status(u8),
    /// The key's answer is not what CTAP defines.
    Malformed(&'static str),
    /// The key agreement or a decryption failed.
    Crypto(CryptoError),
}

impl From<HidError> for ClientError {
    fn from(err: HidError) -> Self {
        ClientError::Hid(err)
    }
}

impl From<CryptoError> for ClientError {
    fn from(err: CryptoError) -> Self {
        ClientError::Crypto(err)
    }
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::RequestTooLarge {
                encoded_bytes,
                limit,
            } => write!(
                f,
                "the encoded CTAP2 request is {encoded_bytes} bytes; the limit is {limit} bytes"
            ),
            ClientError::Hid(err) => err.fmt(f),
            ClientError::Status(status) => write!(f, "the key answered CTAP status {status:#04x}"),
            ClientError::Malformed(what) => write!(f, "the key's answer is malformed: {what}"),
            ClientError::Crypto(err) => write!(f, "{err}"),
        }
    }
}

/// What authenticatorGetInfo reports that `pqkey status` shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    pub versions: Vec<String>,
    /// Advertised maxMsgSize, or the 1,024-byte default when absent.
    pub max_msg_size: u64,
    /// The clientPin option: whether a PIN is set.
    pub pin_set: Option<bool>,
    /// The authnrCfg option: configuration is supported.
    pub authenticator_config: Option<bool>,
    /// The alwaysUv option: registration and present assertions require UV.
    pub always_uv: Option<bool>,
    /// The setMinPINLength option: the minimum can be raised.
    pub set_min_pin_length: Option<bool>,
    /// forcePINChange: a new PIN is required before issuing tokens.
    pub force_pin_change: Option<bool>,
    /// pinComplexityPolicy: ASCII letter and digit requirements are enabled.
    pub pin_complexity_policy: Option<bool>,
    /// minPINLength, in Unicode code points.
    pub min_pin_length: Option<u64>,
    /// maxRPIDsForSetMinPINLength.
    pub max_rp_ids_for_min_pin_length: Option<u64>,
    /// authenticatorConfigCommands.
    pub config_commands: Vec<u8>,
    /// remainingDiscoverableCredentials.
    pub remaining_discoverable: Option<u64>,
}

impl Default for Info {
    fn default() -> Self {
        Self {
            versions: Vec::new(),
            max_msg_size: DEFAULT_MAX_MSG_SIZE,
            pin_set: None,
            authenticator_config: None,
            always_uv: None,
            set_min_pin_length: None,
            force_pin_change: None,
            pin_complexity_policy: None,
            min_pin_length: None,
            max_rp_ids_for_min_pin_length: None,
            config_commands: Vec::new(),
            remaining_discoverable: None,
        }
    }
}

/// getPinRetries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinRetries {
    pub retries: u64,
    /// powerCycleState: the key refuses PIN checks until it restarts.
    pub power_cycle_needed: bool,
}

/// A discoverable credential, as credential management lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Passkey {
    pub rp_id: String,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub credential_id: Vec<u8>,
    /// The COSE algorithm of its public key.
    pub alg: Option<i64>,
    /// Payment metadata, or `None` when an older authenticator omits it.
    pub third_party_payment: Option<bool>,
}

/// A pinUvAuthToken.
pub struct Token(Zeroizing<Vec<u8>>);

impl std::fmt::Debug for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// The running key, through CTAPHID.
pub struct Authenticator<L> {
    hid: CtapHid<L>,
    /// Only a successfully parsed getInfo permits dependent requests.
    max_msg_size: Option<u64>,
}

fn int(value: i64) -> Value {
    Value::Integer(Integer::from(value))
}

fn text(value: &str) -> Value {
    Value::Text(value.into())
}

fn member(map: &Value, key: i64) -> Option<&Value> {
    match map {
        Value::Map(entries) => entries.iter().find(|(k, _)| *k == int(key)).map(|(_, v)| v),
        _ => None,
    }
}

fn text_member<'a>(map: &'a Value, key: &str) -> Option<&'a str> {
    match map {
        Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| *k == text(key))
            .and_then(|(_, v)| v.as_text()),
        _ => None,
    }
}

fn bytes_of(value: Option<&Value>) -> Result<&[u8], ClientError> {
    match value {
        Some(Value::Bytes(bytes)) => Ok(bytes),
        _ => Err(ClientError::Malformed("a byte string is missing")),
    }
}

fn encode(value: &Value) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(value, &mut encoded).expect("encode into memory");
    encoded
}

impl<L: ReportLink> Authenticator<L> {
    pub fn open(link: L) -> Result<Self, ClientError> {
        Ok(Self {
            hid: CtapHid::open(link)?,
            max_msg_size: None,
        })
    }

    /// [`open`](Self::open), waiting at most `patience` for a key that is
    /// busy with another client.
    pub fn open_within(link: L, patience: std::time::Duration) -> Result<Self, ClientError> {
        Ok(Self {
            hid: CtapHid::open_within(link, patience)?,
            max_msg_size: None,
        })
    }

    /// Cancel a request that waits for the user once `flag` is set, for
    /// example by a SIGINT handler.
    pub fn with_cancel_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.hid = self.hid.with_cancel_flag(flag);
        self
    }

    /// Send `command` with `parameters`, whose keys must be in canonical
    /// order, and decode the response of a successful one.
    fn call(
        &mut self,
        command: u8,
        parameters: Option<Value>,
        keepalive: &mut dyn FnMut(u8),
    ) -> Result<Value, ClientError> {
        let mut request = vec![command];
        if let Some(parameters) = &parameters {
            request.extend(encode(parameters));
        }
        self.call_encoded(&request, keepalive)
    }

    /// Send an already encoded request, preserving authenticated CBOR bytes.
    fn call_encoded(
        &mut self,
        request: &[u8],
        keepalive: &mut dyn FnMut(u8),
    ) -> Result<Value, ClientError> {
        if request != [GET_INFO] && self.max_msg_size.is_none() {
            self.info()?;
        }
        // Clamp before converting to usize, including on 32-bit platforms.
        let limit = usize::try_from(
            self.max_msg_size
                .unwrap_or(DEFAULT_MAX_MSG_SIZE)
                .min(MAX_PAYLOAD as u64),
        )
        .expect("HID capacity fits usize");
        if request.len() > limit {
            return Err(ClientError::RequestTooLarge {
                encoded_bytes: request.len(),
                limit,
            });
        }
        let response = self.hid.cbor(request, keepalive)?;
        match response.split_first() {
            Some((0, [])) => Ok(Value::Null),
            Some((0, body)) => {
                ciborium::de::from_reader(body).map_err(|_| ClientError::Malformed("invalid CBOR"))
            }
            Some((status, _)) => Err(ClientError::Status(*status)),
            None => Err(ClientError::Malformed("an empty response")),
        }
    }

    pub fn info(&mut self) -> Result<Info, ClientError> {
        // A failed refresh must not leave a stale, more permissive limit.
        self.max_msg_size = None;
        let info = self.call(GET_INFO, None, &mut |_| {})?;
        let Value::Map(entries) = &info else {
            return Err(ClientError::Malformed("getInfo is not a map"));
        };
        let mut limits = entries.iter().filter(|(key, _)| *key == int(0x05));
        let max_msg_size = match limits.next() {
            None => DEFAULT_MAX_MSG_SIZE,
            Some((_, value)) => value
                .as_integer()
                .and_then(|value| u64::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or(ClientError::Malformed(
                    "maxMsgSize is not a positive unsigned integer",
                ))?,
        };
        if limits.next().is_some() {
            return Err(ClientError::Malformed("duplicate maxMsgSize"));
        }
        self.max_msg_size = Some(max_msg_size);
        let versions = match member(&info, 1) {
            Some(Value::Array(versions)) => versions
                .iter()
                .filter_map(|version| version.as_text().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        };
        let option = |name| {
            member(&info, 4).and_then(|options| match options {
                Value::Map(entries) => entries
                    .iter()
                    .find(|(k, _)| *k == text(name))
                    .and_then(|(_, v)| v.as_bool()),
                _ => None,
            })
        };
        let number = |key| {
            member(&info, key)
                .and_then(Value::as_integer)
                .and_then(|count| u64::try_from(count).ok())
        };
        let config_commands = match member(&info, 0x1F) {
            Some(Value::Array(commands)) => commands
                .iter()
                .filter_map(|command| {
                    command
                        .as_integer()
                        .and_then(|value| u8::try_from(value).ok())
                })
                .collect(),
            _ => Vec::new(),
        };
        Ok(Info {
            versions,
            max_msg_size,
            pin_set: option("clientPin"),
            authenticator_config: option("authnrCfg"),
            always_uv: option("alwaysUv"),
            set_min_pin_length: option("setMinPINLength"),
            force_pin_change: member(&info, 0x0C).and_then(Value::as_bool),
            pin_complexity_policy: member(&info, 0x1B).and_then(Value::as_bool),
            min_pin_length: number(0x0D),
            max_rp_ids_for_min_pin_length: number(0x10),
            config_commands,
            remaining_discoverable: number(0x14),
        })
    }

    pub fn pin_retries(&mut self) -> Result<PinRetries, ClientError> {
        let protocol = int(PROTOCOL.identifier().into());
        let body = self.call(
            CLIENT_PIN,
            Some(Value::Map(vec![(int(1), protocol), (int(2), int(1))])),
            &mut |_| {},
        )?;
        let retries = member(&body, 3)
            .and_then(Value::as_integer)
            .and_then(|count| u64::try_from(count).ok())
            .ok_or(ClientError::Malformed("no pinRetries"))?;
        let power_cycle_needed = member(&body, 4).and_then(Value::as_bool).unwrap_or(false);
        Ok(PinRetries {
            retries,
            power_cycle_needed,
        })
    }

    /// getKeyAgreement, and a shared secret with the key's key agreement key,
    /// with the platform's COSE key for the next request.
    fn shared_secret(&mut self) -> Result<(PlatformKeyAgreement, Value), ClientError> {
        let protocol = int(PROTOCOL.identifier().into());
        let body = self.call(
            CLIENT_PIN,
            Some(Value::Map(vec![(int(1), protocol), (int(2), int(2))])),
            &mut |_| {},
        )?;
        let key = member(&body, 1).ok_or(ClientError::Malformed("no keyAgreement"))?;
        let coordinate = |label| -> Result<[u8; 32], ClientError> {
            bytes_of(member(key, label))?
                .try_into()
                .map_err(|_| ClientError::Malformed("a key agreement coordinate is not 32 bytes"))
        };
        let secret = PlatformKeyAgreement::generate_key()?;
        let shared =
            PlatformKeyAgreement::new(PROTOCOL, &coordinate(-2)?, &coordinate(-3)?, &secret)?;
        let (x, y) = shared.public_key();
        let cose = Value::Map(vec![
            (int(1), int(2)),
            (int(3), int(-25)),
            (int(-1), int(1)),
            (int(-2), Value::Bytes(x.to_vec())),
            (int(-3), Value::Bytes(y.to_vec())),
        ]);
        Ok((shared, cose))
    }

    fn iv() -> Result<[u8; 16], ClientError> {
        let mut iv = [0u8; 16];
        getrandom::fill(&mut iv).map_err(|_| ClientError::Crypto(CryptoError::Randomness))?;
        Ok(iv)
    }

    /// setPIN (CTAP 2.3 §6.5.5.5): `pin` is already NFC and validated.
    pub fn set_pin(&mut self, pin: &[u8]) -> Result<(), ClientError> {
        let (shared, key) = self.shared_secret()?;
        let padded = padded_pin(pin).ok_or(ClientError::Status(0x37))?;
        let new_pin_enc = shared.encrypt(&padded[..], Self::iv()?)?;
        let auth = shared.authenticate(&new_pin_enc);
        self.call(
            CLIENT_PIN,
            Some(Value::Map(vec![
                (int(1), int(PROTOCOL.identifier().into())),
                (int(2), int(3)),
                (int(3), key),
                (int(4), Value::Bytes(auth)),
                (int(5), Value::Bytes(new_pin_enc)),
            ])),
            &mut |_| {},
        )
        .map(drop)
    }

    /// changePIN (§6.5.5.6).
    pub fn change_pin(&mut self, current: &[u8], new: &[u8]) -> Result<(), ClientError> {
        let (shared, key) = self.shared_secret()?;
        let padded = padded_pin(new).ok_or(ClientError::Status(0x37))?;
        let new_pin_enc = shared.encrypt(&padded[..], Self::iv()?)?;
        let pin_hash_enc = shared.encrypt(&pin_hash(current)[..], Self::iv()?)?;
        let mut message = new_pin_enc.clone();
        message.extend_from_slice(&pin_hash_enc);
        let auth = shared.authenticate(&message);
        self.call(
            CLIENT_PIN,
            Some(Value::Map(vec![
                (int(1), int(PROTOCOL.identifier().into())),
                (int(2), int(4)),
                (int(3), key),
                (int(4), Value::Bytes(auth)),
                (int(5), Value::Bytes(new_pin_enc)),
                (int(6), Value::Bytes(pin_hash_enc)),
            ])),
            &mut |_| {},
        )
        .map(drop)
    }

    /// getPinUvAuthTokenUsingPinWithPermissions (§6.5.5.7.2) with the cm
    /// permission and no RP ID.
    pub fn management_token(&mut self, pin: &[u8]) -> Result<Token, ClientError> {
        self.permission_token(pin, PERMISSION_CM)
    }

    /// A token with the acfg permission and no RP ID (§6.11).
    pub fn config_token(&mut self, pin: &[u8]) -> Result<Token, ClientError> {
        self.permission_token(pin, PERMISSION_ACFG)
    }

    fn permission_token(&mut self, pin: &[u8], permission: u8) -> Result<Token, ClientError> {
        let (shared, key) = self.shared_secret()?;
        let pin_hash_enc = shared.encrypt(&pin_hash(pin)[..], Self::iv()?)?;
        let body = self.call(
            CLIENT_PIN,
            Some(Value::Map(vec![
                (int(1), int(PROTOCOL.identifier().into())),
                (int(2), int(9)),
                (int(3), key),
                (int(6), Value::Bytes(pin_hash_enc)),
                (int(9), int(permission.into())),
            ])),
            &mut |_| {},
        )?;
        let token = shared.decrypt(bytes_of(member(&body, 2))?)?;
        Ok(Token(token))
    }

    /// authenticatorConfig (§6.11). Encode the parameters once, then put the
    /// same bytes in both the authenticated message and the request.
    fn configuration(
        &mut self,
        token: Option<&Token>,
        subcommand: u8,
        parameters: Option<Value>,
    ) -> Result<(), ClientError> {
        let parameters = parameters.as_ref().map(encode);
        let fields = 1 + u8::from(parameters.is_some()) + 2 * u8::from(token.is_some());
        let mut request = vec![AUTHENTICATOR_CONFIG, 0xA0 + fields, 0x01, subcommand];
        if let Some(parameters) = &parameters {
            request.push(0x02);
            request.extend_from_slice(parameters);
        }
        if let Some(token) = token {
            let mut message = vec![0xFF; 32];
            message.extend([AUTHENTICATOR_CONFIG, subcommand]);
            if let Some(parameters) = &parameters {
                message.extend_from_slice(parameters);
            }
            request.push(0x03);
            request.extend(encode(&int(PROTOCOL.identifier().into())));
            request.push(0x04);
            request.extend(encode(&Value::Bytes(authenticate(
                PROTOCOL, &token.0, &message,
            ))));
        }
        self.call_encoded(&request, &mut |_| {}).map(drop)
    }

    /// toggleAlwaysUv (§6.11.2). The caller checks the current setting first.
    pub fn toggle_always_uv(&mut self, token: Option<&Token>) -> Result<(), ClientError> {
        self.configuration(token, 0x02, None)
    }

    /// setMinPINLength (§6.11.4). Omitted values leave their settings alone;
    /// an empty RP list also preserves the authorized relying parties.
    /// Complexity can only be enabled; false preserves the current policy.
    pub fn set_min_pin_length(
        &mut self,
        token: Option<&Token>,
        minimum: Option<u8>,
        rp_ids: Option<&[String]>,
        force_change: Option<bool>,
        complexity: Option<bool>,
    ) -> Result<(), ClientError> {
        let mut parameters = Vec::new();
        if let Some(minimum) = minimum {
            parameters.push((int(1), int(minimum.into())));
        }
        if let Some(rp_ids) = rp_ids {
            parameters.push((
                int(2),
                Value::Array(rp_ids.iter().map(|rp| text(rp)).collect()),
            ));
        }
        if let Some(force_change) = force_change {
            parameters.push((int(3), Value::Bool(force_change)));
        }
        if let Some(complexity) = complexity {
            parameters.push((int(4), Value::Bool(complexity)));
        }
        self.configuration(token, 0x03, Some(Value::Map(parameters)))
    }

    /// An authenticated authenticatorCredentialManagement request
    /// (§6.8): the MAC covers the subcommand, and the parameters for those
    /// that take some.
    fn management(
        &mut self,
        token: &Token,
        subcommand: u8,
        parameters: Option<Value>,
    ) -> Result<Value, ClientError> {
        let parameters = parameters.as_ref().map(encode);
        let mut message = vec![subcommand];
        if let Some(parameters) = &parameters {
            message.extend_from_slice(parameters);
        }
        let fields = 3 + u8::from(parameters.is_some());
        let mut request = vec![CREDENTIAL_MANAGEMENT, 0xA0 + fields, 0x01, subcommand];
        if let Some(parameters) = parameters {
            request.push(0x02);
            request.extend(parameters);
        }
        request.push(0x03);
        request.extend(encode(&int(PROTOCOL.identifier().into())));
        request.push(0x04);
        request.extend(encode(&Value::Bytes(authenticate(
            PROTOCOL, &token.0, &message,
        ))));
        self.call_encoded(&request, &mut |_| {})
    }

    /// A continuation subcommand, which carries nothing but itself.
    fn management_next(&mut self, subcommand: u8) -> Result<Value, ClientError> {
        self.call(
            CREDENTIAL_MANAGEMENT,
            Some(Value::Map(vec![(int(1), int(subcommand.into()))])),
            &mut |_| {},
        )
    }

    /// Every discoverable credential: enumerateRPs, then enumerateCredentials
    /// for each (§6.8.3, §6.8.4).
    pub fn passkeys(&mut self, token: &Token) -> Result<Vec<Passkey>, ClientError> {
        let first = match self.management(token, 0x02, None) {
            Err(ClientError::Status(NO_CREDENTIALS)) => return Ok(Vec::new()),
            other => other?,
        };
        let total = member(&first, 5)
            .and_then(Value::as_integer)
            .and_then(|count| u64::try_from(count).ok())
            .unwrap_or(1);
        let mut rps = vec![first];
        for _ in 1..total {
            rps.push(self.management_next(0x03)?);
        }
        let mut passkeys = Vec::new();
        for rp in rps {
            let rp_id = member(&rp, 3)
                .and_then(|entity| text_member(entity, "id"))
                .unwrap_or_default()
                .to_owned();
            let hash = bytes_of(member(&rp, 4))?.to_vec();
            let params = Value::Map(vec![(int(1), Value::Bytes(hash))]);
            let first = self.management(token, 0x04, Some(params))?;
            let total = member(&first, 9)
                .and_then(Value::as_integer)
                .and_then(|count| u64::try_from(count).ok())
                .unwrap_or(1);
            let mut credentials = vec![first];
            for _ in 1..total {
                credentials.push(self.management_next(0x05)?);
            }
            for credential in credentials {
                let user = member(&credential, 6).ok_or(ClientError::Malformed("no user"))?;
                let descriptor =
                    member(&credential, 7).ok_or(ClientError::Malformed("no credentialID"))?;
                passkeys.push(Passkey {
                    rp_id: rp_id.clone(),
                    user_id: match user {
                        Value::Map(entries) => entries
                            .iter()
                            .find(|(k, _)| *k == text("id"))
                            .and_then(|(_, v)| v.as_bytes().cloned())
                            .unwrap_or_default(),
                        _ => Vec::new(),
                    },
                    user_name: text_member(user, "name").map(str::to_owned),
                    user_display_name: text_member(user, "displayName").map(str::to_owned),
                    credential_id: match descriptor {
                        Value::Map(entries) => entries
                            .iter()
                            .find(|(k, _)| *k == text("id"))
                            .and_then(|(_, v)| v.as_bytes().cloned())
                            .ok_or(ClientError::Malformed("no credential ID"))?,
                        _ => return Err(ClientError::Malformed("no credential descriptor")),
                    },
                    alg: member(&credential, 8)
                        .and_then(|key| member(key, 3))
                        .and_then(Value::as_integer)
                        .and_then(|alg| i64::try_from(alg).ok()),
                    third_party_payment: member(&credential, 0x0C).and_then(Value::as_bool),
                });
            }
        }
        Ok(passkeys)
    }

    /// deleteCredential (§6.8.5).
    pub fn delete(&mut self, token: &Token, credential_id: &[u8]) -> Result<(), ClientError> {
        let descriptor = Value::Map(vec![
            (text("id"), Value::Bytes(credential_id.to_vec())),
            (text("type"), text("public-key")),
        ]);
        let params = Value::Map(vec![(int(2), descriptor)]);
        self.management(token, 0x06, Some(params)).map(drop)
    }

    /// authenticatorReset (§6.6), which the key confirms with its user;
    /// `keepalive` sees the key wait for them.
    pub fn reset(&mut self, keepalive: &mut dyn FnMut(u8)) -> Result<(), ClientError> {
        self.call(RESET, None, keepalive).map(drop)
    }
}

#[cfg(test)]
mod size_tests {
    use std::{cell::RefCell, collections::VecDeque, io, rc::Rc, time::Duration};

    use super::*;
    use crate::client::ctaphid::Report;

    #[derive(Default)]
    struct Traffic {
        reports: Vec<Report>,
        requests: Vec<Vec<u8>>,
    }

    /// A scripted key that records every report, including incomplete commands.
    struct RecordingLink {
        traffic: Rc<RefCell<Traffic>>,
        infos: VecDeque<Value>,
        management_replies: VecDeque<Value>,
        answers: VecDeque<Report>,
        pending: Vec<u8>,
        length: usize,
    }

    impl RecordingLink {
        fn answer(&mut self, report: &Report, payload: &[u8]) {
            for (sequence, chunk) in payload.chunks(57).enumerate() {
                assert_eq!(sequence, 0, "these scripted replies fit in one report");
                let mut answer = [0; 64];
                answer[..5].copy_from_slice(&report[..5]);
                answer[5..7].copy_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
                answer[7..7 + chunk.len()].copy_from_slice(chunk);
                self.answers.push_back(answer);
            }
        }
    }

    impl ReportLink for RecordingLink {
        fn send(&mut self, report: &Report) -> io::Result<()> {
            self.traffic.borrow_mut().reports.push(*report);
            if report[4] == 0x86 {
                let mut init = report[7..15].to_vec();
                init.extend([0, 0, 0, 1, 2, 0, 0, 0, 4]);
                self.answer(report, &init);
            } else {
                let start = if report[4] & 0x80 != 0 {
                    assert_eq!(report[4], 0x90);
                    self.pending.clear();
                    self.length = usize::from(u16::from_be_bytes([report[5], report[6]]));
                    7
                } else {
                    5
                };
                let count = (self.length - self.pending.len()).min(64 - start);
                self.pending
                    .extend_from_slice(&report[start..start + count]);
                if self.pending.len() == self.length {
                    self.traffic
                        .borrow_mut()
                        .requests
                        .push(self.pending.clone());
                    let mut response = vec![0];
                    if self.pending == [GET_INFO] {
                        response.extend(encode(&self.infos.pop_front().expect("scripted getInfo")));
                    } else if let Some(reply) = self.management_replies.pop_front() {
                        response.extend(encode(&reply));
                    }
                    let mut header = *report;
                    header[4] = 0x90;
                    self.answer(&header, &response);
                }
            }
            Ok(())
        }

        fn receive(&mut self, _: Duration) -> io::Result<Option<Report>> {
            Ok(self.answers.pop_front())
        }
    }

    fn info(limit: Option<u64>) -> Value {
        Value::Map(
            limit
                .into_iter()
                .map(|limit| (int(5), Value::from(limit)))
                .collect(),
        )
    }

    fn key(infos: Vec<Value>) -> (Authenticator<RecordingLink>, Rc<RefCell<Traffic>>) {
        key_with_management(infos, vec![])
    }

    fn key_with_management(
        infos: Vec<Value>,
        replies: Vec<Value>,
    ) -> (Authenticator<RecordingLink>, Rc<RefCell<Traffic>>) {
        let traffic = Rc::new(RefCell::new(Traffic::default()));
        let link = RecordingLink {
            traffic: traffic.clone(),
            infos: infos.into(),
            management_replies: replies.into(),
            answers: VecDeque::new(),
            pending: Vec::new(),
            length: 0,
        };
        (Authenticator::open(link).unwrap(), traffic)
    }

    #[test]
    fn payment_metadata_distinguishes_older_peers_from_both_boolean_values() {
        for payment in [None, Some(false), Some(true)] {
            let rp = Value::Map(vec![
                (int(3), Value::Map(vec![(text("id"), text("r"))])),
                (int(4), Value::Bytes(vec![0; 32])),
            ]);
            let mut credential = vec![
                (
                    int(6),
                    Value::Map(vec![(text("id"), Value::Bytes(vec![1]))]),
                ),
                (
                    int(7),
                    Value::Map(vec![(text("id"), Value::Bytes(vec![2]))]),
                ),
            ];
            credential.extend(payment.map(|value| (int(12), Value::Bool(value))));
            let (mut key, _) =
                key_with_management(vec![info(None)], vec![rp, Value::Map(credential)]);
            let passkeys = key.passkeys(&Token(Zeroizing::new(vec![1; 32]))).unwrap();
            assert_eq!(passkeys.len(), 1);
            assert_eq!(passkeys[0].third_party_payment, payment);
            assert_eq!(passkeys[0].credential_id, [2]);
        }
    }

    fn too_large(error: ClientError, bytes: usize, limit: usize) {
        assert!(
            matches!(error, ClientError::RequestTooLarge {
            encoded_bytes, limit: actual_limit
        } if encoded_bytes == bytes && actual_limit == limit),
            "{error:?}"
        );
        assert_eq!(
            error.to_string(),
            format!("the encoded CTAP2 request is {bytes} bytes; the limit is {limit} bytes")
        );
    }

    #[test]
    fn absent_limit_defaults_and_discovery_precedes_even_the_first_rejection() {
        let (mut key, traffic) = key(vec![info(None)]);
        too_large(
            key.call(RESET, Some(Value::Bytes(vec![0; 1021])), &mut |_| {})
                .unwrap_err(),
            1025,
            1024,
        );
        assert_eq!(traffic.borrow().requests, [vec![GET_INFO]]);
        assert_eq!(traffic.borrow().reports.len(), 2); // INIT and getInfo only.
        let before = traffic.borrow().reports.len();
        key.call(RESET, Some(Value::Bytes(vec![0; 1020])), &mut |_| {})
            .unwrap();
        assert!(traffic.borrow().reports.len() > before);
        assert_eq!(traffic.borrow().requests[1].len(), 1024);
        assert_eq!(key.max_msg_size, Some(1024));
        assert_eq!(Info::default().max_msg_size, 1024);
    }

    #[test]
    fn command_byte_counts_and_a_refresh_replaces_the_cached_limit() {
        let (mut key, traffic) = key(vec![info(Some(4)), info(Some(3)), info(None)]);
        key.toggle_always_uv(None).unwrap(); // No explicit info(), exactly four bytes.
        assert_eq!(
            traffic.borrow().requests[1],
            [AUTHENTICATOR_CONFIG, 0xA1, 1, 2]
        );
        assert_eq!(key.info().unwrap().max_msg_size, 3);
        let before = traffic.borrow().reports.len();
        too_large(key.toggle_always_uv(None).unwrap_err(), 4, 3);
        assert_eq!(traffic.borrow().reports.len(), before);
        assert_eq!(key.info().unwrap().max_msg_size, 1024);
        key.toggle_always_uv(None).unwrap();
    }

    #[test]
    fn large_unsigned_limits_are_retained_without_narrowing_and_bounded_by_hid() {
        for advertised in [7609, 7610, (1u64 << 32) + 1, u64::MAX] {
            let (mut key, traffic) = key(vec![info(Some(advertised))]);
            assert_eq!(key.info().unwrap().max_msg_size, advertised);
            key.call(RESET, Some(Value::Bytes(vec![0; 7605])), &mut |_| {})
                .unwrap();
            assert_eq!(traffic.borrow().requests[1].len(), 7609);
            let before = traffic.borrow().reports.len();
            too_large(
                key.call(RESET, Some(Value::Bytes(vec![0; 7606])), &mut |_| {})
                    .unwrap_err(),
                7610,
                7609,
            );
            assert_eq!(traffic.borrow().reports.len(), before);
        }
    }

    #[test]
    fn malformed_limits_never_allow_dependent_commands_or_a_stale_limit() {
        let mut malformed = vec![
            int(0),
            int(-1),
            text("1768"),
            Value::Bool(true),
            Value::Null,
            Value::Float(1768.0),
            Value::Bytes(vec![1]),
            Value::Array(vec![]),
            Value::Map(vec![]),
            Value::Tag(2, Box::new(Value::Bytes(vec![1; 9]))),
        ]
        .into_iter()
        .map(|value| Value::Map(vec![(int(5), value)]))
        .collect::<Vec<_>>();
        malformed.extend([
            Value::Map(vec![(int(5), int(1768)), (int(5), int(7609))]),
            Value::Null,
        ]);
        for invalid in malformed {
            let (mut key, traffic) =
                key(vec![info(Some(7609)), invalid.clone(), invalid, info(None)]);
            key.info().unwrap();
            assert!(matches!(key.info(), Err(ClientError::Malformed(_))));
            assert_eq!(key.max_msg_size, None);
            assert!(matches!(
                key.toggle_always_uv(None),
                Err(ClientError::Malformed(_))
            ));
            assert!(
                traffic
                    .borrow()
                    .requests
                    .iter()
                    .all(|request| request == &[GET_INFO])
            );
            assert_eq!(traffic.borrow().reports.len(), 4); // INIT plus three discoveries.
            key.toggle_always_uv(None).unwrap();
            assert_eq!(key.max_msg_size, Some(1024));
        }
    }

    #[test]
    fn complete_authenticated_configuration_is_checked_without_changing_its_mac_bytes() {
        let rps = vec!["x".repeat(253); 8];
        let token = Token(Zeroizing::new(vec![0x37; 32]));
        let (mut key, traffic) = key(vec![
            info(Some(1768)),
            info(Some(2050)),
            info(Some(2087)),
            info(Some(2086)),
        ]);
        too_large(
            key.set_min_pin_length(None, Some(6), Some(&rps), None, None)
                .unwrap_err(),
            2050,
            1768,
        );
        assert_eq!(traffic.borrow().reports.len(), 2);
        too_large(
            key.set_min_pin_length(Some(&token), Some(6), Some(&rps), None, None)
                .unwrap_err(),
            2087,
            1768,
        );
        assert_eq!(traffic.borrow().reports.len(), 2);
        key.info().unwrap();
        key.set_min_pin_length(None, Some(6), Some(&rps), None, None)
            .unwrap();
        let before = traffic.borrow().reports.len();
        too_large(
            key.set_min_pin_length(Some(&token), Some(6), Some(&rps), None, None)
                .unwrap_err(),
            2087,
            2050,
        );
        assert_eq!(traffic.borrow().reports.len(), before);
        key.info().unwrap();
        key.set_min_pin_length(Some(&token), Some(6), Some(&rps), None, None)
            .unwrap();
        let request = traffic.borrow().requests.last().unwrap().clone();
        assert_eq!(request.len(), 2087);
        let parameters = encode(&Value::Map(vec![
            (int(1), int(6)),
            (
                int(2),
                Value::Array(rps.iter().map(|rp| text(rp)).collect()),
            ),
        ]));
        let mut message = vec![0xFF; 32];
        message.extend([AUTHENTICATOR_CONFIG, 3]);
        message.extend_from_slice(&parameters);
        let mut expected = vec![AUTHENTICATOR_CONFIG, 0xA4, 1, 3, 2];
        expected.extend(parameters);
        expected.extend([3, 2, 4, 0x58, 0x20]);
        expected.extend(authenticate(PROTOCOL, &token.0, &message));
        assert_eq!(request, expected);
        key.info().unwrap();
        let before = traffic.borrow().reports.len();
        too_large(
            key.set_min_pin_length(Some(&token), Some(6), Some(&rps), None, None)
                .unwrap_err(),
            2087,
            2086,
        );
        assert_eq!(traffic.borrow().reports.len(), before);
        key.set_min_pin_length(
            Some(&token),
            Some(6),
            Some(&["small.example".into()]),
            None,
            None,
        )
        .unwrap();
    }

    #[test]
    fn complexity_configuration_covers_mac_and_complete_request_limit() {
        let token = Token(Zeroizing::new(vec![0x37; 32]));
        let (mut key, traffic) = key(vec![info(Some(45)), info(Some(44))]);
        key.set_min_pin_length(Some(&token), None, None, None, Some(true))
            .unwrap();
        let mut expected = vec![
            AUTHENTICATOR_CONFIG,
            0xa4,
            1,
            3,
            2,
            0xa1,
            4,
            0xf5,
            3,
            2,
            4,
            0x58,
            0x20,
        ];
        let mut message = vec![0xff; 32];
        message.extend([AUTHENTICATOR_CONFIG, 3, 0xa1, 4, 0xf5]);
        expected.extend(authenticate(PROTOCOL, &token.0, &message));
        assert_eq!(traffic.borrow().requests.last(), Some(&expected));
        key.info().unwrap();
        let before = traffic.borrow().reports.len();
        too_large(
            key.set_min_pin_length(Some(&token), None, None, None, Some(true))
                .unwrap_err(),
            45,
            44,
        );
        assert_eq!(traffic.borrow().reports.len(), before);
    }

    #[test]
    fn credential_management_checks_the_authenticated_encoding_and_continuations() {
        let token = Token(Zeroizing::new(vec![0x37; 32]));
        let (mut key, traffic) = key(vec![info(Some(41)), info(Some(40)), info(Some(3))]);
        key.management(&token, 2, None).unwrap(); // Exactly 41 bytes, including MAC/protocol.
        let mut expected = vec![CREDENTIAL_MANAGEMENT, 0xA3, 1, 2, 3, 2, 4, 0x58, 0x20];
        expected.extend(authenticate(PROTOCOL, &token.0, &[2]));
        assert_eq!(traffic.borrow().requests[1], expected);
        let before = traffic.borrow().reports.len();
        // Even though the credential ID fits, its descriptor and authentication do not.
        too_large(key.delete(&token, &[0xA5; 40]).unwrap_err(), 106, 41);
        assert_eq!(traffic.borrow().reports.len(), before);
        key.info().unwrap();
        let before = traffic.borrow().reports.len();
        too_large(key.management(&token, 2, None).unwrap_err(), 41, 40);
        assert_eq!(traffic.borrow().reports.len(), before);
        key.management_next(3).unwrap();
        key.info().unwrap();
        let before = traffic.borrow().reports.len();
        too_large(key.management_next(3).unwrap_err(), 4, 3);
        assert_eq!(traffic.borrow().reports.len(), before);
    }
}
