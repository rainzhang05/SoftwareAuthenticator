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

use super::ctaphid::{CtapHid, HidError, ReportLink};

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
            ClientError::Hid(err) => err.fmt(f),
            ClientError::Status(status) => write!(f, "the key answered CTAP status {status:#04x}"),
            ClientError::Malformed(what) => write!(f, "the key's answer is malformed: {what}"),
            ClientError::Crypto(err) => write!(f, "{err}"),
        }
    }
}

/// What authenticatorGetInfo reports that `pqkey status` shows.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Info {
    pub versions: Vec<String>,
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
    /// minPINLength, in Unicode code points.
    pub min_pin_length: Option<u64>,
    /// maxRPIDsForSetMinPINLength.
    pub max_rp_ids_for_min_pin_length: Option<u64>,
    /// authenticatorConfigCommands.
    pub config_commands: Vec<u8>,
    /// remainingDiscoverableCredentials.
    pub remaining_discoverable: Option<u64>,
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
        })
    }

    /// [`open`](Self::open), waiting at most `patience` for a key that is
    /// busy with another client.
    pub fn open_within(link: L, patience: std::time::Duration) -> Result<Self, ClientError> {
        Ok(Self {
            hid: CtapHid::open_within(link, patience)?,
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
        let info = self.call(GET_INFO, None, &mut |_| {})?;
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
            pin_set: option("clientPin"),
            authenticator_config: option("authnrCfg"),
            always_uv: option("alwaysUv"),
            set_min_pin_length: option("setMinPINLength"),
            force_pin_change: member(&info, 0x0C).and_then(Value::as_bool),
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
    pub fn set_min_pin_length(
        &mut self,
        token: Option<&Token>,
        minimum: Option<u8>,
        rp_ids: Option<&[String]>,
        force_change: Option<bool>,
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
        let mut message = vec![subcommand];
        if let Some(parameters) = &parameters {
            message.extend(encode(parameters));
        }
        let mut entries = vec![(int(1), int(subcommand.into()))];
        if let Some(parameters) = parameters {
            entries.push((int(2), parameters));
        }
        entries.push((int(3), int(PROTOCOL.identifier().into())));
        entries.push((
            int(4),
            Value::Bytes(authenticate(PROTOCOL, &token.0, &message)),
        ));
        self.call(
            CREDENTIAL_MANAGEMENT,
            Some(Value::Map(entries)),
            &mut |_| {},
        )
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
