//! Structure-aware CTAP2 requests: CBOR maps under the parameter keys each
//! command defines, with values of the right type most of the time, so the
//! fuzzer spends its time past the decoding step.

use arbitrary::{Result, Unstructured};
use ciborium::value::Value;
use pqkey_ctap::ctap::constants::*;

use crate::cbor::{arbitrary_bytes, arbitrary_value, bytes, encode, int, text, MAX_DEPTH};

/// Relying party identifiers: short, over the 32 bytes credential management
/// truncates to (with and without a scheme), multi-byte, and empty.
pub const RP_IDS: &[&str] = &[
    "example.com",
    "a.example",
    "https://a-rather-long-relying-party.example.com",
    "a-rather-long-relying-party-id.example.com",
    "\u{65e5}\u{672c}\u{8a9e}\u{306e}\u{30c9}\u{30e1}\u{30a4}\u{30f3}.example",
    "",
];

/// The COSE algorithms supported, and some that are not.
const ALGORITHMS: &[i64] = &[-7, -48, -49, -50, -8, -9, -257, -51, 0];

/// A parameter: of the expected shape most of the time, sometimes missing,
/// sometimes any CBOR value.
pub fn field(
    u: &mut Unstructured<'_>,
    typed: impl FnOnce(&mut Unstructured<'_>) -> Result<Value>,
) -> Result<Option<Value>> {
    Ok(match u.int_in_range(0u8..=15)? {
        0 | 1 => None,
        2 => Some(arbitrary_value(u, MAX_DEPTH)?),
        _ => Some(typed(u)?),
    })
}

/// A map from `(key, value)` pairs whose value is present, sometimes with a
/// duplicated key or an unknown extra key.  (Its entries are encoded in
/// canonical order whatever their order here; see [`encode`].)
pub fn map(u: &mut Unstructured<'_>, entries: Vec<(Value, Option<Value>)>) -> Result<Value> {
    let mut entries: Vec<(Value, Value)> = entries
        .into_iter()
        .filter_map(|(key, value)| value.map(|value| (key, value)))
        .collect();
    match u.int_in_range(0u8..=11)? {
        0 | 1 if !entries.is_empty() => {
            let index = u.choose_index(entries.len())?;
            let duplicate = (entries[index].0.clone(), arbitrary_value(u, 1)?);
            entries.push(duplicate);
        }
        2 => entries.push((arbitrary_value(u, 0)?, arbitrary_value(u, 1)?)),
        _ => {}
    }
    Ok(Value::Map(entries))
}

pub fn rp_id(u: &mut Unstructured<'_>) -> Result<String> {
    if u.ratio(1, 8)? {
        return u.arbitrary();
    }
    Ok((*u.choose(RP_IDS)?).to_owned())
}

pub fn client_data_hash(u: &mut Unstructured<'_>) -> Result<Value> {
    if u.ratio(1, 8)? {
        return Ok(Value::Bytes(arbitrary_bytes(u)?));
    }
    let mut hash = [0u8; 32];
    u.fill_buffer(&mut hash)?;
    Ok(bytes(&hash))
}

pub fn pin_uv_auth_protocol(u: &mut Unstructured<'_>) -> Result<Value> {
    Ok(match u.int_in_range(0u8..=4)? {
        0 | 1 => int(1),
        2 | 3 => int(2),
        _ => Value::Integer(crate::cbor::arbitrary_integer(u)?),
    })
}

fn options(u: &mut Unstructured<'_>) -> Result<Value> {
    let mut entries = Vec::new();
    for name in ["rk", "up", "uv"] {
        let value = field(u, |u| Ok(Value::Bool(u.arbitrary()?)))?;
        entries.push((text(name), value.filter(|_| u.ratio(2, 3).unwrap_or(false))));
    }
    map(u, entries)
}

fn credential_parameters(u: &mut Unstructured<'_>) -> Result<Value> {
    let len = u.int_in_range(0usize..=4)?;
    let mut params = Vec::with_capacity(len);
    for _ in 0..len {
        let credential_type = field(u, |u| {
            Ok(text(if u.ratio(7, 8)? {
                "public-key"
            } else {
                "private-key"
            }))
        })?;
        let alg = field(u, |u| Ok(int(*u.choose(ALGORITHMS)?)))?;
        params.push(map(
            u,
            vec![(text("type"), credential_type), (text("alg"), alg)],
        )?);
    }
    Ok(Value::Array(params))
}

/// A credential ID: of the length and shape this authenticator issues, or
/// anything.
pub fn credential_id(u: &mut Unstructured<'_>) -> Result<Vec<u8>> {
    if u.ratio(1, 4)? {
        return arbitrary_bytes(u);
    }
    let mut id = vec![0u8; 33];
    u.fill_buffer(&mut id)?;
    id[0] &= 1;
    Ok(id)
}

/// A PublicKeyCredentialDescriptor for `id`.
pub fn descriptor(u: &mut Unstructured<'_>, id: Vec<u8>) -> Result<Value> {
    let credential_type = field(u, |_| Ok(text("public-key")))?;
    let transports = if u.ratio(1, 8)? {
        Some(Value::Array(vec![text("usb")]))
    } else {
        None
    };
    map(
        u,
        vec![
            (text("type"), credential_type),
            (text("id"), Some(Value::Bytes(id))),
            (text("transports"), transports),
        ],
    )
}

fn descriptor_list(u: &mut Unstructured<'_>, known: &[Vec<u8>]) -> Result<Value> {
    let len = u.int_in_range(0usize..=4)?;
    let mut list = Vec::with_capacity(len);
    for _ in 0..len {
        let id = if !known.is_empty() && u.ratio(3, 4)? {
            u.choose(known)?.clone()
        } else {
            credential_id(u)?
        };
        list.push(descriptor(u, id)?);
    }
    Ok(Value::Array(list))
}

/// The platform's key agreement COSE key, well formed or not.
pub fn cose_key(u: &mut Unstructured<'_>) -> Result<Value> {
    let coordinate = |u: &mut Unstructured<'_>| {
        let mut value = [0u8; 32];
        u.fill_buffer(&mut value)?;
        Ok(bytes(&value))
    };
    let entries = vec![
        (int(1), field(u, |_| Ok(int(2)))?),
        (int(3), field(u, |_| Ok(int(-25)))?),
        (int(-1), field(u, |_| Ok(int(1)))?),
        (int(-2), field(u, coordinate)?),
        (int(-3), field(u, coordinate)?),
    ];
    map(u, entries)
}

/// The parts of an authenticatorMakeCredential request the stateful target
/// fills in itself.
#[derive(Default)]
pub struct Overrides {
    pub client_data_hash: Option<Value>,
    pub rp_id: Option<String>,
    pub pin_uv_auth_param: Option<Option<Value>>,
    pub pin_uv_auth_protocol: Option<Option<Value>>,
    pub known_credentials: Vec<Vec<u8>>,
    pub hmac_secret: Option<Value>,
    /// The options map, instead of a generated one.
    pub options: Option<Value>,
    /// Leave the allowList out.
    pub no_allow_list: bool,
    /// pubKeyCredParams, instead of generated ones.
    pub credential_parameters: Option<Value>,
}

/// authenticatorMakeCredential (CTAP 2.3 §6.1), command byte included.
pub fn make_credential(u: &mut Unstructured<'_>, overrides: Overrides) -> Result<Vec<u8>> {
    let hash = match overrides.client_data_hash {
        Some(hash) => Some(hash),
        None => field(u, client_data_hash)?,
    };
    let rp = match overrides.rp_id {
        Some(id) => Some(Value::Map(vec![(text("id"), text(&id))])),
        None => field(u, |u| {
            let id = field(u, |u| Ok(text(&rp_id(u)?)))?;
            let name = if u.ratio(1, 4)? {
                Some(Value::Text(u.arbitrary()?))
            } else {
                None
            };
            map(u, vec![(text("id"), id), (text("name"), name)])
        })?,
    };
    let user = field(u, |u| {
        let id = field(u, |u| {
            let len = u.int_in_range(0usize..=66)?;
            let mut id = vec![0u8; len];
            u.fill_buffer(&mut id)?;
            Ok(Value::Bytes(id))
        })?;
        let optional_text = |u: &mut Unstructured<'_>| -> Result<Option<Value>> {
            Ok(if u.ratio(1, 2)? {
                field(u, |u| Ok(Value::Text(u.arbitrary()?)))?
            } else {
                None
            })
        };
        let name = optional_text(u)?;
        let display_name = optional_text(u)?;
        map(
            u,
            vec![
                (text("id"), id),
                (text("name"), name),
                (text("displayName"), display_name),
            ],
        )
    })?;
    let params = match overrides.credential_parameters {
        Some(params) => Some(params),
        None => field(u, credential_parameters)?,
    };
    let known = overrides.known_credentials;
    let exclude_list = optional(u, |u| descriptor_list(u, &known))?;
    let extensions = optional(u, |u| {
        let hmac_secret = field(u, |u| Ok(Value::Bool(u.arbitrary()?)))?;
        let cred_protect = field(u, |u| Ok(int(u.int_in_range(0..=4)?)))?;
        map(
            u,
            vec![
                (text("hmac-secret"), hmac_secret),
                (text("credProtect"), cred_protect),
            ],
        )
    })?;
    let options = match overrides.options {
        Some(options) => Some(options),
        None => optional(u, options)?,
    };
    let (param, protocol) = pin_uv_auth(
        u,
        overrides.pin_uv_auth_param,
        overrides.pin_uv_auth_protocol,
    )?;
    let enterprise = if u.ratio(1, 32)? { Some(int(1)) } else { None };
    let formats = optional(u, |u| {
        Ok(Value::Array(if u.ratio(1, 2)? {
            vec![text("none")]
        } else {
            vec![text("packed"), arbitrary_value(u, 0)?]
        }))
    })?;
    let request = map(
        u,
        vec![
            (int(1), hash),
            (int(2), rp),
            (int(3), user),
            (int(4), params),
            (int(5), exclude_list),
            (int(6), extensions),
            (int(7), options),
            (int(8), param),
            (int(9), protocol),
            (int(10), enterprise),
            (int(11), formats),
        ],
    )?;
    Ok(command(CTAP_CMD_MAKE_CREDENTIAL, &request))
}

/// authenticatorGetAssertion (CTAP 2.3 §6.2), command byte included.
pub fn get_assertion(u: &mut Unstructured<'_>, overrides: Overrides) -> Result<Vec<u8>> {
    let rp = match overrides.rp_id {
        Some(id) => Some(text(&id)),
        None => field(u, |u| Ok(text(&rp_id(u)?)))?,
    };
    let hash = match overrides.client_data_hash {
        Some(hash) => Some(hash),
        None => field(u, client_data_hash)?,
    };
    let known = overrides.known_credentials;
    let allow_list = if overrides.no_allow_list {
        None
    } else {
        optional(u, |u| descriptor_list(u, &known))?
    };
    let extensions = match overrides.hmac_secret {
        Some(hmac_secret) => Some(Value::Map(vec![(text("hmac-secret"), hmac_secret)])),
        None => optional(u, |u| {
            let hmac_secret = field(u, |u| {
                let salt_enc = field(u, |u| Ok(Value::Bytes(arbitrary_bytes(u)?)))?;
                let salt_auth = field(u, |u| Ok(Value::Bytes(arbitrary_bytes(u)?)))?;
                let protocol = optional(u, pin_uv_auth_protocol)?;
                let key = field(u, cose_key)?;
                map(
                    u,
                    vec![
                        (int(1), key),
                        (int(2), salt_enc),
                        (int(3), salt_auth),
                        (int(4), protocol),
                    ],
                )
            })?;
            map(u, vec![(text("hmac-secret"), hmac_secret)])
        })?,
    };
    let options = match overrides.options {
        Some(options) => Some(options),
        None => optional(u, options)?,
    };
    let (param, protocol) = pin_uv_auth(
        u,
        overrides.pin_uv_auth_param,
        overrides.pin_uv_auth_protocol,
    )?;
    let request = map(
        u,
        vec![
            (int(1), rp),
            (int(2), hash),
            (int(3), allow_list),
            (int(4), extensions),
            (int(5), options),
            (int(6), param),
            (int(7), protocol),
        ],
    )?;
    Ok(command(CTAP_CMD_GET_ASSERTION, &request))
}

/// authenticatorClientPIN (CTAP 2.3 §6.5.5), command byte included.
pub fn client_pin(u: &mut Unstructured<'_>) -> Result<Vec<u8>> {
    let protocol = field(u, pin_uv_auth_protocol)?;
    let subcommand = field(u, |u| Ok(int(u.int_in_range(0..=11)?)))?;
    let key_agreement = optional(u, cose_key)?;
    let param = optional(u, |u| Ok(Value::Bytes(arbitrary_bytes(u)?)))?;
    let new_pin_enc = optional(u, |u| Ok(Value::Bytes(arbitrary_bytes(u)?)))?;
    let pin_hash_enc = optional(u, |u| Ok(Value::Bytes(arbitrary_bytes(u)?)))?;
    let permissions = optional(u, |u| {
        Ok(if u.ratio(3, 4)? {
            int(u.int_in_range(0..=0x7F)?)
        } else {
            Value::Integer(crate::cbor::arbitrary_integer(u)?)
        })
    })?;
    let rp = optional(u, |u| Ok(text(&rp_id(u)?)))?;
    let request = map(
        u,
        vec![
            (int(1), protocol),
            (int(2), subcommand),
            (int(3), key_agreement),
            (int(4), param),
            (int(5), new_pin_enc),
            (int(6), pin_hash_enc),
            (int(9), permissions),
            (int(10), rp),
        ],
    )?;
    Ok(command(CTAP_CMD_CLIENT_PIN, &request))
}

/// subCommandParams of authenticatorCredentialManagement (CTAP 2.3 §6.8).
pub fn credential_management_params(u: &mut Unstructured<'_>, known: &[Vec<u8>]) -> Result<Value> {
    let rp_id_hash = optional(u, |u| {
        if u.ratio(3, 4)? {
            let id = rp_id(u)?;
            Ok(bytes(&sha2_256(id.as_bytes())))
        } else {
            Ok(Value::Bytes(arbitrary_bytes(u)?))
        }
    })?;
    let credential = optional(u, |u| {
        let id = if !known.is_empty() && u.ratio(3, 4)? {
            u.choose(known)?.clone()
        } else {
            credential_id(u)?
        };
        descriptor(u, id)
    })?;
    let user = optional(u, |u| {
        let id = field(u, |u| Ok(Value::Bytes(arbitrary_bytes(u)?)))?;
        let name = optional(u, |u| Ok(Value::Text(u.arbitrary()?)))?;
        let display_name = optional(u, |u| Ok(Value::Text(u.arbitrary()?)))?;
        map(
            u,
            vec![
                (text("id"), id),
                (text("name"), name),
                (text("displayName"), display_name),
            ],
        )
    })?;
    map(
        u,
        vec![(int(1), rp_id_hash), (int(2), credential), (int(3), user)],
    )
}

/// authenticatorCredentialManagement (CTAP 2.3 §6.8), command byte included.
pub fn credential_management(u: &mut Unstructured<'_>) -> Result<Vec<u8>> {
    let subcommand = field(u, |u| Ok(int(u.int_in_range(0..=8)?)))?;
    let params = optional(u, |u| credential_management_params(u, &[]))?;
    let protocol = optional(u, pin_uv_auth_protocol)?;
    let param = optional(u, |u| Ok(Value::Bytes(arbitrary_bytes(u)?)))?;
    let request = map(
        u,
        vec![
            (int(1), subcommand),
            (int(2), params),
            (int(3), protocol),
            (int(4), param),
        ],
    )?;
    Ok(command(CTAP_CMD_CREDENTIAL_MANAGEMENT, &request))
}

/// Any CTAP2 request, structure-aware.
pub fn any_request(u: &mut Unstructured<'_>) -> Result<Vec<u8>> {
    Ok(match u.int_in_range(0u8..=10)? {
        0 | 1 => make_credential(u, Overrides::default())?,
        2 | 3 => get_assertion(u, Overrides::default())?,
        4 | 5 => client_pin(u)?,
        6 | 7 => credential_management(u)?,
        8 => vec![*u.choose(&[
            CTAP_CMD_GET_INFO,
            CTAP_CMD_RESET,
            CTAP_CMD_GET_NEXT_ASSERTION,
            CTAP_CMD_SELECTION,
        ])?],
        9 => {
            // A parameterless command with parameters, or a command code
            // that is not implemented, with any CBOR value.
            let code = *u.choose(&[
                CTAP_CMD_GET_INFO,
                CTAP_CMD_RESET,
                CTAP_CMD_GET_NEXT_ASSERTION,
                CTAP_CMD_BIO_ENROLLMENT,
                CTAP_CMD_BIO_ENROLLMENT_PROTOTYPE,
                CTAP_CMD_SELECTION,
                0x41,
                0xFF,
            ])?;
            command(code, &arbitrary_value(u, MAX_DEPTH)?)
        }
        _ => {
            let code = *u.choose(&[
                CTAP_CMD_MAKE_CREDENTIAL,
                CTAP_CMD_GET_ASSERTION,
                CTAP_CMD_CLIENT_PIN,
                CTAP_CMD_CREDENTIAL_MANAGEMENT,
            ])?;
            command(code, &arbitrary_value(u, MAX_DEPTH)?)
        }
    })
}

/// The command byte followed by the encoded parameters.
pub fn command(code: u8, parameters: &Value) -> Vec<u8> {
    let mut request = vec![code];
    request.extend(encode(parameters));
    request
}

/// Present half of the time.
pub fn optional(
    u: &mut Unstructured<'_>,
    generate: impl FnOnce(&mut Unstructured<'_>) -> Result<Value>,
) -> Result<Option<Value>> {
    if u.ratio(1, 2)? {
        Ok(Some(generate(u)?))
    } else {
        Ok(None)
    }
}

type AuthOverride = Option<Option<Value>>;

fn pin_uv_auth(
    u: &mut Unstructured<'_>,
    param: AuthOverride,
    protocol: AuthOverride,
) -> Result<(Option<Value>, Option<Value>)> {
    let param = match param {
        Some(param) => param,
        None => optional(u, |u| Ok(Value::Bytes(arbitrary_bytes(u)?)))?,
    };
    let protocol = match protocol {
        Some(protocol) => protocol,
        None => optional(u, pin_uv_auth_protocol)?,
    };
    Ok((param, protocol))
}

fn sha2_256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}
