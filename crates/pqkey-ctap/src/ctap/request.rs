//! Parsing of request parameters shared by authenticatorMakeCredential and
//! authenticatorGetAssertion.

use super::CtapApp;
use super::cbor;
use super::presence::{PresenceOperation, PresenceOutcome, PresenceRequest};
use crate::CoseAlg;

use ciborium::value::Value;

use crate::ctap::constants::*;

/// The only credential type there is, PublicKeyCredentialType "public-key"
/// (WebAuthn Level 3 §5.8.2).
const PUBLIC_KEY: &str = "public-key";

/// A required member of a PublicKeyCredentialParameters element of
/// pubKeyCredParams: "If the element is missing required members, including
/// members that are mandatory only for the specific type, then return an
/// error, for example CTAP2_ERR_INVALID_CBOR." (CTAP 2.3 §6.1.2 step 3.1.1)
/// A present member of the wrong type is left to the caller to reject with
/// CTAP2_ERR_CBOR_UNEXPECTED_TYPE ("If the values of any known members have
/// the wrong type then return an error, for example
/// CTAP2_ERR_CBOR_UNEXPECTED_TYPE.", step 3.1.2).  Other structures from the
/// host fall under §8 instead, see [`cbor::structure_member`].
fn member<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a Value, u8> {
    cbor::map_get(entries, Value::Text(name.into())).ok_or(CTAP2_ERR_INVALID_CBOR)
}

fn text_member<'a>(entries: &'a [(Value, Value)], name: &str) -> Result<&'a str, u8> {
    match member(entries, name)? {
        Value::Text(text) => Ok(text),
        _ => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    }
}

/// The algorithm chosen from pubKeyCredParams, CTAP 2.3 §6.1.2 step 3:
///
/// "For each element of pubKeyCredParams: If the element is missing required
/// members [...] return an error [...]. If the values of any known members
/// have the wrong type then return an error [...]. If the element specifies
/// an algorithm that is supported by the authenticator, and no algorithm has
/// yet been chosen by this loop, then let the algorithm specified by the
/// current element be the chosen algorithm.  If the loop completes and no
/// algorithm was chosen then return CTAP2_ERR_UNSUPPORTED_ALGORITHM."
///
/// An element specifies a supported algorithm when its type is "public-key"
/// and its alg is exactly one of [`CoseAlg`]'s identifiers.  The identifier is
/// compared as the full CBOR integer, so a value outside `i32` never aliases a
/// supported one.  ES256 (-7) is always supported.  The fully specified
/// ESP256 (-9), ESP384 (-51) and ESP512 (-52) are algorithms of their own
/// rather than synonyms of ES256, ES384 and ES512: a credential made with one
/// records its identifier, and its public key is labelled with it.  WebAuthn
/// Level 3 §5.4 calls them "NOT RECOMMENDED in pubKeyCredParams", so a
/// relying party that lists the other identifier first gets that.
pub(super) fn chosen_algorithm(pub_key_cred_params: &[Value]) -> Result<CoseAlg, u8> {
    let mut chosen = None;
    for element in pub_key_cred_params {
        let Value::Map(entries) = element else {
            return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        };
        let credential_type = text_member(entries, "type")?;
        let Value::Integer(alg) = member(entries, "alg")? else {
            return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        };
        let alg = i32::try_from(i128::from(*alg))
            .ok()
            .and_then(|alg| CoseAlg::try_from(alg).ok());
        if chosen.is_none() && credential_type == PUBLIC_KEY {
            chosen = alg;
        }
    }
    chosen.ok_or(CTAP2_ERR_UNSUPPORTED_ALGORITHM)
}

/// The credential IDs of an excludeList or allowList, an array of
/// PublicKeyCredentialDescriptor.  Descriptors of a type other than
/// "public-key" cannot denote a credential of this authenticator and are left
/// out.
pub(super) fn credential_ids(list: &Value) -> Result<Vec<Vec<u8>>, u8> {
    let Value::Array(descriptors) = list else {
        return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
    };
    let mut ids = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let Value::Map(entries) = descriptor else {
            return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        };
        if let Some(id) = public_key_credential_id(entries)? {
            ids.push(id.to_vec());
        }
    }
    Ok(ids)
}

/// The id of a PublicKeyCredentialDescriptor, `None` if its type is not
/// "public-key".  Both members are required, a text "type" and a byte string
/// "id", and a descriptor without them, or with members of other types, is
/// CTAP2_ERR_CBOR_UNEXPECTED_TYPE (CTAP 2.3 §8, see
/// [`cbor::structure_member`]).
pub(super) fn public_key_credential_id(descriptor: &[(Value, Value)]) -> Result<Option<&[u8]>, u8> {
    let credential_type = cbor::structure_text(descriptor, "type")?;
    let id = cbor::structure_bytes(descriptor, "id")?;
    Ok((credential_type == PUBLIC_KEY).then_some(id))
}

/// The length of clientDataHash, a SHA-256 hash of the client data.
const CLIENT_DATA_HASH_LENGTH: usize = 32;

/// The clientDataHash parameter of authenticatorMakeCredential and
/// authenticatorGetAssertion.  CTAP 2.3 only types it as a byte string, but
/// it is "Hash of the serialized client data collected by the host", and
/// WebAuthn Level 3 §6.3.2 and §6.3.3 step 1 ask the authenticator to "Check
/// if all the supplied parameters are syntactically well-formed and of the
/// correct length. If not, return an error code equivalent to
/// "UnknownError" and terminate the operation."  A byte string of any length
/// but 32 is CTAP1_ERR_INVALID_LENGTH, "Invalid message or item length" (CTAP
/// 2.3 §8.2), the status this authenticator also gives a user.id longer than
/// 64 bytes: the type is right, only the length is not, so
/// CTAP2_ERR_CBOR_UNEXPECTED_TYPE (§8) does not fit.
pub(super) fn client_data_hash(value: Option<&Value>) -> Result<Vec<u8>, u8> {
    match value {
        Some(Value::Bytes(bytes)) if bytes.len() == CLIENT_DATA_HASH_LENGTH => Ok(bytes.clone()),
        Some(Value::Bytes(_)) => Err(CTAP1_ERR_INVALID_LENGTH),
        Some(_) => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
        None => Err(CTAP2_ERR_MISSING_PARAMETER),
    }
}

/// The option keys of authenticatorMakeCredential and
/// authenticatorGetAssertion that CTAP defines, each `None` when absent.
/// "Treat any option keys that are not understood as absent." (CTAP 2.3
/// §6.1.2 step 5, §6.2.2 step 4)
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct RequestOptions {
    pub(super) rk: Option<bool>,
    pub(super) up: Option<bool>,
    pub(super) uv: Option<bool>,
}

/// Parse the options parameter.  "All option keys have boolean values." (CTAP
/// 2.3 §6.1, §6.2)
pub(super) fn options(value: Option<&Value>) -> Result<RequestOptions, u8> {
    let Some(value) = value else {
        return Ok(RequestOptions::default());
    };
    let Value::Map(entries) = value else {
        return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
    };
    let flag = |name: &str| match cbor::map_get(entries, Value::Text(name.into())) {
        None => Ok(None),
        Some(Value::Bool(flag)) => Ok(Some(*flag)),
        Some(_) => Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE),
    };
    Ok(RequestOptions {
        rk: flag("rk")?,
        up: flag("up")?,
        uv: flag("uv")?,
    })
}

/// Whether a pinUvAuthParam parameter is present and zero length: the
/// platform asking the user to select this authenticator (CTAP 2.3 §6.1.2
/// step 1, §6.2.2 step 1).
pub(super) fn is_zero_length(pin_uv_auth_param: Option<&Value>) -> bool {
    matches!(pin_uv_auth_param, Some(Value::Bytes(bytes)) if bytes.is_empty())
}

/// The longest user handle: "A user handle is an opaque byte sequence with a
/// maximum size of 64 bytes" (WebAuthn Level 3 §5.4.3).
pub(super) const MAX_USER_ID_LENGTH: usize = 64;

/// How many bytes of rp.name, user.name and user.displayName are kept: "When
/// storing a name member's value, the value MAY be truncated as described in
/// § 6.4.1 String Truncation using a size limit greater than or equal to 64
/// bytes." (WebAuthn Level 3 §5.4.1, PublicKeyCredentialEntity, and likewise
/// for displayName in §5.4.3)  Bounding them bounds every response and prompt
/// that shows them.
pub(super) const MAX_NAME_LENGTH: usize = 64;

/// `text` cut to at most `max` bytes at a character boundary.
pub(super) fn truncate_utf8(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

impl CtapApp<'_> {
    /// CTAP 2.3 §6.1.2 step 1 and §6.2.2 step 1, for a zero length
    /// pinUvAuthParam: "Request evidence of user interaction in an
    /// authenticator-specific way (e.g., flash the LED light). If the user
    /// declines permission, or the operation times out, then end the operation
    /// by returning CTAP2_ERR_OPERATION_DENIED. If evidence of user
    /// interaction is provided in this step then return either
    /// CTAP2_ERR_PIN_NOT_SET if PIN is not set or CTAP2_ERR_PIN_INVALID if PIN
    /// has been set."
    ///
    /// The user is asked to select this authenticator
    /// ([`PresenceOperation::Select`]), which is what the platform wants: "This
    /// is done for backwards compatibility with CTAP2.0 platforms in the case
    /// where multiple authenticators are attached to the platform and the
    /// platform wants to enforce pinUvAuthToken feature semantics, but the user
    /// has to select which authenticator to get the pinUvAuthToken from."
    pub(super) fn select_for_pin_uv_auth(&mut self) -> u8 {
        let timeout = self.presence_timeout;
        match self.ask_user(&PresenceRequest::new(PresenceOperation::Select, timeout)) {
            PresenceOutcome::Approved if self.pin_state.is_set() => CTAP2_ERR_PIN_INVALID,
            PresenceOutcome::Approved => CTAP2_ERR_PIN_NOT_SET,
            PresenceOutcome::Denied | PresenceOutcome::TimedOut => CTAP2_ERR_OPERATION_DENIED,
            PresenceOutcome::Cancelled => CTAP2_ERR_KEEPALIVE_CANCEL,
        }
    }
}
