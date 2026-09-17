//! Parsing of request parameters shared by authenticatorMakeCredential and
//! authenticatorGetAssertion.

use super::cbor;
use crate::CoseAlg;

use ciborium::value::Value;

use crate::ctap::constants::*;

/// The only credential type there is, PublicKeyCredentialType "public-key"
/// ([WebAuthn] §5.8.2).
const PUBLIC_KEY: &str = "public-key";

/// A required member of a PublicKeyCredentialParameters or
/// PublicKeyCredentialDescriptor: CTAP2_ERR_INVALID_CBOR if missing ("If the
/// element is missing required members [...] return an error, for example
/// CTAP2_ERR_INVALID_CBOR"), and a present member of the wrong type is left
/// to the caller to reject with CTAP2_ERR_CBOR_UNEXPECTED_TYPE ("If the
/// values of any known members have the wrong type then return an error, for
/// example CTAP2_ERR_CBOR_UNEXPECTED_TYPE"), CTAP 2.3 §6.1.2 step 3.
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
/// supported one.  ES256 (-7) is always supported.  ESP256 (-9) is not
/// accepted as a synonym: WebAuthn Level 3 §5.4.1 calls it "NOT RECOMMENDED
/// in pubKeyCredParams", and a relying party that offers only -9 expects a
/// credential public key labelled -9, which the stored credential cannot
/// record.
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
/// PublicKeyCredentialDescriptor.  Every descriptor needs a text "type" and a
/// byte string "id"; descriptors of a type other than "public-key" cannot
/// denote a credential of this authenticator and are left out.
pub(super) fn credential_ids(list: &Value) -> Result<Vec<Vec<u8>>, u8> {
    let Value::Array(descriptors) = list else {
        return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
    };
    let mut ids = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let Value::Map(entries) = descriptor else {
            return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        };
        let credential_type = text_member(entries, "type")?;
        let Value::Bytes(id) = member(entries, "id")? else {
            return Err(CTAP2_ERR_CBOR_UNEXPECTED_TYPE);
        };
        if credential_type == PUBLIC_KEY {
            ids.push(id.clone());
        }
    }
    Ok(ids)
}
