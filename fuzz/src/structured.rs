//! Structure-aware CTAP requests: up to four syntactically valid CBOR maps
//! under the parameter keys of makeCredential, getAssertion, clientPIN and
//! credentialManagement (plus the parameterless commands and unimplemented
//! command codes), sent to one engine, with presence answered as the input
//! chooses.
//!
//! Invariants: those of `ctap_request`, for every response.

use crate::{engine::Engine, requests};
use arbitrary::Unstructured;
use pqkey_ctap::store::MemoryStore;

/// Run one fuzz input.
pub fn run(data: &[u8]) {
    run_traced(data);
}

/// Run one fuzz input and return the command and status of every request.
pub fn run_traced(data: &[u8]) -> Vec<(u8, u8)> {
    let mut u = Unstructured::new(data);
    let Ok((seed, small_store)) = u.arbitrary::<(u64, bool)>() else {
        return Vec::new();
    };
    let store = if small_store {
        MemoryStore::new().with_max_credentials(1)
    } else {
        MemoryStore::new()
    };
    let mut engine = Engine::with_store(seed, store);
    for _ in 0..4 {
        let Ok(presence) = u.arbitrary::<u8>() else {
            break;
        };
        engine.presence().select(presence);
        let Ok(request) = requests::any_request(&mut u) else {
            break;
        };
        engine.call(&request);
        if u.is_empty() {
            break;
        }
    }
    engine.into_trace()
}
