//! The credential store's record decoders: arbitrary bytes as a credential,
//! PIN state, attestation, signature counter or large-blob array record, as
//! the credential-set manifest, or as an envelope before authentication.
//!
//! Invariants (see `pqkey_ctap::store::fuzzing::check`): no panic; a record
//! or manifest that decodes encodes again into one that decodes to an equal
//! value; and no envelope opens under a key it was not sealed with.

use pqkey_ctap::store::fuzzing::{Object, check};

/// Run one fuzz input: an index into `Object::ALL` (byte 0) and the bytes to
/// decode as that object.
pub fn run(data: &[u8]) {
    let [object, bytes @ ..] = data else {
        return;
    };
    let object = Object::ALL[usize::from(*object) % Object::ALL.len()];
    if let Err(message) = check(object, bytes) {
        panic!("{object:?}: {message}");
    }
}

#[cfg(test)]
mod tests {
    use pqkey_ctap::store::fuzzing::{Object, check, seeds};

    /// The seed corpus's records decode, its envelopes reach authentication,
    /// and every object has some.
    #[test]
    fn every_seed_passes_the_check() {
        let seeds = seeds();
        for object in Object::ALL {
            assert!(
                seeds.iter().any(|(seed, _)| *seed == object),
                "no {object:?} seed"
            );
        }
        for (object, bytes) in &seeds {
            assert_eq!(check(*object, bytes), Ok(true), "{object:?}");
            let index = Object::ALL.iter().position(|o| o == object).unwrap();
            super::run(&[&[index as u8][..], bytes].concat());
        }
    }
}
