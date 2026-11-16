//! Repair of a damaged PIN state and large-blob array, the last step of
//! [`FileStore::repair`].
//!
//! Repair touches either file only where the inspection names it, which it
//! does only for a file that fails authentication or decoding: an intact
//! PIN state, a PIN blocked by wrong guesses included, an intact array, and
//! a file the key cannot read are left as they are.  By this step a damaged
//! one has its name in the quarantine, like every file repair replaces or
//! removes.
//!
//! * The array is removed: a missing one reads as the initial array, which
//!   the key serves in place of a damaged one too.
//! * The PIN state is replaced, by a rename, with one that has no PIN and
//!   always-UV on, and every other setting at its default.  A missing one
//!   reads as no PIN with always-UV off, under which the key registers and
//!   signs in without any PIN, so a crash never leaves it missing.  Until a
//!   new PIN is set, the key then refuses registrations and sign-ins; after
//!   that always-UV stays on, as CTAP defines it, keeping U2F off, until it
//!   is turned off.  Like any PIN state, the new one also marks that
//!   something depends on the credential key (`seal_credential_id`).

use super::*;

/// The files outside the credential set that repair replaces where the
/// inspection names them.
const REPLACED: [&str; 2] = [PIN_STATE_FILE, LARGE_BLOBS_FILE];

/// The damage to the PIN state and the large-blob array, taken out of the
/// inspection's `damage`, which keeps the rest.
pub(super) fn take(damage: &mut Vec<Damage>) -> Vec<Damage> {
    let (replaced, rest) = std::mem::take(damage)
        .into_iter()
        .partition(|damage| REPLACED.contains(&damage.file.as_str()));
    *damage = rest;
    replaced
}

impl RepairPlan {
    /// This plan, which also replaces the files of `damage`, the PIN state,
    /// the large-blob array or both: named first, as the inspection names
    /// them, and moved into the quarantine.
    pub(super) fn replacing(mut self, damage: Vec<Damage>) -> Self {
        self.moved
            .extend(damage.iter().map(|damage| damage.file.clone()));
        self.moved.sort();
        self.damage.splice(0..0, damage);
        self
    }
}

impl<K: KeySource> FileStore<K> {
    /// Remove a damaged large-blob array and write a damaged PIN state
    /// again, as `plan` says.  The PIN state's directory flush covers the
    /// removal too.  A failed flush after the rename, or after the removal
    /// alone, is unconfirmed durability, not a failed repair.
    pub(super) fn replace_pin_state_and_large_blobs(
        &self,
        keys: &CredentialKeys,
        plan: &RepairPlan,
    ) -> Result<CommitDurability, StoreError> {
        let planned = |file| plan.moved.iter().any(|moved| moved == file);
        let removed = planned(LARGE_BLOBS_FILE)
            && fsio::remove_file_if_present(&self.root.join(LARGE_BLOBS_FILE))?;
        if planned(PIN_STATE_FILE) {
            let mut state = PinStateRecord::default();
            state.always_uv = true;
            return self.write_pin_state(keys, &state);
        }
        if removed && let Err(err) = fsio::sync_dir_strict(&self.root) {
            log::warn!(
                "credential store: repaired with unconfirmed durability of the large-blob array's \
                 removal: {err}"
            );
            return Ok(CommitDurability::Unconfirmed);
        }
        Ok(CommitDurability::Flushed)
    }
}

#[cfg(test)]
#[path = "repair_pin_state_tests.rs"]
mod tests;
