//! Explicit repair of a damaged credential set and signature counter.
//!
//! [`FileStore::plan_repair`] finds what to do without changing anything,
//! and [`FileStore::repair`] does it.  `pqkey repair` plans with the key
//! stopped, then plans again and repairs holding the state lock; nothing
//! else repairs a store, and no operation rebuilds membership by itself.
//!
//! Every file of the store that repair replaces or removes, a damaged
//! record, metadata file or signature counter, the replaced manifest, a
//! failed upgrade's prepared manifest, a record the new list does not name,
//! or a record whose counter it raises, first gets a name in a new
//! quarantine directory, `damaged/<UTC time>/`, at its path relative to the
//! state directory: a hard link for anything but a directory, which keeps it
//! in place until whatever replaces or removes it, and a rename for a
//! directory, which cannot be linked.  So a crash leaves every file of the
//! store in its place, in `credential-set/` after a legacy store's rename,
//! or in the quarantine, as [`FileStore::repair`] says.  Membership is
//! published as every commit publishes it, and cleanup after the
//! publication then removes the records' old names, as it removes any file
//! membership no longer names.  A counter whose count is lost is written
//! again above every count the key returned on it, under the conditions
//! [`FileStore::repair`] states.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

/// The largest count a counter holds, `u32::MAX`, read as a time in seconds
/// since 1970: 2106-02-07T06:28:15Z.  The count rule leaves out a time at or
/// past it, the clock's or a file's, which no count can exceed.
const LARGEST_COUNT: u64 = u32::MAX as u64;

/// The directory of the state directory that holds the quarantines: outside
/// both record directories, which cleanup scans, and `credentials`.
const QUARANTINE_DIR: &str = "damaged";

/// How many quarantine names one second has: a repair takes longer.
const QUARANTINE_ATTEMPTS: usize = 100;

/// Why a repair refuses the plan it was given.
const CHANGED: &str = "it changed after its repair was planned";

/// What [`FileStore::repair`] does to a damaged credential set, as
/// [`FileStore::plan_repair`] finds it without changing anything.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RepairPlan {
    /// Every damaged file and directory: what [`FileStore::inspect`]
    /// reports, first, then what damaged membership metadata hid from it:
    /// members whose records are missing or fail authentication or
    /// decoding, or, for a rebuild, the manifest and the records that fail
    /// authentication or decoding.
    pub damage: Vec<Damage>,
    /// How the list of the store's credentials, its membership, is repaired.
    pub membership: Membership,
    /// The accounts the repaired list holds more than one passkey of, by
    /// site and then user handle.  A rebuild keeps the records that
    /// authenticate, so a passkey that was deleted or replaced, or whose
    /// registration failed, can come back if its record was left behind:
    /// alone, or beside another passkey of its account, which is then named
    /// here.
    pub shared: Vec<Account>,
    /// How many passkeys, discoverable credentials, the repaired list holds.
    pub passkeys: usize,
    /// How many other credentials it holds: non-discoverable credentials
    /// that the store keeps as records rather than sealed into their IDs.
    pub others: usize,
    /// The store's credential limit.  The repaired list can hold more: a
    /// rebuild keeps the records that authenticate whatever their number.
    /// While the store holds this many or more, it refuses to add a
    /// credential.
    pub max_credentials: usize,
    /// Whether the format marker, `credential-format`, is written: because
    /// it is damaged, or missing although the store is in the managed
    /// layout, or because a legacy store moves to that layout.
    pub marker: bool,
    /// Whether the shared signature counter, `signature-counter`, is written
    /// again because it is damaged, above every count the key returned on
    /// it, under the conditions [`FileStore::repair`] states.
    pub counter: bool,
    /// The records whose counters are raised the same way, at their paths
    /// relative to the state directory, in order: copies of credentials that
    /// a rebuild keeps while another copy of their record, in the other
    /// record directory, is damaged, and so can have counted higher.
    pub raised: Vec<String>,
    /// Every file and directory moved into the quarantine, at its path
    /// relative to the state directory, in order.
    pub moved: Vec<String>,
    /// The highest counter planning read: of the records it read, and of
    /// the shared counter if it is not damaged.
    highest: u32,
    publication: Publication,
}

/// How [`FileStore::repair`] repairs the list of a store's credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Membership {
    /// The manifest authenticates, and is kept without the members whose
    /// records are missing or fail authentication or decoding.
    Kept,
    /// The manifest, `credential-set/active`, is missing or cannot be used,
    /// and a new one is built from the records in `credential-set/` that
    /// authenticate under the store's key.
    Rebuilt,
    /// A legacy store, which has no list, gets one of its records that
    /// authenticate: it moves to the managed layout, as at its first passkey
    /// registration.
    Listed,
    /// The missing directory of the layout is created again, empty:
    /// `credential-set`, with an empty list, or a legacy store's
    /// `credentials`.
    Created(String),
    /// Nothing but the signature counter is damaged: the list, or a legacy
    /// store's directory of records, stays as it is.
    Intact,
}

/// An account the repaired list holds more than one passkey of: passkeys
/// with the same RP ID and user handle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Account {
    /// The site: the RP ID.
    pub rp_id: String,
    /// The user's name, if the site gave one, as the first of the records
    /// in name order says it.
    pub user_name: Option<String>,
    /// The user's display name, if the site gave one, as that record says it.
    pub user_display_name: Option<String>,
    /// How many passkeys of the account the repaired list holds.
    pub passkeys: usize,
}

/// What [`FileStore::repair`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Repaired {
    /// The new directory the moved files are in, if any were moved:
    /// `damaged/<UTC time>` in the state directory, with a number after it
    /// if a repair in the same second took that name.
    pub quarantine: Option<PathBuf>,
    /// Whether the repair is flushed to storage, or only visible:
    /// [`CommitDurability::Unconfirmed`] after a directory flush failed,
    /// when a power failure can undo it.
    pub durability: CommitDurability,
    /// Whether cleanup after the new list is pending, because it failed or
    /// waits for a flush that failed: then records the list does not name
    /// can still be in place, as well as in the quarantine.  A later commit
    /// whose flushes succeed retries it.
    pub cleanup_pending: bool,
}

/// How the repaired list is published.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Publication {
    /// The list stays: only the marker is written again.
    Nothing,
    /// This manifest, as a managed store's commits publish it.
    Manifest(Manifest),
    /// This manifest, as a legacy store's first commit publishes it.
    Migration(Manifest),
    /// `credential-set`, with an empty manifest.
    Namespace,
    /// A legacy store's empty `credentials`.
    LegacyDirectory,
}

/// What a record that authenticates shows of its credential: what the plan
/// reports, and nothing secret.  The record itself is dropped, and wiped, at
/// once.
struct Kept {
    name: String,
    location: Location,
    discoverable: bool,
    rp_id: String,
    user_id: Vec<u8>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    sign_count: u32,
    created_at: u64,
}

impl Kept {
    fn of(record: &CredentialRecord, name: String, location: Location) -> Self {
        Self {
            name,
            location,
            discoverable: crate::credential_id::is_discoverable(&record.credential_id),
            rp_id: record.rp_id.clone(),
            user_id: record.user_id.clone(),
            user_name: record.user_name.clone(),
            user_display_name: record.user_display_name.clone(),
            sign_count: record.sign_count,
            created_at: record.created_at,
        }
    }
}

impl<K: KeySource> FileStore<K> {
    /// What [`Self::repair`] would do, found without changing anything, or
    /// `None` if there is nothing to repair: [`Self::inspect`] finds no
    /// damage, or the store needs no change.
    ///
    /// * If the manifest authenticates, the members whose records are
    ///   missing, or fail authentication or decoding, are dropped from it
    ///   ([`Membership::Kept`]); a legacy store's records that fail are left
    ///   out of the list it gets ([`Membership::Listed`]).
    /// * If the manifest is missing or cannot be used, a new one is built
    ///   from the records in `credential-set/` that authenticate under the
    ///   current key, discoverable or not ([`Membership::Rebuilt`]).  Only
    ///   the lost manifest said which of them were members, so a passkey
    ///   that was deleted or replaced, or whose registration failed, can
    ///   come back if its record was left behind: alone, or beside another
    ///   passkey of its account, which [`RepairPlan::shared`] then names.
    ///   Of two authentic copies of one credential, in both
    ///   record directories, only one is kept, since the manifest can name
    ///   one: the one with the higher signature counter.  Of an authentic
    ///   copy and a damaged one, the authentic one is kept, and its counter
    ///   is raised, since the damaged one can have counted higher
    ///   ([`RepairPlan::raised`]).  The new list may hold more credentials
    ///   than the store's limit ([`RepairPlan::max_credentials`]).
    /// * A damaged format marker is written again, and so is a missing one
    ///   of a store in the managed layout; a manifest that authenticates is
    ///   used whatever the marker.
    /// * A missing namespace is created again, empty: its records went
    ///   with it ([`Membership::Created`]).
    /// * A shared signature counter that cannot be read, or fails
    ///   authentication or decoding, is written again
    ///   ([`RepairPlan::counter`]); if nothing else is damaged, the
    ///   credential set stays as it is ([`Membership::Intact`]).  A
    ///   directory in its place is an error instead, which changes nothing:
    ///   a rename cannot replace a directory with a file, and moving it away
    ///   first would leave no counter, which reads as one never written.
    ///   Anything else there, an empty file included, is repaired.
    ///
    /// Call it with nothing else writing the store, as `pqkey repair` does
    /// with the key stopped.  A record or credential key it cannot read is
    /// an error, as for the inspection: repair never takes out what it could
    /// not read.  A counter it cannot read is damage instead, since writing
    /// it again needs nothing of its contents.  Records are decrypted on a
    /// stack that is scrubbed afterwards.
    pub fn plan_repair(&self) -> Result<Option<RepairPlan>, StoreError> {
        let damage = self.inspect()?;
        if damage.is_empty() {
            return Ok(None);
        }
        let plan = crate::crypto::scrub::with_scrubbed_stack(|| {
            let Some(keys) = self.credential_keys()? else {
                return Ok(None);
            };
            self.plan_with(&keys, damage).map(Some)
        })?;
        Ok(plan.filter(|plan| {
            plan.publication != Publication::Nothing
                || plan.marker
                || plan.counter
                || !plan.moved.is_empty()
        }))
    }

    /// Repair the store as `plan`, which [`Self::plan_repair`] made, says.
    ///
    /// The store must still be as it was planned for: it is planned again,
    /// and a different plan is an error that changes nothing.  Then:
    ///
    /// 1. Every entry in [`RepairPlan::moved`] gets its name in a new
    ///    quarantine directory, `damaged/<UTC time>/`, which is flushed.
    ///    Anything but a directory keeps its old name for now; a directory,
    ///    which cannot be linked, moves.
    /// 2. A damaged shared signature counter, and the counter of each record
    ///    in [`RepairPlan::raised`], is written at one more than the largest
    ///    of: the clock's seconds since 1970, read after step 1; the newest
    ///    modification time of the state directory, of each entry in it and
    ///    of each entry in a directory of records, read before step 1; and
    ///    every counter planning read.  A time at or past `u32::MAX` seconds,
    ///    2106-02-07T06:28:15Z, the clock's or a file's, is left out, so a
    ///    clock or file that far ahead does not stop the counter.  The count
    ///    is at most `u32::MAX`, where counting stops, which it reaches
    ///    only from a time a second earlier or a counter planning read at
    ///    `u32::MAX - 1` or `u32::MAX`.  A record keeps its creation order and
    ///    the rest of its contents.
    /// 3. The new list is published, as a commit publishes it: for a
    ///    managed store, by renaming a flushed manifest over
    ///    `credential-set/active`; for a legacy store, by renaming the
    ///    prepared `credentials/` to `credential-set/`, after writing the
    ///    format marker if it has no authentic one.  Cleanup then removes the
    ///    old names of the records the list does not name.
    /// 4. A damaged or missing format marker of a managed store is written
    ///    last, since it decides whether the list is used at all.
    ///
    /// A counter is written at every count, and each write renames its file
    /// into one of those directories, so a damaged counter's file, or a
    /// damaged copy of a record, has the clock's reading at its last count as
    /// its modification time, unless something has written it, taken its
    /// place or set its time since: a file created in its place by hand has
    /// the clock's reading then.  Nothing can tell a time set otherwise from
    /// such a reading.  So a counter written again before
    /// 2106-02-07T06:28:15Z is above every count it returned if:
    ///
    /// 1. at each count and each repair, the key had counted fewer times
    ///    than whole seconds had passed since 1970, and since any earlier
    ///    repair ended;
    /// 2. no time that this repair or an earlier one read, the clock's or a
    ///    file's, was ahead of the real time, as when the clock never ran
    ///    ahead and every time on the state directory and its files came from
    ///    this computer's clock, not from a hand edit, a copy that kept its
    ///    times or a fault that damaged the file; and
    /// 3. the clock is right now, or the damaged file still has the time a
    ///    right clock gave it at the last count or later, nothing having
    ///    changed that time since.
    ///
    /// A time ahead that this repair reads can raise the count it writes, so
    /// that a later repair, even under a right clock, can start at or below
    /// the counts returned in between.
    ///
    /// By the order of the steps, an error or a crash at any checkpoint leaves
    /// the store serving the credentials it served before or those of the
    /// repaired list, each counter it writes damaged as before or written
    /// again, and every file of the store in its place, in `credential-set/`
    /// after a legacy store's rename, or in the quarantine; repairing again
    /// finishes the work, unless an error stops it too.  Only where the store
    /// could serve no credential before, because its metadata or namespace is
    /// damaged, can such a crash leave another fault of that kind: a
    /// directory in a metadata file's place, moved away, or a recreated
    /// namespace without its list yet.
    ///
    /// The PIN state, the large-blob array, the attestation record and the
    /// keys are left as they are, and so is the shared signature counter
    /// unless it is damaged; no record is rewritten but to raise its counter,
    /// so each other keeps its own.
    pub fn repair(&self, plan: &RepairPlan) -> Result<Repaired, StoreError> {
        if self.plan_repair()?.as_ref() != Some(plan) {
            return Err(fsio::io_error(&self.root, std::io::Error::other(CHANGED)));
        }
        crate::crypto::scrub::with_scrubbed_stack(|| {
            let keys = self
                .credential_keys()?
                .ok_or_else(|| fsio::io_error(&self.root, std::io::Error::other(CHANGED)))?;
            self.carry_out(&keys, plan)
        })
    }

    fn plan_with(
        &self,
        keys: &CredentialKeys,
        damage: Vec<Damage>,
    ) -> Result<RepairPlan, StoreError> {
        // A damaged counter, which the inspection names first, says nothing
        // of the credential set, and is repaired on its own.
        let (counter, damage): (Vec<Damage>, Vec<Damage>) = damage
            .into_iter()
            .partition(|damage| damage.file == SIGNATURE_COUNTER_FILE);
        let mut plan = if damage.is_empty() {
            self.plan_intact(keys)?
        } else if !exists(&self.root.join(MANAGED_DIR))? {
            if exists(&self.credentials_dir)? {
                self.plan_listing(keys, damage)?
            } else if exists(&self.root.join(FORMAT_FILE))? {
                let mut plan = RepairPlan::new(
                    damage,
                    Membership::Created(MANAGED_DIR.to_owned()),
                    Publication::Namespace,
                );
                plan.mark(self.format_marker(keys).err(), true);
                plan
            } else {
                RepairPlan::new(
                    damage,
                    Membership::Created(CREDENTIALS_DIR.to_owned()),
                    Publication::LegacyDirectory,
                )
            }
        } else {
            let marker = self.format_marker(keys).err();
            let mut plan = match self.manifest(keys) {
                Ok(manifest) => self.plan_kept(keys, damage, &manifest)?,
                Err(lost) => self.plan_rebuild(keys, damage, lost)?,
            };
            plan.mark(marker, true);
            plan
        };
        if counter.is_empty() {
            plan.highest = plan.highest.max(self.counter(keys)?);
        } else {
            // A rename cannot replace a directory with a file, and moving it
            // away first would leave no counter, which reads as one never
            // written: a crash in between would let counts start again.
            let path = self.root.join(SIGNATURE_COUNTER_FILE);
            if fs::symlink_metadata(&path)
                .map_err(|err| fsio::io_error(&path, err))?
                .is_dir()
            {
                return Err(fsio::io_error(
                    &path,
                    std::io::Error::new(
                        ErrorKind::IsADirectory,
                        "is a directory, which repair cannot replace with a counter in one step",
                    ),
                ));
            }
            plan.counter = true;
            plan.moved.push(SIGNATURE_COUNTER_FILE.to_owned());
            plan.damage.splice(0..0, counter);
        }
        plan.moved.sort();
        plan.max_credentials = self.max_credentials;
        Ok(plan)
    }

    /// Only the signature counter is damaged: the credential set stays as
    /// it is, and is read for its counters and what the plan reports.
    fn plan_intact(&self, keys: &CredentialKeys) -> Result<RepairPlan, StoreError> {
        let members: Vec<(String, Location, PathBuf)> = match self.active_manifest(keys)? {
            Some(manifest) => manifest
                .into_iter()
                .map(|(name, location)| (name, location, self.record_dir(location)))
                .collect(),
            None => self
                .credential_file_names()?
                .into_iter()
                .map(|name| (name, Location::Legacy, self.credentials_dir.clone()))
                .collect(),
        };
        let mut kept = Vec::new();
        for (name, location, dir) in members {
            if let Some(record) = self.read_credential_in(keys, &name, &dir, location)? {
                kept.push(Kept::of(&record, name, location));
            }
        }
        let mut plan = RepairPlan::new(Vec::new(), Membership::Intact, Publication::Nothing);
        plan.keep(&kept);
        Ok(plan)
    }

    /// The manifest authenticates: drop the members whose records are lost.
    fn plan_kept(
        &self,
        keys: &CredentialKeys,
        mut damage: Vec<Damage>,
        manifest: &Manifest,
    ) -> Result<RepairPlan, StoreError> {
        let mut kept = Vec::new();
        for (name, &location) in manifest {
            let dir = self.record_dir(location);
            match self.read_credential_in(keys, name, &dir, location) {
                Ok(Some(record)) => kept.push(Kept::of(&record, name.clone(), location)),
                Ok(None) => add(&mut damage, Damage::missing(self.relative(&dir, name))),
                Err(StoreError::Corrupt { object, reason }) => {
                    add(&mut damage, Damage::corrupt(object, reason));
                }
                Err(err) => return Err(err),
            }
        }
        let mut plan = RepairPlan::new(damage, Membership::Kept, Publication::Nothing);
        let list = listed(&kept);
        if list != *manifest {
            // The new manifest takes the old one's place, which keeps its
            // contents in the quarantine like everything else repair
            // replaces or removes.
            plan.moved.push(format!("{MANAGED_DIR}/{ACTIVE_FILE}"));
            plan.moved.extend(self.reclaimed(&list)?);
            plan.publication = Publication::Manifest(list);
        }
        plan.keep(&kept);
        Ok(plan)
    }

    /// The manifest cannot be used: rebuild the list from the records that
    /// authenticate.
    fn plan_rebuild(
        &self,
        keys: &CredentialKeys,
        mut damage: Vec<Damage>,
        lost: Damage,
    ) -> Result<RepairPlan, StoreError> {
        add(&mut damage, lost);
        let mut found = Vec::new();
        let mut damaged = BTreeSet::new();
        for location in [Location::Legacy, Location::Managed] {
            let dir = self.record_dir(location);
            for name in record_files(&dir)? {
                match self.read_credential_in(keys, &name, &dir, location) {
                    Ok(Some(record)) => found.push(Kept::of(&record, name, location)),
                    Ok(None) => {}
                    Err(StoreError::Corrupt { object, reason }) => {
                        add(&mut damage, Damage::corrupt(object, reason));
                        damaged.insert(name);
                    }
                    Err(err) => return Err(err),
                }
            }
        }
        let kept = one_per_name(found);
        let list = listed(&kept);
        // Fail before anything changes if the list cannot be written.
        let _ = manifest::encode(&list)?;
        let mut plan = RepairPlan::new(damage, Membership::Rebuilt, Publication::Nothing);
        // The manifest's place is taken by the new one: whatever is there
        // gets a name in the quarantine first, and a directory moves there.
        let active = format!("{MANAGED_DIR}/{ACTIVE_FILE}");
        if exists(&self.root.join(&active))? {
            plan.moved.push(active);
        }
        plan.moved.extend(self.reclaimed(&list)?);
        // A kept copy whose name a damaged copy in the other directory has
        // too: that copy's counter is lost, and can be higher than this one.
        plan.raised = kept
            .iter()
            .filter(|kept| damaged.contains(&kept.name))
            .map(|kept| self.relative(&self.record_dir(kept.location), &kept.name))
            .collect();
        plan.raised.sort();
        plan.moved.extend(plan.raised.iter().cloned());
        plan.publication = Publication::Manifest(list);
        plan.keep(&kept);
        Ok(plan)
    }

    /// A legacy store: list its records that are intact, moving it to the
    /// managed layout as its first registration would.
    fn plan_listing(
        &self,
        keys: &CredentialKeys,
        mut damage: Vec<Damage>,
    ) -> Result<RepairPlan, StoreError> {
        let mut names = self.credential_file_names()?;
        names.sort();
        let mut kept = Vec::new();
        let mut moved = Vec::new();
        for name in names {
            match self.read_credential(keys, &name) {
                Ok(Some(record)) => kept.push(Kept::of(&record, name, Location::Legacy)),
                // Deleted since the directory was listed.
                Ok(None) => {}
                Err(StoreError::Corrupt { object, reason }) => {
                    add(&mut damage, Damage::corrupt(object, reason));
                    moved.push(format!("{CREDENTIALS_DIR}/{name}"));
                }
                Err(err) => return Err(err),
            }
        }
        // What the first commit's preparation replaces, and what its cleanup
        // removes: a manifest and records an earlier upgrade prepared.
        let prepared = format!("{CREDENTIALS_DIR}/{ACTIVE_FILE}");
        if exists(&self.root.join(&prepared))? {
            moved.push(prepared);
        }
        let staged = self.credentials_dir.join(RECORDS_DIR);
        moved.extend(
            record_files(&staged)?
                .into_iter()
                .map(|name| format!("{CREDENTIALS_DIR}/{RECORDS_DIR}/{name}")),
        );
        let mut plan = RepairPlan::new(
            damage,
            Membership::Listed,
            Publication::Migration(listed(&kept)),
        );
        plan.moved = moved;
        plan.keep(&kept);
        // The managed layout needs an authentic marker before its first
        // commit.  A legacy store has none, or one from an upgrade that
        // failed; either way it uses no marker, so a bad one is no damage.
        plan.mark(self.format_marker(keys).err(), false);
        Ok(plan)
    }

    /// The record files cleanup after publishing `manifest` removes, as
    /// paths relative to the state directory, in order.
    fn reclaimed(&self, manifest: &Manifest) -> Result<Vec<String>, StoreError> {
        let mut reclaimed = Vec::new();
        for location in [Location::Legacy, Location::Managed] {
            let dir = self.record_dir(location);
            for name in record_files(&dir)? {
                if self.reclaimable(manifest, location, &name)? {
                    reclaimed.push(self.relative(&dir, &name));
                }
            }
        }
        Ok(reclaimed)
    }

    fn carry_out(&self, keys: &CredentialKeys, plan: &RepairPlan) -> Result<Repaired, StoreError> {
        // Read before the quarantine changes the state directory's time.
        let newest = if plan.counter || !plan.raised.is_empty() {
            Some(self.newest_change()?)
        } else {
            None
        };
        let quarantine = if plan.moved.is_empty() {
            None
        } else {
            Some(self.quarantine(&plan.moved)?)
        };
        if let Some(newest) = newest {
            let count = count_above(plan.highest, newest, SystemTime::now());
            if plan.counter {
                let plaintext = codec::encode_signature_counter(count)?;
                self.write_object(
                    &keys.record,
                    RecordType::SignatureCounter,
                    SIGNATURE_COUNTER_FILE,
                    &plaintext,
                )?;
            }
            for raised in &plan.raised {
                self.raise(keys, raised, count)?;
            }
        }
        let mut commit = CredentialCommit {
            durability: CommitDurability::Flushed,
            cleanup_pending: false,
        };
        let mut marker = plan.marker;
        match &plan.publication {
            Publication::Nothing => {}
            Publication::Manifest(manifest) => {
                // Cleanup reads both record directories.
                fsio::ensure_private_dir(&self.record_dir(Location::Managed))?;
                commit = self.publish_manifest(keys, manifest)?;
            }
            Publication::Migration(manifest) => {
                if marker {
                    self.write_format_marker(keys)?;
                    marker = false;
                }
                fsio::ensure_private_dir(&self.credentials_dir.join(RECORDS_DIR))?;
                commit = self.publish_migration(keys, manifest)?;
            }
            Publication::Namespace => {
                fsio::ensure_private_dir(&self.root.join(MANAGED_DIR))?;
                fsio::ensure_private_dir(&self.record_dir(Location::Managed))?;
                commit = self.publish_manifest(keys, &Manifest::new())?;
            }
            Publication::LegacyDirectory => fsio::ensure_private_dir(&self.credentials_dir)?,
        }
        if marker && self.replace_format_marker(keys)? == CommitDurability::Unconfirmed {
            commit.durability = CommitDurability::Unconfirmed;
        }
        Ok(Repaired {
            quarantine,
            durability: commit.durability,
            cleanup_pending: commit.cleanup_pending,
        })
    }

    /// The newest modification time, in seconds since 1970, of the state
    /// directory, of each entry in it, and of each entry in a directory of
    /// records, leaving out a time at or past [`LARGEST_COUNT`].  The store
    /// writes the counter's file at each count, and a record at each of its
    /// counts, so their time is the clock's reading at their last count,
    /// unless something else has written them, taken their place or set
    /// their time since.  Each time is taken for a reading of this computer's
    /// clock, which nothing here can check: [`FileStore::repair`] states what
    /// its guarantee needs of them.
    fn newest_change(&self) -> Result<u64, StoreError> {
        let mut newest = 0;
        let mut note = |path: &Path, metadata: fs::Metadata| {
            let time = seconds(
                metadata
                    .modified()
                    .map_err(|err| fsio::io_error(path, err))?,
            );
            if time < LARGEST_COUNT {
                newest = newest.max(time);
            }
            Ok::<_, StoreError>(())
        };
        note(
            &self.root,
            fs::symlink_metadata(&self.root).map_err(|err| fsio::io_error(&self.root, err))?,
        )?;
        for dir in [
            self.root.clone(),
            self.record_dir(Location::Legacy),
            self.record_dir(Location::Managed),
            self.credentials_dir.clone(),
        ] {
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => return Err(fsio::io_error(&dir, err)),
            };
            for entry in entries {
                let entry = entry.map_err(|err| fsio::io_error(&dir, err))?;
                let path = entry.path();
                let metadata = entry.metadata().map_err(|err| fsio::io_error(&path, err))?;
                note(&path, metadata)?;
            }
        }
        Ok(newest)
    }

    /// Write the record at `raised`, its path relative to the state
    /// directory, again with the counter `count`, as a same-ID update writes
    /// it: in place, under its logical name, with its creation order.
    fn raise(&self, keys: &CredentialKeys, raised: &str, count: u32) -> Result<(), StoreError> {
        let path = Path::new(raised);
        let location = if path.starts_with(Path::new(MANAGED_DIR).join(RECORDS_DIR)) {
            Location::Managed
        } else {
            Location::Legacy
        };
        let dir = self.record_dir(location);
        let changed = || fsio::io_error(&self.root.join(raised), std::io::Error::other(CHANGED));
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(changed)?;
        let mut record = self
            .read_credential_in(keys, name, &dir, location)?
            .ok_or_else(changed)?;
        record.sign_count = count;
        let plaintext = codec::encode_credential(&record, record.created_at)?;
        let sealed = envelope::seal(
            &keys.record,
            RecordType::Credential,
            &credential_object(name, location),
            &plaintext,
        )?;
        fsio::replace_file(&dir, name, &sealed)
    }

    /// Give each of `moved` its name in a new quarantine directory, at its
    /// path relative to the state directory, and flush the directories it
    /// is in before anything replaces or removes the old names.
    fn quarantine(&self, moved: &[String]) -> Result<PathBuf, StoreError> {
        let parent = self.root.join(QUARANTINE_DIR);
        fsio::ensure_private_dir(&parent)?;
        let quarantine = new_quarantine(&parent, SystemTime::now())?;
        let mut held = BTreeSet::new();
        for relative in moved {
            let mut dir = quarantine.clone();
            for component in Path::new(relative)
                .parent()
                .into_iter()
                .flat_map(Path::components)
            {
                dir.push(component);
                fsio::ensure_private_dir(&dir)?;
            }
            let to = quarantine.join(relative);
            fsio::quarantine(&self.root.join(relative), &to)?;
            held.insert(dir);
        }
        for dir in &held {
            fsio::sync_dir_strict(dir)?;
        }
        Ok(quarantine)
    }

    /// Write the format marker of a managed store again, after its list is
    /// published.  An error after the rename is publication with
    /// unconfirmed durability, not a failed repair.
    fn replace_format_marker(&self, keys: &CredentialKeys) -> Result<CommitDurability, StoreError> {
        let sealed = envelope::seal(
            &keys.record,
            RecordType::CredentialFormat,
            FORMAT_FILE,
            FORMAT,
        )?;
        let temp = fsio::write_temp_file(&self.root, &sealed)?;
        let renamed = match fsio::rename(&temp, &self.root.join(FORMAT_FILE), "rename", "renamed") {
            Ok(renamed) => renamed,
            Err(err) => {
                let _ = fsio::remove_file_if_present(&temp);
                return Err(err);
            }
        };
        Ok(
            match renamed.and_then(|()| fsio::sync_dir_strict(&self.root)) {
                Ok(()) => CommitDurability::Flushed,
                Err(err) => {
                    log::warn!(
                        "credential store: repaired with unconfirmed durability of the format \
                         marker: {err}"
                    );
                    CommitDurability::Unconfirmed
                }
            },
        )
    }
}

impl RepairPlan {
    fn new(damage: Vec<Damage>, membership: Membership, publication: Publication) -> Self {
        Self {
            damage,
            membership,
            shared: Vec::new(),
            passkeys: 0,
            others: 0,
            max_credentials: 0,
            marker: false,
            counter: false,
            raised: Vec::new(),
            moved: Vec::new(),
            highest: 0,
            publication,
        }
    }

    /// Count the credentials of the repaired list, `kept`, and the accounts
    /// it holds more than one passkey of, and note their highest counter.
    fn keep(&mut self, kept: &[Kept]) {
        self.passkeys = kept.iter().filter(|kept| kept.discoverable).count();
        self.others = kept.len() - self.passkeys;
        self.highest = kept.iter().map(|kept| kept.sign_count).max().unwrap_or(0);
        let mut accounts: BTreeMap<(&str, &[u8]), (&Kept, usize)> = BTreeMap::new();
        for passkey in kept.iter().filter(|kept| kept.discoverable) {
            accounts
                .entry((&passkey.rp_id, &passkey.user_id))
                .or_insert((passkey, 0))
                .1 += 1;
        }
        self.shared = accounts
            .into_values()
            .filter(|&(_, passkeys)| passkeys > 1)
            .map(|(first, passkeys)| Account {
                rp_id: first.rp_id.clone(),
                user_name: first.user_name.clone(),
                user_display_name: first.user_display_name.clone(),
                passkeys,
            })
            .collect();
    }

    /// Write the marker, which is `damaged` or missing, again, moving a
    /// damaged one into the quarantine first, and list it as damage if it
    /// is `reported`: if the store needs it.
    fn mark(&mut self, damaged: Option<Damage>, reported: bool) {
        let Some(damaged) = damaged else {
            return;
        };
        self.marker = true;
        if damaged.fault != super::super::Fault::Missing {
            self.moved.push(FORMAT_FILE.to_owned());
        }
        if reported {
            add(&mut self.damage, damaged);
        }
    }
}

/// Add `damage` to `found` unless it is there: the inspection may have
/// found it already.
fn add(found: &mut Vec<Damage>, damage: Damage) {
    if !found.contains(&damage) {
        found.push(damage);
    }
}

/// The names of the regular files in `dir` that are named as credential
/// records are, in order; none if `dir` does not exist.
pub(super) fn record_files(dir: &Path) -> Result<Vec<String>, StoreError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(fsio::io_error(dir, err)),
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| fsio::io_error(dir, err))?;
        let regular = entry
            .file_type()
            .map_err(|err| fsio::io_error(&entry.path(), err))?
            .is_file();
        if let Some(name) = entry.file_name().to_str()
            && regular
            && is_credential_file_name(name)
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

/// The records a rebuild finds that authenticate, one per file name: of two
/// authentic copies of one credential, in both record directories, the one
/// with the higher signature counter, then the higher creation order, since
/// the list can name only one.  Everything else is kept.
fn one_per_name(found: Vec<Kept>) -> Vec<Kept> {
    let mut by_name: BTreeMap<String, Kept> = BTreeMap::new();
    for record in found {
        match by_name.entry(record.name.clone()) {
            Entry::Vacant(slot) => {
                slot.insert(record);
            }
            Entry::Occupied(mut slot) => {
                let held = slot.get();
                if (record.sign_count, record.created_at) > (held.sign_count, held.created_at) {
                    slot.insert(record);
                }
            }
        }
    }
    by_name.into_values().collect()
}

/// The list of `kept`, as the manifest says it.
fn listed(kept: &[Kept]) -> Manifest {
    kept.iter()
        .map(|kept| (kept.name.clone(), kept.location))
        .collect()
}

/// Create a new quarantine directory in `parent`, named by the UTC time
/// `now`, and by a number after it if a repair in the same second took that
/// name.
fn new_quarantine(parent: &Path, now: SystemTime) -> Result<PathBuf, StoreError> {
    let stamp = utc_stamp(now);
    for attempt in 1..=QUARANTINE_ATTEMPTS {
        let name = if attempt == 1 {
            stamp.clone()
        } else {
            format!("{stamp}-{attempt}")
        };
        let dir = parent.join(name);
        if fsio::create_private_dir(&dir)? {
            return Ok(dir);
        }
    }
    Err(fsio::io_error(
        parent,
        std::io::Error::new(
            ErrorKind::AlreadyExists,
            "could not find an unused quarantine directory name",
        ),
    ))
}

/// The count a repair writes a counter at whose count is lost: one more than
/// the largest of `now`, the clock's reading, in seconds since 1970, unless
/// it is at or past [`LARGEST_COUNT`]; `newest`, the store's newest change
/// ([`FileStore::newest_change`]); and `highest`, the highest counter
/// planning read.  At most `u32::MAX`, where counting stops, which it
/// reaches only from a time a second earlier or a counter planning read at
/// `u32::MAX - 1` or `u32::MAX`.
fn count_above(highest: u32, newest: u64, now: SystemTime) -> u32 {
    let clock = Some(seconds(now)).filter(|&clock| clock < LARGEST_COUNT);
    let largest = newest.max(clock.unwrap_or(0)).max(u64::from(highest));
    u32::try_from(largest.saturating_add(1)).unwrap_or(u32::MAX)
}

/// `time` in whole seconds since 1970; a time before 1970 counts as 1970.
fn seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// `time` in UTC as ISO 8601's basic format, `20261104T221507Z`, which needs
/// no colon in a file name.  A time before 1970 counts as 1970.
fn utc_stamp(time: SystemTime) -> String {
    let seconds = seconds(time);
    let (year, month, day) = civil_from_days(seconds / 86_400);
    let second = seconds % 86_400;
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        second / 3600,
        second % 3600 / 60,
        second % 60
    )
}

/// The proleptic Gregorian date `days` after 1970-01-01: Howard Hinnant's
/// `civil_from_days` (<https://howardhinnant.github.io/date_algorithms.html>),
/// for days that are not negative.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let days = days + 719_468;
    let era = days / 146_097;
    let day_of_era = days % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The count rule: one more than the largest of the clock, the store's
    /// newest change and the counters planning read.  A clock at or past the
    /// largest count is left out; the count reaches it only from a clock a
    /// second before it or a counter one below it or at it.
    #[test]
    fn a_lost_count_starts_above_the_clock_the_last_change_and_every_count() {
        let at = |seconds| UNIX_EPOCH + std::time::Duration::from_secs(seconds);
        let now = 1_794_500_000;
        assert_eq!(count_above(7, 100, at(now)), 1_794_500_001);
        assert_eq!(count_above(7, now + 50, at(now)), 1_794_500_051);
        assert_eq!(count_above(1_794_600_000, 100, at(now)), 1_794_600_001);
        // 2106-02-07T06:28:15Z and 2200-01-01: the clock is left out.
        for clock in [u64::from(u32::MAX), 7_258_118_400] {
            assert_eq!(count_above(7, now, at(clock)), 1_794_500_001, "{clock}");
            assert_eq!(count_above(7, 0, at(clock)), 8, "{clock}");
        }
        // 2106-02-07T06:28:14Z, the last time a count can be above.
        assert_eq!(count_above(7, 0, at(u64::from(u32::MAX) - 1)), u32::MAX);
        assert_eq!(count_above(u32::MAX - 1, now, at(now)), u32::MAX);
        assert_eq!(count_above(u32::MAX, now, at(now)), u32::MAX);
        assert_eq!(
            count_above(0, 0, UNIX_EPOCH - std::time::Duration::from_secs(1)),
            1
        );
    }

    /// Checked against Python's `datetime.fromtimestamp(t, timezone.utc)`.
    #[test]
    fn quarantines_are_named_by_the_utc_time() {
        for (seconds, stamp) in [
            (0, "19700101T000000Z"),
            (951_782_399, "20000228T235959Z"),
            (951_782_400, "20000229T000000Z"),
            (1_709_251_199, "20240229T235959Z"),
            (1_793_836_799, "20261104T235959Z"),
            (1_793_920_027, "20261105T230707Z"),
            (4_107_542_400, "21000301T000000Z"),
        ] {
            let time = UNIX_EPOCH + std::time::Duration::from_secs(seconds);
            assert_eq!(utc_stamp(time), stamp, "{seconds}");
        }
        assert_eq!(
            utc_stamp(UNIX_EPOCH - std::time::Duration::from_secs(1)),
            "19700101T000000Z"
        );
    }
}
