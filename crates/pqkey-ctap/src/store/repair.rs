//! Explicit repair of a damaged credential set.
//!
//! [`FileStore::plan_repair`] finds what to do without changing anything,
//! and [`FileStore::repair`] does it.  `pqkey repair` plans with the key
//! stopped, then plans again and repairs holding the state lock; nothing
//! else repairs a store, and no operation rebuilds membership by itself.
//!
//! Every file of the store that repair replaces or removes, a damaged
//! record or metadata file, the replaced manifest, a failed upgrade's
//! prepared manifest, or a record the new list does not name, first gets a
//! name in a new quarantine directory, `damaged/<UTC time>/`, at its path
//! relative to the state directory: a hard link for a file, which keeps it
//! in place until then, so that a crash before publication leaves the store
//! as it was, and a rename for anything else in a file's place.  Membership
//! is published as every commit publishes it, and cleanup after the
//! publication then removes the records' old names, as it removes any file
//! membership no longer names.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

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
    /// Every file and directory moved into the quarantine, at its path
    /// relative to the state directory, in order.
    pub moved: Vec<String>,
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
    ///   one: the one with the higher signature counter.  The new list may
    ///   hold more credentials than the store's limit
    ///   ([`RepairPlan::max_credentials`]).
    /// * A damaged format marker is written again, and so is a missing one
    ///   of a store in the managed layout; a manifest that authenticates is
    ///   used whatever the marker.
    /// * A missing namespace is created again, empty: its records went
    ///   with it ([`Membership::Created`]).
    ///
    /// Call it with nothing else writing the store, as `pqkey repair` does
    /// with the key stopped.  A record or credential key it cannot read is
    /// an error, as for the inspection: repair never takes out what it could
    /// not read.  Records are decrypted on a stack that is scrubbed
    /// afterwards.
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
            plan.publication != Publication::Nothing || plan.marker || !plan.moved.is_empty()
        }))
    }

    /// Repair the store as `plan`, which [`Self::plan_repair`] made, says.
    ///
    /// The store must still be as it was planned for: it is planned again,
    /// and a different plan is an error that changes nothing.  Then:
    ///
    /// 1. Every entry in [`RepairPlan::moved`] gets its name in a new
    ///    quarantine directory, `damaged/<UTC time>/`, which is flushed.  A
    ///    file keeps its old name for now; anything else, which cannot be
    ///    linked, moves.
    /// 2. The new list is published, as a commit publishes it: for a
    ///    managed store, by renaming a flushed manifest over
    ///    `credential-set/active`; for a legacy store, by renaming the
    ///    prepared `credentials/` to `credential-set/`, after writing the
    ///    format marker if it has no authentic one.  Cleanup then removes the
    ///    old names of the records the list does not name.
    /// 3. A damaged or missing format marker of a managed store is written
    ///    last, since it decides whether the list is used at all.
    ///
    /// So an error or a crash at any checkpoint leaves the store serving
    /// the credentials it served before or those of the repaired list, and
    /// every file of the store in its place, in `credential-set/` after a
    /// legacy store's rename, or in the quarantine; repairing again finishes
    /// the work.  Only where the store could serve no credential before,
    /// because its metadata or namespace is damaged, can such a crash leave
    /// another fault of that kind: a damaged metadata entry that is not a
    /// file, moved away, or a recreated namespace without its list yet.
    ///
    /// The shared signature counter, the PIN state, the large-blob array,
    /// the attestation record and the keys are left as they are, and no
    /// record is rewritten, so each keeps its own counter.
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
        let mut plan = if !exists(&self.root.join(MANAGED_DIR))? {
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
        plan.moved.sort();
        plan.max_credentials = self.max_credentials;
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
        for location in [Location::Legacy, Location::Managed] {
            let dir = self.record_dir(location);
            for name in record_files(&dir)? {
                match self.read_credential_in(keys, &name, &dir, location) {
                    Ok(Some(record)) => found.push(Kept::of(&record, name, location)),
                    Ok(None) => {}
                    Err(StoreError::Corrupt { object, reason }) => {
                        add(&mut damage, Damage::corrupt(object, reason));
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
        // The manifest's place is taken by the new one: a file there keeps
        // its contents in the quarantine, and anything else moves there.
        let active = format!("{MANAGED_DIR}/{ACTIVE_FILE}");
        if exists(&self.root.join(&active))? {
            plan.moved.push(active);
        }
        plan.moved.extend(self.reclaimed(&list)?);
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
        let quarantine = if plan.moved.is_empty() {
            None
        } else {
            Some(self.quarantine(&plan.moved)?)
        };
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
            moved: Vec::new(),
            publication,
        }
    }

    /// Count the credentials of the repaired list, `kept`, and the accounts
    /// it holds more than one passkey of.
    fn keep(&mut self, kept: &[Kept]) {
        self.passkeys = kept.iter().filter(|kept| kept.discoverable).count();
        self.others = kept.len() - self.passkeys;
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

/// `time` in UTC as ISO 8601's basic format, `20261104T221507Z`, which needs
/// no colon in a file name.  A time before 1970 counts as 1970.
fn utc_stamp(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
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
