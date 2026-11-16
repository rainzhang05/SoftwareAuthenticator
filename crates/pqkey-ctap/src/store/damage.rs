//! Damage to a file store's credential set, its shared signature counter,
//! its PIN state and its large-blob array: which file, what is wrong with
//! it, what fails because of it, and what to do about it.
//!
//! The key's log ([`StoreError::damage_hint`], [`damage_log`],
//! [`damage_unchecked_log`]) and `pqkey status` ([`damage_summary`],
//! [`damage_unchecked`], [`damage_fix`]) take all their wording from here,
//! and `pqkey repair` its wording of the damage and of what fails
//! ([`Damage`]'s display, [`damage_consequence`]), so that it changes in one
//! place.  Each claim the wording makes about what fails is tested for every
//! kind of damage it is said of (`tests/store/damage.rs`, and the `pqkey`
//! crate's status and start-up tests); it claims nothing about what still
//! works.

use core::fmt;

use super::file::{CREDENTIALS_DIR, LARGE_BLOBS_FILE, PIN_STATE_FILE, SIGNATURE_COUNTER_FILE};
use super::keys::is_credential_file_name;
use super::{Corruption, CredentialStore, StoreError};

/// How many damaged files a summary names before it counts the rest.
const NAMED: usize = 3;

/// Why an inspection whose looks never agreed could not check the store.
/// What to do follows it ([`damage_fix`]): `pqkey repair` looks again with
/// the key stopped, so that none of the key's own changes come between its
/// looks.
pub(super) const UNSETTLED: &str = "it kept changing while it was checked";

/// A file or directory of a [`FileStore`](super::FileStore)'s credential set,
/// or its shared signature counter, PIN state or large-blob array, that is
/// missing or cannot be used, as
/// [`FileStore::inspect`](super::FileStore::inspect) finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Damage {
    /// Its path, relative to the state directory: a credential's record, such
    /// as `credential-set/records/<64 hex digits>`; the membership metadata
    /// of a store in the managed layout, `credential-format` or
    /// `credential-set/active`, or the directory `credential-set` that holds
    /// it; a legacy store's directory `credentials`; the shared signature
    /// counter, `signature-counter`; the PIN state, `pin-state`; or the
    /// large-blob array, `large-blobs`.
    pub file: String,
    /// What is wrong with it.
    pub fault: Fault,
}

/// What is wrong with a damaged file.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Fault {
    /// It is missing.
    Missing,
    /// It fails authentication or decoding.
    Corrupt(Corruption),
    /// Reading it failed, for this reason. Only membership metadata and the
    /// signature counter are damaged by a failed read: the store cannot do
    /// without them, and a repair writes them again without reading them,
    /// unless a directory is in the counter's place, which it refuses to
    /// replace.  A record that cannot be read fails the inspection instead,
    /// and a PIN state or large-blob array that cannot be read is no damage:
    /// the key reads it again.
    Unreadable(String),
}

impl Damage {
    /// Whether the damaged file is a credential's record, rather than
    /// membership metadata or a directory.
    #[must_use]
    pub fn is_record(&self) -> bool {
        kind(&self.file) == Kind::Record
    }

    /// Whether the damaged file is the PIN state, which blocks the PIN.
    #[must_use]
    pub fn is_pin_state(&self) -> bool {
        kind(&self.file) == Kind::PinState
    }

    pub(super) fn missing(file: impl Into<String>) -> Self {
        Self {
            file: file.into(),
            fault: Fault::Missing,
        }
    }

    pub(super) fn corrupt(file: impl Into<String>, reason: Corruption) -> Self {
        Self {
            file: file.into(),
            fault: Fault::Corrupt(reason),
        }
    }

    /// `file`, which could not be read for `err`.
    pub(super) fn unreadable(file: impl Into<String>, err: StoreError) -> Self {
        let fault = match err {
            StoreError::Corrupt { reason, .. } => Fault::Corrupt(reason),
            err => Fault::Unreadable(err.to_string()),
        };
        Self {
            file: file.into(),
            fault,
        }
    }
}

/// The damage to `store`'s PIN state and large-blob array, read as the
/// engine reads them: each only if it fails authentication or decoding, as
/// the engine then takes the PIN for set and blocked, or serves the initial
/// array in its place (CTAP 2.3 §6.10.2).  A missing file is no damage: no
/// PIN, or the initial array.  Nor is any other error, which the engine
/// handles on its own, and which fails neither the inspection nor a repair
/// of other damage.  The PIN state read, whose PIN hash can authenticate as
/// the user, is dropped, and wiped, at once.
pub(super) fn pin_state_and_large_blobs(store: &impl CredentialStore) -> Vec<Damage> {
    [store.pin_state().err(), store.large_blob_array().err()]
        .into_iter()
        .flatten()
        .filter_map(|err| match err {
            StoreError::Corrupt { object, reason } => Some(Damage::corrupt(object, reason)),
            // The storage could not be read, which says nothing of the file;
            // and a key that cannot be used fails the inspection's own read.
            StoreError::Io { .. } | StoreError::KeyUnavailable { .. } => None,
            // These reads never report them.
            StoreError::CredentialSetUnavailable { .. }
            | StoreError::Full { .. }
            | StoreError::InvalidRecord(_)
            | StoreError::Random => None,
        })
        .collect()
}

/// The error with which operations refuse to go on despite `damage`, which
/// is not empty: unavailable membership, naming the first damaged file, and
/// in its detail every one.
pub(super) fn unavailable(damage: &[Damage]) -> StoreError {
    StoreError::CredentialSetUnavailable {
        object: damage
            .first()
            .map(|first| first.file.clone())
            .unwrap_or_default(),
        detail: damage
            .iter()
            .map(Damage::to_string)
            .collect::<Vec<_>>()
            .join("; "),
    }
}

impl fmt::Display for Damage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let file = &self.file;
        match &self.fault {
            Fault::Missing => write!(f, "{file} is missing"),
            Fault::Corrupt(reason) => write!(f, "{file} is corrupt: {reason}"),
            Fault::Unreadable(reason) => write!(f, "{file} cannot be read: {reason}"),
        }
    }
}

/// What damage to a file costs, which its path tells.  The credential set's
/// kinds come last, ordered by cost; the others cost nothing of the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    /// The PIN state, which the key then takes for a PIN set and blocked,
    /// with always-UV on.
    PinState,
    /// The large-blob array, which the key then serves as the initial one.
    LargeBlobs,
    /// The shared signature counter, which every sign-in with a credential
    /// sealed into its ID counts on.
    Counter,
    /// A credential's record.
    Record,
    /// A legacy store's directory `credentials`, which opening the store
    /// creates again, empty.
    LegacyDirectory,
    /// Membership metadata, or the directory holding it.
    Membership,
}

impl Kind {
    /// Whether damage of this kind is to the credential set.
    fn in_set(self) -> bool {
        self >= Self::Record
    }
}

fn kind(file: &str) -> Kind {
    match file {
        PIN_STATE_FILE => Kind::PinState,
        LARGE_BLOBS_FILE => Kind::LargeBlobs,
        SIGNATURE_COUNTER_FILE => Kind::Counter,
        CREDENTIALS_DIR => Kind::LegacyDirectory,
        _ if file.rsplit('/').next().is_some_and(is_credential_file_name) => Kind::Record,
        _ => Kind::Membership,
    }
}

/// What fails after damage of `kind` to `files` files: only what fails
/// whatever else is damaged, and for a legacy store's lost `credentials`
/// directory only what fails both before and after the key opens the store,
/// which creates the directory again, empty.  That directory may have held
/// no passkey at all, as in a new store: a legacy store keeps no list of its
/// credentials, so nothing tells once the directory is lost.  The counter
/// fails only the sign-ins that count on it: those with a credential sealed
/// into its ID, which a site registers when it uses the key as a security
/// key, over CTAP 2 or U2F, unless the key stores the credential.  A damaged
/// PIN state fails everything that needs the PIN, which always-UV makes
/// every registration and sign-in; a damaged large-blob array, the large
/// blobs in it.
fn consequence(kind: Kind, files: usize) -> &'static str {
    match (kind, files) {
        (Kind::PinState, _) => {
            "the key treats its PIN as blocked and requires it, so it cannot register passkeys, \
             sign in or set a new PIN"
        }
        (Kind::LargeBlobs, _) => "the key cannot return the large blobs that sites stored on it",
        (Kind::Counter, _) => {
            "the key cannot sign in to sites that registered it as a security key and whose \
             credentials it did not store"
        }
        (Kind::Record, 1) => "the key cannot register passkeys, or use the credential in that file",
        (Kind::Record, _) => {
            "the key cannot register passkeys, or use the credentials in those files"
        }
        (Kind::LegacyDirectory, _) => "the key cannot use any passkeys that were in it",
        (Kind::Membership, _) => "the key cannot register, use or list passkeys",
    }
}

/// What fails in a credential store found to have `damage`, which is not
/// empty, as [`damage_summary`] says it: what damage to each file outside
/// the credential set costs, in the order of `damage`, then what the worst
/// damage to the set costs, which only the set's damaged files count towards.
#[must_use]
pub fn damage_consequence(damage: &[Damage]) -> String {
    let (set, others): (Vec<Kind>, Vec<Kind>) = damage
        .iter()
        .map(|damage| kind(&damage.file))
        .partition(|kind| kind.in_set());
    let mut consequences: Vec<&str> = others
        .into_iter()
        .map(|kind| consequence(kind, 1))
        .collect();
    if let Some(&worst) = set.iter().max() {
        consequences.push(consequence(worst, set.len()));
    }
    consequences.join("; ")
}

/// What `pqkey status` says is wrong with a credential store found to have
/// `damage`, which is not empty: the damaged files and what fails.
#[must_use]
pub fn damage_summary(damage: &[Damage]) -> String {
    let mut files: Vec<String> = damage.iter().take(NAMED).map(Damage::to_string).collect();
    if damage.len() > NAMED {
        files.push(format!("and {} more", damage.len() - NAMED));
    }
    format!(
        "the credential store is damaged ({}): {}",
        files.join("; "),
        damage_consequence(damage)
    )
}

/// What `pqkey status` and the key's log say when a credential store
/// cannot be checked for damage, failing with `err`.
#[must_use]
pub fn damage_unchecked(err: &StoreError) -> String {
    format!("the credential store cannot be checked: {err}")
}

/// What to do about `damage` to the credential store in `state_dir`, as
/// `pqkey status` and the key's log say it, or, with no damage named, about
/// a store that cannot be checked: with the key stopped, keep a copy of the
/// store and repair it; start the key again, and set a new PIN in place of
/// a damaged PIN state; and reset only as the last resort, which a damaged
/// large-blob array alone never needs.
#[must_use]
pub fn damage_fix(damage: &[Damage], state_dir: &str) -> String {
    let files: Vec<&str> = damage.iter().map(|damage| damage.file.as_str()).collect();
    fix(&files, state_dir)
}

/// [`damage_fix`] for damage to `files`.
fn fix(files: &[&str], state_dir: &str) -> String {
    let mut fix = format!(
        "stop the key with `pqkey stop`, keep a copy of {state_dir}, run `pqkey repair`, then \
         start the key again with `pqkey start`"
    );
    if files.contains(&PIN_STATE_FILE) {
        fix.push_str(" and set a new PIN with `pqkey pin`");
    }
    if files != [LARGE_BLOBS_FILE] {
        fix.push_str("; `pqkey reset` erases every passkey, so use it only as a last resort");
    }
    fix
}

/// What the key logs as it starts about `damage` to the credential store
/// in `state_dir`: [`damage_summary`], then [`damage_fix`].
#[must_use]
pub fn damage_log(damage: &[Damage], state_dir: &str) -> String {
    format!(
        "{}. {}",
        damage_summary(damage),
        sentence(&damage_fix(damage, state_dir))
    )
}

/// What the key logs as it starts when the credential store in `state_dir`
/// cannot be checked, failing with `err`: [`damage_unchecked`], then
/// [`damage_fix`].
#[must_use]
pub fn damage_unchecked_log(err: &StoreError, state_dir: &str) -> String {
    format!(
        "{}. {}",
        damage_unchecked(err),
        sentence(&damage_fix(&[], state_dir))
    )
}

/// `text` with its first letter capitalised.
fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default()
}

impl StoreError {
    /// What the key logs after this error when it reports damage to the
    /// credential set, a file or directory that is missing or cannot be
    /// used, or a record, signature counter, PIN state or large-blob array
    /// that fails authentication or decoding: where it is, what fails, and
    /// what to do.  `None` for any other error.
    #[must_use]
    pub fn damage_hint(&self) -> Option<String> {
        let file = match self {
            StoreError::CredentialSetUnavailable { object, .. } => object,
            StoreError::Corrupt { object, .. }
                if matches!(
                    kind(object),
                    Kind::Record | Kind::Counter | Kind::PinState | Kind::LargeBlobs
                ) =>
            {
                object
            }
            _ => return None,
        };
        Some(format!(
            "The credential store is damaged at {file}: {}. {}",
            consequence(kind(file), 1),
            sentence(&fix(&[file.as_str()], "the state directory"))
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD: &str =
        "credential-set/records/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const FIX: &str = "stop the key with `pqkey stop`, keep a copy of /state, run `pqkey \
                       repair`, then start the key again with `pqkey start`; `pqkey reset` \
                       erases every passkey, so use it only as a last resort";
    const PIN_STATE: &str = "the key treats its PIN as blocked and requires it, so it cannot \
                             register passkeys, sign in or set a new PIN";
    const LARGE_BLOBS: &str = "the key cannot return the large blobs that sites stored on it";

    /// The advice keeps a copy of the store with the key stopped before
    /// anything else, then repairs it and starts the key, and names reset
    /// once, last, as what erases every passkey.
    fn assert_reset_is_the_last_resort(text: &str) {
        let at = |part: &str| {
            text.find(part)
                .unwrap_or_else(|| panic!("{part:?} is not in {text:?}"))
        };
        assert!(at("top the key with `pqkey stop`") < at("keep a copy of"));
        assert!(at("keep a copy of") < at("run `pqkey repair`"));
        assert!(at("run `pqkey repair`") < at("then start the key again with `pqkey start`"));
        assert!(at("`pqkey start`") < at("`pqkey reset` erases every passkey"));
        assert!(text.ends_with("use it only as a last resort"), "{text}");
        assert_eq!(text.matches("pqkey reset").count(), 1, "{text}");
        assert_eq!(text.matches("pqkey repair").count(), 1, "{text}");
    }

    #[test]
    fn damage_names_its_file_and_fault() {
        assert_eq!(
            Damage::missing(RECORD).to_string(),
            format!("{RECORD} is missing")
        );
        assert_eq!(
            Damage::corrupt("credential-set/active", Corruption::Authentication).to_string(),
            "credential-set/active is corrupt: authentication failed"
        );
        let unreadable = Damage::unreadable(
            "credential-format",
            StoreError::Io {
                path: "/state/credential-format".into(),
                source: std::io::Error::other("injected"),
            },
        );
        assert_eq!(
            unreadable.to_string(),
            "credential-format cannot be read: /state/credential-format: injected"
        );
        let corrupt = Damage::unreadable(
            "credential-format",
            StoreError::Corrupt {
                object: "credential-format".into(),
                reason: Corruption::Length,
            },
        );
        assert_eq!(
            corrupt,
            Damage::corrupt("credential-format", Corruption::Length)
        );
    }

    /// Records are told from membership metadata and from the legacy
    /// directory by their path, wherever they are.
    #[test]
    fn the_path_tells_what_damage_costs() {
        for record in [
            RECORD,
            &RECORD.replace("credential-set/records/", "credential-set/"),
            &RECORD.replace("credential-set/records/", "credentials/"),
        ] {
            assert_eq!(kind(record), Kind::Record, "{record}");
        }
        for membership in [
            "credential-format",
            "credential-set/active",
            "credential-set",
        ] {
            assert_eq!(kind(membership), Kind::Membership, "{membership}");
            assert!(!Damage::missing(membership).is_record(), "{membership}");
        }
        assert_eq!(kind("credentials"), Kind::LegacyDirectory);
        assert!(!Damage::missing("credentials").is_record());
        assert!(Damage::missing(RECORD).is_record());
        assert_eq!(kind("signature-counter"), Kind::Counter);
        assert!(!Damage::missing("signature-counter").is_record());
        assert_eq!(kind("pin-state"), Kind::PinState);
        assert_eq!(kind("large-blobs"), Kind::LargeBlobs);
        for file in ["pin-state", "large-blobs", "signature-counter"] {
            assert!(!kind(file).in_set(), "{file}");
            assert!(!Damage::missing(file).is_record(), "{file}");
        }
        assert!(Damage::missing("pin-state").is_pin_state());
        for file in [RECORD, "large-blobs", "signature-counter", "credential-set"] {
            assert!(!Damage::missing(file).is_pin_state(), "{file}");
        }
    }

    /// Operations refuse damage as the store always has: as unavailable
    /// membership, naming the file, or the first of several and each in the
    /// detail.
    #[test]
    fn damage_refuses_operations_as_unavailable_membership() {
        let StoreError::CredentialSetUnavailable { object, detail } =
            unavailable(&[Damage::missing(RECORD)])
        else {
            panic!("not unavailable membership");
        };
        assert_eq!(object, RECORD);
        assert_eq!(detail, format!("{RECORD} is missing"));
        let StoreError::CredentialSetUnavailable { object, detail } = unavailable(&[
            Damage::missing("credential-set"),
            Damage::missing(CREDENTIALS_DIR),
        ]) else {
            panic!("not unavailable membership");
        };
        assert_eq!(object, "credential-set");
        assert_eq!(detail, "credential-set is missing; credentials is missing");
    }

    /// The whole of each summary: the files, and what fails, for each kind
    /// of damage.
    #[test]
    fn a_summary_names_the_files_and_what_fails() {
        assert_eq!(
            damage_summary(&[Damage::corrupt(RECORD, Corruption::Authentication)]),
            format!(
                "the credential store is damaged ({RECORD} is corrupt: authentication failed): \
                 the key cannot register passkeys, or use the credential in that file"
            )
        );
        let other = RECORD.replace("records/0123", "records/4567");
        assert_eq!(
            damage_summary(&[Damage::missing(RECORD), Damage::missing(other.clone())]),
            format!(
                "the credential store is damaged ({RECORD} is missing; {other} is missing): the \
                 key cannot register passkeys, or use the credentials in those files"
            )
        );
        for file in [
            "credential-set/active",
            "credential-format",
            "credential-set",
        ] {
            assert_eq!(
                damage_summary(&[Damage::missing(file)]),
                format!(
                    "the credential store is damaged ({file} is missing): the key cannot \
                     register, use or list passkeys"
                )
            );
        }
        assert_eq!(
            damage_summary(&[Damage::missing("credentials")]),
            "the credential store is damaged (credentials is missing): the key cannot use any \
             passkeys that were in it"
        );
        // A store whose format marker shows the managed layout, and that has
        // lost the directories of both layouts.
        assert_eq!(
            damage_summary(&[
                Damage::missing("credential-set"),
                Damage::missing("credentials")
            ]),
            "the credential store is damaged (credential-set is missing; credentials is \
             missing): the key cannot register, use or list passkeys"
        );
        assert_eq!(
            damage_consequence(&[Damage::missing(RECORD)]),
            "the key cannot register passkeys, or use the credential in that file"
        );
    }

    /// A damaged signature counter costs what it costs whatever else is
    /// damaged, and it is said first, as the inspection names it first; what
    /// damage to the credential set costs follows, counting only its files.
    #[test]
    fn a_damaged_counter_is_said_first_and_costs_the_set_nothing() {
        const COUNTER: &str = "the key cannot sign in to sites that registered it as a security \
                               key and whose credentials it did not store";
        let counter = Damage::corrupt("signature-counter", Corruption::Authentication);
        assert_eq!(
            damage_summary(std::slice::from_ref(&counter)),
            format!(
                "the credential store is damaged (signature-counter is corrupt: authentication \
                 failed): {COUNTER}"
            )
        );
        let other = RECORD.replace("records/0123", "records/4567");
        for (set, costs) in [
            (
                vec![Damage::missing(RECORD)],
                "the key cannot register passkeys, or use the credential in that file",
            ),
            (
                vec![Damage::missing(RECORD), Damage::missing(other)],
                "the key cannot register passkeys, or use the credentials in those files",
            ),
            (
                vec![Damage::missing("credential-set/active")],
                "the key cannot register, use or list passkeys",
            ),
            (
                vec![Damage::missing("credentials")],
                "the key cannot use any passkeys that were in it",
            ),
        ] {
            let damage: Vec<_> = std::iter::once(counter.clone()).chain(set).collect();
            assert_eq!(damage_consequence(&damage), format!("{COUNTER}; {costs}"));
        }
        let unreadable = Damage::unreadable(
            "signature-counter",
            StoreError::Io {
                path: "/state/signature-counter".into(),
                source: std::io::Error::other("injected"),
            },
        );
        assert_eq!(
            unreadable.to_string(),
            "signature-counter cannot be read: /state/signature-counter: injected"
        );
        assert_eq!(damage_consequence(&[unreadable]), COUNTER);
    }

    /// Many damaged files are counted after the first few.
    #[test]
    fn a_summary_counts_files_beyond_the_first_three() {
        let damage: Vec<_> = (0..5)
            .map(|i| Damage::missing(format!("credentials/{}", format!("{i:x}").repeat(64))))
            .collect();
        let summary = damage_summary(&damage);
        assert!(summary.contains(&damage[2].to_string()), "{summary}");
        assert!(!summary.contains(&damage[3].to_string()), "{summary}");
        assert!(summary.contains("; and 2 more): "), "{summary}");
        assert!(
            summary.ends_with("use the credentials in those files"),
            "{summary}"
        );
    }

    /// Damage to the credential set or the counter, and a store that cannot
    /// be checked, have one fix, which repairs the store.
    #[test]
    fn the_fix_keeps_a_copy_and_leaves_reset_last() {
        let counter = Damage::corrupt("signature-counter", Corruption::Authentication);
        for damage in [vec![Damage::missing(RECORD)], vec![counter], Vec::new()] {
            assert_eq!(damage_fix(&damage, "/state"), FIX, "{damage:?}");
        }
        assert_reset_is_the_last_resort(FIX);
        let damage = [Damage::missing(RECORD)];
        assert_eq!(
            damage_log(&damage, "/state"),
            format!("{}. S{}", damage_summary(&damage), &FIX[1..])
        );
        let err = StoreError::Random;
        assert_eq!(
            damage_unchecked_log(&err, "/state"),
            format!(
                "the credential store cannot be checked: {err}. S{}",
                &FIX[1..]
            )
        );
    }

    /// What a damaged PIN state and large-blob array cost: each its own, in
    /// the order the inspection names them, before what the credential set's
    /// damage costs.
    #[test]
    fn a_damaged_pin_state_or_array_costs_its_own() {
        let pin = Damage::corrupt("pin-state", Corruption::Authentication);
        let blobs = Damage::corrupt("large-blobs", Corruption::Encoding);
        assert_eq!(
            damage_summary(std::slice::from_ref(&pin)),
            format!(
                "the credential store is damaged (pin-state is corrupt: authentication failed): \
                 {PIN_STATE}"
            )
        );
        assert_eq!(
            damage_summary(std::slice::from_ref(&blobs)),
            format!(
                "the credential store is damaged (large-blobs is corrupt: malformed record \
                 encoding): {LARGE_BLOBS}"
            )
        );
        let counter = Damage::corrupt("signature-counter", Corruption::Authentication);
        assert_eq!(
            damage_consequence(&[
                pin,
                blobs,
                counter,
                Damage::missing("credential-set/active")
            ]),
            format!(
                "{PIN_STATE}; {LARGE_BLOBS}; the key cannot sign in to sites that registered it \
                 as a security key and whose credentials it did not store; the key cannot \
                 register, use or list passkeys"
            )
        );
    }

    /// A damaged PIN state or large-blob array has the fix every damage has,
    /// in one sequence with any other: repair, with a new PIN after it for
    /// the PIN state, and reset the last resort, which the array alone does
    /// not need.
    #[test]
    fn a_damaged_pin_state_or_array_is_repaired_in_one_sequence() {
        let pin_fix = FIX.replace(
            "`pqkey start`;",
            "`pqkey start` and set a new PIN with `pqkey pin`;",
        );
        assert_reset_is_the_last_resort(&pin_fix);
        let pin = Damage::corrupt("pin-state", Corruption::Authentication);
        let blobs = Damage::corrupt("large-blobs", Corruption::Authentication);
        assert_eq!(damage_fix(std::slice::from_ref(&pin), "/state"), pin_fix);
        assert_eq!(
            damage_fix(std::slice::from_ref(&blobs), "/state"),
            "stop the key with `pqkey stop`, keep a copy of /state, run `pqkey repair`, then start \
             the key again with `pqkey start`"
        );
        assert_eq!(damage_fix(&[pin.clone(), blobs.clone()], "/state"), pin_fix);
        let counter = Damage::corrupt("signature-counter", Corruption::Authentication);
        for other in [Damage::missing(RECORD), counter] {
            let damage = [pin.clone(), blobs.clone(), other.clone()];
            assert_eq!(damage_fix(&damage, "/state"), pin_fix);
            assert_eq!(
                damage_log(&damage, "/state"),
                format!("{}. S{}", damage_summary(&damage), &pin_fix[1..])
            );
            assert_eq!(damage_fix(&[blobs.clone(), other], "/state"), FIX);
        }
    }

    /// Errors about membership metadata, about the legacy directory, about
    /// records, the counter, the PIN state and the large-blob array get the
    /// advice for their kind of damage; others get none.
    #[test]
    fn hints_follow_errors_that_report_damage() {
        let fix = "Stop the key with `pqkey stop`, keep a copy of the state directory, run \
                   `pqkey repair`, then start the key again with `pqkey start`; `pqkey reset` \
                   erases every passkey, so use it only as a last resort";
        for (error, hint) in [
            (
                unavailable(&[Damage::corrupt(
                    "credential-set/active",
                    Corruption::Authentication,
                )]),
                "The credential store is damaged at credential-set/active: the key cannot \
                 register, use or list passkeys."
                    .to_owned(),
            ),
            (
                unavailable(&[Damage::missing("credentials")]),
                "The credential store is damaged at credentials: the key cannot use any passkeys \
                 that were in it."
                    .to_owned(),
            ),
            (
                StoreError::Corrupt {
                    object: RECORD.into(),
                    reason: Corruption::Authentication,
                },
                format!(
                    "The credential store is damaged at {RECORD}: the key cannot register \
                     passkeys, or use the credential in that file."
                ),
            ),
            (
                unavailable(&[Damage::missing(RECORD)]),
                format!(
                    "The credential store is damaged at {RECORD}: the key cannot register \
                     passkeys, or use the credential in that file."
                ),
            ),
            (
                StoreError::Corrupt {
                    object: "signature-counter".into(),
                    reason: Corruption::Authentication,
                },
                "The credential store is damaged at signature-counter: the key cannot sign in \
                 to sites that registered it as a security key and whose credentials it did not \
                 store."
                    .to_owned(),
            ),
        ] {
            let found = error.damage_hint().unwrap();
            assert_eq!(found, format!("{hint} {fix}"));
            assert_reset_is_the_last_resort(&found);
        }
        let corrupt = |object: &str| StoreError::Corrupt {
            object: object.into(),
            reason: Corruption::Authentication,
        };
        assert_eq!(
            corrupt("pin-state").damage_hint().unwrap(),
            format!(
                "The credential store is damaged at pin-state: {PIN_STATE}. {}",
                fix.replace(
                    "`pqkey start`;",
                    "`pqkey start` and set a new PIN with `pqkey pin`;"
                )
            )
        );
        assert_eq!(
            corrupt("large-blobs").damage_hint().unwrap(),
            format!(
                "The credential store is damaged at large-blobs: {LARGE_BLOBS}. Stop the key \
                 with `pqkey stop`, keep a copy of the state directory, run `pqkey repair`, then \
                 start the key again with `pqkey start`"
            )
        );
        for other in [
            corrupt("attestation"),
            StoreError::Full { max: 1 },
            StoreError::Random,
            StoreError::Io {
                path: "/state/credential-set/active".into(),
                source: std::io::Error::other("injected"),
            },
        ] {
            assert_eq!(other.damage_hint(), None, "{other}");
        }
    }
}
