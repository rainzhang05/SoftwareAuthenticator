//! Damage to a file store's credential set and to its shared signature
//! counter: which file, what is wrong with it, what fails because of it, and
//! what to do about it.
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

use super::file::{CREDENTIALS_DIR, SIGNATURE_COUNTER_FILE};
use super::keys::is_credential_file_name;
use super::{Corruption, StoreError};

/// How many damaged files a summary names before it counts the rest.
const NAMED: usize = 3;

/// Why an inspection whose looks never agreed could not check the store.
/// What to do follows it ([`damage_fix`]): `pqkey repair` looks again with
/// the key stopped, so that none of the key's own changes come between its
/// looks.
pub(super) const UNSETTLED: &str = "it kept changing while it was checked";

/// A file or directory of a [`FileStore`](super::FileStore)'s credential set,
/// or its shared signature counter, that is missing or cannot be used, as
/// [`FileStore::inspect`](super::FileStore::inspect) finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Damage {
    /// Its path, relative to the state directory: a credential's record, such
    /// as `credential-set/records/<64 hex digits>`; the membership metadata
    /// of a store in the managed layout, `credential-format` or
    /// `credential-set/active`, or the directory `credential-set` that holds
    /// it; a legacy store's directory `credentials`; or the shared signature
    /// counter, `signature-counter`.
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
    /// replace.  A record that cannot be read fails the inspection instead.
    Unreadable(String),
}

impl Damage {
    /// Whether the damaged file is a credential's record, rather than
    /// membership metadata or a directory.
    #[must_use]
    pub fn is_record(&self) -> bool {
        kind(&self.file) == Kind::Record
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
/// kinds are ordered by cost; the counter's costs nothing of the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
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

fn kind(file: &str) -> Kind {
    if file.rsplit('/').next().is_some_and(is_credential_file_name) {
        Kind::Record
    } else if file == CREDENTIALS_DIR {
        Kind::LegacyDirectory
    } else if file == SIGNATURE_COUNTER_FILE {
        Kind::Counter
    } else {
        Kind::Membership
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
/// key, over CTAP 2 or U2F, unless the key stores the credential.  Nothing
/// is said of the PIN: the inspection does not read the PIN state, which
/// `pqkey status` shows on a line of its own.
fn consequence(kind: Kind, files: usize) -> &'static str {
    match (kind, files) {
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
/// empty, as [`damage_summary`] says it: what damage to the signature counter
/// costs, if it is damaged, then what the worst damage to the credential set
/// costs, which only the set's damaged files count towards.
#[must_use]
pub fn damage_consequence(damage: &[Damage]) -> String {
    let set: Vec<Kind> = damage
        .iter()
        .map(|damage| kind(&damage.file))
        .filter(|&kind| kind != Kind::Counter)
        .collect();
    let mut consequences = Vec::new();
    if set.len() < damage.len() {
        consequences.push(consequence(Kind::Counter, 1));
    }
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

/// What to do about damage to the credential store in `state_dir`, as
/// `pqkey status` and the key's log say it: keep a copy of the store with the
/// key stopped, repair it, and reset only as the last resort.
#[must_use]
pub fn damage_fix(state_dir: &str) -> String {
    format!(
        "stop the key with `pqkey stop`, keep a copy of {state_dir}, run `pqkey repair`, then \
         start the key again with `pqkey start`; `pqkey reset` erases every passkey, so use it \
         only as a last resort"
    )
}

/// What the key logs as it starts about `damage` to the credential store
/// in `state_dir`: [`damage_summary`], then [`damage_fix`].
#[must_use]
pub fn damage_log(damage: &[Damage], state_dir: &str) -> String {
    format!(
        "{}. {}",
        damage_summary(damage),
        sentence(&damage_fix(state_dir))
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
        sentence(&damage_fix(state_dir))
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
    /// used, or a signature counter that fails authentication or decoding:
    /// where it is, what fails, and what to do. `None` for any other error.
    #[must_use]
    pub fn damage_hint(&self) -> Option<String> {
        let file = match self {
            StoreError::CredentialSetUnavailable { object, .. } => object,
            StoreError::Corrupt { object, .. }
                if matches!(kind(object), Kind::Record | Kind::Counter) =>
            {
                object
            }
            _ => return None,
        };
        Some(format!(
            "The credential store is damaged at {file}: {}. {}",
            consequence(kind(file), 1),
            sentence(&damage_fix("the state directory"))
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

    #[test]
    fn the_fix_keeps_a_copy_and_leaves_reset_last() {
        assert_eq!(damage_fix("/state"), FIX);
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

    /// Errors about membership metadata, about the legacy directory and
    /// about records get the advice for their kind of damage; others get
    /// none.
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
        for other in [
            StoreError::Corrupt {
                object: "pin-state".into(),
                reason: Corruption::Authentication,
            },
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
