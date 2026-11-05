//! Damage to a file store's credential set: which file, what is wrong with
//! it, what fails because of it, and what to do about it.
//!
//! The key's log ([`StoreError::damage_hint`], [`damage_log`],
//! [`damage_unchecked_log`]) and `pqkey status` ([`damage_summary`],
//! [`damage_unchecked`], [`damage_fix`]) take all their wording from here, so
//! that it changes in one place.  Each claim the wording makes about what
//! fails is tested for every kind of damage it is said of
//! (`tests/store/damage.rs`, and the `pqkey` crate's status and start-up
//! tests); it claims nothing about what still works.

use core::fmt;

use super::file::CREDENTIALS_DIR;
use super::keys::is_credential_file_name;
use super::{Corruption, StoreError};

/// How many damaged files a summary names before it counts the rest.
const NAMED: usize = 3;

/// Why an inspection whose looks never agreed could not check the store.
pub(super) const UNSETTLED: &str =
    "it kept changing while it was checked; run `pqkey status` again";

/// A file or directory of a [`FileStore`](super::FileStore)'s credential set
/// that is missing or cannot be used, as
/// [`FileStore::inspect`](super::FileStore::inspect) finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Damage {
    /// Its path, relative to the state directory: a credential's record, such
    /// as `credential-set/records/<64 hex digits>`; the membership metadata
    /// of a store in the managed layout, `credential-format` or
    /// `credential-set/active`, or the directory `credential-set` that holds
    /// it; or a legacy store's directory `credentials`.
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
    /// Reading it failed, for this reason. Only membership metadata is
    /// damaged by a failed read: the store cannot do without it.
    Unreadable(String),
}

impl Damage {
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

    /// The error with which operations refuse to go on despite this damage.
    pub(super) fn unavailable(self) -> StoreError {
        StoreError::CredentialSetUnavailable {
            detail: self.to_string(),
            object: self.file,
        }
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

/// What damage to a file costs, which its path tells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
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
    } else {
        Kind::Membership
    }
}

/// What fails after damage of `kind` to `files` files: only what fails
/// whatever else is damaged, and for a legacy store's lost `credentials`
/// directory only what fails both before and after the key opens the store,
/// which creates the directory again, empty.  Nothing is said of the PIN:
/// the inspection does not read the PIN state, which `pqkey status` shows on
/// a line of its own.
fn consequence(kind: Kind, files: usize) -> &'static str {
    match (kind, files) {
        (Kind::Record, 1) => "the key cannot register passkeys, or use the credential in that file",
        (Kind::Record, _) => {
            "the key cannot register passkeys, or use the credentials in those files"
        }
        (Kind::LegacyDirectory, _) => "the key cannot use the passkeys that were in that directory",
        (Kind::Membership, _) => "the key cannot register, use or list passkeys",
    }
}

/// What `pqkey status` says is wrong with a credential store found to have
/// `damage`, which is not empty: the damaged files and what fails.
#[must_use]
pub fn damage_summary(damage: &[Damage]) -> String {
    let mut files: Vec<String> = damage.iter().take(NAMED).map(Damage::to_string).collect();
    if damage.len() > NAMED {
        files.push(format!("and {} more", damage.len() - NAMED));
    }
    let worst = damage
        .iter()
        .map(|damage| kind(&damage.file))
        .max()
        .unwrap_or(Kind::Record);
    format!(
        "the credential store is damaged ({}): {}",
        files.join("; "),
        consequence(worst, damage.len())
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
/// key stopped, and reset only as the last resort.
#[must_use]
pub fn damage_fix(state_dir: &str) -> String {
    format!(
        "stop the key with `pqkey stop`, keep a copy of {state_dir}, then start it again with \
         `pqkey start`; `pqkey reset` erases every passkey, so use it only as a last resort"
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
    /// used: where it is, what fails, and what to do. `None` for any other
    /// error.
    #[must_use]
    pub fn damage_hint(&self) -> Option<String> {
        let file = match self {
            StoreError::CredentialSetUnavailable { object, .. } => object,
            StoreError::Corrupt { object, .. } if kind(object) == Kind::Record => object,
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
    const FIX: &str = "stop the key with `pqkey stop`, keep a copy of /state, then start it \
                       again with `pqkey start`; `pqkey reset` erases every passkey, so use it \
                       only as a last resort";

    /// The advice keeps a copy of the store with the key stopped before
    /// anything else, and names reset once, last, as what erases every
    /// passkey.
    fn assert_reset_is_the_last_resort(text: &str) {
        let at = |part: &str| {
            text.find(part)
                .unwrap_or_else(|| panic!("{part:?} is not in {text:?}"))
        };
        assert!(at("top the key with `pqkey stop`") < at("keep a copy of"));
        assert!(at("keep a copy of") < at("then start it again with `pqkey start`"));
        assert!(at("`pqkey start`") < at("`pqkey reset` erases every passkey"));
        assert!(text.ends_with("use it only as a last resort"), "{text}");
        assert_eq!(text.matches("pqkey reset").count(), 1, "{text}");
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
        }
        assert_eq!(kind("credentials"), Kind::LegacyDirectory);
    }

    /// Operations refuse damage as the store always has: as unavailable
    /// membership, naming the file.
    #[test]
    fn damage_refuses_operations_as_unavailable_membership() {
        let StoreError::CredentialSetUnavailable { object, detail } =
            Damage::missing(RECORD).unavailable()
        else {
            panic!("not unavailable membership");
        };
        assert_eq!(object, RECORD);
        assert_eq!(detail, format!("{RECORD} is missing"));
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
            "the credential store is damaged (credentials is missing): the key cannot use the \
             passkeys that were in that directory"
        );
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
        let fix = "Stop the key with `pqkey stop`, keep a copy of the state directory, then \
                   start it again with `pqkey start`; `pqkey reset` erases every passkey, so use \
                   it only as a last resort";
        for (error, hint) in [
            (
                Damage::corrupt("credential-set/active", Corruption::Authentication).unavailable(),
                "The credential store is damaged at credential-set/active: the key cannot \
                 register, use or list passkeys."
                    .to_owned(),
            ),
            (
                Damage::missing("credentials").unavailable(),
                "The credential store is damaged at credentials: the key cannot use the passkeys \
                 that were in that directory."
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
                Damage::missing(RECORD).unavailable(),
                format!(
                    "The credential store is damaged at {RECORD}: the key cannot register \
                     passkeys, or use the credential in that file."
                ),
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
