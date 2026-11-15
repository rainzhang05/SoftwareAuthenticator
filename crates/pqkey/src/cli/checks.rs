//! Diagnostics rendered by the portable command line.

/// The fix for a full filesystem where the key writes, in status and start-up errors.
pub(crate) const FREE_SPACE: &str =
    "free some space on that filesystem (`df -h` and `df -i` show what each one has left)";
/// The fix for a read-only filesystem where the key writes, in the same places.
pub(crate) const MAKE_WRITABLE: &str = "remount that filesystem read-write (one the kernel made \
    read-only after an error needs `fsck` first)";

/// Something the key needs that is missing, and how to fix it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    pub what: String,
    pub fix: String,
}

impl Problem {
    pub(crate) fn new(what: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            fix: fix.into(),
        }
    }
}
