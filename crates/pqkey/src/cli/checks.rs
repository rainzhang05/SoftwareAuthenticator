//! Diagnostics rendered by the portable command line.

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
