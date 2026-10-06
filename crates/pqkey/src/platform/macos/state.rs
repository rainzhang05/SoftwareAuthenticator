//! The macOS application-support directory.

use std::{ffi::OsStr, path::PathBuf};

fn state_dir(home: Option<&OsStr>) -> PathBuf {
    match home {
        Some(home) => PathBuf::from(home).join("Library/Application Support/pqkey"),
        None => PathBuf::from(".").join("pqkey"),
    }
}

/// Where state lives unless a command-line or environment override says so.
pub fn default_state_dir() -> PathBuf {
    state_dir(std::env::var_os("HOME").as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_uses_application_support_and_keeps_the_home_path() {
        assert_eq!(
            state_dir(Some(OsStr::new("/Users/a user"))),
            PathBuf::from("/Users/a user/Library/Application Support/pqkey")
        );
    }

    #[test]
    fn an_absent_home_keeps_the_relative_fallback() {
        assert_eq!(state_dir(None), PathBuf::from("./pqkey"));
    }
}
