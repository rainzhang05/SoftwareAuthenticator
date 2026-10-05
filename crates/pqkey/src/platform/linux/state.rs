//! Linux state paths.

use std::path::PathBuf;

/// The name of the default state directory.
const STATE_DIR_NAME: &str = "pqkey";

/// `name` in the user's data directory: `$XDG_DATA_HOME/name`, or
/// `~/.local/share/name` when XDG_DATA_HOME is unset.
fn data_dir(name: &str) -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(dir).join(name)
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".local/share").join(name)
    } else {
        PathBuf::from(".").join(name)
    }
}

/// Where the state lives unless `--state-dir` says otherwise.
pub fn default_state_dir() -> PathBuf {
    data_dir(STATE_DIR_NAME)
}
