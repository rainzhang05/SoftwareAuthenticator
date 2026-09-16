//! Helpers shared by the store's unit tests.

use std::fs;
use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};

use super::fsio::hex;

/// A uniquely named directory under the system temporary directory, removed
/// together with its contents when dropped.
///
/// This stands in for the `tempfile` crate, which would pull `rustix` into the
/// dependency graph and with it a second, differently featured build of
/// `bitflags`.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new() -> Self {
        let mut random = [0u8; 16];
        OsRng.fill_bytes(&mut random);
        let path = std::env::temp_dir().join(format!("authenticator-store-{}", hex(&random)));
        fs::create_dir(&path).expect("create temporary directory");
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
