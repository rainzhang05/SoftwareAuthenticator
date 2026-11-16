//! Helpers shared by the store's unit tests.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use rand_core::Rng;

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
        crate::crypto::os_rng().fill_bytes(&mut random);
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

/// Every regular file under `dir`, by its path relative to `dir`.
pub(crate) fn files(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut found = BTreeMap::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(current) = dirs.pop() {
        for entry in fs::read_dir(&current).unwrap() {
            let path = entry.unwrap().path();
            let metadata = fs::symlink_metadata(&path).unwrap();
            if metadata.is_dir() {
                dirs.push(path);
            } else if metadata.is_file() {
                found.insert(
                    path.strip_prefix(dir).unwrap().to_path_buf(),
                    fs::read(&path).unwrap(),
                );
            }
        }
    }
    found
}

/// A copy of `from`, every file and directory, at `to`, with each symbolic
/// link copied as a link: those these tests make point by relative names.
pub(crate) fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let path = entry.unwrap().path();
        let target = to.join(path.file_name().unwrap());
        let metadata = fs::symlink_metadata(&path).unwrap();
        if metadata.file_type().is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(&path).unwrap(), &target).unwrap();
        } else if metadata.is_dir() {
            copy_tree(&path, &target);
        } else {
            fs::copy(&path, &target).unwrap();
        }
    }
}
