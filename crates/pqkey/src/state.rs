//! The state directory: where the key keeps its
//! [`FileStore`](pqkey_ctap::store::FileStore), and how it is created.
//!
//! Only the running key reads and writes the store. The commands that manage
//! it go through the key over CTAP ([`crate::client`]), so its PIN rules,
//! retry counters and reset window apply to them as to a browser.

use std::{
    fs::{self, DirBuilder},
    io,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::Path,
};

pub use crate::platform::default_state_dir;

/// Create the state directory if needed and make it private to this user.
///
/// A new directory is created with mode 0700, and an existing one is
/// tightened to it. A shared directory, one with the sticky bit set such as
/// `/tmp`, is refused instead: making it private would take it away from
/// everyone else.
pub fn ensure_state_dir(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => return Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err),
    }
    let metadata = fs::metadata(path)?;
    if !metadata.is_dir() {
        return Err(io::Error::other("state path exists but is not a directory"));
    }
    if metadata.permissions().mode() & 0o1000 != 0 {
        return Err(io::Error::other(format!(
            "{} is a shared directory (its sticky bit is set); use a directory of your own",
            path.display()
        )));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TempDir;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn the_state_directory_is_private_and_never_a_shared_one() {
        let dir = TempDir::new("state-dir-mode");
        let fresh = dir.path().join("parent").join("state");
        ensure_state_dir(&fresh).unwrap();
        assert_eq!(mode(&fresh), 0o700);

        let loose = dir.path().join("loose");
        fs::create_dir(&loose).unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_state_dir(&loose).unwrap();
        assert_eq!(mode(&loose), 0o700);

        let shared = dir.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        let err = ensure_state_dir(&shared).unwrap_err();
        assert!(err.to_string().contains("sticky bit"), "{err}");
        assert_eq!(mode(&shared), 0o1777);
    }

    #[test]
    fn the_default_state_dir_is_named_pqkey() {
        assert_eq!(default_state_dir().file_name().unwrap(), "pqkey");
    }
}
