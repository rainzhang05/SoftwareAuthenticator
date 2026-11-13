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

use nix::{
    errno::Errno,
    sys::statvfs::{FsFlags, statvfs},
};

pub use crate::platform::default_state_dir;

/// Create the state directory if needed and make it private to this user.
///
/// A new directory is created with mode 0700, and an existing one is
/// tightened to it. A shared directory, one with the sticky bit set such as
/// `/tmp`, is refused instead: making it private would take it away from
/// everyone else. Every error names the directory.
pub fn ensure_state_dir(path: &Path) -> io::Result<()> {
    let create = |err| path_error(err, "create the state directory", path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(create)?;
    }
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => return Ok(()),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(create(err)),
    }
    let metadata =
        fs::metadata(path).map_err(|err| path_error(err, "read the state directory", path))?;
    if !metadata.is_dir() {
        return Err(io::Error::other(format!(
            "the state directory {} exists but is not a directory",
            path.display()
        )));
    }
    if metadata.permissions().mode() & 0o1000 != 0 {
        return Err(io::Error::other(format!(
            "{} is a shared directory (its sticky bit is set); use a directory of your own",
            path.display()
        )));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|err| path_error(err, "restrict access to the state directory", path))
}

/// `err`, from trying to `act` on `path`, with its kind and the path: an
/// error such as "No space left on device" alone does not say where.
pub(crate) fn path_error(err: io::Error, act: &str, path: &Path) -> io::Error {
    io::Error::new(
        err.kind(),
        format!("cannot {act} {}: {err}", path.display()),
    )
}

/// The room left on a filesystem, as statvfs(3) reports it to a process
/// without privileges, such as the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Room {
    /// Bytes, or `None` where the filesystem reports no size, as procfs does.
    pub bytes: Option<u64>,
    /// Inodes, that is files and directories, or `None` where the filesystem
    /// has no fixed number of them, as btrfs does.
    pub files: Option<u64>,
    /// Whether it is mounted read-only.
    pub read_only: bool,
}

/// The [`Room`] on the filesystem of `state_dir`, or for a state directory
/// that does not exist yet, on that of its nearest ancestor, where the key
/// would create it. It writes, creates and flushes nothing.
pub fn room(state_dir: &Path) -> io::Result<Room> {
    let mut found = Err(Errno::ENOENT);
    for dir in state_dir.ancestors() {
        // The last ancestor of a relative path is empty: the current directory.
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        found = statvfs(dir);
        if found != Err(Errno::ENOENT) {
            break;
        }
    }
    let found = found?;
    let count = |n: u128| u64::try_from(n).unwrap_or(u64::MAX);
    Ok(Room {
        bytes: (found.blocks() > 0).then(|| {
            count(u128::from(found.blocks_available()) * u128::from(found.fragment_size()))
        }),
        files: (found.files() > 0).then(|| count(u128::from(found.files_available()))),
        read_only: found.flags().contains(FsFlags::ST_RDONLY),
    })
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

    /// The state directory that cannot be created, or that is something
    /// else, is named, with the error.
    #[test]
    fn a_state_directory_that_cannot_be_made_is_named() {
        let dir = TempDir::new("state-dir-errors");
        let file = dir.path().join("file");
        fs::write(&file, b"").unwrap();
        let under_file = file.join("pqkey");
        let err = ensure_state_dir(&under_file).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            err.to_string(),
            format!(
                "cannot create the state directory {}: File exists (os error 17)",
                under_file.display()
            )
        );
        assert_eq!(
            ensure_state_dir(&file).unwrap_err().to_string(),
            format!(
                "the state directory {} exists but is not a directory",
                file.display()
            )
        );
    }

    /// The room on the filesystem of the state directory, or of the
    /// directory it would be created in, which is not created; and the error
    /// where statvfs(3) fails, as under a file. procfs reports no size.
    #[test]
    fn room_is_that_of_the_state_directorys_filesystem() {
        let dir = TempDir::new("state-room");
        let found = room(dir.path()).unwrap();
        assert!(!found.read_only, "{found:?}");
        assert!(found.bytes.is_some(), "{found:?}");
        let missing = dir.path().join("missing").join("pqkey");
        let ancestor = room(&missing).unwrap();
        assert_eq!(
            (
                ancestor.read_only,
                ancestor.bytes.is_some(),
                ancestor.files.is_some()
            ),
            (found.read_only, true, found.files.is_some())
        );
        assert!(!dir.path().join("missing").exists());
        // A relative path, in the current directory.
        assert!(room(Path::new("pqkey-room-missing")).is_ok());
        let file = dir.path().join("file");
        fs::write(&file, b"").unwrap();
        assert_eq!(
            room(&file.join("pqkey")).unwrap_err().kind(),
            io::ErrorKind::NotADirectory
        );
        let proc = room(Path::new("/proc")).unwrap();
        assert_eq!((proc.bytes, proc.files), (None, None));
    }

    #[test]
    fn the_default_state_dir_is_named_pqkey() {
        assert_eq!(default_state_dir().file_name().unwrap(), "pqkey");
    }
}
