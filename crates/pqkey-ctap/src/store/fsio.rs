//! Filesystem primitives with the permission and durability guarantees the
//! file-backed store relies on.
//!
//! * Directories are created `0700` and files `0600`, with the mode passed to
//!   the creating system call, so no file or directory is ever visible with
//!   wider permissions.  (The process umask can only narrow them further.)
//! * Files are never written in place.  Contents go to a fresh, uniquely named
//!   temporary file in the same directory, which is flushed with `fsync` before
//!   it is renamed or linked into place, and the directory is flushed after
//!   that, so a crash leaves either the old file or the complete new one.

use std::fs::{self, DirBuilder, File, OpenOptions, Permissions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use getrandom::SysRng;
use rand_core::TryRng;

use super::StoreError;

/// Mode of every directory the store creates.
pub(crate) const DIR_MODE: u32 = 0o700;
/// Mode of every file the store creates.
pub(crate) const FILE_MODE: u32 = 0o600;
/// Prefix of temporary files.  Record names never start with a dot, so a
/// leftover temporary file can never be mistaken for a record.
pub(crate) const TEMP_PREFIX: &str = ".tmp-";

/// How often to retry when a randomly named temporary file already exists.
const TEMP_NAME_ATTEMPTS: usize = 8;

pub(crate) fn io_error(path: &Path, source: io::Error) -> StoreError {
    StoreError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Make sure `dir` exists, is a directory, and is private to its owner.
///
/// A directory created here gets mode `0700` at creation.  An existing
/// directory with group or other permission bits is tightened to `0700`, which
/// is safe because nothing is written into it before that happens.
pub(crate) fn ensure_private_dir(dir: &Path) -> Result<(), StoreError> {
    match DirBuilder::new().mode(DIR_MODE).create(dir) {
        Ok(()) => return sync_dir(parent_of(dir)),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
        Err(err) => return Err(io_error(dir, err)),
    }
    let metadata = fs::metadata(dir).map_err(|err| io_error(dir, err))?;
    if !metadata.is_dir() {
        return Err(io_error(
            dir,
            io::Error::new(ErrorKind::NotADirectory, "exists but is not a directory"),
        ));
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        log::warn!(
            "credential store: tightening permissions of {} from {mode:o} to {DIR_MODE:o}",
            dir.display()
        );
        fs::set_permissions(dir, Permissions::from_mode(DIR_MODE))
            .map_err(|err| io_error(dir, err))?;
    }
    Ok(())
}

/// Flush a directory, making the creation, renaming, and removal of entries in
/// it durable.
pub(crate) fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    let handle = File::open(dir).map_err(|err| io_error(dir, err))?;
    match handle.sync_all() {
        Ok(()) => Ok(()),
        // Some filesystems cannot flush a directory handle.  Nothing more can
        // be done there, and the file contents themselves were already flushed.
        Err(err) if matches!(err.kind(), ErrorKind::InvalidInput | ErrorKind::Unsupported) => {
            Ok(())
        }
        Err(err) => Err(io_error(dir, err)),
    }
}

/// Read at most `limit` bytes of a file, or `None` if it does not exist.
///
/// A file longer than `limit` yields exactly `limit + 1` bytes, so the caller
/// can reject it without reading all of it.
pub(crate) fn read_file(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, StoreError> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(io_error(path, err)),
    };
    let expected = file.metadata().map_err(|err| io_error(path, err))?.len();
    let capacity = usize::try_from(expected.min(limit.saturating_add(1))).unwrap_or(0);
    let mut contents = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut contents)
        .map_err(|err| io_error(path, err))?;
    Ok(Some(contents))
}

/// Atomically replace `dir/name` with `contents`.
pub(crate) fn replace_file(dir: &Path, name: &str, contents: &[u8]) -> Result<(), StoreError> {
    let target = dir.join(name);
    let temp = write_temp_file(dir, contents)?;
    if let Err(err) = fs::rename(&temp, &target) {
        let _ = fs::remove_file(&temp);
        return Err(io_error(&target, err));
    }
    sync_dir(dir)
}

/// Atomically create `dir/name` with `contents` unless it already exists.
///
/// Returns `false`, and leaves the existing file untouched, if `dir/name`
/// already exists.  Unlike opening the target with `O_EXCL` and then writing
/// to it, a concurrent reader never observes a partially written file, and a
/// crash never leaves an empty one behind: the complete file is linked into
/// place, and `link(2)` refuses to replace an existing name just as `O_EXCL`
/// does.
pub(crate) fn create_file_exclusive(
    dir: &Path,
    name: &str,
    contents: &[u8],
) -> Result<bool, StoreError> {
    let target = dir.join(name);
    let temp = write_temp_file(dir, contents)?;
    let linked = fs::hard_link(&temp, &target);
    let _ = fs::remove_file(&temp);
    match linked {
        Ok(()) => {
            sync_dir(dir)?;
            Ok(true)
        }
        Err(err) if err.kind() == ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(io_error(&target, err)),
    }
}

/// Remove a file if it exists, returning whether it did.  The caller is
/// responsible for flushing the directory.
pub(crate) fn remove_file_if_present(path: &Path) -> Result<bool, StoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(io_error(path, err)),
    }
}

/// Remove every non-directory entry of `dir`, then flush it.  A missing
/// directory counts as empty.
pub(crate) fn remove_all_files(dir: &Path) -> Result<(), StoreError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(io_error(dir, err)),
    };
    for entry in entries {
        let entry = entry.map_err(|err| io_error(dir, err))?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|err| io_error(&path, err))?;
        if file_type.is_dir() {
            log::warn!(
                "credential store: leaving unexpected directory {} in place",
                path.display()
            );
            continue;
        }
        remove_file_if_present(&path)?;
    }
    sync_dir(dir)
}

/// Remove leftover temporary files from `dir`, ignoring failures.
pub(crate) fn remove_temp_files(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Overwrite the whole of an open file with zeros and flush it.
///
/// Used on a key file that has already been unlinked, so no reader can see
/// the zeros.  On filesystems that update data in place this destroys the old
/// key's blocks; on copy-on-write filesystems and SSDs it may not, which is
/// why this is only a best effort.
pub(crate) fn overwrite_with_zeros(file: &File) -> io::Result<()> {
    const CHUNK: [u8; 4096] = [0; 4096];
    let len = file.metadata()?.len();
    let mut offset = 0u64;
    while offset < len {
        let remaining = usize::try_from(len - offset).unwrap_or(CHUNK.len());
        let chunk = &CHUNK[..remaining.min(CHUNK.len())];
        file.write_all_at(chunk, offset)?;
        offset += chunk.len() as u64;
    }
    file.sync_all()
}

/// Write `contents` to a new, uniquely named `0600` file in `dir`, flush it,
/// and return its path.
fn write_temp_file(dir: &Path, contents: &[u8]) -> Result<PathBuf, StoreError> {
    for _ in 0..TEMP_NAME_ATTEMPTS {
        let path = dir.join(temp_name()?);
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .open(&path)
        {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(io_error(&path, err)),
        };
        return match file.write_all(contents).and_then(|()| file.sync_all()) {
            Ok(()) => Ok(path),
            Err(err) => {
                drop(file);
                let _ = fs::remove_file(&path);
                Err(io_error(&path, err))
            }
        };
    }
    Err(io_error(
        dir,
        io::Error::new(
            ErrorKind::AlreadyExists,
            "could not find an unused temporary file name",
        ),
    ))
}

fn temp_name() -> Result<String, StoreError> {
    let mut random = [0u8; 8];
    SysRng
        .try_fill_bytes(&mut random)
        .map_err(|_| StoreError::Random)?;
    Ok(format!("{TEMP_PREFIX}{}", hex(&random)))
}

/// The directory containing `path`, as something that can be opened.
fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Lowercase hex encoding.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::test_support::TempDir;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn scratch_dir() -> TempDir {
        TempDir::new()
    }

    #[test]
    fn hex_is_lowercase_and_complete() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    #[test]
    fn creates_private_directories_and_tightens_existing_ones() {
        let scratch = scratch_dir();
        let fresh = scratch.path().join("fresh");
        ensure_private_dir(&fresh).unwrap();
        assert_eq!(mode(&fresh), 0o700);

        let loose = scratch.path().join("loose");
        fs::create_dir(&loose).unwrap();
        fs::set_permissions(&loose, Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&loose).unwrap();
        assert_eq!(mode(&loose), 0o700);

        let file = scratch.path().join("file");
        fs::write(&file, b"x").unwrap();
        assert!(matches!(
            ensure_private_dir(&file),
            Err(StoreError::Io { .. })
        ));
    }

    #[test]
    fn replace_file_writes_private_files_atomically() {
        let scratch = scratch_dir();
        replace_file(scratch.path(), "object", b"first").unwrap();
        replace_file(scratch.path(), "object", b"second").unwrap();
        let target = scratch.path().join("object");
        assert_eq!(fs::read(&target).unwrap(), b"second");
        assert_eq!(mode(&target), 0o600);
        let names: Vec<_> = fs::read_dir(scratch.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["object"], "no temporary file may be left behind");
    }

    #[test]
    fn create_file_exclusive_never_replaces() {
        let scratch = scratch_dir();
        assert!(create_file_exclusive(scratch.path(), "key", b"winner").unwrap());
        assert!(!create_file_exclusive(scratch.path(), "key", b"loser").unwrap());
        let target = scratch.path().join("key");
        assert_eq!(fs::read(&target).unwrap(), b"winner");
        assert_eq!(mode(&target), 0o600);
        assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 1);
    }

    #[test]
    fn read_file_distinguishes_missing_and_caps_length() {
        let scratch = scratch_dir();
        let path = scratch.path().join("data");
        assert_eq!(read_file(&path, 4).unwrap(), None);
        fs::write(&path, b"0123456789").unwrap();
        assert_eq!(read_file(&path, 64).unwrap().unwrap(), b"0123456789");
        assert_eq!(read_file(&path, 4).unwrap().unwrap(), b"01234");
    }

    #[test]
    fn remove_all_files_empties_a_directory() {
        let scratch = scratch_dir();
        for name in ["a", ".tmp-1", "b"] {
            fs::write(scratch.path().join(name), b"x").unwrap();
        }
        remove_all_files(scratch.path()).unwrap();
        assert_eq!(fs::read_dir(scratch.path()).unwrap().count(), 0);
        remove_all_files(&scratch.path().join("missing")).unwrap();
    }

    #[test]
    fn overwrite_with_zeros_clears_every_byte() {
        let scratch = scratch_dir();
        let path = scratch.path().join("secret");
        fs::write(&path, vec![0xa5; 5000]).unwrap();
        let file = OpenOptions::new().write(true).open(&path).unwrap();
        overwrite_with_zeros(&file).unwrap();
        assert_eq!(fs::read(&path).unwrap(), vec![0; 5000]);
    }
}
