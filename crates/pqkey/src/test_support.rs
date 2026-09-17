//! Helpers shared by the unit tests.

use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Serializes tests that change process-wide signal dispositions, so one
/// cannot save and later restore a handler another has just installed.
pub fn lock_signal_handlers() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A uniquely named directory under the system temporary directory, removed
/// again when dropped.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(label: &str) -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("pqkey-{label}-{}-{unique}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temporary directory");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Captures everything logged anywhere in the unit test binary.
///
/// The logger is process-wide and tests run in parallel, so callers look for
/// messages naming something unique to their own test.
pub mod logs {
    use std::sync::{Mutex, Once};

    use log::{Level, LevelFilter, Log, Metadata, Record};

    static MESSAGES: Mutex<Vec<(Level, String)>> = Mutex::new(Vec::new());
    static INSTALL: Once = Once::new();

    struct Capture;

    impl Log for Capture {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &Record<'_>) {
            MESSAGES
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((record.level(), record.args().to_string()));
        }

        fn flush(&self) {}
    }

    pub fn install() {
        INSTALL.call_once(|| {
            log::set_logger(&Capture).expect("no other logger is installed");
            log::set_max_level(LevelFilter::Trace);
        });
    }

    /// The messages logged so far that contain `needle`, with their level.
    pub fn containing(needle: &str) -> Vec<(Level, String)> {
        MESSAGES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .filter(|(_, message)| message.contains(needle))
            .cloned()
            .collect()
    }
}
