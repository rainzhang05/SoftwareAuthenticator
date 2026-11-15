//! Helpers shared by the unit tests.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
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

/// Asserts that `text` names each of `words`, in order. A test of a cause or
/// a fix checks what it names, the cause's words and the fix's commands,
/// rather than its whole wording, which is not the contract.
#[track_caller]
pub fn assert_names(text: &str, words: &[&str]) {
    let mut rest = text;
    for word in words {
        let Some(at) = rest.find(word) else {
            panic!("{word:?} is missing or out of order in: {text}");
        };
        rest = &rest[at + word.len()..];
    }
}

/// Asserts that `problem`'s cause names `cause` and its fix names `fix`,
/// each in order ([`assert_names`]).
#[track_caller]
pub fn assert_problem(problem: &crate::cli::checks::Problem, cause: &[&str], fix: &[&str]) {
    assert_names(&problem.what, cause);
    assert_names(&problem.fix, fix);
}

/// The problem whose cause names `word` among those that `output` lists as
/// `pqkey status` and `pqkey setup` print them, `  ! cause` with `    Fix: fix`
/// under it, if there is one; more than one fails.
#[track_caller]
pub fn listed(output: &str, word: &str) -> Option<crate::cli::checks::Problem> {
    let lines: Vec<&str> = output.lines().collect();
    let mut found = lines.windows(2).filter_map(|pair| {
        let what = pair[0].strip_prefix("  ! ")?;
        let fix = pair[1].strip_prefix("    Fix: ")?;
        what.contains(word)
            .then(|| crate::cli::checks::Problem::new(what, fix))
    });
    let problem = found.next();
    assert!(
        found.next().is_none(),
        "two problems name {word:?}: {output}"
    );
    problem
}

/// The `#[test]` function `$test` of the calling module, as a [`ChildTest`].
/// Its libtest name comes from `module_path!()`, and the function itself is
/// passed along, so that renaming or moving it fails to compile here instead
/// of leaving a child that runs no test.
macro_rules! child_test {
    ($test:ident) => {
        $crate::test_support::ChildTest::new(
            concat!(module_path!(), "::", stringify!($test)),
            $test,
        )
    };
}
pub(crate) use child_test;

/// A test of this binary that another test runs as a child process, to see
/// what it does in a process of its own: made by [`child_test!`], and checked
/// with [`assert_ran`].
pub struct ChildTest(&'static str);

impl ChildTest {
    /// `_test`, whose path is `path` with the crate's name first, as
    /// [`child_test!`] gives them.
    pub fn new(path: &'static str, _test: fn()) -> Self {
        // libtest names a test by its path from the crate root.
        let (_crate, name) = path.split_once("::").unwrap();
        Self(name)
    }

    /// Its libtest name.
    pub fn name(&self) -> &'static str {
        self.0
    }

    /// libtest's arguments that run it alone, its output not captured.
    pub fn args(&self) -> [&'static str; 3] {
        ["--exact", self.0, "--nocapture"]
    }

    /// This test binary, run with [`Self::args`].
    pub fn command(&self) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(self.args());
        command
    }
}

/// Fails unless `stdout`, a [`ChildTest`]'s standard output, shows that
/// libtest ran the test: a name that matches no test, or an ignored test,
/// runs nothing and exits with status 0, as a child that found nothing would.
#[track_caller]
pub fn assert_ran(stdout: &[u8]) {
    let stdout = String::from_utf8_lossy(stdout);
    assert!(
        stdout.starts_with("\nrunning 1 test\n") && !stdout.contains(" ... ignored"),
        "the child test did not run: {stdout}"
    );
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

pub(crate) mod callback;

/// An elapsed clock for portable service tests, injected at app creation.
pub(crate) struct TestClock(std::time::Instant);
impl pqkey_ctap::ctap::Clock for TestClock {
    fn now(&self) -> std::time::Duration {
        self.0.elapsed()
    }
}
pub(crate) fn clock() -> std::io::Result<TestClock> {
    Ok(TestClock(std::time::Instant::now()))
}
pub(crate) fn serve_ctap(
    device: crate::platform::test_support::Device,
    data: crate::service::AppData,
    shutdown: crate::shutdown::ShutdownSignal,
    ready: impl FnOnce() -> std::io::Result<()>,
) -> std::io::Result<()> {
    crate::service::serve_ctap_with_clock(device, data, clock, shutdown, ready)
}
pub(crate) fn daemon_info(args: &crate::cli::DaemonArgs) -> crate::cli::daemon_info::DaemonInfo {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(std::env::current_exe().unwrap()).unwrap();
    crate::cli::daemon_info::DaemonInfo::from_identity(args, (metadata.dev(), metadata.ino()))
}
