//! Standard output and standard error for the commands.
//!
//! `println!` and `eprintln!` panic when writing fails, for example when
//! standard output is a pipe whose reader has exited (`pqkey status | head
//! -1`) or a full device. The commands' `outln!` ([`line()`]) returns the error
//! instead, marked as an [`OutputError`], so `main` can tell a closed standard
//! output, after which there is nothing left to do, from a real failure.
//! Their `errln!` ([`error_line()`]) ignores failures: there is nowhere left to
//! report them.

use std::{
    env,
    error::Error,
    fmt,
    io::{self, IsTerminal, Write},
};

/// Writing standard output failed.
#[derive(Debug)]
pub struct OutputError(io::Error);

impl fmt::Display for OutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cannot write to standard output: {}", self.0)
    }
}

impl Error for OutputError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

/// Write `args` and a newline to standard output.
pub fn line(args: fmt::Arguments<'_>) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{args}")
        .and_then(|()| out.flush())
        .map_err(|err| io::Error::new(err.kind(), OutputError(err)))
}

/// Whether standard output gets colour: it is a terminal, and `NO_COLOR` is
/// not set (<https://no-color.org>).
fn colour() -> bool {
    io::stdout().is_terminal() && env::var_os("NO_COLOR").is_none_or(|value| value.is_empty())
}

/// `text` in the ANSI colour `code` when standard output has colour.
fn paint(code: &str, text: &str) -> String {
    if colour() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

/// A step that is done, as a line of its own: `  ✓ text`.
pub fn done(text: impl fmt::Display) -> io::Result<()> {
    line(format_args!("  {} {text}", paint("1;32", "✓")))
}

/// Something left to fix, and under it how: `  ! what` and `    Fix: fix`.
pub fn problem(what: impl fmt::Display, fix: impl fmt::Display) -> io::Result<()> {
    line(format_args!("  {} {what}", paint("1;33", "!")))?;
    line(format_args!("    Fix: {fix}"))
}

/// [`problem`] lines for each of `problems`.
pub fn problems(problems: &[super::checks::Problem]) -> io::Result<()> {
    problems
        .iter()
        .try_for_each(|found| problem(&found.what, &found.fix))
}

/// Whether `err` is standard output having been closed by its reader: it
/// has read all it wanted, so that is no failure.
pub fn is_closed_output(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::BrokenPipe
        && err.get_ref().is_some_and(|inner| inner.is::<OutputError>())
}

/// Write `args` and a newline to standard error, ignoring failure.
pub fn error_line(args: fmt::Arguments<'_>) {
    let _ = writeln!(io::stderr().lock(), "{args}");
}

/// `println!` that returns an [`io::Error`] instead of panicking.
macro_rules! outln {
    () => {
        $crate::cli::output::line(format_args!(""))
    };
    ($($arg:tt)*) => {
        $crate::cli::output::line(format_args!($($arg)*))
    };
}
pub(crate) use outln;

/// `eprintln!` that does not panic when standard error fails.
macro_rules! errln {
    ($($arg:tt)*) => {
        $crate::cli::output::error_line(format_args!($($arg)*))
    };
}
pub(crate) use errln;
