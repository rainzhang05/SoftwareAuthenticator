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
    error::Error,
    fmt,
    io::{self, Write},
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
