use std::process::ExitCode;

use pqkey::cli::output;

fn main() -> ExitCode {
    match pqkey::cli::run_cli() {
        Ok(()) => ExitCode::SUCCESS,
        // Whoever read the output has all they wanted, as with `| head`.
        Err(err) if output::is_closed_output(&err) => ExitCode::SUCCESS,
        Err(err) => {
            output::error_line(format_args!("pqkey: {err}"));
            ExitCode::FAILURE
        }
    }
}
