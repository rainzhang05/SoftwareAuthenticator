use std::process::ExitCode;

fn main() -> ExitCode {
    match pqkey::cli::run_cli() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("pqkey: {err}");
            ExitCode::FAILURE
        }
    }
}
