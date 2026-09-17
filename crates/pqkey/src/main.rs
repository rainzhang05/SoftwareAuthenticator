use std::process::ExitCode;

fn main() -> ExitCode {
    match pc_hid_runner::cli::run_cli() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("pc-hid-runner: {err}");
            ExitCode::FAILURE
        }
    }
}
