//! `omnidecomp` command-line front end. This file only wires the pieces: parse arguments (`args`), build the
//! job `session`, run one command (`commands`), and turn an error into its stable exit code.

mod args;
mod commands;
mod output;
mod session;

use args::Cli;
use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let session = session::Session::new(&cli);
    match commands::dispatch(cli.command, &session) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error[{}]: {}", e.code.as_str(), e.message);
            ExitCode::from(e.code.exit_code() as u8)
        }
    }
}
