//! `agent-uri` — the command-line tool for the `agent://` identity scheme.
//!
//! Key ceremony, attestation minting, verification, and inspection.
//!
//! The design rests on two rules that the rest of the crate is built to keep:
//!
//! 1. **stdout is data; stderr is prose.** In both human and JSON modes, without
//!    exception. That is what lets `attest issue ... | pbcopy` yield a token
//!    rather than a paragraph, and what lets `--json` be parsed without first
//!    being cleaned. Nothing here calls `println!`; every byte goes through
//!    [`output::Output`].
//! 2. **A refusal is not a crash.** An invalid URI, or a token that fails
//!    verification, exits 1 with a precise reason and a remedy. A missing key or
//!    an unsafely-permissioned one exits 3. A malformed command line exits 2.
//!    Nothing exits with a `Debug` dump.

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

mod cli;
mod commands;
mod error;
mod keyfile;
mod output;
mod reports;
mod timefmt;
mod token;
mod trust;
mod ttl;

use std::io::{self, IsTerminal};
use std::process::ExitCode;

use clap::Parser;

use cli::Cli;
use output::{Format, Output};

fn main() -> ExitCode {
    // clap exits 2 by itself on a malformed command line.
    let cli = Cli::parse();

    let format = if cli.json {
        Format::Json
    } else {
        Format::Human
    };

    // Color is a courtesy to a human at a terminal and an obstacle to everyone
    // else: a pipe, a log file, a CI job, or an operator who asked for quiet with
    // NO_COLOR. It is applied only to verdict lines, and only on stderr.
    let color = format == Format::Human
        && io::stderr().is_terminal()
        && std::env::var_os("NO_COLOR").is_none();

    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut out = Output::new(stdout.lock(), stderr.lock(), format, color);

    match commands::dispatch(&cli, &mut out) {
        Ok(()) => {
            out.flush();
            ExitCode::SUCCESS
        }
        Err(error) => {
            out.emit_error(&error);
            out.flush();
            ExitCode::from(error.exit_code())
        }
    }
}
