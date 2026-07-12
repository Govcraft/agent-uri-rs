//! Command implementations.

pub mod attest;
pub mod key;
pub mod shell;
pub mod uri;

use std::io::{self, Read, Write};

use crate::cli::{Cli, Command};
use crate::error::CliError;
use crate::output::Output;

/// Runs the requested command.
///
/// # Errors
///
/// Returns the [`CliError`] the command failed with; `main` turns it into an
/// exit code and a diagnostic on stderr.
pub fn dispatch<O: Write, E: Write>(cli: &Cli, out: &mut Output<O, E>) -> Result<(), CliError> {
    match &cli.command {
        Command::Key(command) => key::run(command, out),
        Command::Attest(command) => attest::run(command, out),
        Command::Uri(command) => uri::run(command, out),
        Command::Completions { shell } => shell::completions(*shell, out),
        Command::Man => shell::man(out),
    }
}

/// Resolves a token argument, reading stdin when it is `-`.
///
/// A token is a bearer credential, and anything on the command line is visible
/// to every other process via `ps`. Reading from stdin is the safe path, and `-`
/// is how the operator asks for it.
///
/// # Errors
///
/// Returns [`CliError::Fault`] when stdin cannot be read.
pub fn resolve_token(argument: &str) -> Result<String, CliError> {
    if argument != "-" {
        return Ok(argument.to_string());
    }

    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer).map_err(|source| {
        CliError::fault(
            "stdin_error",
            format!("cannot read the token from stdin: {source}"),
            "pipe a token in, e.g. 'agent-uri attest verify - < token.txt'",
        )
    })?;

    Ok(buffer.trim().to_string())
}
