//! Shell completions and the man page.
//!
//! Both are hidden subcommands rather than build-time artifacts: a single static
//! binary can then install its own completions and its own man page, with no
//! build script and nothing to keep in sync.

use std::io::Write;

use clap::CommandFactory;
use clap_complete::Shell;

use crate::cli::Cli;
use crate::error::CliError;
use crate::output::{Format, Output};

/// The binary name, as it appears in completions and the man page.
const BINARY: &str = "agent-uri";

/// Writes a shell completion script to stdout.
///
/// # Errors
///
/// Returns [`CliError::Fault`] when stdout cannot be written.
pub fn completions<O: Write, E: Write>(shell: Shell, out: &mut Output<O, E>) -> Result<(), CliError> {
    reject_json(out, "completions")?;

    let mut command = Cli::command();
    let mut buffer = Vec::new();

    clap_complete::generate(shell, &mut command, BINARY, &mut buffer);
    out.write_raw(&buffer)
}

/// Writes the man page, in roff, to stdout.
///
/// # Errors
///
/// Returns [`CliError::Fault`] when the page cannot be rendered or written.
pub fn man<O: Write, E: Write>(out: &mut Output<O, E>) -> Result<(), CliError> {
    reject_json(out, "man")?;

    let mut buffer = Vec::new();

    clap_mangen::Man::new(Cli::command())
        .render(&mut buffer)
        .map_err(|source| {
            CliError::fault(
                "output_error",
                format!("cannot render the man page: {source}"),
                "this is a bug; please report it",
            )
        })?;

    out.write_raw(&buffer)
}

/// Both generators emit text that is already in its final form, so neither has a
/// JSON representation. Asking for one is a category error, and saying so beats
/// emitting a JSON-wrapped roff blob nobody wants.
pub fn reject_json<O: Write, E: Write>(out: &Output<O, E>, what: &str) -> Result<(), CliError> {
    if out.format() == Format::Json {
        return Err(CliError::fault(
            "unsupported_format",
            format!("{what} is not available as JSON; it is already a text artifact"),
            format!("drop --json: 'agent-uri {what}'"),
        ));
    }

    Ok(())
}
