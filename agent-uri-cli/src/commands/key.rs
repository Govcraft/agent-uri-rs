//! `agent-uri key` — the key ceremony.

use std::io::Write;
use std::path::PathBuf;

use agent_uri_attestation::SigningKey;

use crate::cli::KeyCommand;
use crate::error::CliError;
use crate::keyfile;
use crate::output::Output;
use crate::reports::{KeyGenerated, PublicKey};
use crate::trust;

/// Runs a `key` subcommand.
///
/// # Errors
///
/// Returns [`CliError::Fault`] when a key cannot be written, found, or read.
pub fn run<O: Write, E: Write>(
    command: &KeyCommand,
    out: &mut Output<O, E>,
) -> Result<(), CliError> {
    match command {
        KeyCommand::Generate {
            out: path,
            force,
            stdout,
        } => generate(path.clone(), *force, *stdout, out),
        KeyCommand::Public { key } => public(key.clone(), out),
    }
}

/// Generates a signing key, either to a file or to stdout.
fn generate<O: Write, E: Write>(
    path: Option<PathBuf>,
    force: bool,
    to_stdout: bool,
    out: &mut Output<O, E>,
) -> Result<(), CliError> {
    let key = SigningKey::generate();
    let public_key = trust::encode_public(&key.verifying_key());

    if to_stdout {
        // The private key is the payload the operator asked to pipe, so it is the
        // only thing on stdout. Its public half, and the warning, go to stderr.
        out.verdict_caution("PRIVATE KEY ON STDOUT");
        out.note("  the private key is being written to stdout rather than a 0600 file.");
        out.note("  redirect it into a secret store; do not let it reach a log or shell history.");
        out.blank();
        out.field("public key", &public_key);
        out.blank();

        return out.emit(&KeyGenerated {
            public_key,
            path: None,
            // The one place the private key is meant to leave the process in
            // the clear, because `--stdout` asked for exactly that. Taking it
            // out of the wrapper is the acknowledgement; it is not an oversight
            // that this copy is not wiped, since it is on its way to stdout.
            secret_key: Some(keyfile::encode(&key).to_string()),
        });
    }

    let path = match path {
        Some(path) => path,
        None => keyfile::default_path()?,
    };

    keyfile::store(&path, &key, force)?;

    out.note("Generated an Ed25519 signing key.");
    out.blank();
    out.field("key file", &path.display().to_string());
    out.field("permissions", "0600 (owner read/write only)");
    out.blank();
    out.note("Register the public key with your trust-root registry. Relying parties verify with:");
    out.note(&format!(
        "  agent-uri attest verify - --trust-root <your-authority>={public_key}"
    ));
    out.blank();

    out.emit(&KeyGenerated {
        public_key,
        path: Some(path.display().to_string()),
        secret_key: None,
    })
}

/// Prints the public half of a stored key.
fn public<O: Write, E: Write>(
    path: Option<PathBuf>,
    out: &mut Output<O, E>,
) -> Result<(), CliError> {
    let path = match path {
        Some(path) => path,
        None => keyfile::default_path()?,
    };

    let key = keyfile::load(&path)?;

    out.emit(&PublicKey {
        public_key: trust::encode_public(&key.verifying_key()),
    })
}
