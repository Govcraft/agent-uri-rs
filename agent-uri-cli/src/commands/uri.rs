//! `agent-uri uri` — URI validation.

use std::io::Write;

use agent_uri::AgentUri;

use crate::cli::UriCommand;
use crate::error::CliError;
use crate::output::Output;
use crate::reports::UriValidated;

/// Runs a `uri` subcommand.
///
/// # Errors
///
/// Returns [`CliError::Refused`] when the URI does not parse.
pub fn run<O: Write, E: Write>(command: &UriCommand, out: &mut Output<O, E>) -> Result<(), CliError> {
    match command {
        UriCommand::Validate { uri } => validate(uri, out),
    }
}

/// Validates a URI and prints its canonical form.
fn validate<O: Write, E: Write>(input: &str, out: &mut Output<O, E>) -> Result<(), CliError> {
    let uri = AgentUri::parse(input).map_err(|source| {
        CliError::refused(
            "invalid_uri",
            format!("'{input}' is not a valid agent:// URI: {source}"),
            "an agent URI looks like \
             agent://<trust-root>/<capability-path>/<prefix>_<26-char-id>, e.g. \
             agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q",
        )
    })?;

    let report = UriValidated::new(&uri);

    out.verdict_good("VALID");
    out.field("trust root", &report.trust_root);
    out.field("capability", &report.capability_path);
    out.field("agent id", &report.agent_id);
    out.blank();

    // The canonical form is the data: bare on stdout, ready to pipe onward.
    out.emit(&report)
}
