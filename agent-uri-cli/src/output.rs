//! The stdout/stderr contract.
//!
//! One rule, enforced by construction rather than by discipline: **stdout is
//! data, stderr is prose.** Nothing in this crate calls `println!`; every byte
//! written to either stream passes through [`Output`], which is generic over its
//! writers so tests can capture both exactly.
//!
//! That rule is what makes `agent-uri attest issue ... | pbcopy` work: the token
//! is the only thing on stdout, while the claims summary, the fingerprint, and
//! every warning go to stderr where a pipe will not swallow them.

use std::io::{self, Write};

use serde::Serialize;

use crate::error::CliError;

/// Whether output is rendered for a human or for a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Aligned, restrained text.
    Human,
    /// A single JSON object on stdout.
    Json,
}

/// A value that can be written to stdout in either format.
pub trait Report: Serialize {
    /// Renders the human form. This is the *data*, not a description of it.
    ///
    /// # Errors
    ///
    /// Propagates write failures from the underlying stream.
    fn render_human(&self, w: &mut dyn Write) -> io::Result<()>;
}

/// ANSI styling, applied only to verdict lines and only when the terminal wants it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Style {
    Good,
    Bad,
    Caution,
}

impl Style {
    /// The ANSI escape sequence introducing this style.
    const fn code(self) -> &'static str {
        match self {
            Self::Good => "\x1b[1;32m",
            Self::Bad => "\x1b[1;31m",
            Self::Caution => "\x1b[1;33m",
        }
    }
}

/// The writer pair every command reports through.
pub struct Output<O: Write, E: Write> {
    out: O,
    err: E,
    format: Format,
    color: bool,
}

impl<O: Write, E: Write> Output<O, E> {
    /// Builds an output pair.
    ///
    /// `color` should already account for both TTY detection and `NO_COLOR`.
    pub const fn new(out: O, err: E, format: Format, color: bool) -> Self {
        Self {
            out,
            err,
            format,
            color,
        }
    }

    /// The active format.
    pub const fn format(&self) -> Format {
        self.format
    }

    /// Whether the human format is active.
    pub const fn is_human(&self) -> bool {
        matches!(self.format, Format::Human)
    }

    /// Writes a report to **stdout**: JSON when `--json`, the human form otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Fault`] when the report cannot be serialized or written.
    pub fn emit<R: Report>(&mut self, report: &R) -> Result<(), CliError> {
        let result = match self.format {
            Format::Json => serde_json::to_writer(&mut self.out, report)
                .map_err(io::Error::from)
                .and_then(|()| writeln!(self.out)),
            Format::Human => report.render_human(&mut self.out),
        };

        result.map_err(|source| {
            CliError::fault(
                "output_error",
                format!("cannot write to stdout: {source}"),
                "check that stdout is writable and the receiving pipe is still open",
            )
        })
    }

    /// Writes pre-rendered bytes to **stdout** verbatim.
    ///
    /// For artifacts that are already in their final form and have no other
    /// representation: completion scripts and roff.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Fault`] when stdout cannot be written.
    pub fn write_raw(&mut self, bytes: &[u8]) -> Result<(), CliError> {
        self.out.write_all(bytes).map_err(|source| {
            CliError::fault(
                "output_error",
                format!("cannot write to stdout: {source}"),
                "check that stdout is writable and the receiving pipe is still open",
            )
        })
    }

    /// Writes a line of prose to **stderr**. Suppressed in JSON mode, where the
    /// caller is a machine that asked for data, not narration.
    pub fn note(&mut self, line: &str) {
        if self.is_human() {
            let _ = writeln!(self.err, "{line}");
        }
    }

    /// Writes an aligned `label  value` field to **stderr**, for claim summaries.
    pub fn field(&mut self, label: &str, value: &str) {
        if self.is_human() {
            let _ = writeln!(self.err, "  {label:<14}{value}");
        }
    }

    /// Writes a blank separator line to **stderr**.
    pub fn blank(&mut self) {
        if self.is_human() {
            let _ = writeln!(self.err);
        }
    }

    /// Writes a positive verdict to **stderr**, e.g. `VERIFIED`.
    pub fn verdict_good(&mut self, line: &str) {
        self.verdict(Style::Good, line);
    }

    /// Writes a cautionary banner to **stderr**, e.g. the UNVERIFIED warning.
    pub fn verdict_caution(&mut self, line: &str) {
        self.verdict(Style::Caution, line);
    }

    /// Writes a styled verdict line to stderr.
    fn verdict(&mut self, style: Style, line: &str) {
        if !self.is_human() {
            return;
        }

        let _ = if self.color {
            writeln!(self.err, "{}{line}\x1b[0m", style.code())
        } else {
            writeln!(self.err, "{line}")
        };
    }

    /// Reports an error on **stderr**, in the active format. Never touches stdout.
    ///
    /// In JSON mode the error is itself a JSON object, so a machine driving the
    /// tool can parse a failure as readily as a success, without either stream
    /// contaminating the other.
    pub fn emit_error(&mut self, error: &CliError) {
        let diagnosis = error.diagnosis();

        match self.format {
            Format::Json => {
                let payload = serde_json::json!({
                    "error": {
                        "kind": diagnosis.kind,
                        "message": diagnosis.message,
                        "remedy": diagnosis.remedy,
                        "exit_code": error.exit_code(),
                    }
                });
                let _ = serde_json::to_writer(&mut self.err, &payload);
                let _ = writeln!(self.err);
            }
            Format::Human => {
                let label = if self.color {
                    format!("{}error:\x1b[0m", Style::Bad.code())
                } else {
                    "error:".to_string()
                };
                let _ = writeln!(self.err, "{label} {}", diagnosis.message);
                let _ = writeln!(self.err, "  fix: {}", diagnosis.remedy);
            }
        }
    }

    /// Flushes both streams, ignoring a closed pipe.
    pub fn flush(&mut self) {
        let _ = self.out.flush();
        let _ = self.err.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Probe {
        value: &'static str,
    }

    impl Report for Probe {
        fn render_human(&self, w: &mut dyn Write) -> io::Result<()> {
            writeln!(w, "{}", self.value)
        }
    }

    fn capture(format: Format, color: bool) -> Output<Vec<u8>, Vec<u8>> {
        Output::new(Vec::new(), Vec::new(), format, color)
    }

    fn streams(output: Output<Vec<u8>, Vec<u8>>) -> (String, String) {
        (
            String::from_utf8(output.out).unwrap(),
            String::from_utf8(output.err).unwrap(),
        )
    }

    #[test]
    fn human_mode_emits_the_rendered_form_to_stdout() {
        let mut output = capture(Format::Human, false);
        output.emit(&Probe { value: "data" }).unwrap();

        let (out, err) = streams(output);
        assert_eq!(out, "data\n");
        assert!(err.is_empty());
    }

    #[test]
    fn json_mode_emits_one_object_to_stdout() {
        let mut output = capture(Format::Json, false);
        output.emit(&Probe { value: "data" }).unwrap();

        let (out, err) = streams(output);
        assert_eq!(out, "{\"value\":\"data\"}\n");
        assert!(err.is_empty());
        assert!(serde_json::from_str::<serde_json::Value>(&out).is_ok());
    }

    #[test]
    fn prose_goes_to_stderr_and_never_to_stdout() {
        let mut output = capture(Format::Human, false);
        output.note("a note");
        output.field("issuer", "acme.com");
        output.verdict_good("VERIFIED");

        let (out, err) = streams(output);
        assert!(out.is_empty(), "stdout must carry data only");
        assert!(err.contains("a note"));
        assert!(err.contains("issuer"));
        assert!(err.contains("VERIFIED"));
    }

    #[test]
    fn json_mode_suppresses_prose_entirely() {
        let mut output = capture(Format::Json, false);
        output.note("a note");
        output.field("issuer", "acme.com");
        output.verdict_good("VERIFIED");

        let (out, err) = streams(output);
        assert!(out.is_empty());
        assert!(err.is_empty(), "machine output must not be narrated");
    }

    #[test]
    fn errors_go_to_stderr_leaving_stdout_empty() {
        let mut output = capture(Format::Human, false);
        output.emit_error(&CliError::refused(
            "token_expired",
            "expired at T",
            "re-issue it",
        ));

        let (out, err) = streams(output);
        assert!(out.is_empty(), "a failure must not put anything on stdout");
        assert!(err.contains("error: expired at T"));
        assert!(err.contains("fix: re-issue it"));
    }

    #[test]
    fn json_errors_are_json_on_stderr() {
        let mut output = capture(Format::Json, false);
        output.emit_error(&CliError::refused(
            "token_expired",
            "expired at T",
            "re-issue it",
        ));

        let (out, err) = streams(output);
        assert!(out.is_empty());

        let parsed: serde_json::Value = serde_json::from_str(&err).unwrap();
        assert_eq!(parsed["error"]["kind"], "token_expired");
        assert_eq!(parsed["error"]["message"], "expired at T");
        assert_eq!(parsed["error"]["remedy"], "re-issue it");
        assert_eq!(parsed["error"]["exit_code"], 1);
    }

    #[test]
    fn color_is_applied_only_when_enabled() {
        let mut plain = capture(Format::Human, false);
        plain.verdict_good("VERIFIED");
        let (_, err) = streams(plain);
        assert_eq!(err, "VERIFIED\n");

        let mut colored = capture(Format::Human, true);
        colored.verdict_good("VERIFIED");
        let (_, err) = streams(colored);
        assert!(err.contains("\x1b[1;32m"));
        assert!(err.ends_with("\x1b[0m\n"));
    }

    #[test]
    fn color_never_leaks_into_json() {
        let mut output = capture(Format::Json, true);
        output.emit_error(&CliError::refused("k", "m", "r"));

        let (_, err) = streams(output);
        assert!(!err.contains('\x1b'), "machine output must never be styled");
    }
}
