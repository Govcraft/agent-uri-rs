//! Loading and reporting for the canonical test vectors.
//!
//! Failures accumulate and are reported together: one run tells you every
//! vector that disagrees with the code, not just the first.

use serde_json::Value;

/// Reads `test-vectors.json` from the workspace root.
///
/// # Panics
///
/// Panics if the file is missing or is not valid JSON. Either means the
/// canonical artifact is unusable, which is a failure worth stopping on.
pub fn load() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors.json");
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|error| panic!("cannot read {path}: {error}"));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("cannot parse {path}: {error}"))
}

pub struct Report {
    section: &'static str,
    failures: Vec<String>,
}

impl Report {
    pub const fn new(section: &'static str) -> Self {
        Self {
            section,
            failures: Vec::new(),
        }
    }

    /// Returns this report's section, which must exist and must not be empty.
    ///
    /// # Panics
    ///
    /// Panics if the section is absent or empty. A section that silently
    /// vanished would otherwise report as a passing run over nothing.
    pub fn section<'a>(&self, doc: &'a Value) -> &'a [Value] {
        let section = doc[self.section]
            .as_array()
            .unwrap_or_else(|| panic!("section '{}' is missing or not an array", self.section));
        assert!(!section.is_empty(), "section '{}' is empty", self.section);
        section
    }

    /// Returns a vector's id, or a placeholder that fails the run.
    pub fn id(&mut self, case: &Value) -> String {
        match case["id"].as_str() {
            Some(id) => id.to_string(),
            None => {
                self.failures
                    .push(format!("[{}] a vector has no id: {case}", self.section));
                "<no id>".to_string()
            }
        }
    }

    /// Returns a required string field, recording a failure if it is absent.
    pub fn str_field(&mut self, id: &str, case: &Value, name: &str) -> String {
        match case[name].as_str() {
            Some(value) => value.to_string(),
            None => {
                self.fail(id, format!("missing '{name}'"));
                String::new()
            }
        }
    }

    pub fn eq(&mut self, id: &str, label: &str, actual: &str, expected: &str) {
        if actual != expected {
            self.fail(id, format!("{label}: {actual:?} != expected {expected:?}"));
        }
    }

    pub fn fail(&mut self, id: &str, message: String) {
        self.failures
            .push(format!("[{}] {id}: {message}", self.section));
    }

    /// Fails the test with every disagreement found, or returns quietly.
    ///
    /// # Panics
    ///
    /// Panics if any vector disagreed with the code.
    pub fn finish(self) {
        assert!(
            self.failures.is_empty(),
            "{} vector(s) in section '{}' disagree with this crate:\n  {}",
            self.failures.len(),
            self.section,
            self.failures.join("\n  ")
        );
    }
}
