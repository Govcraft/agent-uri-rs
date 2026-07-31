//! Fuzzes the whole parser: `AgentUri::parse` must return, never panic.
//!
//! A successful parse also has to hold its invariants, so a corpus entry that
//! parses into something the crate will not parse back is a finding too.

#![no_main]

use agent_uri::AgentUri;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    let Ok(uri) = AgentUri::parse(input) else {
        return;
    };

    let rendered = uri.as_str();
    let reparsed = AgentUri::parse(rendered).expect("a parsed URI must reparse from its rendering");
    assert_eq!(reparsed.as_str(), rendered);
    assert_eq!(reparsed, uri);

    let canonical = uri.canonical();
    let recanonical = AgentUri::parse(&canonical).expect("a canonical form must parse");
    assert_eq!(recanonical.canonical(), canonical);
});
