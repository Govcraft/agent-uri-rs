//! Fuzzes `AgentId::parse`, where both of this crate's known panics-in-waiting
//! lived: a byte-counted length check and a byte-truncating alphabet check
//! (issues #33 and #89).

#![no_main]

use agent_uri::AgentId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    let Ok(id) = AgentId::parse(input) else {
        return;
    };

    let rendered = id.to_string();
    let reparsed = AgentId::parse(&rendered).expect("an agent ID must reparse from its rendering");
    assert_eq!(reparsed.to_string(), rendered);

    // Both halves are fixed by the grammar in characters, not bytes.
    assert_eq!(id.suffix().chars().count(), agent_uri::AGENT_SUFFIX_LENGTH);
    assert!(id.prefix().as_str().chars().count() <= agent_uri::MAX_AGENT_PREFIX_LENGTH);
    assert!(
        id.prefix()
            .as_str()
            .chars()
            .all(|c| c.is_ascii_lowercase() || c == '_')
    );
});
