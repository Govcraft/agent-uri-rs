//! Fuzzes `QueryParams::parse`, the one component that percent-decodes.
//!
//! Decoding turns attacker bytes into a byte sequence that must be valid UTF-8,
//! and rendering encodes them back, so the round trip is the invariant worth
//! holding: a value that survives parse-render-parse unchanged cannot have been
//! silently rewritten.

#![no_main]

use agent_uri::QueryParams;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    let Ok(query) = QueryParams::parse(input) else {
        return;
    };

    let rendered = query.to_string();
    let reparsed = QueryParams::parse(&rendered).expect("a query must reparse from its rendering");
    assert_eq!(reparsed.to_string(), rendered);
    assert_eq!(reparsed.len(), query.len());
    for (name, value) in query.iter() {
        assert_eq!(reparsed.get(name), Some(value));
    }
});
