//! Fuzzes `TrustRoot::parse`, which holds the IPv4, IPv6, DNS, and port paths.

#![no_main]

use agent_uri::TrustRoot;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    let Ok(root) = TrustRoot::parse(input) else {
        return;
    };

    let rendered = root.as_str().to_string();
    let reparsed =
        TrustRoot::parse(&rendered).expect("a trust root must reparse from its rendering");
    assert_eq!(reparsed.as_str(), rendered);
    assert_eq!(reparsed, root);
});
