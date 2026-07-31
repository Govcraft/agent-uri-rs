//! Fuzzes `Fragment::parse`.

#![no_main]

use agent_uri::Fragment;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    let Ok(fragment) = Fragment::parse(input) else {
        return;
    };

    let rendered = fragment.as_str().to_string();
    let reparsed = Fragment::parse(&rendered).expect("a fragment must reparse from its rendering");
    assert_eq!(reparsed.as_str(), rendered);
});
