//! Adversarial property tests: parsing untrusted input never panics.
//!
//! Every other property test in this crate generates input that conforms to the
//! grammar and checks that the parser accepts it. That is the easy half. This
//! crate's job is to be handed a string by someone hostile and decide whether it
//! is a valid identity, so the property that matters most is that no input —
//! valid, invalid, or malformed in a way nobody anticipated — can make it panic
//! instead of returning `Err`.
//!
//! A panic in a parser of untrusted input is a denial of service in every
//! service that parses one. The two defects these tests are shaped to catch are
//! the ones this crate has actually had: an index that assumes a byte offset
//! falls on a character boundary, and a length check counted in bytes standing
//! in for one counted in characters (issues #33 and #89).
//!
//! proptest reports a panic in the body as a test failure, so `parse` merely
//! being called is the no-panic assertion. The checks written out below are the
//! invariants a successful parse must also hold.

use agent_uri::{
    AgentId, AgentUri, AgentUriBuilder, CapabilityPath, Fragment, QueryParams, TrustRoot,
};
use proptest::prelude::*;

/// Valid URIs to mutate, chosen to put a mutation next to every boundary the
/// parser reasons about: the scheme, a port, an IPv6 literal, a deep path, a
/// query, a fragment, and the shortest and longest identifiers.
const SEEDS: &[&str] = &[
    "agent://a.co/x/a_01234567890123456789012345",
    "agent://anthropic.com/assistant/chat/llm_chat_01h455vb4pex5vsknk084sn02q",
    "agent://localhost:8472/debug/test/llm_01h455vb4pex5vsknk084sn02q",
    "agent://127.0.0.1/test/llm_01h455vb4pex5vsknk084sn02q",
    "agent://[2001:db8:85a3::8a2e:370:7334]/monitoring/sensor_01h455vb4pex5vsknk084sn02q",
    "agent://acme.corp/workflow/approval/invoice/high-value/rule_fsm_01h5fskfsk4fpeqwnsyz5hj55t",
    "agent://example.com/chat/llm_01h455vb4pex5vsknk084sn02q?version=2.0&ttl=3600#sub/task",
    "agent://example.com/ch/llm_01h455vb4pex5vsknk084sn02q?name=%C3%A9",
];

/// Characters a mutation can splice in.
///
/// The multi-byte entries are the point rather than decoration: `İ` is the
/// character whose first byte is ASCII `0` once truncated, and the combining
/// mark and the emoji put a character boundary where a byte index would not
/// expect one.
const SPLICE: &[char] = &[
    'A',
    'Z',
    '/',
    ':',
    '?',
    '#',
    '%',
    '.',
    '-',
    '_',
    '[',
    ']',
    '@',
    '\\',
    '\0',
    '\n',
    '\t',
    ' ',
    '\u{7f}',
    'é',
    'İ',
    'ß',
    '\u{0301}',
    '\u{200b}',
    '中',
    '🙂',
    '\u{10ffff}',
];

/// Any string at all, including one that is nothing like a URI.
fn arbitrary_string() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..=64).prop_map(|chars| chars.into_iter().collect())
}

/// Arbitrary bytes read as UTF-8, so that byte-level nonsense still arrives as
/// a `&str` the way it would from a network decoder.
fn lossy_string() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<u8>(), 0..=64)
        .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
}

/// A string that looks enough like a URI to get past the first few checks.
fn near_miss_string() -> impl Strategy<Value = String> {
    (
        prop::sample::select(vec!["agent://", "AGENT://", "agent:/", "agent:", "//", ""]),
        prop::collection::vec(prop::sample::select(SPLICE.to_vec()), 0..=24),
    )
        .prop_map(|(scheme, tail)| {
            let mut s = scheme.to_string();
            s.extend(tail);
            s
        })
}

/// One valid URI with one mutation applied.
///
/// Indices are drawn as fractions of the length and snapped to a character
/// boundary, so a mutation lands anywhere in the string without the strategy
/// itself panicking on a slice.
fn mutated_uri() -> impl Strategy<Value = String> {
    (
        prop::sample::select(SEEDS.to_vec()),
        0..7usize,
        0..1000usize,
        prop::sample::select(SPLICE.to_vec()),
    )
        .prop_map(|(seed, operation, position, splice)| {
            let boundary = |s: &str, fraction: usize| {
                let target = s.len() * fraction / 1000;
                (0..=s.len())
                    .rev()
                    .find(|index| s.is_char_boundary(*index) && *index <= target)
                    .unwrap_or(0)
            };
            let at = boundary(seed, position);

            match operation {
                0 => format!("{}{splice}{}", &seed[..at], &seed[at..]),
                1 => {
                    // Delete the character at `at`, if there is one.
                    let end = seed[at..].chars().next().map_or(at, |c| at + c.len_utf8());
                    format!("{}{}", &seed[..at], &seed[end..])
                }
                2 => {
                    let end = seed[at..].chars().next().map_or(at, |c| at + c.len_utf8());
                    format!("{}{splice}{}", &seed[..at], &seed[end..])
                }
                3 => seed[..at].to_string(),
                4 => format!("{}{}", seed, &seed[at..]),
                5 => seed[..at].to_uppercase() + &seed[at..],
                _ => format!("{}{}", &seed[at..], &seed[..at]),
            }
        })
}

/// Every strategy above, so each property covers all of them.
fn hostile_input() -> impl Strategy<Value = String> {
    prop_oneof![
        mutated_uri(),
        near_miss_string(),
        arbitrary_string(),
        lossy_string(),
    ]
}

proptest! {
    // Adversarial input is cheap to generate and each case is a parse, so the
    // budget buys a wider search rather than a faster run.
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// The whole parser, over everything.
    #[test]
    fn agent_uri_parse_never_panics(input in hostile_input()) {
        match AgentUri::parse(&input) {
            Ok(uri) => {
                // A URI that parsed must render to something that parses back to
                // it, or the type is handing out a string it will not accept.
                let rendered = uri.as_str().to_string();
                let reparsed = AgentUri::parse(&rendered)
                    .expect("a parsed URI must reparse from its own rendering");
                prop_assert_eq!(reparsed.as_str(), rendered.as_str());
                prop_assert_eq!(&reparsed, &uri);

                let canonical = uri.canonical();
                let recanonical = AgentUri::parse(&canonical)
                    .expect("a canonical form must parse");
                prop_assert_eq!(recanonical.canonical(), canonical);

                prop_assert!(uri.as_str().len() <= agent_uri::MAX_URI_LENGTH);
            }
            Err(error) => {
                // Rendering an error is part of the error path, so it is part of
                // what must not panic.
                prop_assert!(!error.to_string().is_empty());
            }
        }
    }

    /// Each component parser on its own, reached directly rather than through a
    /// URI, since callers can and do call them that way.
    #[test]
    fn component_parsers_never_panic(input in hostile_input()) {
        if let Ok(root) = TrustRoot::parse(&input) {
            prop_assert!(TrustRoot::parse(root.as_str()).is_ok());
        }
        if let Ok(path) = CapabilityPath::parse(&input) {
            prop_assert!(CapabilityPath::parse(path.as_str()).is_ok());
            prop_assert!(path.depth() >= 1);
        }
        if let Ok(id) = AgentId::parse(&input) {
            prop_assert!(AgentId::parse(&id.to_string()).is_ok());
        }
        if let Ok(query) = QueryParams::parse(&input) {
            // A query renders re-encoded, so the round trip is through the
            // rendering rather than through the input.
            let rendered = query.to_string();
            let reparsed = QueryParams::parse(&rendered)
                .expect("a parsed query must reparse from its own rendering");
            prop_assert_eq!(reparsed.to_string(), rendered);
        }
        if let Ok(fragment) = Fragment::parse(&input) {
            prop_assert!(Fragment::parse(fragment.as_str()).is_ok());
        }
    }

    /// The builder reaches the same validators by another route.
    #[test]
    fn builder_never_panics(root in hostile_input(), path in hostile_input(), id in hostile_input()) {
        let Ok(builder) = AgentUriBuilder::new().try_trust_root(&root) else {
            return Ok(());
        };
        let Ok(builder) = builder.try_capability_path(&path) else {
            return Ok(());
        };
        let Ok(builder) = builder.try_agent_id(&id) else {
            return Ok(());
        };
        if let Ok(uri) = builder.build() {
            prop_assert!(AgentUri::parse(uri.as_str()).is_ok());
        }
    }

    /// Two hostile inputs that both parse must compare and order without
    /// panicking, and must do so consistently.
    #[test]
    fn comparison_never_panics(left in hostile_input(), right in hostile_input()) {
        let (Ok(left), Ok(right)) = (AgentUri::parse(&left), AgentUri::parse(&right)) else {
            return Ok(());
        };
        let ordering = left.cmp(&right);
        prop_assert_eq!(ordering == std::cmp::Ordering::Equal, left == right);
        prop_assert_eq!(ordering.reverse(), right.cmp(&left));
    }
}
