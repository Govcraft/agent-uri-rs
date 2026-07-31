//! Round-trip tests for the `serde` feature (issue #34).
//!
//! Every serde impl in this crate is hand-written and works the same way: it
//! serializes the type's rendered form as a JSON string and deserializes by
//! handing that string back to the type's own parser. Nothing checked that,
//! which meant a rendering that its parser would not accept, or a parser that
//! accepted something the renderer would not produce, would have gone
//! unnoticed until it reached a wire.
//!
//! Three things are asserted throughout:
//!
//! 1. The wire form is a bare JSON string, so the format is the URI syntax and
//!    not a struct that happens to hold one.
//! 2. The value survives the round trip.
//! 3. What comes back **serializes to the same string**. [`AgentUri`] equality
//!    ignores the query and the fragment, so `==` alone would pass for an impl
//!    that dropped both — which is exactly what the third check catches and
//!    the second does not.

#![cfg(feature = "serde")]

use std::collections::HashMap;

use agent_uri::{
    AgentId, AgentPrefix, AgentUri, CapabilityPath, Fragment, Host, PathSegment, QueryParams,
    TrustRoot,
};

const URI: &str = "agent://anthropic.com/assistant/chat/llm_chat_01h455vb4pex5vsknk084sn02q";
const DECORATED: &str =
    "agent://anthropic.com/assistant/chat/llm_chat_01h455vb4pex5vsknk084sn02q?ttl=300#invoice";

/// Serializes, deserializes, and returns both the JSON and the value back.
///
/// The check that matters is the last one. Comparing the values would pass for
/// an [`AgentUri`] impl that dropped the query and the fragment, because
/// equality ignores both; comparing what the recovered value serializes to
/// would not. Every assertion in this file wants the same three things, and
/// asking for them separately in each test is how one of them goes missing
/// from one of them.
fn round_trip<T>(value: &T) -> (String, T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let json = serde_json::to_string(value).expect("serializing must succeed");

    assert!(
        json.starts_with('"') && json.ends_with('"'),
        "the wire form must be a JSON string, not a struct: {json}"
    );

    let back: T = serde_json::from_str(&json).expect("deserializing our own output must succeed");

    assert_eq!(&back, value, "the round trip changed the value");
    assert_eq!(
        serde_json::to_string(&back).expect("serializing must succeed"),
        json,
        "the round trip changed the wire form"
    );

    (json, back)
}

#[test]
fn an_agent_uri_round_trips() {
    let uri = AgentUri::parse(URI).expect("valid URI");

    let (json, back) = round_trip(&uri);

    assert_eq!(json, format!("\"{URI}\""));
    assert_eq!(back, uri);
    assert_eq!(back.as_str(), uri.as_str());
}

#[test]
fn serde_keeps_the_query_and_fragment_that_equality_ignores() {
    // The caveat this file exists for. `AgentUri` compares by identity, so a
    // serde impl that dropped the query and the fragment would still satisfy
    // `assert_eq!(back, uri)` — the assertion an author reaches for first.
    let decorated = AgentUri::parse(DECORATED).expect("valid URI");
    let plain = AgentUri::parse(URI).expect("valid URI");

    assert_eq!(decorated, plain, "the two are one identity");

    let (json, back) = round_trip(&decorated);

    assert_eq!(json, format!("\"{DECORATED}\""));
    assert_eq!(back.as_str(), DECORATED);
    assert_eq!(back.query().ttl(), Some(300));
    assert_eq!(back.fragment().map(|f| f.as_str()), Some("invoice"));

    // And the two identities that compare equal do not serialize equal, which
    // is the whole reason the check above has to be on the string.
    assert_ne!(
        serde_json::to_string(&decorated).expect("serializable"),
        serde_json::to_string(&plain).expect("serializable"),
    );
}

#[test]
fn every_component_type_round_trips() {
    let uri = AgentUri::parse(DECORATED).expect("valid URI");

    round_trip(uri.trust_root());
    round_trip(uri.capability_path());
    round_trip(uri.agent_id());
    round_trip(uri.agent_id().prefix());
    round_trip(uri.query());
    round_trip(uri.fragment().expect("the decorated URI has one"));
    round_trip(&uri.capability_path().segments()[0]);
}

#[test]
fn each_host_shape_round_trips() {
    // `Host` renders an IPv6 address in brackets and the other two bare, and
    // deserializes by parsing a whole trust root, so each variant takes a
    // different path back.
    for input in ["anthropic.com", "192.168.1.1", "[2001:db8::1]"] {
        let root = TrustRoot::parse(input).expect("valid trust root");
        let host: &Host = root.host();

        let (json, back) = round_trip(host);

        assert_eq!(json, format!("\"{input}\""));
        assert_eq!(&back, host);
    }
}

#[test]
fn a_trust_root_keeps_its_port() {
    // The port is part of the trust root and not of the host, so it survives
    // one round trip and is absent from the other.
    let root = TrustRoot::parse("anthropic.com:8443").expect("valid trust root");

    let (json, back) = round_trip(&root);

    assert_eq!(json, "\"anthropic.com:8443\"");
    assert_eq!(back.port(), Some(8443));
    assert_eq!(
        serde_json::to_string(root.host()).expect("serializable"),
        "\"anthropic.com\""
    );
}

#[test]
fn an_empty_query_round_trips_as_an_empty_string() {
    let query = QueryParams::new();

    let (json, back) = round_trip(&query);

    assert_eq!(json, "\"\"");
    assert!(back.is_empty());
}

#[test]
fn a_query_value_survives_its_own_encoding() {
    // The rendering percent-encodes and the parser decodes, so a value that
    // needs encoding is the one that catches the two disagreeing.
    let query = QueryParams::new()
        .with_param("filter", "a&b=c d")
        .expect("valid parameter name");

    let (json, back) = round_trip(&query);

    assert!(
        json.contains("%26"),
        "the ampersand must be encoded: {json}"
    );
    assert_eq!(back.get("filter"), Some("a&b=c d"));
}

#[test]
fn a_uri_works_as_a_json_map_key() {
    // Map keys must serialize as strings, which is a stricter demand than
    // serializing as a value, and a registry keyed by agent is the obvious
    // thing to want.
    let mut agents = HashMap::new();
    agents.insert(AgentUri::parse(URI).expect("valid URI"), "healthy");

    let json = serde_json::to_string(&agents).expect("a string key serializes");
    assert_eq!(json, format!("{{\"{URI}\":\"healthy\"}}"));

    let back: HashMap<AgentUri, String> = serde_json::from_str(&json).expect("deserializable");
    assert_eq!(back.len(), 1);
    assert_eq!(
        back.get(&AgentUri::parse(URI).expect("valid URI"))
            .map(String::as_str),
        Some("healthy")
    );
}

#[test]
fn a_uri_nests_in_a_struct() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Registration {
        agent: AgentUri,
        healthy: bool,
    }

    let json = format!("{{\"agent\":\"{DECORATED}\",\"healthy\":true}}");

    let value: Registration = serde_json::from_str(&json).expect("deserializable");
    assert_eq!(value.agent.as_str(), DECORATED);
    assert!(value.healthy);

    assert_eq!(serde_json::to_string(&value).expect("serializable"), json);
}

#[test]
fn deserializing_an_invalid_string_is_an_error_and_says_why() {
    // The impls forward their parser's error through `de::Error::custom`, so
    // the reason has to survive the crossing or the caller gets "invalid
    // value" and nothing else.
    let cases = [
        ("\"not-a-uri\"", "scheme"),
        (
            "\"agent://anthropic.com/Chat/llm_01h455vb4pex5vsknk084sn02q\"",
            "capability path",
        ),
        (
            "\"agent://anthropic.com/chat/LLM_01h455vb4pex5vsknk084sn02q\"",
            "agent ID",
        ),
        ("\"\"", "empty"),
    ];

    for (json, expected) in cases {
        let result: Result<AgentUri, _> = serde_json::from_str(json);

        let Err(error) = result else {
            panic!("{json} must not deserialize");
        };
        assert!(
            error.to_string().contains(expected),
            "{json} was refused as {error}, which does not mention {expected}"
        );
    }
}

#[test]
fn every_type_refuses_a_json_value_that_is_not_a_string() {
    // Each impl asks for a `String` first. A number or an object has to be
    // refused rather than coerced, and it must not panic doing it.
    for json in ["42", "true", "null", "[]", "{}"] {
        assert!(serde_json::from_str::<AgentUri>(json).is_err(), "{json}");
        assert!(serde_json::from_str::<TrustRoot>(json).is_err(), "{json}");
        assert!(serde_json::from_str::<Host>(json).is_err(), "{json}");
        assert!(
            serde_json::from_str::<CapabilityPath>(json).is_err(),
            "{json}"
        );
        assert!(serde_json::from_str::<PathSegment>(json).is_err(), "{json}");
        assert!(serde_json::from_str::<AgentId>(json).is_err(), "{json}");
        assert!(serde_json::from_str::<AgentPrefix>(json).is_err(), "{json}");
        assert!(serde_json::from_str::<QueryParams>(json).is_err(), "{json}");
        assert!(serde_json::from_str::<Fragment>(json).is_err(), "{json}");
    }
}

#[test]
fn deserializing_normalizes_exactly_as_parsing_does() {
    // Deserialization is parsing, so the scheme and the DNS name fold and
    // nothing else does. A wire format that accepted more than the parser
    // would be a second, laxer grammar nobody wrote down.
    let value: AgentUri = serde_json::from_str(
        "\"AGENT://Anthropic.COM/assistant/chat/llm_chat_01h455vb4pex5vsknk084sn02q\"",
    )
    .expect("case differences fold");

    assert_eq!(value.as_str(), URI);
    assert_eq!(
        serde_json::to_string(&value).expect("serializable"),
        format!("\"{URI}\""),
        "what comes back out is the folded form"
    );
}

#[test]
fn a_uri_at_the_length_limit_round_trips() {
    // Length is checked on the way in, and deserializing is parsing, so the
    // longest URI the components can spell is where a round trip would fail if
    // it were going to. Built to the component maxima: a 128-character trust
    // root, a 256-character capability path, and a 90-character agent ID.
    let root = format!("{}.{}.a", "a".repeat(63), "a".repeat(62));
    let mut segments = vec!["a".repeat(7); 31];
    segments.push("a".repeat(8));
    let path = segments.join("/");
    let id = format!("{}_01h455vb4pex5vsknk084sn02q", "l".repeat(63));

    let input = format!("agent://{root}/{path}/{id}");

    // The figure SPECIFICATION.md section 3.3 states, re-derived here rather
    // than trusted, since it is the reason the 512 cap is unreachable.
    assert_eq!(input.len(), 484);

    let uri = AgentUri::parse(&input).expect("the longest constructible URI must parse");

    let (_, back) = round_trip(&uri);

    assert_eq!(back.as_str(), uri.as_str());
}
