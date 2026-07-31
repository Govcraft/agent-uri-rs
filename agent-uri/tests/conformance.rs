//! Conformance suite over the canonical test vectors.
//!
//! `test-vectors.json` at the workspace root is the artifact third parties
//! validate their implementations against. This suite runs the sections that
//! belong to this crate against the parser, so the file and the code cannot
//! drift apart unnoticed. The remaining sections run where their subject lives:
//! `dht_keys` in `agent-uri-dht`, `capability_coverage` and
//! `attestation_verification` in `agent-uri-attestation`.
//!
//! Every vector in a section this suite claims MUST be checked. A vector whose
//! shape the runner does not recognize fails the run rather than being skipped,
//! because a silently skipped vector is indistinguishable from a passing one.

use agent_uri::{AgentId, AgentUri, ParseError, ParseErrorKind};
use serde_json::Value;

mod vectors;
use vectors::{Report, load};

/// The component that refused an input.
///
/// The vectors label a rejection with an `error_type` drawn from the
/// specification's vocabulary; the parser reports which component refused it.
/// Checking rejections at component granularity catches the regression that
/// matters — an input refused for the wrong reason — without binding the suite
/// to error-message wording.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Component {
    Empty,
    Length,
    Scheme,
    Structure,
    TrustRoot,
    CapabilityPath,
    AgentId,
    Query,
    Fragment,
}

fn component_of(kind: &ParseErrorKind) -> Component {
    match kind {
        ParseErrorKind::Empty => Component::Empty,
        ParseErrorKind::TooLong { .. } => Component::Length,
        ParseErrorKind::InvalidScheme { .. } => Component::Scheme,
        ParseErrorKind::MissingComponent { .. } | ParseErrorKind::UnexpectedChar { .. } => {
            Component::Structure
        }
        ParseErrorKind::InvalidTrustRoot(_) => Component::TrustRoot,
        ParseErrorKind::InvalidCapabilityPath(_) => Component::CapabilityPath,
        ParseErrorKind::InvalidAgentId(_) => Component::AgentId,
        ParseErrorKind::InvalidQuery(_) => Component::Query,
        ParseErrorKind::InvalidFragment(_) => Component::Fragment,
    }
}

/// Which components may legitimately refuse an input carrying this `error_type`.
///
/// A label naming one component admits exactly that component. A label naming a
/// property that more than one component enforces — case, or a stray character —
/// admits every component that enforces it.
fn components_for(error_type: &str) -> &'static [Component] {
    match error_type {
        "empty_input" => &[Component::Empty],
        "uri_too_long" => &[Component::Length],
        "invalid_scheme" => &[Component::Scheme],
        "missing_trust_root" | "missing_capability_path" | "incomplete_uri" | "trailing_slash" => {
            &[Component::Structure]
        }
        // A URI whose last segment was meant as a path rather than an agent ID
        // is indistinguishable from one carrying a malformed agent ID, so the
        // agent ID is where the refusal lands.
        "missing_agent_id" => &[Component::Structure, Component::AgentId],
        "invalid_trust_root"
        | "invalid_ipv4"
        | "invalid_ipv6"
        | "invalid_port"
        | "trust_root_too_long"
        | "domain_label_too_long" => &[Component::TrustRoot],
        "empty_path_segment"
        | "invalid_capability_segment"
        | "capability_path_too_long"
        | "segment_too_long"
        | "too_many_segments" => &[Component::CapabilityPath],
        "invalid_agent_id"
        | "invalid_agent_id_prefix"
        | "invalid_agent_id_suffix"
        | "agent_id_prefix_too_long" => &[Component::AgentId],
        "invalid_query" => &[Component::Query],
        "invalid_fragment" => &[Component::Fragment],
        // Lowercase is required of both the capability path and the agent ID.
        "case_sensitivity" => &[Component::CapabilityPath, Component::AgentId],
        // A character no component admits can be refused by whichever component
        // it landed in.
        "invalid_character" => &[
            Component::TrustRoot,
            Component::CapabilityPath,
            Component::AgentId,
            Component::Query,
            Component::Fragment,
        ],
        _ => &[],
    }
}

fn check_rejection(report: &mut Report, id: &str, error_type: &str, error: &ParseError) {
    let expected = components_for(error_type);
    if expected.is_empty() {
        report.fail(id, format!("unknown error_type '{error_type}'"));
        return;
    }
    let actual = component_of(&error.kind);
    if !expected.contains(&actual) {
        report.fail(
            id,
            format!("rejected by {actual:?}, expected one of {expected:?} for '{error_type}'"),
        );
    }
}

#[test]
fn parsing_vectors() {
    let doc = load();
    let mut report = Report::new("parsing");

    for case in report.section(&doc) {
        let id = report.id(case);
        let input = report.str_field(&id, case, "input");
        let expect_valid = case["valid"].as_bool().unwrap_or(true);

        match (AgentUri::parse(&input), expect_valid) {
            (Ok(uri), true) => {
                let c = &case["components"];
                report.eq(
                    &id,
                    "scheme",
                    "agent",
                    c["scheme"].as_str().unwrap_or("agent"),
                );
                report.eq(
                    &id,
                    "trust_root",
                    uri.trust_root().as_str(),
                    &field(c, "trust_root"),
                );
                report.eq(&id, "host", uri.trust_root().host_str(), &field(c, "host"));
                report.eq(
                    &id,
                    "port",
                    &uri.trust_root()
                        .port()
                        .map_or_else(String::new, |p| p.to_string()),
                    &c["port"]
                        .as_u64()
                        .map_or_else(String::new, |p| p.to_string()),
                );
                report.eq(
                    &id,
                    "capability_path",
                    uri.capability_path().as_str(),
                    &field(c, "capability_path"),
                );
                let segments: Vec<String> = uri
                    .capability_path()
                    .segments()
                    .iter()
                    .map(|s| s.as_str().to_string())
                    .collect();
                let expected_segments: Vec<String> = c["capability_segments"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                report.eq(
                    &id,
                    "capability_segments",
                    &segments.join(","),
                    &expected_segments.join(","),
                );
                report.eq(
                    &id,
                    "agent_id",
                    &uri.agent_id().to_string(),
                    &field(c, "agent_id"),
                );
                report.eq(
                    &id,
                    "agent_id_prefix",
                    uri.agent_id().prefix().as_str(),
                    &field(c, "agent_id_prefix"),
                );
                report.eq(
                    &id,
                    "agent_id_suffix",
                    uri.agent_id().suffix(),
                    &field(c, "agent_id_suffix"),
                );
                let query = if uri.query().is_empty() {
                    String::new()
                } else {
                    uri.query().to_string()
                };
                report.eq(&id, "query", &query, &field(c, "query"));
                report.eq(
                    &id,
                    "fragment",
                    uri.fragment().map_or("", agent_uri::Fragment::as_str),
                    &field(c, "fragment"),
                );
            }
            (Err(error), true) => report.fail(&id, format!("expected valid, rejected: {error}")),
            (Ok(_), false) => report.fail(&id, "expected invalid, parsed".to_string()),
            (Err(error), false) => {
                let error_type = report.str_field(&id, case, "error_type");
                check_rejection(&mut report, &id, &error_type, &error);
            }
        }
    }

    report.finish();
}

/// A null component field means absent, which the runner compares as an empty
/// string so that "absent" and "present but empty" cannot be confused.
fn field(components: &Value, name: &str) -> String {
    components[name].as_str().unwrap_or_default().to_string()
}

#[test]
fn invalid_vectors() {
    let doc = load();
    let mut report = Report::new("invalid");

    for case in report.section(&doc) {
        let id = report.id(case);
        let input = report.str_field(&id, case, "input");
        let error_type = report.str_field(&id, case, "error_type");

        match AgentUri::parse(&input) {
            Ok(_) => report.fail(&id, format!("parsed, expected rejection ({error_type})")),
            Err(error) => check_rejection(&mut report, &id, &error_type, &error),
        }
    }

    report.finish();
}

#[test]
fn normalization_vectors() {
    let doc = load();
    let mut report = Report::new("normalization");

    for case in report.section(&doc) {
        let id = report.id(case);
        let input = report.str_field(&id, case, "input");
        let canonical = report.str_field(&id, case, "canonical");

        match AgentUri::parse(&input) {
            Ok(uri) => {
                report.eq(&id, "canonical", &uri.canonical(), &canonical);
                // A canonical form that does not itself parse back to itself
                // would not be canonical.
                match AgentUri::parse(&uri.canonical()) {
                    Ok(round) => report.eq(
                        &id,
                        "canonical is a fixed point",
                        &round.canonical(),
                        &canonical,
                    ),
                    Err(error) => {
                        report.fail(&id, format!("canonical form does not parse: {error}"))
                    }
                }
            }
            Err(error) => report.fail(&id, format!("expected canonical form, rejected: {error}")),
        }
    }

    report.finish();
}

#[test]
fn equivalence_vectors() {
    let doc = load();
    let mut report = Report::new("equivalence");

    for case in report.section(&doc) {
        let id = report.id(case);
        let a = report.str_field(&id, case, "uri_a");
        let b = report.str_field(&id, case, "uri_b");
        let Some(expected) = case["equivalent"].as_bool() else {
            report.fail(&id, "missing 'equivalent'".to_string());
            continue;
        };

        match (AgentUri::parse(&a), AgentUri::parse(&b)) {
            (Ok(x), Ok(y)) => {
                if (x == y) != expected {
                    report.fail(&id, format!("equivalent={}, expected {expected}", x == y));
                }
                // Section 5.2 defines equivalence as byte equality of canonical
                // forms, so `Eq` and `canonical()` must never disagree.
                if (x.canonical() == y.canonical()) != (x == y) {
                    report.fail(&id, "Eq and canonical() disagree".to_string());
                }
            }
            (x, y) => report.fail(
                &id,
                format!(
                    "both must parse: a={:?} b={:?}",
                    x.err().map(|e| e.to_string()),
                    y.err().map(|e| e.to_string())
                ),
            ),
        }
    }

    report.finish();
}

#[test]
fn length_limit_vectors() {
    let doc = load();
    let mut report = Report::new("length_limits");

    for case in report.section(&doc) {
        let id = report.id(case);
        let input = report.str_field(&id, case, "input");
        let Some(expect_valid) = case["valid"].as_bool() else {
            report.fail(&id, "missing 'valid'".to_string());
            continue;
        };

        if let Some(declared) = case["length"].as_u64() {
            report.eq(
                &id,
                "declared length",
                &input.len().to_string(),
                &declared.to_string(),
            );
        }

        match (AgentUri::parse(&input), expect_valid) {
            (Ok(_), true) | (Err(_), false) if expect_valid => {}
            (Ok(_), true) => {}
            (Err(error), false) => {
                let error_type = report.str_field(&id, case, "error_type");
                check_rejection(&mut report, &id, &error_type, &error);
            }
            (Err(error), true) => report.fail(&id, format!("expected valid, rejected: {error}")),
            (Ok(_), false) => report.fail(&id, "expected invalid, parsed".to_string()),
        }
    }

    report.finish();
}

#[test]
fn agent_id_vectors() {
    let doc = load();
    let mut report = Report::new("agent_id");

    for case in report.section(&doc) {
        let id = report.id(case);
        // Some vectors carry a table of related identifiers rather than one.
        if let Some(nested) = case["test_cases"].as_array() {
            if nested.is_empty() {
                report.fail(&id, "empty 'test_cases'".to_string());
            }
            for (index, nested_case) in nested.iter().enumerate() {
                let nested_id = format!("{id}[{index}]");
                check_agent_id(
                    &mut report,
                    &nested_id,
                    nested_case,
                    case["error_type"].as_str(),
                );
            }
            continue;
        }
        check_agent_id(&mut report, &id, case, None);
    }

    report.finish();
}

fn check_agent_id(report: &mut Report, id: &str, case: &Value, inherited_error: Option<&str>) {
    let agent_id = report.str_field(id, case, "agent_id");
    let Some(expect_valid) = case["valid"].as_bool() else {
        report.fail(id, "missing 'valid'".to_string());
        return;
    };

    match (AgentId::parse(&agent_id), expect_valid) {
        (Ok(parsed), true) => {
            if let Some(prefix) = case["prefix"].as_str() {
                report.eq(id, "prefix", parsed.prefix().as_str(), prefix);
            }
            if let Some(suffix) = case["suffix"].as_str() {
                report.eq(id, "suffix", parsed.suffix(), suffix);
            }
        }
        (Err(error), true) => report.fail(id, format!("expected valid, rejected: {error}")),
        (Ok(_), false) => {
            let error_type = case["error_type"]
                .as_str()
                .or(inherited_error)
                .unwrap_or("?");
            report.fail(id, format!("parsed, expected rejection ({error_type})"));
        }
        (Err(_), false) => {}
    }
}
