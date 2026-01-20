//! Kani Arbitrary implementations and proof harnesses for property verification.
//!
//! This module provides `kani::Arbitrary` trait implementations for
//! the crate's public types, enabling property-based verification
//! with the Kani model checker.
//!
//! # Usage
//!
//! Kani is not a Cargo dependency. Install and run with:
//!
//! ```bash
//! cargo install --locked kani-verifier
//! cargo kani setup
//! cargo kani --features kani
//! ```
//!
//! This module is only compiled when using Kani (`#[cfg(kani)]`).

use crate::{
    AgentId, AgentPrefix, AgentUri, CapabilityPath, Fragment, PathSegment, QueryParams, TrustRoot,
};

/// Valid characters for path segments: lowercase letters, digits, hyphen
const SEGMENT_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";

/// Valid characters for domain labels: alphanumeric and hyphen
const DOMAIN_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";

/// Generate a valid segment character
fn arbitrary_segment_char() -> char {
    let idx: usize = kani::any();
    let idx = idx % SEGMENT_CHARS.len();
    SEGMENT_CHARS[idx] as char
}

/// Generate a valid domain character (for non-leading/trailing positions)
fn arbitrary_domain_char() -> char {
    let idx: usize = kani::any();
    let idx = idx % DOMAIN_CHARS.len();
    DOMAIN_CHARS[idx] as char
}

/// Generate a valid domain label start/end character (letters and digits only)
fn arbitrary_domain_boundary_char() -> char {
    let chars = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let idx: usize = kani::any();
    let idx = idx % chars.len();
    chars[idx] as char
}

/// Generate a valid prefix character (lowercase letters and underscore)
fn arbitrary_prefix_char(is_boundary: bool) -> char {
    if is_boundary {
        // Start/end must be letter
        let chars = b"abcdefghijklmnopqrstuvwxyz";
        let idx: usize = kani::any();
        let idx = idx % chars.len();
        chars[idx] as char
    } else {
        // Middle can have underscore
        let chars = b"abcdefghijklmnopqrstuvwxyz_";
        let idx: usize = kani::any();
        let idx = idx % chars.len();
        chars[idx] as char
    }
}

impl kani::Arbitrary for PathSegment {
    fn any() -> Self {
        // Generate 1-8 char segment for tractability
        let len: usize = kani::any();
        let len = 1 + (len % 8);

        let s: String = (0..len).map(|_| arbitrary_segment_char()).collect();

        // The string should be valid by construction, but assume to constrain search
        kani::assume(!s.is_empty() && s.len() <= 64);
        kani::assume(s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'));

        PathSegment::parse(&s).expect("valid segment by construction")
    }
}

impl kani::Arbitrary for CapabilityPath {
    fn any() -> Self {
        // Generate 1-4 segments for tractability
        let num_segments: usize = kani::any();
        let num_segments = 1 + (num_segments % 4);

        let segments: Vec<PathSegment> = (0..num_segments).map(|_| kani::any()).collect();

        CapabilityPath::from_segments(segments).expect("valid path by construction")
    }
}

impl kani::Arbitrary for AgentPrefix {
    fn any() -> Self {
        // Generate 1-10 char prefix for tractability
        let len: usize = kani::any();
        let len = 1 + (len % 10);

        let prefix: String = (0..len)
            .enumerate()
            .map(|(i, _)| {
                let is_boundary = i == 0 || i == len - 1;
                arbitrary_prefix_char(is_boundary)
            })
            .collect();

        kani::assume(!prefix.is_empty() && prefix.len() <= 63);

        AgentPrefix::parse(&prefix).expect("valid prefix by construction")
    }
}

impl kani::Arbitrary for TrustRoot {
    fn any() -> Self {
        // Generate simple domain: label.label format
        // Labels: 1-6 chars for tractability
        let len1: usize = kani::any();
        let len1 = 1 + (len1 % 6);
        let len2: usize = kani::any();
        let len2 = 2 + (len2 % 4); // TLD must be >= 2 chars

        // First label
        let label1: String = (0..len1)
            .enumerate()
            .map(|(i, _)| {
                if i == 0 || i == len1 - 1 {
                    arbitrary_domain_boundary_char()
                } else {
                    arbitrary_domain_char()
                }
            })
            .collect();

        // Second label (TLD)
        let label2: String = (0..len2)
            .enumerate()
            .map(|(i, _)| {
                if i == 0 || i == len2 - 1 {
                    arbitrary_domain_boundary_char()
                } else {
                    arbitrary_domain_char()
                }
            })
            .collect();

        let domain = format!("{label1}.{label2}");

        // Optionally add port
        let has_port: bool = kani::any();
        let full = if has_port {
            let port: u16 = kani::any();
            kani::assume(port > 0); // Avoid port 0
            format!("{domain}:{port}")
        } else {
            domain
        };

        TrustRoot::parse(&full).expect("valid trust root by construction")
    }
}

impl kani::Arbitrary for AgentId {
    fn any() -> Self {
        let prefix: AgentPrefix = kani::any();
        AgentId::try_new(prefix.as_str()).expect("valid agent id by construction")
    }
}

impl kani::Arbitrary for AgentUri {
    fn any() -> Self {
        let trust_root: TrustRoot = kani::any();
        let capability_path: CapabilityPath = kani::any();
        let agent_id: AgentId = kani::any();

        AgentUri::new(trust_root, capability_path, agent_id, QueryParams::new(), None)
            .expect("valid URI by construction")
    }
}

// ============================================================================
// Kani Proof Harnesses
// ============================================================================

/// Proof: Parse then serialize equals original (for canonical URIs)
#[kani::proof]
#[kani::unwind(10)]
fn proof_parse_roundtrip() {
    let uri: AgentUri = kani::any();
    let canonical = uri.canonical();
    let reparsed = AgentUri::parse(&canonical).expect("canonical should parse");
    assert_eq!(reparsed.canonical(), canonical);
}

/// Proof: Canonical form has no query (?) or fragment (#)
#[kani::proof]
#[kani::unwind(10)]
fn proof_canonical_strips_query_fragment() {
    let uri: AgentUri = kani::any();
    let canonical = uri.canonical();
    assert!(!canonical.contains('?'));
    assert!(!canonical.contains('#'));
}

/// Proof: A path always starts_with itself (reflexive property)
#[kani::proof]
#[kani::unwind(5)]
fn proof_starts_with_reflexive() {
    let path: CapabilityPath = kani::any();
    assert!(path.starts_with(&path));
}

/// Proof: If a.starts_with(b) and b.starts_with(c) then a.starts_with(c) (transitive)
#[kani::proof]
#[kani::unwind(5)]
fn proof_starts_with_transitive() {
    let a: CapabilityPath = kani::any();
    let b: CapabilityPath = kani::any();
    let c: CapabilityPath = kani::any();

    kani::assume(a.starts_with(&b));
    kani::assume(b.starts_with(&c));

    assert!(a.starts_with(&c));
}

/// Proof: from_segments produces same result as parsing joined string
#[kani::proof]
#[kani::unwind(5)]
fn proof_from_segments_equivalent_to_parse() {
    let segments: Vec<PathSegment> = vec![kani::any(), kani::any()];

    let from_segments =
        CapabilityPath::from_segments(segments.clone()).expect("valid by construction");

    let joined: String = segments.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("/");

    let parsed = CapabilityPath::parse(&joined).expect("joined string should parse");

    assert_eq!(from_segments.as_str(), parsed.as_str());
}

/// Proof: try_from_strs produces same result as from_segments with parsed segments
#[kani::proof]
#[kani::unwind(5)]
fn proof_try_from_strs_equivalent() {
    // Use fixed valid strings for tractability
    let strs = ["alpha", "beta"];

    let from_strs = CapabilityPath::try_from_strs(&strs).expect("valid strings");

    let segments: Vec<PathSegment> = strs
        .iter()
        .map(|s| PathSegment::parse(s).expect("valid"))
        .collect();
    let from_segments = CapabilityPath::from_segments(segments).expect("valid segments");

    assert_eq!(from_strs.as_str(), from_segments.as_str());
}
