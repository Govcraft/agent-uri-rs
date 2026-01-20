//! Property-based tests validating the parser against the ABNF grammar.
//!
//! These tests generate random valid inputs according to grammar constraints
//! and verify the parser accepts them, ensuring parser-grammar conformance.

use proptest::prelude::*;

use agent_uri::{
    AgentId, AgentPrefix, AgentUri, AgentUriBuilder, CapabilityPath, PathSegment, TrustRoot,
    AGENT_SUFFIX_LENGTH, MAX_AGENT_PREFIX_LENGTH, MAX_CAPABILITY_PATH_LENGTH, MAX_PATH_SEGMENTS,
    MAX_PATH_SEGMENT_LENGTH, MAX_TRUST_ROOT_LENGTH, MAX_URI_LENGTH,
};

/// Strategies for generating valid grammar-conformant inputs.
mod strategies {
    use super::*;

    /// Base32 alphabet for TypeID suffix (excludes i, l, o, u)
    const BASE32_ALPHABET: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";

    /// Valid lowercase letters for prefixes
    const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";

    /// Valid alphanumeric characters for DNS labels
    const ALPHANUMERIC: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

    /// Valid characters for DNS labels (alphanumeric + hyphen)
    const DNS_LABEL_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";

    /// Valid characters for path segments (lowercase + digits + hyphen)
    const PATH_SEGMENT_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789-";

    /// Generate a valid DNS label (1-20 chars for reasonable generation, alphanumeric + hyphen)
    /// Note: DNS spec allows up to 63 chars, but we use shorter labels to reduce rejection rate.
    pub fn dns_label() -> impl Strategy<Value = String> {
        // Use 1-20 to keep domains reasonable and avoid too many rejections
        (1..=20usize).prop_flat_map(|len| {
            if len == 1 {
                // Single char must be alphanumeric
                prop::sample::select(ALPHANUMERIC.to_vec())
                    .prop_map(|c| (c as char).to_string())
                    .boxed()
            } else {
                // First char: alphanumeric
                // Middle chars: alphanumeric or hyphen
                // Last char: alphanumeric
                let first = prop::sample::select(ALPHANUMERIC.to_vec());
                let middle_len = len.saturating_sub(2);
                let middle = prop::collection::vec(
                    prop::sample::select(DNS_LABEL_CHARS.to_vec()),
                    middle_len..=middle_len,
                );
                let last = prop::sample::select(ALPHANUMERIC.to_vec());

                (first, middle, last)
                    .prop_map(|(f, m, l)| {
                        let mut s = String::with_capacity(2 + m.len());
                        s.push(f as char);
                        for c in m {
                            s.push(c as char);
                        }
                        s.push(l as char);
                        s
                    })
                    .boxed()
            }
        })
    }

    /// Generate a valid domain name (labels separated by dots, max 253 chars)
    pub fn domain() -> impl Strategy<Value = String> {
        // Generate 1-4 labels, ensure total length fits
        prop::collection::vec(dns_label(), 1..=4).prop_filter_map(
            "domain too long or invalid",
            |labels| {
                let domain = labels.join(".");
                if domain.len() <= 253 && !domain.is_empty() {
                    Some(domain)
                } else {
                    None
                }
            },
        )
    }

    /// Generate a valid IPv4 address
    pub fn ipv4() -> impl Strategy<Value = String> {
        (0u8..=255, 0u8..=255, 0u8..=255, 0u8..=255)
            .prop_map(|(a, b, c, d)| format!("{a}.{b}.{c}.{d}"))
    }

    /// Generate a valid IPv6 address (simplified: full form only)
    pub fn ipv6() -> impl Strategy<Value = String> {
        prop::collection::vec(0u16..=0xffff, 8).prop_map(|groups| {
            groups
                .iter()
                .map(|g| format!("{g:x}"))
                .collect::<Vec<_>>()
                .join(":")
        })
    }

    /// Generate a valid trust root (domain, IPv4, or IPv6 with optional port)
    pub fn trust_root() -> impl Strategy<Value = String> {
        let domain_with_port = domain().prop_flat_map(|d| {
            prop::option::of(1u16..=65535).prop_map(move |port| match port {
                Some(p) => format!("{d}:{p}"),
                None => d.clone(),
            })
        });

        let ipv4_with_port = ipv4().prop_flat_map(|ip| {
            prop::option::of(1u16..=65535).prop_map(move |port| match port {
                Some(p) => format!("{ip}:{p}"),
                None => ip.clone(),
            })
        });

        let ipv6_with_port = ipv6().prop_flat_map(|ip| {
            prop::option::of(1u16..=65535).prop_map(move |port| match port {
                Some(p) => format!("[{ip}]:{p}"),
                None => format!("[{ip}]"),
            })
        });

        prop_oneof![
            8 => domain_with_port,
            1 => ipv4_with_port,
            1 => ipv6_with_port,
        ]
        .prop_filter("trust root too long", |tr| tr.len() <= MAX_TRUST_ROOT_LENGTH)
    }

    /// Generate a valid path segment (1-16 chars to keep paths reasonably sized)
    /// Note: Grammar allows up to 64 chars, but shorter segments reduce rejection rate.
    pub fn path_segment() -> impl Strategy<Value = String> {
        // Use 1-16 to keep capability paths within 256 char limit more reliably
        (1..=16usize).prop_flat_map(|len| {
            prop::collection::vec(
                prop::sample::select(PATH_SEGMENT_CHARS.to_vec()),
                len..=len,
            )
            .prop_map(|chars| chars.into_iter().map(|c| c as char).collect())
        })
    }

    /// Generate a valid capability path (1-16 segments for reasonable generation)
    /// Note: Grammar allows up to 32 segments, but we limit to avoid length constraint rejections.
    pub fn capability_path() -> impl Strategy<Value = String> {
        // Use 1-16 segments with shorter segments to stay within 256 char limit
        (1..=16usize).prop_flat_map(|num_segments| {
            prop::collection::vec(path_segment(), num_segments..=num_segments).prop_filter_map(
                "path too long",
                |segments| {
                    let path = segments.join("/");
                    if path.len() <= MAX_CAPABILITY_PATH_LENGTH {
                        Some(path)
                    } else {
                        None
                    }
                },
            )
        })
    }

    /// Generate a valid type modifier (1-8 lowercase letters)
    pub fn type_modifier() -> impl Strategy<Value = String> {
        (1..=8usize).prop_flat_map(|len| {
            prop::collection::vec(prop::sample::select(LOWERCASE.to_vec()), len..=len)
                .prop_map(|chars| chars.into_iter().map(|c| c as char).collect())
        })
    }

    /// Generate a valid agent prefix (type class + optional modifiers, max 63 chars)
    pub fn agent_prefix() -> impl Strategy<Value = String> {
        let type_classes = prop::sample::select(vec![
            "llm",
            "rule",
            "human",
            "composite",
            "sensor",
            "actuator",
            "hybrid",
        ]);

        (type_classes, prop::collection::vec(type_modifier(), 0..=3)).prop_filter_map(
            "prefix too long",
            |(class, modifiers)| {
                let mut prefix = class.to_string();
                for m in modifiers {
                    prefix.push('_');
                    prefix.push_str(&m);
                }
                if prefix.len() <= MAX_AGENT_PREFIX_LENGTH {
                    Some(prefix)
                } else {
                    None
                }
            },
        )
    }

    /// Generate a valid TypeID suffix (26 chars, first char 0-7, rest base32)
    pub fn type_suffix() -> impl Strategy<Value = String> {
        let first = prop::sample::select(b"01234567".to_vec());
        let rest = prop::collection::vec(prop::sample::select(BASE32_ALPHABET.to_vec()), 25..=25);

        (first, rest).prop_map(|(f, r)| {
            let mut s = String::with_capacity(26);
            s.push(f as char);
            for c in r {
                s.push(c as char);
            }
            s
        })
    }

    /// Generate a valid agent ID (prefix_suffix)
    pub fn agent_id() -> impl Strategy<Value = String> {
        (agent_prefix(), type_suffix())
            .prop_map(|(prefix, suffix)| format!("{prefix}_{suffix}"))
            .prop_filter("agent id too long", |id| id.len() <= 90)
    }

    /// Generate a valid complete agent URI
    pub fn agent_uri() -> impl Strategy<Value = String> {
        (trust_root(), capability_path(), agent_id()).prop_filter_map(
            "uri too long",
            |(tr, cp, id)| {
                let uri = format!("agent://{tr}/{cp}/{id}");
                if uri.len() <= MAX_URI_LENGTH {
                    Some(uri)
                } else {
                    None
                }
            },
        )
    }
}

mod trust_root_tests {
    use super::strategies::*;
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn valid_domains_parse(d in domain()) {
            let result = TrustRoot::parse(&d);
            prop_assert!(result.is_ok(), "Failed to parse domain: {}", d);
        }

        #[test]
        fn valid_ipv4_parses(ip in ipv4()) {
            let result = TrustRoot::parse(&ip);
            prop_assert!(result.is_ok(), "Failed to parse IPv4: {}", ip);
        }

        #[test]
        fn valid_ipv6_parses(ip in ipv6()) {
            let bracketed = format!("[{ip}]");
            let result = TrustRoot::parse(&bracketed);
            prop_assert!(result.is_ok(), "Failed to parse IPv6: {}", bracketed);
        }

        #[test]
        fn valid_trust_roots_parse(tr in trust_root()) {
            let result = TrustRoot::parse(&tr);
            prop_assert!(result.is_ok(), "Failed to parse trust root: {}", tr);
        }

        #[test]
        fn trust_root_length_constraint(tr in trust_root()) {
            prop_assert!(tr.len() <= MAX_TRUST_ROOT_LENGTH);
        }
    }
}

mod capability_path_tests {
    use super::strategies::*;
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn valid_path_segments_parse(seg in path_segment()) {
            let result = PathSegment::parse(&seg);
            prop_assert!(result.is_ok(), "Failed to parse segment: {}", seg);
        }

        #[test]
        fn valid_capability_paths_parse(path in capability_path()) {
            let result = CapabilityPath::parse(&path);
            prop_assert!(result.is_ok(), "Failed to parse path: {}", path);
        }

        #[test]
        fn capability_path_length_constraint(path in capability_path()) {
            prop_assert!(path.len() <= MAX_CAPABILITY_PATH_LENGTH);
        }

        #[test]
        fn capability_path_segment_count_constraint(path in capability_path()) {
            let parsed = CapabilityPath::parse(&path).unwrap();
            prop_assert!(parsed.depth() <= MAX_PATH_SEGMENTS);
        }
    }
}

mod agent_id_tests {
    use super::strategies::*;
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn valid_agent_prefixes_parse(prefix in agent_prefix()) {
            let result = AgentPrefix::parse(&prefix);
            prop_assert!(result.is_ok(), "Failed to parse prefix: {}", prefix);
        }

        #[test]
        fn valid_agent_ids_parse(id in agent_id()) {
            let result = AgentId::parse(&id);
            prop_assert!(result.is_ok(), "Failed to parse agent ID: {}", id);
        }

        #[test]
        fn agent_prefix_length_constraint(prefix in agent_prefix()) {
            prop_assert!(prefix.len() <= MAX_AGENT_PREFIX_LENGTH);
        }

        #[test]
        fn agent_suffix_length_is_fixed(id in agent_id()) {
            let parsed = AgentId::parse(&id).unwrap();
            prop_assert_eq!(parsed.suffix().len(), AGENT_SUFFIX_LENGTH);
        }
    }
}

mod full_uri_tests {
    use super::strategies::*;
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn valid_uris_parse(uri in agent_uri()) {
            let result = AgentUri::parse(&uri);
            prop_assert!(result.is_ok(), "Failed to parse URI: {}", uri);
        }

        #[test]
        fn uri_length_constraint(uri in agent_uri()) {
            prop_assert!(uri.len() <= MAX_URI_LENGTH);
        }

        #[test]
        fn roundtrip_parse_serialize(uri in agent_uri()) {
            let parsed = AgentUri::parse(&uri).unwrap();
            let serialized = parsed.to_string();
            let reparsed = AgentUri::parse(&serialized).unwrap();

            prop_assert_eq!(parsed.trust_root().as_str(), reparsed.trust_root().as_str());
            prop_assert_eq!(parsed.capability_path().as_str(), reparsed.capability_path().as_str());
            prop_assert_eq!(parsed.agent_id().prefix().as_str(), reparsed.agent_id().prefix().as_str());
            prop_assert_eq!(parsed.agent_id().suffix(), reparsed.agent_id().suffix());
        }

        #[test]
        fn components_accessible_after_parse(uri in agent_uri()) {
            let parsed = AgentUri::parse(&uri).unwrap();

            // Trust root accessible
            let _ = parsed.trust_root().host_str();

            // Capability path accessible
            let _ = parsed.capability_path().depth();
            let _ = parsed.capability_path().segments();

            // Agent ID accessible
            let _ = parsed.agent_id().prefix();
            let _ = parsed.agent_id().suffix();
        }
    }
}

mod length_constraint_tests {
    use super::*;

    #[test]
    fn uri_at_max_length_parses() {
        // Construct a URI that fits within max length while respecting all constraints
        let trust_root = "a.co";
        let agent_id = "llm_01h455vb4pex5vsknk084sn02q";
        let overhead = "agent://".len() + trust_root.len() + 2 + agent_id.len(); // 2 for slashes
        let remaining = MAX_URI_LENGTH - overhead;

        // Fill with path segments, respecting:
        // - Max 64 chars per segment
        // - Max 32 segments
        // - Max 256 total path length
        let path_budget = remaining.min(MAX_CAPABILITY_PATH_LENGTH);

        // Create segments of 63 chars each (with room for "/" separators)
        let segment = "x".repeat(63);
        let mut path_parts = Vec::new();
        let mut current_len = 0;

        // Add segments while staying under budget
        while current_len + segment.len() + (if path_parts.is_empty() { 0 } else { 1 })
            <= path_budget
            && path_parts.len() < MAX_PATH_SEGMENTS
        {
            if !path_parts.is_empty() {
                current_len += 1; // for "/"
            }
            current_len += segment.len();
            path_parts.push(segment.clone());
        }

        // If we have room for a partial segment, add it
        let remaining_space =
            path_budget - current_len - (if path_parts.is_empty() { 0 } else { 1 });
        if remaining_space > 0 && path_parts.len() < MAX_PATH_SEGMENTS {
            let partial_segment = "x".repeat(remaining_space.min(MAX_PATH_SEGMENT_LENGTH));
            path_parts.push(partial_segment);
        }

        let path = path_parts.join("/");
        assert!(
            path.len() <= MAX_CAPABILITY_PATH_LENGTH,
            "Path too long: {}",
            path.len()
        );

        let uri = format!("agent://{trust_root}/{path}/{agent_id}");
        assert!(
            uri.len() <= MAX_URI_LENGTH,
            "URI too long: {} > {}",
            uri.len(),
            MAX_URI_LENGTH
        );

        let result = AgentUri::parse(&uri);
        assert!(
            result.is_ok(),
            "Failed to parse max-length URI: {:?}",
            result.err()
        );
    }

    #[test]
    fn uri_over_max_length_fails() {
        let long_path = "a".repeat(500);
        let uri = format!("agent://x.com/{long_path}/llm_01h455vb4pex5vsknk084sn02q");
        assert!(uri.len() > MAX_URI_LENGTH);

        let result = AgentUri::parse(&uri);
        assert!(result.is_err());
    }

    #[test]
    fn trust_root_at_max_length_parses() {
        // Create a trust root near max length
        let label = "a".repeat(63);
        let trust_root = format!("{label}.{label}"); // ~127 chars
        assert!(trust_root.len() <= MAX_TRUST_ROOT_LENGTH);

        let result = TrustRoot::parse(&trust_root);
        assert!(result.is_ok());
    }

    #[test]
    fn trust_root_over_max_length_fails() {
        let long_label = "a".repeat(130);
        let result = TrustRoot::parse(&long_label);
        assert!(result.is_err());
    }

    #[test]
    fn capability_path_at_max_segments_parses() {
        let segments: Vec<&str> = (0..MAX_PATH_SEGMENTS).map(|_| "x").collect();
        let path = segments.join("/");

        let result = CapabilityPath::parse(&path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().depth(), MAX_PATH_SEGMENTS);
    }

    #[test]
    fn capability_path_over_max_segments_fails() {
        let segments: Vec<&str> = (0..=MAX_PATH_SEGMENTS).map(|_| "x").collect();
        let path = segments.join("/");

        let result = CapabilityPath::parse(&path);
        assert!(result.is_err());
    }

    #[test]
    fn path_segment_at_max_length_parses() {
        let segment = "a".repeat(MAX_PATH_SEGMENT_LENGTH);
        let result = PathSegment::parse(&segment);
        assert!(result.is_ok());
    }

    #[test]
    fn path_segment_over_max_length_fails() {
        let segment = "a".repeat(MAX_PATH_SEGMENT_LENGTH + 1);
        let result = PathSegment::parse(&segment);
        assert!(result.is_err());
    }

    #[test]
    fn agent_prefix_at_max_length_parses() {
        // Max 63 chars, must start with valid type class (llm, rule, etc.)
        // "llm" (3) + "_" (1) + 59 more chars arranged as modifiers
        // e.g., "llm_" + "aaaaaaaaaa_" * 5 + "aaaaaaaaa" = 3 + 1 + 55 + 4 = 63
        // Actually: "llm_" (4) + then we need 59 more chars
        // Use "llm_" + "abcdefghi_" * 5 + "abcdefghij" = 4 + 50 + 10 = 64 (too long)
        // Use "llm_" + "abcdefgh_" * 6 + "abc" = 4 + 54 + 3 = 61 (valid but not max)
        // For max 63: "llm_" (4) + "abcdefghi_" (10) * 5 + "abcdefghi" (9) = 4 + 50 + 9 = 63
        let prefix = format!("llm_{}", "abcdefghi_".repeat(5) + "abcdefghi");
        assert_eq!(prefix.len(), 63);
        let result = AgentPrefix::parse(&prefix);
        assert!(result.is_ok(), "Failed to parse: {:?}", result);
    }

    #[test]
    fn agent_prefix_over_max_length_fails() {
        let prefix = "a".repeat(MAX_AGENT_PREFIX_LENGTH + 1);
        let result = AgentPrefix::parse(&prefix);
        assert!(result.is_err());
    }
}

mod roundtrip_tests {
    use super::strategies::*;
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]

        #[test]
        fn builder_roundtrip(
            tr in trust_root(),
            path in capability_path(),
            prefix in agent_prefix()
        ) {
            // Build URI from components
            let trust_root = TrustRoot::parse(&tr).unwrap();
            let capability_path = CapabilityPath::parse(&path).unwrap();
            let agent_id = AgentId::try_new(&prefix).unwrap();

            let uri = AgentUriBuilder::new()
                .trust_root(trust_root.clone())
                .capability_path(capability_path.clone())
                .agent_id(agent_id.clone())
                .build();

            if let Ok(uri) = uri {
                // Serialize and reparse
                let serialized = uri.to_string();
                let reparsed = AgentUri::parse(&serialized).unwrap();

                prop_assert_eq!(uri.trust_root().as_str(), reparsed.trust_root().as_str());
                prop_assert_eq!(uri.capability_path().as_str(), reparsed.capability_path().as_str());
            }
            // If build fails due to length, that's expected behavior
        }
    }
}
