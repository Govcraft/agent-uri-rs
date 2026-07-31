//! Conformance suite over the `dht_keys` section of the canonical test vectors.
//!
//! `test-vectors.json` at the workspace root is the artifact third parties
//! validate their implementations against, and a key derivation is the one
//! thing two implementations cannot merely disagree about politely: nodes that
//! derive different keys for the same path cannot see each other's
//! registrations at all. This suite runs every `dht_keys` vector against
//! [`DhtKey`], so the file and the code cannot drift apart unnoticed.

use agent_uri::{CapabilityPath, TrustRoot};
use agent_uri_dht::DhtKey;
use serde_json::Value;

fn load() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../test-vectors.json");
    let text =
        std::fs::read_to_string(path).unwrap_or_else(|error| panic!("cannot read {path}: {error}"));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("cannot parse {path}: {error}"))
}

fn hex(key: &DhtKey) -> String {
    key.as_bytes()
        .iter()
        .fold(String::with_capacity(64), |mut acc, byte| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{byte:02x}");
            acc
        })
}

/// Derives the key a case names and checks it against the declared digest.
///
/// Returns the derived key so a caller can compare cases with one another.
fn check_case(failures: &mut Vec<String>, id: &str, case: &Value) -> Option<DhtKey> {
    let (Some(root), Some(path)) = (
        case["trust_root"].as_str(),
        case["capability_path"].as_str(),
    ) else {
        failures.push(format!("{id}: needs trust_root and capability_path"));
        return None;
    };
    let (Ok(root), Ok(path)) = (TrustRoot::parse(root), CapabilityPath::parse(path)) else {
        failures.push(format!(
            "{id}: trust_root or capability_path does not parse"
        ));
        return None;
    };

    let key = DhtKey::derive(&root, &path);

    // The preimage is the contract; the digest only follows from it.
    let preimage = case["input_string"]
        .as_str()
        .or_else(|| case["normalized_input"].as_str());
    if let Some(preimage) = preimage {
        let expected = format!("{root}/{path}");
        if preimage != expected {
            failures.push(format!(
                "{id}: preimage {preimage:?} != canonical {expected:?}"
            ));
        }
    } else {
        failures.push(format!("{id}: needs input_string or normalized_input"));
    }

    match case["sha256_hex"].as_str() {
        Some(expected) if hex(&key) == expected => {}
        Some(expected) => failures.push(format!("{id}: key {} != {expected}", hex(&key))),
        None => failures.push(format!("{id}: needs sha256_hex")),
    }

    Some(key)
}

#[test]
fn dht_key_vectors() {
    let doc = load();
    let section = doc["dht_keys"]
        .as_array()
        .expect("section 'dht_keys' is missing or not an array");
    assert!(!section.is_empty(), "section 'dht_keys' is empty");

    let mut failures = Vec::new();

    for case in section {
        let id = case["id"].as_str().unwrap_or("<no id>").to_string();

        // A family of cases that must derive to distinct keys.
        if let Some(cases) = case["cases"].as_array() {
            let keys: Vec<DhtKey> = cases
                .iter()
                .enumerate()
                .filter_map(|(index, nested)| {
                    check_case(&mut failures, &format!("{id}[{index}]"), nested)
                })
                .collect();
            for (i, left) in keys.iter().enumerate() {
                for right in &keys[i + 1..] {
                    assert_ne!(left, right, "{id}: cases must derive to distinct keys");
                }
            }
            continue;
        }

        // A path and each of its ancestors, one key per depth.
        if let Some(prefixes) = case["prefix_keys"].as_array() {
            let (Some(root), Some(path)) = (
                case["trust_root"].as_str(),
                case["capability_path"].as_str(),
            ) else {
                failures.push(format!("{id}: needs trust_root and capability_path"));
                continue;
            };
            let (Ok(root), Ok(path)) = (TrustRoot::parse(root), CapabilityPath::parse(path)) else {
                failures.push(format!(
                    "{id}: trust_root or capability_path does not parse"
                ));
                continue;
            };

            for prefix in prefixes {
                let depth = usize::try_from(prefix["depth"].as_u64().unwrap_or(0)).unwrap_or(0);
                let prefix_id = format!("{id}[depth {depth}]");
                let Some(key) = DhtKey::derive_at_depth(&root, &path, depth) else {
                    failures.push(format!("{prefix_id}: no key at this depth"));
                    continue;
                };
                if let Some(preimage) = prefix["input_string"].as_str() {
                    let segments: Vec<&str> = path.segments()[..depth]
                        .iter()
                        .map(agent_uri::PathSegment::as_str)
                        .collect();
                    let expected = format!("{root}/{}", segments.join("/"));
                    if preimage != expected {
                        failures.push(format!(
                            "{prefix_id}: preimage {preimage:?} != canonical {expected:?}"
                        ));
                    }
                } else {
                    failures.push(format!("{prefix_id}: needs input_string"));
                }
                match prefix["sha256_hex"].as_str() {
                    Some(expected) if hex(&key) == expected => {}
                    Some(expected) => {
                        failures.push(format!("{prefix_id}: key {} != {expected}", hex(&key)));
                    }
                    None => failures.push(format!("{prefix_id}: needs sha256_hex")),
                }
                // The deepest prefix key is the path's own key.
                if depth == path.depth() {
                    assert_eq!(
                        key,
                        DhtKey::derive(&root, &path),
                        "{prefix_id}: full-depth prefix key must equal the path key"
                    );
                }
            }
            continue;
        }

        check_case(&mut failures, &id, case);
    }

    assert!(
        failures.is_empty(),
        "{} vector(s) in section 'dht_keys' disagree with this crate:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}
