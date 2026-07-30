//! Derivation of the Kademlia record keys this backend reads and writes.
//!
//! The specification derives one key per capability path,
//! `SHA-256(trust_root || "/" || path)`, and materializes a registration at its
//! exact path and every ancestor (SPECIFICATION.md §6.2). A real overlay cannot
//! hold a subtree under one key: `libp2p-kad`'s wire limit is 16 KiB, which the
//! spike in issue #72 measured at 1 to 27 registrations. So the spec's single
//! key becomes a small family of keys here.
//!
//! Three kinds, each domain-separated so that no value written for one purpose
//! can be read as another:
//!
//! | key | holds | derived from |
//! |---|---|---|
//! | identity | the signed registration | the canonical agent URI |
//! | descriptor | the shard level of one capability path | trust root and path |
//! | page | pointers to agent URIs beneath a path | trust root, path, page index |
//!
//! # Sharding
//!
//! A capability path's pointers are spread across `2^level` pages. A publisher
//! writes to the page selected by its agent ID; a reader fans out across every
//! page. Growth raises the level by one, doubling the page count.
//!
//! The level is a power of two rather than an arbitrary page count for a
//! specific reason. With `page = hash mod P`, raising `P` moves nearly every
//! existing publisher to a different page, and every pointer already written
//! becomes unreadable until its publisher happens to rewrite it. With
//! `page = hash & (2^level - 1)`, raising the level splits each page in two and
//! leaves every existing pointer where it is: a publisher still using the old
//! level writes into a page a new reader still reads. Growth is therefore
//! backward compatible, and a stale level costs coverage rather than
//! correctness.

use agent_uri::{AgentUri, CapabilityPath, TrustRoot};
use libp2p::kad::RecordKey;
use sha2::{Digest, Sha256};

/// Domain separator for the record holding one agent's signed registration.
const IDENTITY_DOMAIN: &[u8] = b"agent-uri/dht/identity/v1\x00";

/// Domain separator for the record holding a capability path's shard level.
const DESCRIPTOR_DOMAIN: &[u8] = b"agent-uri/dht/shard-descriptor/v1\x00";

/// Domain separator for the records holding a capability path's pointers.
const PAGE_DOMAIN: &[u8] = b"agent-uri/dht/shard-page/v1\x00";

/// Domain separator for the hash that assigns a publisher to a page.
const PLACEMENT_DOMAIN: &[u8] = b"agent-uri/dht/shard-placement/v1\x00";

/// The highest shard level this backend will derive keys for.
///
/// Level 16 is 65 536 pages under one capability path, which at the measured
/// ~200 pointers per page is on the order of ten million registrations. The cap
/// exists so that a corrupt or hostile descriptor cannot make a reader derive
/// an unbounded number of keys; a reader is separately bounded by
/// [`ReadOptions::max_keys`](agent_uri_dht::ReadOptions::max_keys).
pub const MAX_SHARD_LEVEL: u8 = 16;

/// Returns the record key holding the signed registration for one agent.
///
/// Derived from the canonical URI, so query parameters and fragments, which
/// name a view of an agent rather than an agent, do not change where its
/// registration lives.
#[must_use]
pub fn identity_key(agent_uri: &AgentUri) -> RecordKey {
    let mut hasher = Sha256::new();
    hasher.update(IDENTITY_DOMAIN);
    hasher.update(agent_uri.canonical().as_bytes());
    RecordKey::new(&hasher.finalize().as_slice())
}

/// Returns the record key holding the shard level for one capability path.
#[must_use]
pub fn descriptor_key(trust_root: &TrustRoot, path: &str) -> RecordKey {
    let mut hasher = Sha256::new();
    hasher.update(DESCRIPTOR_DOMAIN);
    hasher.update(trust_root.as_str().as_bytes());
    hasher.update(b"/");
    hasher.update(path.as_bytes());
    RecordKey::new(&hasher.finalize().as_slice())
}

/// Returns the record key holding one page of pointers for a capability path.
#[must_use]
pub fn page_key(trust_root: &TrustRoot, path: &str, page: u32) -> RecordKey {
    let mut hasher = Sha256::new();
    hasher.update(PAGE_DOMAIN);
    hasher.update(trust_root.as_str().as_bytes());
    hasher.update(b"/");
    hasher.update(path.as_bytes());
    hasher.update(b"#");
    hasher.update(page.to_be_bytes());
    RecordKey::new(&hasher.finalize().as_slice())
}

/// Returns the page an agent's pointer belongs on at a given shard level.
///
/// Placement is by agent ID, not by URI, so an agent keeps its page across
/// every ancestor path it materializes at. A reader that fans out across a
/// level's pages therefore sees each agent exactly once per path.
#[must_use]
pub fn page_for(agent_uri: &AgentUri, level: u8) -> u32 {
    let level = level.min(MAX_SHARD_LEVEL);
    if level == 0 {
        return 0;
    }

    let mut hasher = Sha256::new();
    hasher.update(PLACEMENT_DOMAIN);
    hasher.update(agent_uri.agent_id().to_string().as_bytes());
    let digest = hasher.finalize();

    let mut head = [0u8; 4];
    head.copy_from_slice(&digest[..4]);
    // Masking rather than a modulus is what makes growth non-disruptive: see
    // the module docs.
    u32::from_be_bytes(head) & (page_count(level) - 1)
}

/// Returns how many pages a shard level spreads a capability path across.
#[must_use]
pub fn page_count(level: u8) -> u32 {
    1u32 << level.min(MAX_SHARD_LEVEL)
}

/// Returns the capability path and each of its ancestors, shallowest first.
///
/// These are the paths a registration materializes at, per SPECIFICATION.md
/// §6.2, and the paths a prefix lookup reads from.
#[must_use]
pub fn path_and_ancestors(path: &CapabilityPath) -> Vec<String> {
    let segments = path.segments();
    (1..=segments.len())
        .map(|depth| {
            segments[..depth]
                .iter()
                .map(agent_uri::PathSegment::as_str)
                .collect::<Vec<_>>()
                .join("/")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(agent: &str) -> AgentUri {
        AgentUri::parse(&format!("agent://anthropic.com/assistant/chat/{agent}")).unwrap()
    }

    fn trust_root() -> TrustRoot {
        TrustRoot::parse("anthropic.com").unwrap()
    }

    #[test]
    fn identity_key_is_deterministic() {
        assert_eq!(
            identity_key(&uri("llm_01h455vb4pex5vsknk084sn02q")),
            identity_key(&uri("llm_01h455vb4pex5vsknk084sn02q"))
        );
    }

    #[test]
    fn identity_key_ignores_query_and_fragment() {
        // A query names a view of an agent, not another agent, so both must
        // resolve to the one registration record.
        let plain =
            AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        let decorated = AgentUri::parse(
            "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q?version=2#sum",
        )
        .unwrap();

        assert_eq!(identity_key(&plain), identity_key(&decorated));
    }

    #[test]
    fn different_agents_get_different_identity_keys() {
        assert_ne!(
            identity_key(&uri("llm_01h455vb4pex5vsknk084sn02q")),
            identity_key(&uri("llm_01h455vb4pex5vsknk084sn02r"))
        );
    }

    #[test]
    fn the_three_key_kinds_never_collide() {
        // Domain separation is the only thing stopping a pointer page from
        // being written over an agent's registration.
        let root = trust_root();
        let identity = identity_key(&uri("llm_01h455vb4pex5vsknk084sn02q"));
        let descriptor = descriptor_key(&root, "assistant/chat");
        let page = page_key(&root, "assistant/chat", 0);

        assert_ne!(identity, descriptor);
        assert_ne!(identity, page);
        assert_ne!(descriptor, page);
    }

    #[test]
    fn pages_of_one_path_are_distinct() {
        let root = trust_root();
        let a = page_key(&root, "assistant", 0);
        let b = page_key(&root, "assistant", 1);
        assert_ne!(a, b);
    }

    #[test]
    fn trust_roots_do_not_share_pages() {
        // Cross-trust-root isolation is a security property (§8.2), and it
        // rests on the trust root being inside every key derivation.
        let a = page_key(&trust_root(), "assistant", 0);
        let b = page_key(&TrustRoot::parse("openai.com").unwrap(), "assistant", 0);
        assert_ne!(a, b);
    }

    #[test]
    fn level_zero_puts_everyone_on_one_page() {
        assert_eq!(page_for(&uri("llm_01h455vb4pex5vsknk084sn02q"), 0), 0);
        assert_eq!(page_count(0), 1);
    }

    #[test]
    fn placement_is_stable_across_a_level_increase() {
        // The property that makes growth safe: raising the level either leaves
        // an agent where it was or moves it into a page that did not exist
        // before, so no already-written pointer becomes unreadable.
        for n in 0..64u32 {
            let agent = uri(&format!("llm_01h455vb4pex5vsknk084s{n:04}"));
            let low = page_for(&agent, 3);
            let high = page_for(&agent, 4);
            assert!(
                high == low || high == low + page_count(3),
                "agent moved from page {low} to {high}, which a level-3 reader never visits"
            );
        }
    }

    #[test]
    fn placement_spreads_across_pages() {
        let pages: std::collections::HashSet<u32> = (0..256u32)
            .map(|n| page_for(&uri(&format!("llm_01h455vb4pex5vsknk084s{n:04}")), 4))
            .collect();
        // 256 agents over 16 pages: a derivation that ignored the agent ID
        // would collapse to one, which is the failure worth catching.
        assert!(pages.len() > 8, "only {} of 16 pages used", pages.len());
    }

    #[test]
    fn level_is_capped() {
        assert_eq!(page_count(u8::MAX), 1 << MAX_SHARD_LEVEL);
        let agent = uri("llm_01h455vb4pex5vsknk084sn02q");
        assert!(page_for(&agent, u8::MAX) < page_count(MAX_SHARD_LEVEL));
    }

    #[test]
    fn ancestors_run_shallowest_first() {
        let path = CapabilityPath::parse("workflow/approval/finance").unwrap();
        assert_eq!(
            path_and_ancestors(&path),
            vec![
                "workflow".to_string(),
                "workflow/approval".to_string(),
                "workflow/approval/finance".to_string(),
            ]
        );
    }

    #[test]
    fn a_single_segment_path_is_its_own_only_ancestor() {
        let path = CapabilityPath::parse("workflow").unwrap();
        assert_eq!(path_and_ancestors(&path), vec!["workflow".to_string()]);
    }

    #[test]
    fn ancestor_paths_agree_with_the_specs_key_derivation() {
        // The strings fed to page_key must be exactly the paths the spec
        // derives keys for, or a prefix lookup reads keys nobody wrote to.
        let path = CapabilityPath::parse("assistant/chat/streaming").unwrap();
        let root = trust_root();
        for (depth, ancestor) in path_and_ancestors(&path).iter().enumerate() {
            let spec_key = agent_uri_dht::DhtKey::derive_at_depth(&root, &path, depth + 1).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(root.as_str().as_bytes());
            hasher.update(b"/");
            hasher.update(ancestor.as_bytes());
            assert_eq!(spec_key.as_bytes()[..], hasher.finalize()[..]);
        }
    }
}
