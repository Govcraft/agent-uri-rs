//! Lookup queries.

use agent_uri::{CapabilityPath, TrustRoot};

/// How a capability path is matched during lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MatchMode {
    /// Return only agents registered at exactly this path.
    Exact,
    /// Return agents at this path and every descendant path.
    Prefix,
}

/// A capability lookup.
///
/// Every query is scoped to one trust root, because every DHT key is derived
/// from one. There is deliberately no cross-trust-root query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    trust_root: TrustRoot,
    capability_path: CapabilityPath,
    match_mode: MatchMode,
}

impl Query {
    /// Creates a query for agents at exactly this capability path.
    #[must_use]
    pub const fn exact(trust_root: TrustRoot, capability_path: CapabilityPath) -> Self {
        Self {
            trust_root,
            capability_path,
            match_mode: MatchMode::Exact,
        }
    }

    /// Creates a query for agents at this capability path and its descendants.
    #[must_use]
    pub const fn prefix(trust_root: TrustRoot, capability_path: CapabilityPath) -> Self {
        Self {
            trust_root,
            capability_path,
            match_mode: MatchMode::Prefix,
        }
    }

    /// Returns the trust root this query is scoped to.
    #[must_use]
    pub const fn trust_root(&self) -> &TrustRoot {
        &self.trust_root
    }

    /// Returns the capability path being queried.
    #[must_use]
    pub const fn capability_path(&self) -> &CapabilityPath {
        &self.capability_path
    }

    /// Returns the match mode.
    #[must_use]
    pub const fn match_mode(&self) -> MatchMode {
        self.match_mode
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts() -> (TrustRoot, CapabilityPath) {
        (
            TrustRoot::parse("anthropic.com").unwrap(),
            CapabilityPath::parse("assistant/chat").unwrap(),
        )
    }

    #[test]
    fn exact_query_records_its_mode() {
        let (tr, path) = parts();
        let q = Query::exact(tr, path);
        assert_eq!(q.match_mode(), MatchMode::Exact);
        assert_eq!(q.trust_root().as_str(), "anthropic.com");
        assert_eq!(q.capability_path().as_str(), "assistant/chat");
    }

    #[test]
    fn prefix_query_records_its_mode() {
        let (tr, path) = parts();
        let q = Query::prefix(tr, path);
        assert_eq!(q.match_mode(), MatchMode::Prefix);
    }

    #[test]
    fn queries_differing_only_in_mode_are_not_equal() {
        let (tr, path) = parts();
        assert_ne!(
            Query::exact(tr.clone(), path.clone()),
            Query::prefix(tr, path)
        );
    }
}
