//! Simulated DHT implementation for evaluation.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use agent_uri::AgentUri;
use agent_uri_attestation::Verifier;
use async_trait::async_trait;

use crate::{
    Cursor, Dht, DhtError, DhtKey, DhtStats, Endpoint, MatchMode, MigrationResult, NodeId, Page,
    PeerAddr, Query, Quorum, ReadOptions, Registration, SimulationConfig, WriteOptions,
    WriteReceipt,
};

/// Hands each simulator instance a distinct identity without pulling in a
/// random-number dependency. Distinctness is what callers rely on; the values
/// themselves carry no meaning.
static NEXT_NODE_ID: AtomicU64 = AtomicU64::new(1);

/// Simulated DHT for evaluation.
///
/// Single-process, in-memory implementation that faithfully models
/// DHT behavior without network overhead. Suitable for evaluation
/// and testing.
///
/// # Thread Safety
///
/// Uses `RwLock` for interior mutability, allowing concurrent reads
/// and exclusive writes.
///
/// # Examples
///
/// ```
/// use agent_uri::{AgentUri, CapabilityPath, TrustRoot};
/// use agent_uri_dht::{
///     Dht, Endpoint, Query, ReadOptions, Registration, SimulatedDht, SimulationConfig,
///     WriteOptions,
/// };
/// use futures::executor::block_on;
///
/// // Explicitly unverified because this example isolates indexing behavior.
/// let dht = SimulatedDht::new(
///     SimulationConfig::default().with_verify_attestations(false)
/// );
///
/// let uri = AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q").unwrap();
/// let registration = Registration::new(uri.clone(), vec![Endpoint::https("agent.anthropic.com")]);
///
/// block_on(dht.register(registration, WriteOptions::default())).unwrap();
///
/// let query = Query::exact(
///     TrustRoot::parse("anthropic.com").unwrap(),
///     CapabilityPath::parse("assistant/chat").unwrap(),
/// );
/// let page = block_on(dht.lookup(&query, &ReadOptions::default())).unwrap();
///
/// assert_eq!(page.len(), 1);
/// ```
pub struct SimulatedDht {
    /// Primary index: `DhtKey` -> Registrations
    by_key: RwLock<HashMap<DhtKey, Vec<Registration>>>,

    /// Secondary index: canonical `AgentUri` -> exact and ancestor keys.
    by_uri: RwLock<HashMap<String, Vec<DhtKey>>>,

    /// Enforces that a stable trust-root/agent-ID pair has one immutable path.
    by_identity: RwLock<HashMap<String, String>>,

    /// Trusted roots used for registration-time attestation verification.
    verifier: Verifier,

    /// This instance's identity in the (notional) overlay.
    node_id: NodeId,

    /// Configuration
    config: SimulationConfig,
}

impl SimulatedDht {
    fn next_node_id() -> NodeId {
        NodeId::from_bytes(NEXT_NODE_ID.fetch_add(1, Ordering::Relaxed).to_be_bytes())
    }

    /// The simulator holds one authoritative copy, so every quorum resolves to
    /// one against it and every accepted write acknowledges exactly that.
    fn receipt(&self, quorum: Quorum) -> WriteReceipt {
        let required = quorum.resolve(self.config.replication_factor);
        WriteReceipt::new(self.config.replication_factor.get(), required)
    }

    fn identity_key(uri: &AgentUri) -> String {
        format!("{}/{}", uri.trust_root(), uri.agent_id())
    }

    fn ancestor_keys(uri: &AgentUri) -> Vec<DhtKey> {
        (1..=uri.capability_path().depth())
            .filter_map(|depth| {
                DhtKey::derive_at_depth(uri.trust_root(), uri.capability_path(), depth)
            })
            .collect()
    }

    /// Creates a new simulated DHT with the given configuration.
    #[must_use]
    pub fn new(config: SimulationConfig) -> Self {
        Self {
            by_key: RwLock::new(HashMap::new()),
            by_uri: RwLock::new(HashMap::new()),
            by_identity: RwLock::new(HashMap::new()),
            verifier: Verifier::new(),
            node_id: Self::next_node_id(),
            config,
        }
    }

    /// Creates a simulated DHT with trusted roots for registration verification.
    #[must_use]
    pub fn with_verifier(config: SimulationConfig, verifier: Verifier) -> Self {
        Self {
            by_key: RwLock::new(HashMap::new()),
            by_uri: RwLock::new(HashMap::new()),
            by_identity: RwLock::new(HashMap::new()),
            verifier,
            node_id: Self::next_node_id(),
            config,
        }
    }

    /// Creates a new simulated DHT with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(SimulationConfig::default())
    }

    /// Returns the configuration.
    #[must_use]
    pub const fn config(&self) -> &SimulationConfig {
        &self.config
    }

    /// Registers multiple agents in batch.
    ///
    /// More efficient than individual registrations for bulk setup.
    ///
    /// # Returns
    ///
    /// The number of successfully registered agents.
    ///
    /// # Errors
    ///
    /// Returns `DhtError` if a critical error occurs (though individual
    /// registration failures are silently counted).
    pub fn register_batch(&self, registrations: Vec<Registration>) -> Result<usize, DhtError> {
        let mut count = 0;
        for registration in registrations {
            if self.do_register(&registration).is_ok() {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Returns statistics about the DHT state.
    ///
    /// # Panics
    ///
    /// Panics if any of the internal locks are poisoned.
    #[must_use]
    pub fn stats(&self) -> DhtStats {
        let by_key = self.by_key.read().expect("lock poisoned");
        let by_uri = self.by_uri.read().expect("lock poisoned");

        let total_registrations = by_uri.len();
        let unique_keys = by_key.len();
        // Derived on demand rather than kept as a standing index. `stats` is a
        // diagnostic that already walks both indices, so the parse cost lands
        // here instead of on every write.
        let unique_trust_roots = by_uri
            .keys()
            .filter_map(|uri| AgentUri::parse(uri).ok())
            .map(|uri| uri.trust_root().as_str().to_string())
            .collect::<HashSet<_>>()
            .len();

        let max_registrations_per_key = by_key.values().map(Vec::len).max().unwrap_or(0);

        // Use f64::from for u32 to avoid precision loss; saturate for stats safety
        let indexed_copies = by_key.values().map(Vec::len).sum::<usize>();
        let total_u32 = u32::try_from(indexed_copies).unwrap_or(u32::MAX);
        let keys_u32 = u32::try_from(unique_keys).unwrap_or(u32::MAX);
        let avg_registrations_per_key = if keys_u32 > 0 {
            f64::from(total_u32) / f64::from(keys_u32)
        } else {
            0.0
        };

        // Estimate memory usage
        let memory_bytes = Self::estimate_memory_usage_inner(&by_key, &by_uri);

        DhtStats {
            total_registrations,
            unique_keys,
            unique_trust_roots,
            max_registrations_per_key,
            avg_registrations_per_key,
            path_depth_histogram: Vec::new(),
            memory_bytes,
        }
    }

    /// Simulates agent migration with timing.
    ///
    /// # Errors
    ///
    /// Returns `DhtError::NotFound` if the agent is not registered.
    ///
    /// # Panics
    ///
    /// Panics if any of the internal locks are poisoned.
    pub fn simulate_migration(
        &self,
        agent_uri: &AgentUri,
        new_endpoint: Endpoint,
    ) -> Result<MigrationResult, DhtError> {
        let uri_str = agent_uri.canonical();

        // Get old endpoints
        let old_endpoints = {
            let by_uri = self.by_uri.read().expect("lock poisoned");
            let keys = by_uri
                .get(&uri_str)
                .ok_or_else(|| DhtError::not_found(&uri_str))?;
            let key = keys.last().ok_or_else(|| DhtError::not_found(&uri_str))?;

            let by_key = self.by_key.read().expect("lock poisoned");
            let registrations = by_key
                .get(key)
                .ok_or_else(|| DhtError::not_found(&uri_str))?;

            registrations
                .iter()
                .find(|r| r.agent_uri().canonical() == uri_str)
                .map(|r| r.endpoints().to_vec())
                .ok_or_else(|| DhtError::not_found(&uri_str))?
        };

        // Time the update
        let start = Instant::now();
        self.do_update_endpoint(agent_uri, std::slice::from_ref(&new_endpoint))?;
        let update_latency = start.elapsed();

        Ok(MigrationResult::success(
            uri_str,
            old_endpoints,
            vec![new_endpoint],
            update_latency,
        ))
    }

    /// Clears all registrations.
    ///
    /// # Panics
    ///
    /// Panics if any of the internal locks are poisoned.
    pub fn clear(&self) {
        let mut by_key = self.by_key.write().expect("lock poisoned");
        let mut by_uri = self.by_uri.write().expect("lock poisoned");
        let mut by_identity = self.by_identity.write().expect("lock poisoned");

        by_key.clear();
        by_uri.clear();
        by_identity.clear();
    }

    /// Removes expired registrations.
    ///
    /// Returns the number of registrations removed.
    ///
    /// # Panics
    ///
    /// Panics if any of the internal locks are poisoned.
    pub fn expire_stale(&self) -> usize {
        let mut by_key = self.by_key.write().expect("lock poisoned");
        let mut by_uri = self.by_uri.write().expect("lock poisoned");
        let mut by_identity = self.by_identity.write().expect("lock poisoned");

        let mut expired_uris: Vec<String> = Vec::new();

        // Find expired registrations
        for registrations in by_key.values() {
            for reg in registrations {
                if reg.is_expired() {
                    expired_uris.push(reg.agent_uri().canonical());
                }
            }
        }
        expired_uris.sort();
        expired_uris.dedup();

        // Remove from all indices
        for uri_str in &expired_uris {
            if let Ok(uri) = AgentUri::parse(uri_str) {
                by_identity.remove(&Self::identity_key(&uri));
            }
            if let Some(keys) = by_uri.remove(uri_str) {
                for key in keys {
                    if let Some(registrations) = by_key.get_mut(&key) {
                        registrations.retain(|r| r.agent_uri().canonical() != *uri_str);
                        if registrations.is_empty() {
                            by_key.remove(&key);
                        }
                    }
                }
            }
        }

        expired_uris.len()
    }

    fn estimate_memory_usage_inner(
        by_key: &HashMap<DhtKey, Vec<Registration>>,
        by_uri: &HashMap<String, Vec<DhtKey>>,
    ) -> usize {
        // Rough estimate:
        // - Each DhtKey: 32 bytes
        // - Each Registration: ~500 bytes (URI + endpoints + attestation)
        // - HashMap overhead: ~64 bytes per entry

        let key_bytes = by_key.len() * (32 + 64);
        let registration_bytes = by_uri.len() * 500;
        let uri_index_bytes = by_uri
            .values()
            .map(|keys| 100 + keys.len() * 32 + 64)
            .sum::<usize>();

        key_bytes + registration_bytes + uri_index_bytes
    }
}

impl SimulatedDht {
    /// Applies a registration to the indices. Shared by the async trait method
    /// and by the synchronous evaluation helpers.
    fn do_register(&self, registration: &Registration) -> Result<(), DhtError> {
        if registration.endpoints().is_empty() {
            return Err(DhtError::NoEndpoints);
        }

        let uri_str = registration.agent_uri().canonical();
        let keys = Self::ancestor_keys(registration.agent_uri());
        let identity = Self::identity_key(registration.agent_uri());

        if self.config.verify_attestations {
            let token = registration.attestation().ok_or_else(|| {
                DhtError::invalid_attestation(&uri_str, "registration has no attestation token")
            })?;
            self.verifier
                .verify_for_capability(
                    token,
                    registration.agent_uri(),
                    registration.agent_uri().capability_path(),
                )
                .map_err(|error| DhtError::invalid_attestation(&uri_str, error.to_string()))?;
        }

        // Check and insert while holding every write lock. The identity
        // binding, capacity checks, and ancestor writes are one atomic update.
        {
            let mut by_key = self.by_key.write().expect("lock poisoned");
            let mut by_uri = self.by_uri.write().expect("lock poisoned");
            let mut by_identity = self.by_identity.write().expect("lock poisoned");

            if by_uri.contains_key(&uri_str) {
                return Err(DhtError::already_registered(&uri_str));
            }
            if let Some(existing_path) = by_identity.get(&identity)
                && existing_path != registration.agent_uri().capability_path().as_str()
            {
                return Err(DhtError::IdentityCapabilityConflict {
                    identity,
                    existing_path: existing_path.clone(),
                    requested_path: registration
                        .agent_uri()
                        .capability_path()
                        .as_str()
                        .to_string(),
                });
            }
            for key in &keys {
                if let Some(registrations) = by_key.get(key)
                    && registrations.len() >= self.config.max_registrations_per_key
                {
                    return Err(DhtError::key_capacity_exceeded(
                        format!("{key}"),
                        self.config.max_registrations_per_key,
                    ));
                }
            }

            // Primary index: write once at every ancestor key. A GET for any
            // ancestor therefore returns that path and all descendants without
            // attempting to enumerate SHA-256 children.
            for key in &keys {
                by_key.entry(*key).or_default().push(registration.clone());
            }

            by_uri.insert(uri_str, keys);
            by_identity.insert(
                identity,
                registration
                    .agent_uri()
                    .capability_path()
                    .as_str()
                    .to_string(),
            );
        }

        Ok(())
    }

    /// Rewrites every ancestor-key copy of a registration in place.
    ///
    /// `mutate` runs once per copy and must be idempotent across copies: the
    /// copies are the same logical record, so they must end up identical.
    fn mutate_registration(
        &self,
        agent_uri: &AgentUri,
        mut mutate: impl FnMut(&mut Registration),
    ) -> Result<(), DhtError> {
        let uri_str = agent_uri.canonical();

        let keys = {
            let by_uri = self.by_uri.read().expect("lock poisoned");
            by_uri
                .get(&uri_str)
                .cloned()
                .ok_or_else(|| DhtError::not_found(&uri_str))?
        };

        let mut mutated_any = false;
        {
            let mut by_key = self.by_key.write().expect("lock poisoned");
            for key in &keys {
                let registrations = by_key
                    .get_mut(key)
                    .ok_or_else(|| DhtError::not_found(&uri_str))?;
                let registration = registrations
                    .iter_mut()
                    .find(|r| r.agent_uri().canonical() == uri_str)
                    .ok_or_else(|| DhtError::not_found(&uri_str))?;
                if registration.is_expired() && self.config.auto_expire {
                    return Err(DhtError::expired(&uri_str));
                }
                mutate(registration);
                mutated_any = true;
            }
        }

        if mutated_any {
            Ok(())
        } else {
            Err(DhtError::not_found(&uri_str))
        }
    }

    fn do_update_endpoint(
        &self,
        agent_uri: &AgentUri,
        new_endpoints: &[Endpoint],
    ) -> Result<(), DhtError> {
        if new_endpoints.is_empty() {
            return Err(DhtError::NoEndpoints);
        }
        self.mutate_registration(agent_uri, |registration| {
            registration.update_endpoints(new_endpoints.to_vec());
        })
    }

    fn do_refresh(&self, agent_uri: &AgentUri, ttl: Duration) -> Result<(), DhtError> {
        self.mutate_registration(agent_uri, |registration| registration.refresh(ttl))
    }

    fn do_deregister(&self, agent_uri: &AgentUri) -> Result<(), DhtError> {
        let uri_str = agent_uri.canonical();

        // Mutate all indices under the same lock order as registration.
        let mut by_key = self.by_key.write().expect("lock poisoned");
        let mut by_uri = self.by_uri.write().expect("lock poisoned");
        let mut by_identity = self.by_identity.write().expect("lock poisoned");
        let keys = by_uri
            .remove(&uri_str)
            .ok_or_else(|| DhtError::not_found(&uri_str))?;

        for key in keys {
            if let Some(registrations) = by_key.get_mut(&key) {
                registrations.retain(|r| r.agent_uri().canonical() != uri_str);
                if registrations.is_empty() {
                    by_key.remove(&key);
                }
            }
        }
        by_identity.remove(&Self::identity_key(agent_uri));

        Ok(())
    }

    fn do_lookup(
        &self,
        query: &Query,
        options: &ReadOptions,
    ) -> Result<Page<Registration>, DhtError> {
        let key = DhtKey::derive(query.trust_root(), query.capability_path());

        let mut matches: Vec<Registration> = {
            let by_key = self.by_key.read().expect("lock poisoned");
            by_key
                .get(&key)
                .map(|registrations| {
                    registrations
                        .iter()
                        .filter(|r| match query.match_mode() {
                            // Ancestor-key materialization means the key already
                            // holds the whole subtree, so a prefix query keeps
                            // everything and an exact query filters back down.
                            MatchMode::Prefix => true,
                            MatchMode::Exact => {
                                r.agent_uri().capability_path() == query.capability_path()
                            }
                        })
                        .filter(|r| !r.is_expired() || !self.config.auto_expire)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        };

        // Paging is only coherent over a stable order, and insertion order is
        // not stable across deregistrations. Canonical URI is total and cheap.
        matches.sort_by_key(|r| r.agent_uri().canonical());

        let offset = options.cursor.map_or(0, |c| c.position() as usize);
        if offset >= matches.len() {
            return Ok(Page::complete(Vec::new()));
        }

        let page_size = self.config.page_size.get();
        let end = offset.saturating_add(page_size).min(matches.len());
        let items = matches[offset..end].to_vec();

        if end < matches.len() {
            let next = u32::try_from(end).map_err(|_| DhtError::QuorumFailed {
                achieved: 0,
                required: 1,
            })?;
            Ok(Page::partial(items, Cursor::at(next)))
        } else {
            Ok(Page::complete(items))
        }
    }
}

#[async_trait]
impl Dht for SimulatedDht {
    async fn register(
        &self,
        registration: Registration,
        options: WriteOptions,
    ) -> Result<WriteReceipt, DhtError> {
        self.do_register(&registration)?;
        Ok(self.receipt(options.quorum))
    }

    async fn update_endpoint(
        &self,
        agent_uri: &AgentUri,
        new_endpoints: Vec<Endpoint>,
        options: WriteOptions,
    ) -> Result<WriteReceipt, DhtError> {
        self.do_update_endpoint(agent_uri, &new_endpoints)?;
        Ok(self.receipt(options.quorum))
    }

    async fn refresh(
        &self,
        agent_uri: &AgentUri,
        ttl: Duration,
        options: WriteOptions,
    ) -> Result<WriteReceipt, DhtError> {
        self.do_refresh(agent_uri, ttl)?;
        Ok(self.receipt(options.quorum))
    }

    async fn deregister(
        &self,
        agent_uri: &AgentUri,
        _options: WriteOptions,
    ) -> Result<(), DhtError> {
        self.do_deregister(agent_uri)
    }

    async fn lookup(
        &self,
        query: &Query,
        options: &ReadOptions,
    ) -> Result<Page<Registration>, DhtError> {
        self.do_lookup(query, options)
    }

    fn local_id(&self) -> NodeId {
        self.node_id.clone()
    }

    async fn bootstrap(&self, peers: &[PeerAddr]) -> Result<(), DhtError> {
        // There is no overlay to join. Rejecting an empty peer list anyway
        // keeps the failure shape identical to a real backend, so a caller that
        // forgets to configure peers finds out here rather than in production.
        if peers.is_empty() {
            return Err(DhtError::NoPeers);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_uri::{CapabilityPath, TrustRoot};
    use agent_uri_attestation::{Issuer, SigningKey};
    use futures::executor::block_on;
    use std::num::NonZeroUsize;
    use std::time::Duration;

    fn unverified_dht() -> SimulatedDht {
        SimulatedDht::new(SimulationConfig::default().with_verify_attestations(false))
    }

    fn test_uri(suffix: &str) -> AgentUri {
        AgentUri::parse(&format!(
            "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn0{suffix}"
        ))
        .unwrap()
    }

    fn test_endpoint() -> Endpoint {
        Endpoint::https("agent.anthropic.com:443")
    }

    // The trait is async so that a distributed backend can implement it. The
    // simulator never actually yields, so these drive it to completion without
    // a runtime and keep the tests reading like the operations they describe.
    fn register(dht: &SimulatedDht, registration: Registration) -> Result<WriteReceipt, DhtError> {
        block_on(dht.register(registration, WriteOptions::default()))
    }

    fn deregister(dht: &SimulatedDht, uri: &AgentUri) -> Result<(), DhtError> {
        block_on(dht.deregister(uri, WriteOptions::default()))
    }

    fn update_endpoint(
        dht: &SimulatedDht,
        uri: &AgentUri,
        endpoints: Vec<Endpoint>,
    ) -> Result<WriteReceipt, DhtError> {
        block_on(dht.update_endpoint(uri, endpoints, WriteOptions::default()))
    }

    fn refresh(
        dht: &SimulatedDht,
        uri: &AgentUri,
        ttl: Duration,
    ) -> Result<WriteReceipt, DhtError> {
        block_on(dht.refresh(uri, ttl, WriteOptions::default()))
    }

    fn lookup(dht: &SimulatedDht, query: &Query) -> Vec<Registration> {
        block_on(dht.lookup(query, &ReadOptions::default()))
            .unwrap()
            .into_items()
    }

    fn exact(trust_root: &str, path: &str) -> Query {
        Query::exact(
            TrustRoot::parse(trust_root).unwrap(),
            CapabilityPath::parse(path).unwrap(),
        )
    }

    fn prefix(trust_root: &str, path: &str) -> Query {
        Query::prefix(
            TrustRoot::parse(trust_root).unwrap(),
            CapabilityPath::parse(path).unwrap(),
        )
    }

    #[test]
    fn register_and_lookup_exact() {
        let dht = unverified_dht();
        let uri = test_uri("2q");
        let registration = Registration::new(uri.clone(), vec![test_endpoint()]);

        register(&dht, registration).unwrap();

        let results = lookup(&dht, &exact("anthropic.com", "assistant/chat"));

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_uri(), &uri);
    }

    #[test]
    fn register_empty_endpoints_fails() {
        let dht = unverified_dht();
        let uri = test_uri("2q");
        let registration = Registration::new(uri, vec![]);

        let result = register(&dht, registration);

        assert!(matches!(result, Err(DhtError::NoEndpoints)));
    }

    #[test]
    fn double_registration_fails() {
        let dht = unverified_dht();
        let uri = test_uri("2q");

        register(&dht, Registration::new(uri.clone(), vec![test_endpoint()])).unwrap();

        let result = register(&dht, Registration::new(uri, vec![test_endpoint()]));

        assert!(matches!(result, Err(DhtError::AlreadyRegistered { .. })));
    }

    #[test]
    fn deregister_removes_agent() {
        let dht = unverified_dht();
        let uri = test_uri("2q");

        register(&dht, Registration::new(uri.clone(), vec![test_endpoint()])).unwrap();
        deregister(&dht, &uri).unwrap();

        let results = lookup(&dht, &exact("anthropic.com", "assistant/chat"));

        assert!(results.is_empty());
    }

    #[test]
    fn lookup_prefix_finds_descendants() {
        let dht = unverified_dht();

        let uri1 =
            AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        let uri2 =
            AgentUri::parse("agent://anthropic.com/assistant/code/llm_01h455vb4pex5vsknk084sn02r")
                .unwrap();

        register(
            &dht,
            Registration::new(uri1, vec![Endpoint::https("a.com")]),
        )
        .unwrap();
        register(
            &dht,
            Registration::new(uri2, vec![Endpoint::https("b.com")]),
        )
        .unwrap();

        let results = lookup(&dht, &prefix("anthropic.com", "assistant"));

        assert_eq!(results.len(), 2);
    }

    #[test]
    fn lookup_is_scoped_to_one_trust_root() {
        let dht = unverified_dht();

        let uri1 =
            AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        let uri2 =
            AgentUri::parse("agent://openai.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02r")
                .unwrap();

        register(
            &dht,
            Registration::new(uri1, vec![Endpoint::https("a.com")]),
        )
        .unwrap();
        register(
            &dht,
            Registration::new(uri2, vec![Endpoint::https("b.com")]),
        )
        .unwrap();

        // Identical capability paths under two authorities derive two distinct
        // keys, so neither lookup can observe the other's registration. This is
        // the cross-trust-root isolation that removing the global scan defends.
        let anthropic = lookup(&dht, &exact("anthropic.com", "assistant/chat"));
        let openai = lookup(&dht, &exact("openai.com", "assistant/chat"));

        assert_eq!(anthropic.len(), 1);
        assert_eq!(
            anthropic[0].agent_uri().trust_root().as_str(),
            "anthropic.com"
        );
        assert_eq!(openai.len(), 1);
        assert_eq!(openai[0].agent_uri().trust_root().as_str(), "openai.com");
    }

    #[test]
    fn update_endpoint_changes_endpoints() {
        let dht = unverified_dht();
        let uri = test_uri("2q");

        register(&dht, Registration::new(uri.clone(), vec![test_endpoint()])).unwrap();

        let new_endpoint = Endpoint::grpc("agent.anthropic.com:50051");
        update_endpoint(&dht, &uri, vec![new_endpoint.clone()]).unwrap();

        let results = lookup(&dht, &exact("anthropic.com", "assistant/chat"));

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].endpoints(), &[new_endpoint]);
    }

    #[test]
    fn stats_reports_correct_counts() {
        let dht = unverified_dht();

        let uri1 = test_uri("2q");
        let uri2 =
            AgentUri::parse("agent://anthropic.com/assistant/code/llm_01h455vb4pex5vsknk084sn02r")
                .unwrap();

        register(&dht, Registration::new(uri1, vec![test_endpoint()])).unwrap();
        register(&dht, Registration::new(uri2, vec![test_endpoint()])).unwrap();

        let stats = dht.stats();
        assert_eq!(stats.total_registrations(), 2);
        assert_eq!(stats.unique_trust_roots(), 1);
    }

    #[test]
    fn key_capacity_exceeded() {
        let config = SimulationConfig::new()
            .with_max_registrations_per_key(1)
            .with_verify_attestations(false);
        let dht = SimulatedDht::new(config);

        let uri1 = test_uri("2q");
        let uri2 = test_uri("2r");

        register(&dht, Registration::new(uri1, vec![test_endpoint()])).unwrap();

        let result = register(&dht, Registration::new(uri2, vec![test_endpoint()]));

        assert!(matches!(result, Err(DhtError::KeyCapacityExceeded { .. })));
    }

    #[test]
    fn clear_removes_all() {
        let dht = unverified_dht();
        let uri = test_uri("2q");

        register(&dht, Registration::new(uri, vec![test_endpoint()])).unwrap();

        dht.clear();

        let stats = dht.stats();
        assert_eq!(stats.total_registrations(), 0);
    }

    #[test]
    fn register_batch_counts_successes() {
        let dht = unverified_dht();

        let registrations = vec![
            Registration::new(test_uri("2q"), vec![test_endpoint()]),
            Registration::new(test_uri("2r"), vec![test_endpoint()]),
            Registration::new(test_uri("2s"), vec![]), // Will fail - no endpoints
        ];

        let count = dht.register_batch(registrations).unwrap();

        assert_eq!(count, 2);
    }

    #[test]
    fn secure_default_rejects_missing_attestation() {
        let dht = SimulatedDht::with_defaults();
        let uri = test_uri("2q");

        let result = register(&dht, Registration::new(uri, vec![test_endpoint()]));

        assert!(matches!(result, Err(DhtError::InvalidAttestation { .. })));
    }

    #[test]
    fn trusted_attestation_is_verified_before_registration() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new(
            "anthropic.com",
            signing_key.clone(),
            Duration::from_hours(1),
        );
        let mut verifier = Verifier::new();
        verifier.add_trusted_root("anthropic.com", signing_key.verifying_key());
        let dht = SimulatedDht::with_verifier(SimulationConfig::default(), verifier);
        let uri = test_uri("2q");
        let token = issuer
            .issue(&uri, vec!["assistant/chat".to_string()])
            .unwrap();

        register(
            &dht,
            Registration::new(uri.clone(), vec![test_endpoint()]).with_attestation(token),
        )
        .unwrap();

        let results = lookup(
            &dht,
            &Query::exact(uri.trust_root().clone(), uri.capability_path().clone()),
        );
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn refresh_extends_an_expiring_registration() {
        let dht = unverified_dht();
        let uri = test_uri("2q");
        register(
            &dht,
            Registration::new(uri.clone(), vec![test_endpoint()])
                .with_ttl(Duration::from_millis(50)),
        )
        .unwrap();

        let before = lookup(&dht, &exact("anthropic.com", "assistant/chat"))[0].expires_at();
        refresh(&dht, &uri, Duration::from_hours(1)).unwrap();
        let after = lookup(&dht, &exact("anthropic.com", "assistant/chat"))[0].expires_at();

        assert!(
            after > before,
            "refresh must push expiry out, got {before:?} -> {after:?}"
        );
    }

    #[test]
    fn refresh_updates_every_ancestor_copy() {
        // The record is materialized at each ancestor key. A refresh that
        // touched only one would leave the others to expire, silently pruning
        // the agent from prefix queries while exact lookup still found it.
        let dht = unverified_dht();
        let uri = test_uri("2q");
        register(
            &dht,
            Registration::new(uri.clone(), vec![test_endpoint()])
                .with_ttl(Duration::from_millis(50)),
        )
        .unwrap();

        refresh(&dht, &uri, Duration::from_hours(1)).unwrap();

        let from_ancestor = lookup(&dht, &prefix("anthropic.com", "assistant"));
        assert_eq!(from_ancestor.len(), 1);
        assert!(!from_ancestor[0].is_expired());
    }

    #[test]
    fn refresh_of_unknown_agent_is_not_found() {
        let dht = unverified_dht();
        let result = refresh(&dht, &test_uri("2q"), Duration::from_hours(1));
        assert!(matches!(result, Err(DhtError::NotFound { .. })));
    }

    #[test]
    fn lookup_pages_and_the_pages_partition_the_results() {
        let config = SimulationConfig::new()
            .with_verify_attestations(false)
            .with_page_size(NonZeroUsize::new(2).unwrap());
        let dht = SimulatedDht::new(config);

        for suffix in ["2q", "2r", "2s", "2t", "2v"] {
            register(
                &dht,
                Registration::new(test_uri(suffix), vec![test_endpoint()]),
            )
            .unwrap();
        }

        let query = exact("anthropic.com", "assistant/chat");
        let mut options = ReadOptions::default();
        let mut seen: Vec<String> = Vec::new();
        let mut pages = 0;
        loop {
            let page = block_on(dht.lookup(&query, &options)).unwrap();
            pages += 1;
            assert!(page.len() <= 2, "page exceeded the configured page size");
            let next = page.next_cursor();
            seen.extend(page.into_items().iter().map(|r| r.agent_uri().canonical()));
            match next {
                Some(cursor) => options = options.with_cursor(cursor),
                None => break,
            }
        }

        assert_eq!(pages, 3, "5 results at page size 2 should take 3 pages");
        assert_eq!(seen.len(), 5);
        let mut deduped = seen.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(deduped.len(), 5, "pages must not repeat a registration");
    }

    #[test]
    fn paging_order_is_stable_across_calls() {
        // Cursors index into the result order, so an unstable order would let a
        // second page skip or repeat records that the first already moved past.
        let config = SimulationConfig::new()
            .with_verify_attestations(false)
            .with_page_size(NonZeroUsize::new(2).unwrap());
        let dht = SimulatedDht::new(config);
        for suffix in ["2v", "2q", "2s", "2r"] {
            register(
                &dht,
                Registration::new(test_uri(suffix), vec![test_endpoint()]),
            )
            .unwrap();
        }

        let query = exact("anthropic.com", "assistant/chat");
        let first = block_on(dht.lookup(&query, &ReadOptions::default())).unwrap();
        let again = block_on(dht.lookup(&query, &ReadOptions::default())).unwrap();

        assert_eq!(
            first
                .items()
                .iter()
                .map(|r| r.agent_uri().canonical())
                .collect::<Vec<_>>(),
            again
                .items()
                .iter()
                .map(|r| r.agent_uri().canonical())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn cursor_past_the_end_yields_an_exhausted_page() {
        let dht = unverified_dht();
        register(
            &dht,
            Registration::new(test_uri("2q"), vec![test_endpoint()]),
        )
        .unwrap();

        let page = block_on(dht.lookup(
            &exact("anthropic.com", "assistant/chat"),
            &ReadOptions::default().with_cursor(Cursor::at(99)),
        ))
        .unwrap();

        assert!(page.is_empty());
        assert!(!page.has_more());
    }

    #[test]
    fn write_receipt_reports_the_resolved_quorum() {
        let dht = unverified_dht();
        let receipt = register(
            &dht,
            Registration::new(test_uri("2q"), vec![test_endpoint()]),
        )
        .unwrap();

        // One authoritative copy, so every quorum resolves to one against it.
        assert_eq!(receipt.acknowledged(), 1);
        assert_eq!(receipt.required(), 1);
        assert!(!receipt.exceeded_quorum());
    }

    #[test]
    fn instances_have_distinct_identities() {
        let a = unverified_dht();
        let b = unverified_dht();
        assert_ne!(a.local_id(), b.local_id());
        assert!(!a.local_id().is_empty());
    }

    #[test]
    fn bootstrap_without_peers_fails_the_way_a_real_backend_would() {
        let dht = unverified_dht();
        assert!(matches!(
            block_on(dht.bootstrap(&[])),
            Err(DhtError::NoPeers)
        ));
        assert!(block_on(dht.bootstrap(&[PeerAddr::new("/ip4/127.0.0.1/tcp/4001")])).is_ok());
    }

    #[test]
    fn the_simulator_is_usable_as_a_trait_object() {
        // Dyn-compatibility is the reason this trait uses async_trait at all,
        // so it needs a test that actually fails if that regresses.
        let dht: Box<dyn Dht> = Box::new(unverified_dht());
        block_on(dht.register(
            Registration::new(test_uri("2q"), vec![test_endpoint()]),
            WriteOptions::default(),
        ))
        .unwrap();

        let page = block_on(dht.lookup(
            &exact("anthropic.com", "assistant/chat"),
            &ReadOptions::default(),
        ))
        .unwrap();
        assert_eq!(page.len(), 1);
    }

    #[test]
    fn agent_id_cannot_be_reused_under_a_different_capability_path() {
        let dht = unverified_dht();
        let first =
            AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        let reclassified =
            AgentUri::parse("agent://anthropic.com/assistant/code/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        register(&dht, Registration::new(first, vec![test_endpoint()])).unwrap();

        let result = register(&dht, Registration::new(reclassified, vec![test_endpoint()]));

        assert!(matches!(
            result,
            Err(DhtError::IdentityCapabilityConflict { .. })
        ));

        // Ancestor materialization must not make the ancestor look like a
        // legitimate second identity for the same Agent ID.
        let dht = unverified_dht();
        let first =
            AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        let ancestor_reuse =
            AgentUri::parse("agent://anthropic.com/assistant/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        register(&dht, Registration::new(first, vec![test_endpoint()])).unwrap();

        let result = register(
            &dht,
            Registration::new(ancestor_reuse, vec![test_endpoint()]),
        );

        assert!(matches!(
            result,
            Err(DhtError::IdentityCapabilityConflict { .. })
        ));
    }
}
