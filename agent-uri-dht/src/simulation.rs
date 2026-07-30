//! Simulated DHT implementation for evaluation.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use agent_uri::AgentUri;
use agent_uri_attestation::{SigningKey, Verifier};
use async_trait::async_trait;

use crate::{
    Cursor, Dht, DhtError, DhtKey, DhtStats, Endpoint, MatchMode, MigrationResult, Mutation,
    MutationKind, MutationProof, NodeId, Page, PeerAddr, Query, Quorum, ReadOptions, Registration,
    SimulationConfig, WriteOptions, WriteReceipt,
};

/// Hands each simulator instance a distinct identity without pulling in a
/// random-number dependency. Distinctness is what callers rely on; the values
/// themselves carry no meaning.
static NEXT_NODE_ID: AtomicU64 = AtomicU64::new(1);

/// The three indices that together hold the simulator's state.
///
/// They live behind one lock rather than three. Every path that mutates state
/// touches all three, so a lock apiece never let two writers run concurrently;
/// it only created an order to acquire them in, and therefore an order to get
/// wrong. One lock has no order to get wrong.
///
/// The indices are consistent with each other only between operations, which
/// is why they are grouped: a registration exists in all three or in none, and
/// nothing may observe the state in between.
struct Indices {
    /// Primary index: `DhtKey` -> Registrations
    records: HashMap<DhtKey, Vec<Registration>>,

    /// Secondary index: canonical `AgentUri` -> exact and ancestor keys.
    keys_by_uri: HashMap<String, Vec<DhtKey>>,

    /// Enforces that a stable trust-root/agent-ID pair has one immutable path.
    path_by_identity: HashMap<String, String>,
}

impl Indices {
    fn new() -> Self {
        Self {
            records: HashMap::new(),
            keys_by_uri: HashMap::new(),
            path_by_identity: HashMap::new(),
        }
    }

    fn clear(&mut self) {
        self.records.clear();
        self.keys_by_uri.clear();
        self.path_by_identity.clear();
    }

    fn estimate_memory_usage(&self) -> usize {
        // Rough estimate:
        // - Each DhtKey: 32 bytes
        // - Each Registration: ~500 bytes (URI + endpoints + attestation)
        // - HashMap overhead: ~64 bytes per entry

        let key_bytes = self.records.len() * (32 + 64);
        let registration_bytes = self.keys_by_uri.len() * 500;
        let uri_index_bytes = self
            .keys_by_uri
            .values()
            .map(|keys| 100 + keys.len() * 32 + 64)
            .sum::<usize>();

        key_bytes + registration_bytes + uri_index_bytes
    }
}

/// Simulated DHT for evaluation.
///
/// Single-process, in-memory implementation that faithfully models
/// DHT behavior without network overhead. Suitable for evaluation
/// and testing.
///
/// # Thread Safety
///
/// One `RwLock` covers all of the state, so lookups run concurrently with each
/// other and writes are exclusive. There is deliberately not a lock per index:
/// every write already touches all of them, so splitting them bought no
/// concurrency and cost an acquisition order to get wrong.
///
/// # Examples
///
/// ```
/// use agent_uri::{AgentUri, CapabilityPath, TrustRoot};
/// use agent_uri_attestation::SigningKey;
/// use agent_uri_dht::{
///     Dht, Endpoint, MutationProof, Query, ReadOptions, Registration, SimulatedDht,
///     SimulationConfig, WriteOptions,
/// };
/// use futures::executor::block_on;
///
/// // Explicitly unverified because this example isolates indexing behavior.
/// let dht = SimulatedDht::new(
///     SimulationConfig::default().with_verify_attestations(false)
/// );
///
/// let uri = AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q").unwrap();
/// let agent_key = SigningKey::generate();
/// let registration = Registration::new(
///     uri.clone(),
///     agent_key.verifying_key(),
///     vec![Endpoint::https("agent.anthropic.com")],
/// );
///
/// let proof = MutationProof::sign_registration(&agent_key, &registration);
///
/// block_on(dht.register(registration, &proof, WriteOptions::default())).unwrap();
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
    /// Every index, under one lock. See [`Indices`] for why it is one.
    indices: RwLock<Indices>,

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
            indices: RwLock::new(Indices::new()),
            verifier: Verifier::new(),
            node_id: Self::next_node_id(),
            config,
        }
    }

    /// Creates a simulated DHT with trusted roots for registration verification.
    #[must_use]
    pub fn with_verifier(config: SimulationConfig, verifier: Verifier) -> Self {
        Self {
            indices: RwLock::new(Indices::new()),
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
    pub fn register_batch(
        &self,
        registrations: Vec<(Registration, MutationProof)>,
    ) -> Result<usize, DhtError> {
        let mut count = 0;
        for (registration, proof) in registrations {
            if self.do_register(&registration, &proof).is_ok() {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Returns statistics about the DHT state.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    #[must_use]
    pub fn stats(&self) -> DhtStats {
        let indices = self.indices.read().expect("lock poisoned");

        let total_registrations = indices.keys_by_uri.len();
        let unique_keys = indices.records.len();
        // Derived on demand rather than kept as a standing index. `stats` is a
        // diagnostic that already walks both indices, so the parse cost lands
        // here instead of on every write.
        let unique_trust_roots = indices
            .keys_by_uri
            .keys()
            .filter_map(|uri| AgentUri::parse(uri).ok())
            .map(|uri| uri.trust_root().as_str().to_string())
            .collect::<HashSet<_>>()
            .len();

        let max_registrations_per_key = indices.records.values().map(Vec::len).max().unwrap_or(0);

        // Use f64::from for u32 to avoid precision loss; saturate for stats safety
        let indexed_copies = indices.records.values().map(Vec::len).sum::<usize>();
        let total_u32 = u32::try_from(indexed_copies).unwrap_or(u32::MAX);
        let keys_u32 = u32::try_from(unique_keys).unwrap_or(u32::MAX);
        let avg_registrations_per_key = if keys_u32 > 0 {
            f64::from(total_u32) / f64::from(keys_u32)
        } else {
            0.0
        };

        // Estimate memory usage
        let memory_bytes = indices.estimate_memory_usage();

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
    /// Takes the agent's signing key because it plays the part of the agent:
    /// it reads the record's current sequence number and mints the proof the
    /// migration needs, exactly as a migrating agent would.
    ///
    /// # Errors
    ///
    /// Returns `DhtError::NotFound` if the agent is not registered, or
    /// `DhtError::Unauthorized` if `agent_key` is not the key the record names.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn simulate_migration(
        &self,
        agent_uri: &AgentUri,
        new_endpoint: Endpoint,
        agent_key: &SigningKey,
    ) -> Result<MigrationResult, DhtError> {
        let uri_str = agent_uri.canonical();

        // Read the record the agent is about to move: its endpoints for the
        // before/after report, its version to sign against. The guard is
        // dropped before `apply_mutation` runs, because that takes the write
        // lock and `RwLock` is not reentrant.
        let current = {
            let indices = self.indices.read().expect("lock poisoned");
            let keys = indices
                .keys_by_uri
                .get(&uri_str)
                .ok_or_else(|| DhtError::not_found(&uri_str))?;
            let key = keys.last().ok_or_else(|| DhtError::not_found(&uri_str))?;

            let registrations = indices
                .records
                .get(key)
                .ok_or_else(|| DhtError::not_found(&uri_str))?;

            registrations
                .iter()
                .find(|r| r.agent_uri().canonical() == uri_str)
                .cloned()
                .ok_or_else(|| DhtError::not_found(&uri_str))?
        };
        let old_endpoints = current.endpoints().to_vec();

        let endpoints = std::slice::from_ref(&new_endpoint);
        let mutation = Mutation::UpdateEndpoint { endpoints };
        let proof = MutationProof::sign_next(agent_key, &current, &mutation);

        // Time the update
        let start = Instant::now();
        self.apply_mutation(agent_uri, &mutation, &proof)?;
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
    /// Panics if the internal lock is poisoned.
    pub fn clear(&self) {
        self.indices.write().expect("lock poisoned").clear();
    }

    /// Removes expired registrations.
    ///
    /// Returns the number of registrations removed.
    ///
    /// # Panics
    ///
    /// Panics if the internal lock is poisoned.
    pub fn expire_stale(&self) -> usize {
        let mut indices = self.indices.write().expect("lock poisoned");

        let mut expired_uris: Vec<String> = Vec::new();

        // Find expired registrations
        for registrations in indices.records.values() {
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
                indices.path_by_identity.remove(&Self::identity_key(&uri));
            }
            if let Some(keys) = indices.keys_by_uri.remove(uri_str) {
                for key in keys {
                    if let Some(registrations) = indices.records.get_mut(&key) {
                        registrations.retain(|r| r.agent_uri().canonical() != *uri_str);
                        if registrations.is_empty() {
                            indices.records.remove(&key);
                        }
                    }
                }
            }
        }

        expired_uris.len()
    }
}

impl SimulatedDht {
    /// Applies a registration to the indices. Shared by the async trait method
    /// and by the synchronous evaluation helpers.
    fn do_register(
        &self,
        registration: &Registration,
        proof: &MutationProof,
    ) -> Result<(), DhtError> {
        if registration.endpoints().is_empty() {
            return Err(DhtError::NoEndpoints);
        }

        let uri_str = registration.agent_uri().canonical();
        let keys = Self::ancestor_keys(registration.agent_uri());
        let identity = Self::identity_key(registration.agent_uri());

        // Possession first. The attestation says the trust root vouches for a
        // key; the proof says the party registering holds it. Checking the
        // token alone would accept a token lifted from any public record.
        proof.authorizes_registration(registration)?;

        if self.config.verify_attestations {
            let token = registration.attestation().ok_or_else(|| {
                DhtError::invalid_attestation(&uri_str, "registration has no attestation token")
            })?;
            let claims = self
                .verifier
                .verify_for_capability(
                    token,
                    registration.agent_uri(),
                    registration.agent_uri().capability_path(),
                )
                .map_err(|error| DhtError::invalid_attestation(&uri_str, error.to_string()))?;

            // The token has to be about this record's key, or it is somebody
            // else's token: an attestation is world-readable and says nothing
            // about who presented it.
            let attested = claims
                .agent_verifying_key()
                .map_err(|error| DhtError::invalid_attestation(&uri_str, error.to_string()))?;
            if attested != *registration.agent_key() {
                return Err(DhtError::AgentKeyMismatch { agent_uri: uri_str });
            }
        }

        // Check and insert under one acquisition of the write lock. The
        // identity binding, capacity checks, and ancestor writes are one
        // atomic update.
        {
            let mut indices = self.indices.write().expect("lock poisoned");

            if indices.keys_by_uri.contains_key(&uri_str) {
                return Err(DhtError::already_registered(&uri_str));
            }
            if let Some(existing_path) = indices.path_by_identity.get(&identity)
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
                if let Some(registrations) = indices.records.get(key)
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
                indices
                    .records
                    .entry(*key)
                    .or_default()
                    .push(registration.clone());
            }

            indices.keys_by_uri.insert(uri_str, keys);
            indices.path_by_identity.insert(
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
    fn rewrite_copies(
        records: &mut HashMap<DhtKey, Vec<Registration>>,
        keys: &[DhtKey],
        uri_str: &str,
        sequence: u64,
        mut mutate: impl FnMut(&mut Registration),
    ) -> Result<(), DhtError> {
        for key in keys {
            let registrations = records
                .get_mut(key)
                .ok_or_else(|| DhtError::not_found(uri_str))?;
            let registration = registrations
                .iter_mut()
                .find(|r| r.agent_uri().canonical() == uri_str)
                .ok_or_else(|| DhtError::not_found(uri_str))?;
            mutate(registration);
            registration.set_sequence(sequence);
        }
        Ok(())
    }

    /// Removes every ancestor-key copy of a registration.
    fn remove_copies(
        records: &mut HashMap<DhtKey, Vec<Registration>>,
        keys: &[DhtKey],
        uri_str: &str,
    ) {
        for key in keys {
            if let Some(registrations) = records.get_mut(key) {
                registrations.retain(|r| r.agent_uri().canonical() != uri_str);
                if registrations.is_empty() {
                    records.remove(key);
                }
            }
        }
    }

    /// Authorizes a write against the record it targets, then applies it.
    ///
    /// This is the only path by which a stored record changes, so it is the
    /// only place authorization has to be enforced. Checking and applying
    /// happen under one acquisition of the write lock: split apart, two
    /// writers could clear the same sequence check and both proceed, and the
    /// second would overwrite the first while its proof said otherwise.
    fn apply_mutation(
        &self,
        agent_uri: &AgentUri,
        mutation: &Mutation<'_>,
        proof: &MutationProof,
    ) -> Result<(), DhtError> {
        let uri_str = agent_uri.canonical();

        let mut guard = self.indices.write().expect("lock poisoned");
        let indices = &mut *guard;

        let keys = indices
            .keys_by_uri
            .get(&uri_str)
            .cloned()
            .ok_or_else(|| DhtError::not_found(&uri_str))?;

        // Every ancestor key holds the same logical record, so the first copy
        // found answers for all of them.
        let current = keys
            .iter()
            .filter_map(|key| indices.records.get(key))
            .flatten()
            .find(|r| r.agent_uri().canonical() == uri_str)
            .cloned()
            .ok_or_else(|| DhtError::not_found(&uri_str))?;

        if current.is_expired() && self.config.auto_expire {
            return Err(DhtError::expired(&uri_str));
        }

        proof.authorizes(&current, mutation)?;

        match mutation {
            Mutation::UpdateEndpoint { endpoints } => Self::rewrite_copies(
                &mut indices.records,
                &keys,
                &uri_str,
                proof.sequence(),
                |registration| registration.update_endpoints((*endpoints).to_vec()),
            ),
            Mutation::Refresh { ttl } => Self::rewrite_copies(
                &mut indices.records,
                &keys,
                &uri_str,
                proof.sequence(),
                |registration| registration.refresh(*ttl),
            ),
            Mutation::Deregister => {
                Self::remove_copies(&mut indices.records, &keys, &uri_str);
                indices.keys_by_uri.remove(&uri_str);
                indices
                    .path_by_identity
                    .remove(&Self::identity_key(agent_uri));
                Ok(())
            }
            // Registration creates a record rather than changing one, so it
            // never reaches here; `do_register` authorizes it directly.
            Mutation::Register { .. } => Err(DhtError::Unauthorized {
                agent_uri: uri_str,
                operation: MutationKind::Register,
            }),
        }
    }

    fn do_lookup(
        &self,
        query: &Query,
        options: &ReadOptions,
    ) -> Result<Page<Registration>, DhtError> {
        let key = DhtKey::derive(query.trust_root(), query.capability_path());

        let mut matches: Vec<Registration> = {
            let indices = self.indices.read().expect("lock poisoned");
            indices
                .records
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
        proof: &MutationProof,
        options: WriteOptions,
    ) -> Result<WriteReceipt, DhtError> {
        self.do_register(&registration, proof)?;
        Ok(self.receipt(options.quorum))
    }

    async fn update_endpoint(
        &self,
        agent_uri: &AgentUri,
        new_endpoints: Vec<Endpoint>,
        proof: &MutationProof,
        options: WriteOptions,
    ) -> Result<WriteReceipt, DhtError> {
        // Checked before authorization: an empty list is a malformed request,
        // not a rejected one, and saying so costs no signature verification.
        if new_endpoints.is_empty() {
            return Err(DhtError::NoEndpoints);
        }
        self.apply_mutation(
            agent_uri,
            &Mutation::UpdateEndpoint {
                endpoints: &new_endpoints,
            },
            proof,
        )?;
        Ok(self.receipt(options.quorum))
    }

    async fn refresh(
        &self,
        agent_uri: &AgentUri,
        ttl: Duration,
        proof: &MutationProof,
        options: WriteOptions,
    ) -> Result<WriteReceipt, DhtError> {
        self.apply_mutation(agent_uri, &Mutation::Refresh { ttl }, proof)?;
        Ok(self.receipt(options.quorum))
    }

    async fn deregister(
        &self,
        agent_uri: &AgentUri,
        proof: &MutationProof,
        _options: WriteOptions,
    ) -> Result<(), DhtError> {
        self.apply_mutation(agent_uri, &Mutation::Deregister, proof)
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
    use crate::RecordVersion;
    use agent_uri::{CapabilityPath, TrustRoot};
    use agent_uri_attestation::Issuer;
    use futures::executor::block_on;
    use std::num::NonZeroUsize;
    use std::time::{Duration, SystemTime};

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

    fn registration(uri: &AgentUri, key: &SigningKey) -> Registration {
        Registration::new(uri.clone(), key.verifying_key(), vec![test_endpoint()])
    }

    // The trait is async so that a distributed backend can implement it. The
    // simulator never actually yields, so these drive it to completion without
    // a runtime and keep the tests reading like the operations they describe.
    /// Registers with a proof from `key`. Tests that pass a key other than the
    /// record's own are checking that registration is a write like any other.
    fn register(
        dht: &SimulatedDht,
        registration: Registration,
        key: &SigningKey,
    ) -> Result<WriteReceipt, DhtError> {
        let proof = MutationProof::sign_registration(key, &registration);
        block_on(dht.register(registration, &proof, WriteOptions::default()))
    }

    /// Returns the record the DHT currently holds, which is what a caller
    /// preparing a write would have looked up.
    fn record(dht: &SimulatedDht, uri: &AgentUri) -> Registration {
        stored(dht, uri).expect("record is registered")
    }

    fn stored(dht: &SimulatedDht, uri: &AgentUri) -> Option<Registration> {
        lookup(
            dht,
            &Query::exact(uri.trust_root().clone(), uri.capability_path().clone()),
        )
        .into_iter()
        .find(|r| r.agent_uri() == uri)
    }

    /// The version a caller would sign against, or an invented one when there
    /// is nothing to look up. Tests that write to an unregistered URI need a
    /// proof to hand over, and a real caller working from a stale cache would
    /// be in exactly that position.
    fn version_at(dht: &SimulatedDht, uri: &AgentUri, sequence: u64) -> RecordVersion {
        RecordVersion::new(
            stored(dht, uri).map_or_else(SystemTime::now, |r| r.registered_at()),
            sequence,
        )
    }

    fn deregister(
        dht: &SimulatedDht,
        uri: &AgentUri,
        key: &SigningKey,
        sequence: u64,
    ) -> Result<(), DhtError> {
        let proof = MutationProof::sign(
            key,
            uri,
            version_at(dht, uri, sequence),
            &Mutation::Deregister,
        );
        block_on(dht.deregister(uri, &proof, WriteOptions::default()))
    }

    fn update_endpoint(
        dht: &SimulatedDht,
        uri: &AgentUri,
        key: &SigningKey,
        sequence: u64,
        endpoints: Vec<Endpoint>,
    ) -> Result<WriteReceipt, DhtError> {
        let proof = MutationProof::sign(
            key,
            uri,
            version_at(dht, uri, sequence),
            &Mutation::UpdateEndpoint {
                endpoints: &endpoints,
            },
        );
        block_on(dht.update_endpoint(uri, endpoints, &proof, WriteOptions::default()))
    }

    fn refresh(
        dht: &SimulatedDht,
        uri: &AgentUri,
        key: &SigningKey,
        sequence: u64,
        ttl: Duration,
    ) -> Result<WriteReceipt, DhtError> {
        let proof = MutationProof::sign(
            key,
            uri,
            version_at(dht, uri, sequence),
            &Mutation::Refresh { ttl },
        );
        block_on(dht.refresh(uri, ttl, &proof, WriteOptions::default()))
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
        let key = SigningKey::generate();
        let uri = test_uri("2q");

        register(&dht, registration(&uri, &key), &key).unwrap();

        let results = lookup(&dht, &exact("anthropic.com", "assistant/chat"));

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_uri(), &uri);
    }

    #[test]
    fn register_empty_endpoints_fails() {
        let dht = unverified_dht();
        let key = SigningKey::generate();
        let registration = Registration::new(test_uri("2q"), key.verifying_key(), vec![]);

        let result = register(&dht, registration, &key);

        assert!(matches!(result, Err(DhtError::NoEndpoints)));
    }

    #[test]
    fn double_registration_fails() {
        let dht = unverified_dht();
        let key = SigningKey::generate();
        let uri = test_uri("2q");

        register(&dht, registration(&uri, &key), &key).unwrap();

        let result = register(&dht, registration(&uri, &key), &key);

        assert!(matches!(result, Err(DhtError::AlreadyRegistered { .. })));
    }

    #[test]
    fn deregister_removes_agent() {
        let dht = unverified_dht();
        let key = SigningKey::generate();
        let uri = test_uri("2q");

        register(&dht, registration(&uri, &key), &key).unwrap();
        deregister(&dht, &uri, &key, 1).unwrap();

        let results = lookup(&dht, &exact("anthropic.com", "assistant/chat"));

        assert!(results.is_empty());
    }

    #[test]
    fn lookup_prefix_finds_descendants() {
        let dht = unverified_dht();
        let key = SigningKey::generate();

        let uri1 =
            AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        let uri2 =
            AgentUri::parse("agent://anthropic.com/assistant/code/llm_01h455vb4pex5vsknk084sn02r")
                .unwrap();

        register(&dht, registration(&uri1, &key), &key).unwrap();
        register(&dht, registration(&uri2, &key), &key).unwrap();

        let results = lookup(&dht, &prefix("anthropic.com", "assistant"));

        assert_eq!(results.len(), 2);
    }

    #[test]
    fn lookup_is_scoped_to_one_trust_root() {
        let dht = unverified_dht();
        let key = SigningKey::generate();

        let uri1 =
            AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        let uri2 =
            AgentUri::parse("agent://openai.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02r")
                .unwrap();

        register(&dht, registration(&uri1, &key), &key).unwrap();
        register(&dht, registration(&uri2, &key), &key).unwrap();

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
        let key = SigningKey::generate();
        let uri = test_uri("2q");

        register(&dht, registration(&uri, &key), &key).unwrap();

        let new_endpoint = Endpoint::grpc("agent.anthropic.com:50051");
        update_endpoint(&dht, &uri, &key, 1, vec![new_endpoint.clone()]).unwrap();

        let results = lookup(&dht, &exact("anthropic.com", "assistant/chat"));

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].endpoints(), &[new_endpoint]);
    }

    #[test]
    fn stats_reports_correct_counts() {
        let dht = unverified_dht();
        let key = SigningKey::generate();

        let uri1 = test_uri("2q");
        let uri2 =
            AgentUri::parse("agent://anthropic.com/assistant/code/llm_01h455vb4pex5vsknk084sn02r")
                .unwrap();

        register(&dht, registration(&uri1, &key), &key).unwrap();
        register(&dht, registration(&uri2, &key), &key).unwrap();

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
        let key = SigningKey::generate();

        register(&dht, registration(&test_uri("2q"), &key), &key).unwrap();

        let result = register(&dht, registration(&test_uri("2r"), &key), &key);

        assert!(matches!(result, Err(DhtError::KeyCapacityExceeded { .. })));
    }

    #[test]
    fn clear_removes_all() {
        let dht = unverified_dht();
        let key = SigningKey::generate();

        register(&dht, registration(&test_uri("2q"), &key), &key).unwrap();

        dht.clear();

        let stats = dht.stats();
        assert_eq!(stats.total_registrations(), 0);
    }

    #[test]
    fn register_batch_counts_successes() {
        let dht = unverified_dht();
        let key = SigningKey::generate();

        let registrations = vec![
            registration(&test_uri("2q"), &key),
            registration(&test_uri("2r"), &key),
            // Will fail - no endpoints
            Registration::new(test_uri("2s"), key.verifying_key(), vec![]),
        ]
        .into_iter()
        .map(|r| {
            let proof = MutationProof::sign_registration(&key, &r);
            (r, proof)
        })
        .collect();

        let count = dht.register_batch(registrations).unwrap();

        assert_eq!(count, 2);
    }

    #[test]
    fn secure_default_rejects_missing_attestation() {
        let dht = SimulatedDht::with_defaults();
        let key = SigningKey::generate();

        let result = register(&dht, registration(&test_uri("2q"), &key), &key);

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
        let agent_key = SigningKey::generate();
        let uri = test_uri("2q");
        let token = issuer
            .issue(
                &uri,
                &agent_key.verifying_key(),
                vec!["assistant/chat".to_string()],
            )
            .unwrap();

        register(
            &dht,
            registration(&uri, &agent_key).with_attestation(token),
            &agent_key,
        )
        .unwrap();

        let results = lookup(
            &dht,
            &Query::exact(uri.trust_root().clone(), uri.capability_path().clone()),
        );
        assert_eq!(results.len(), 1);
    }

    /// A trust root that vouches for `agent_key`, and a DHT that trusts it.
    fn attesting_dht(agent_key: &SigningKey, uri: &AgentUri) -> (SimulatedDht, String) {
        let root_key = SigningKey::generate();
        let issuer = Issuer::new("anthropic.com", root_key.clone(), Duration::from_hours(1));
        let mut verifier = Verifier::new();
        verifier.add_trusted_root("anthropic.com", root_key.verifying_key());
        let token = issuer
            .issue(
                uri,
                &agent_key.verifying_key(),
                vec!["assistant/chat".to_string()],
            )
            .unwrap();
        (
            SimulatedDht::with_verifier(SimulationConfig::default(), verifier),
            token,
        )
    }

    #[test]
    fn a_lifted_token_does_not_register_the_thief_at_its_own_endpoints() {
        // The replay this binding exists to stop. Registration records are
        // world-readable by design, so assume the attacker read one and kept
        // the token. Presenting it under their own key must fail, because the
        // trust root attested the victim's key, not theirs.
        let victim = SigningKey::generate();
        let attacker = SigningKey::generate();
        let uri = test_uri("2q");
        let (dht, lifted) = attesting_dht(&victim, &uri);

        let hijack = Registration::new(
            uri.clone(),
            attacker.verifying_key(),
            vec![Endpoint::https("attacker.example")],
        )
        .with_attestation(lifted);

        let result = register(&dht, hijack, &attacker);

        assert!(matches!(result, Err(DhtError::AgentKeyMismatch { .. })));
    }

    #[test]
    fn a_lifted_token_does_not_register_the_thief_under_the_victims_key_either() {
        // Keeping the victim's key in the record satisfies the token, so the
        // register proof is what has to stop this one: the attacker cannot
        // sign for a key they do not hold.
        let victim = SigningKey::generate();
        let attacker = SigningKey::generate();
        let uri = test_uri("2q");
        let (dht, lifted) = attesting_dht(&victim, &uri);

        let hijack = Registration::new(
            uri.clone(),
            victim.verifying_key(),
            vec![Endpoint::https("attacker.example")],
        )
        .with_attestation(lifted);

        let result = register(&dht, hijack, &attacker);

        assert!(matches!(
            result,
            Err(DhtError::Unauthorized {
                operation: MutationKind::Register,
                ..
            })
        ));
    }

    #[test]
    fn the_attested_agent_registers_normally() {
        let agent = SigningKey::generate();
        let uri = test_uri("2q");
        let (dht, token) = attesting_dht(&agent, &uri);

        register(
            &dht,
            registration(&uri, &agent).with_attestation(token),
            &agent,
        )
        .unwrap();

        assert_eq!(
            lookup(&dht, &exact("anthropic.com", "assistant/chat")).len(),
            1
        );
    }

    #[test]
    fn a_registration_proof_does_not_cover_endpoints_it_did_not_sign() {
        // Signed by the right key, for the right URI, but over other
        // endpoints. Without binding them, a relay could forward a
        // registration pointing somewhere else.
        let dht = unverified_dht();
        let agent = SigningKey::generate();
        let uri = test_uri("2q");
        let honest = Registration::new(
            uri.clone(),
            agent.verifying_key(),
            vec![Endpoint::https("honest.example")],
        );
        let proof = MutationProof::sign_registration(&agent, &honest);

        let substituted = Registration::new(
            uri,
            agent.verifying_key(),
            vec![Endpoint::https("attacker.example")],
        )
        .with_registered_at(honest.registered_at());

        let result = block_on(dht.register(substituted, &proof, WriteOptions::default()));

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn a_registration_proof_does_not_cover_a_different_expiry() {
        let dht = unverified_dht();
        let agent = SigningKey::generate();
        let uri = test_uri("2q");
        let honest = registration(&uri, &agent).with_ttl(Duration::from_mins(1));
        let proof = MutationProof::sign_registration(&agent, &honest);

        let stretched = honest.clone().with_ttl(Duration::from_hours(24));

        let result = block_on(dht.register(stretched, &proof, WriteOptions::default()));

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn a_registration_proof_does_not_transfer_to_another_agent() {
        let dht = unverified_dht();
        let agent = SigningKey::generate();
        let mine = registration(&test_uri("2q"), &agent);
        let proof = MutationProof::sign_registration(&agent, &mine);

        let theirs = registration(&test_uri("2r"), &agent).with_registered_at(mine.registered_at());

        let result = block_on(dht.register(theirs, &proof, WriteOptions::default()));

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn refresh_extends_an_expiring_registration() {
        let dht = unverified_dht();
        let key = SigningKey::generate();
        let uri = test_uri("2q");
        register(
            &dht,
            registration(&uri, &key).with_ttl(Duration::from_millis(50)),
            &key,
        )
        .unwrap();

        let before = lookup(&dht, &exact("anthropic.com", "assistant/chat"))[0].expires_at();
        refresh(&dht, &uri, &key, 1, Duration::from_hours(1)).unwrap();
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
        let key = SigningKey::generate();
        let uri = test_uri("2q");
        register(
            &dht,
            registration(&uri, &key).with_ttl(Duration::from_millis(50)),
            &key,
        )
        .unwrap();

        refresh(&dht, &uri, &key, 1, Duration::from_hours(1)).unwrap();

        let from_ancestor = lookup(&dht, &prefix("anthropic.com", "assistant"));
        assert_eq!(from_ancestor.len(), 1);
        assert!(!from_ancestor[0].is_expired());
    }

    #[test]
    fn refresh_of_unknown_agent_is_not_found() {
        let dht = unverified_dht();
        let key = SigningKey::generate();
        let result = refresh(&dht, &test_uri("2q"), &key, 1, Duration::from_hours(1));
        assert!(matches!(result, Err(DhtError::NotFound { .. })));
    }

    #[test]
    fn lookup_pages_and_the_pages_partition_the_results() {
        let config = SimulationConfig::new()
            .with_verify_attestations(false)
            .with_page_size(NonZeroUsize::new(2).unwrap());
        let dht = SimulatedDht::new(config);
        let key = SigningKey::generate();

        for suffix in ["2q", "2r", "2s", "2t", "2v"] {
            register(&dht, registration(&test_uri(suffix), &key), &key).unwrap();
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
        let key = SigningKey::generate();
        for suffix in ["2v", "2q", "2s", "2r"] {
            register(&dht, registration(&test_uri(suffix), &key), &key).unwrap();
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
        let key = SigningKey::generate();
        register(&dht, registration(&test_uri("2q"), &key), &key).unwrap();

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
        let key = SigningKey::generate();
        let receipt = register(&dht, registration(&test_uri("2q"), &key), &key).unwrap();

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
        let key = SigningKey::generate();
        let dht: Box<dyn Dht> = Box::new(unverified_dht());
        let record = registration(&test_uri("2q"), &key);
        let proof = MutationProof::sign_registration(&key, &record);
        block_on(dht.register(record, &proof, WriteOptions::default())).unwrap();

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
        let key = SigningKey::generate();
        let first =
            AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        let reclassified =
            AgentUri::parse("agent://anthropic.com/assistant/code/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        register(&dht, registration(&first, &key), &key).unwrap();

        let result = register(&dht, registration(&reclassified, &key), &key);

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
        register(&dht, registration(&first, &key), &key).unwrap();

        let result = register(&dht, registration(&ancestor_reuse, &key), &key);

        assert!(matches!(
            result,
            Err(DhtError::IdentityCapabilityConflict { .. })
        ));
    }

    #[test]
    fn an_attacker_cannot_repoint_an_agents_endpoints() {
        // The hijack this authorization exists to stop. The attacker knows the
        // URI, which is public, and holds every key except the agent's.
        let dht = unverified_dht();
        let agent = SigningKey::generate();
        let attacker = SigningKey::generate();
        let uri = test_uri("2q");
        register(&dht, registration(&uri, &agent), &agent).unwrap();

        let result = update_endpoint(
            &dht,
            &uri,
            &attacker,
            1,
            vec![Endpoint::https("attacker.example")],
        );

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
        assert_eq!(
            lookup(&dht, &exact("anthropic.com", "assistant/chat"))[0].endpoints(),
            &[test_endpoint()]
        );
    }

    #[test]
    fn an_attacker_cannot_evict_an_agent() {
        let dht = unverified_dht();
        let agent = SigningKey::generate();
        let attacker = SigningKey::generate();
        let uri = test_uri("2q");
        register(&dht, registration(&uri, &agent), &agent).unwrap();

        let result = deregister(&dht, &uri, &attacker, 1);

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
        assert_eq!(
            lookup(&dht, &exact("anthropic.com", "assistant/chat")).len(),
            1
        );
    }

    #[test]
    fn an_attacker_cannot_refresh_an_agent() {
        // Refresh looks harmless, but keeping a record alive that its owner
        // meant to let expire is still a write nobody authorized.
        let dht = unverified_dht();
        let agent = SigningKey::generate();
        let attacker = SigningKey::generate();
        let uri = test_uri("2q");
        register(&dht, registration(&uri, &agent), &agent).unwrap();

        let result = refresh(&dht, &uri, &attacker, 1, Duration::from_hours(9));

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn a_proof_does_not_authorize_endpoints_it_did_not_sign() {
        // Signing the operation is not enough on its own: the proof has to
        // cover the arguments, or an intercepted migration could be re-aimed
        // while keeping the agent's own signature.
        let dht = unverified_dht();
        let agent = SigningKey::generate();
        let uri = test_uri("2q");
        register(&dht, registration(&uri, &agent), &agent).unwrap();

        let honest = vec![Endpoint::https("honest.example")];
        let proof = MutationProof::sign_next(
            &agent,
            &record(&dht, &uri),
            &Mutation::UpdateEndpoint { endpoints: &honest },
        );

        let result = block_on(dht.update_endpoint(
            &uri,
            vec![Endpoint::https("attacker.example")],
            &proof,
            WriteOptions::default(),
        ));

        assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    }

    #[test]
    fn a_successful_mutation_advances_the_record_sequence() {
        let dht = unverified_dht();
        let key = SigningKey::generate();
        let uri = test_uri("2q");
        register(&dht, registration(&uri, &key), &key).unwrap();

        assert_eq!(
            lookup(&dht, &exact("anthropic.com", "assistant/chat"))[0].sequence(),
            0
        );

        refresh(&dht, &uri, &key, 4, Duration::from_hours(1)).unwrap();

        // Sequences only have to increase, not increase by one: an agent that
        // lost a response has no way to learn which of its writes landed.
        assert_eq!(
            lookup(&dht, &exact("anthropic.com", "assistant/chat"))[0].sequence(),
            4
        );
    }

    #[test]
    fn every_ancestor_copy_carries_the_new_sequence() {
        // A copy left behind at a lower sequence would accept a replay that the
        // exact key already rejected.
        let dht = unverified_dht();
        let key = SigningKey::generate();
        let uri = test_uri("2q");
        register(&dht, registration(&uri, &key), &key).unwrap();

        refresh(&dht, &uri, &key, 3, Duration::from_hours(1)).unwrap();

        assert_eq!(
            lookup(&dht, &prefix("anthropic.com", "assistant"))[0].sequence(),
            3
        );
    }

    #[test]
    fn a_replayed_proof_is_refused_the_second_time() {
        let dht = unverified_dht();
        let key = SigningKey::generate();
        let uri = test_uri("2q");
        register(&dht, registration(&uri, &key), &key).unwrap();

        let endpoints = vec![Endpoint::https("first.example")];
        let proof = MutationProof::sign_next(
            &key,
            &record(&dht, &uri),
            &Mutation::UpdateEndpoint {
                endpoints: &endpoints,
            },
        );

        block_on(dht.update_endpoint(&uri, endpoints.clone(), &proof, WriteOptions::default()))
            .unwrap();
        let replay =
            block_on(dht.update_endpoint(&uri, endpoints, &proof, WriteOptions::default()));

        assert!(matches!(
            replay,
            Err(DhtError::StaleSequence {
                presented: 1,
                current: 1,
                ..
            })
        ));
    }

    #[test]
    fn a_captured_proof_does_not_reach_a_later_record_instance() {
        // Proofs travel in the clear, so assume the attacker kept one. A
        // re-registered record starts counting from zero again, so the sequence
        // number alone would leave the captured copy sitting above it.
        let dht = unverified_dht();
        let key = SigningKey::generate();
        let uri = test_uri("2q");
        register(&dht, registration(&uri, &key), &key).unwrap();

        let captured = MutationProof::sign_next(&key, &record(&dht, &uri), &Mutation::Deregister);
        block_on(dht.deregister(&uri, &captured, WriteOptions::default())).unwrap();

        // The agent comes back a second later, which is what makes this a
        // different record instance rather than a continuation of the old one.
        register(
            &dht,
            registration(&uri, &key).with_registered_at(SystemTime::now() + Duration::from_secs(1)),
            &key,
        )
        .unwrap();
        let replay = block_on(dht.deregister(&uri, &captured, WriteOptions::default()));

        assert!(matches!(replay, Err(DhtError::Unauthorized { .. })));
        assert_eq!(
            lookup(&dht, &exact("anthropic.com", "assistant/chat")).len(),
            1
        );
    }

    #[test]
    fn continuing_the_sequence_defeats_a_captured_proof_without_relying_on_the_clock() {
        // Instance identity is the registration time, which a coarse clock can
        // fail to distinguish. An agent that remembers how far it counted does
        // not depend on the clock: it re-registers above every proof it ever
        // signed.
        let dht = unverified_dht();
        let key = SigningKey::generate();
        let uri = test_uri("2q");
        let opened_at = SystemTime::now();
        register(
            &dht,
            registration(&uri, &key).with_registered_at(opened_at),
            &key,
        )
        .unwrap();

        let captured = MutationProof::sign_next(&key, &record(&dht, &uri), &Mutation::Deregister);
        block_on(dht.deregister(&uri, &captured, WriteOptions::default())).unwrap();

        // Same instant, so the instance binding cannot help here.
        register(
            &dht,
            registration(&uri, &key)
                .with_registered_at(opened_at)
                .with_sequence(captured.sequence()),
            &key,
        )
        .unwrap();
        let replay = block_on(dht.deregister(&uri, &captured, WriteOptions::default()));

        assert!(matches!(replay, Err(DhtError::StaleSequence { .. })));
        assert_eq!(
            lookup(&dht, &exact("anthropic.com", "assistant/chat")).len(),
            1
        );
    }

    #[test]
    fn a_write_at_the_records_own_sequence_does_not_advance_it() {
        let dht = unverified_dht();
        let key = SigningKey::generate();
        let uri = test_uri("2q");
        register(&dht, registration(&uri, &key), &key).unwrap();

        // The record opens at 0, so 0 is already spent.
        let result = refresh(&dht, &uri, &key, 0, Duration::from_hours(1));

        assert!(matches!(
            result,
            Err(DhtError::StaleSequence {
                presented: 0,
                current: 0,
                ..
            })
        ));
    }

    #[test]
    fn migration_is_authorized_by_the_agents_own_key() {
        let dht = unverified_dht();
        let agent = SigningKey::generate();
        let attacker = SigningKey::generate();
        let uri = test_uri("2q");
        register(&dht, registration(&uri, &agent), &agent).unwrap();

        let moved = Endpoint::https("eu-west-1.agent.anthropic.com");
        assert!(
            dht.simulate_migration(&uri, moved.clone(), &attacker)
                .is_err()
        );

        let result = dht.simulate_migration(&uri, moved.clone(), &agent).unwrap();

        assert_eq!(result.new_endpoints(), &[moved]);
    }

    /// Registration and migration used to take the simulator's indices in
    /// opposite orders, back when each had its own lock: a registration held
    /// the record store and waited on the URI index while a migration held the
    /// URI index and waited on the record store, and neither ever moved
    /// (issue #47). Reading the lock sites is what found that; nothing
    /// ever ran the two against each other, which is how it outlived three
    /// refactors of this file.
    ///
    /// One lock has replaced the three, so the hang is now impossible by
    /// construction rather than avoided by convention, and this test cannot
    /// fail for the original reason. What it does is keep the pairing
    /// exercised: it asserts the answers a caller is owed when the two paths
    /// overlap, and it bounds the wait, because a lock-ordering regression
    /// reports as a stuck run rather than a failing one unless something is
    /// holding a stopwatch.
    #[test]
    fn concurrent_registration_and_migration_do_not_deadlock() {
        use std::sync::Arc;
        use std::sync::mpsc;
        use std::thread;

        const WORKERS: usize = 4;
        const ROUNDS: usize = 60;
        /// Crockford base32, which is what an agent ID's characters are drawn
        /// from. `test_uri` appends two of them.
        const ALPHABET: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";

        fn agent(index: usize) -> AgentUri {
            test_uri(&format!(
                "{}{}",
                ALPHABET[index / ALPHABET.len()] as char,
                ALPHABET[index % ALPHABET.len()] as char,
            ))
        }

        let dht = Arc::new(unverified_dht());

        // Two disjoint sets, so the threads contend on the indices rather than
        // on each other's records. A migrator moves an agent that is already
        // registered; a churner adds and removes its own. Sharing an agent
        // would test sequence handling instead, and would make a lost race
        // look like the deadlock this is watching for.
        let migrators: Vec<(AgentUri, SigningKey)> = (0..WORKERS)
            .map(|index| {
                let (uri, key) = (agent(index), SigningKey::generate());
                register(&dht, registration(&uri, &key), &key).expect("a fresh agent registers");
                (uri, key)
            })
            .collect();
        let churners: Vec<(AgentUri, SigningKey)> = (WORKERS..2 * WORKERS)
            .map(|index| (agent(index), SigningKey::generate()))
            .collect();

        let mut handles = Vec::new();
        for (uri, key) in migrators {
            let dht = Arc::clone(&dht);
            handles.push(thread::spawn(move || {
                for round in 0..ROUNDS {
                    let endpoint = Endpoint::https(format!("eu-west-{round}.anthropic.com"));
                    dht.simulate_migration(&uri, endpoint, &key)
                        .expect("a registered agent migrates");
                }
            }));
        }
        for (uri, key) in churners {
            let dht = Arc::clone(&dht);
            handles.push(thread::spawn(move || {
                for _ in 0..ROUNDS {
                    register(&dht, registration(&uri, &key), &key)
                        .expect("a deregistered agent registers again");
                    deregister(&dht, &uri, &key, 1).expect("its own key removes it");
                }
            }));
        }

        // Joining on this thread rather than the test's, so that a hang is a
        // failure with a name on it instead of a run that never returns. A
        // panicking worker still surfaces as a panic: its join result is
        // carried back and unwrapped below.
        let (done, finished) = mpsc::channel();
        thread::spawn(move || {
            let outcomes: Vec<_> = handles.into_iter().map(thread::JoinHandle::join).collect();
            let _ = done.send(outcomes);
        });

        let outcomes = finished
            .recv_timeout(Duration::from_mins(1))
            .expect("registration and migration deadlocked against each other");
        for outcome in outcomes {
            outcome.expect("no worker panicked");
        }

        // Every migrator's agent is still registered and every churner's last
        // act was to leave, so the indices agree on who is present.
        let registered = lookup(&dht, &prefix("anthropic.com", "assistant"));
        assert_eq!(registered.len(), WORKERS);
        assert_eq!(dht.stats().total_registrations, WORKERS);
    }
}
