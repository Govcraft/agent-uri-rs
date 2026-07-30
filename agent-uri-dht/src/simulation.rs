//! Simulated DHT implementation for evaluation.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::time::Instant;

use agent_uri::{AgentUri, CapabilityPath, TrustRoot};
use agent_uri_attestation::Verifier;

use crate::{
    Dht, DhtError, DhtKey, DhtStats, Endpoint, MigrationResult, Registration, SimulationConfig,
};

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
/// use agent_uri_dht::{Endpoint, Registration, SimulatedDht, SimulationConfig, Dht};
///
/// // Explicitly unverified because this example isolates indexing behavior.
/// let dht = SimulatedDht::new(
///     SimulationConfig::default().with_verify_attestations(false)
/// );
///
/// let uri = AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q").unwrap();
/// let registration = Registration::new(uri.clone(), vec![Endpoint::https("agent.anthropic.com")]);
///
/// dht.register(registration).unwrap();
///
/// let results = dht.lookup_exact(
///     &TrustRoot::parse("anthropic.com").unwrap(),
///     &CapabilityPath::parse("assistant/chat").unwrap(),
/// ).unwrap();
///
/// assert_eq!(results.len(), 1);
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

    /// Configuration
    config: SimulationConfig,
}

impl SimulatedDht {
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
            if self.register(registration).is_ok() {
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
        self.update_endpoint(agent_uri, vec![new_endpoint.clone()])?;
        let update_latency = start.elapsed();

        // Add simulated delay if configured
        if let Some(delay) = self.config.simulated_delay {
            std::thread::sleep(delay);
        }

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

impl Dht for SimulatedDht {
    fn register(&self, registration: Registration) -> Result<(), DhtError> {
        // Validate
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

        // Simulate delay if configured
        if let Some(delay) = self.config.simulated_delay {
            std::thread::sleep(delay);
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

            // Tertiary index
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

    fn update_endpoint(
        &self,
        agent_uri: &AgentUri,
        new_endpoints: Vec<Endpoint>,
    ) -> Result<(), DhtError> {
        if new_endpoints.is_empty() {
            return Err(DhtError::NoEndpoints);
        }

        let uri_str = agent_uri.canonical();

        // Simulate delay if configured
        if let Some(delay) = self.config.simulated_delay {
            std::thread::sleep(delay);
        }

        // Get the key
        let keys = {
            let by_uri = self.by_uri.read().expect("lock poisoned");
            by_uri
                .get(&uri_str)
                .cloned()
                .ok_or_else(|| DhtError::not_found(&uri_str))?
        };

        // Update every ancestor-key copy in the primary index.
        let mut updated_any = false;
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
                registration.update_endpoints(new_endpoints.clone());
                updated_any = true;
            }
        }
        if !updated_any {
            return Err(DhtError::not_found(&uri_str));
        }

        Ok(())
    }

    fn deregister(&self, agent_uri: &AgentUri) -> Result<(), DhtError> {
        let uri_str = agent_uri.canonical();

        // Simulate delay if configured
        if let Some(delay) = self.config.simulated_delay {
            std::thread::sleep(delay);
        }

        // Mutate all indices under the same lock order as registration.
        {
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
        }

        Ok(())
    }

    fn lookup_exact(
        &self,
        trust_root: &TrustRoot,
        capability_path: &CapabilityPath,
    ) -> Result<Vec<Registration>, DhtError> {
        // Simulate delay if configured
        if let Some(delay) = self.config.simulated_delay {
            std::thread::sleep(delay);
        }

        let key = DhtKey::derive(trust_root, capability_path);

        let by_key = self.by_key.read().expect("lock poisoned");

        let results = by_key
            .get(&key)
            .map(|registrations| {
                registrations
                    .iter()
                    .filter(|r| r.agent_uri().capability_path() == capability_path)
                    .filter(|r| !r.is_expired() || !self.config.auto_expire)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        Ok(results)
    }

    fn lookup_prefix(
        &self,
        trust_root: &TrustRoot,
        capability_path: &CapabilityPath,
    ) -> Result<Vec<Registration>, DhtError> {
        // Simulate delay if configured
        if let Some(delay) = self.config.simulated_delay {
            std::thread::sleep(delay);
        }

        let key = DhtKey::derive(trust_root, capability_path);
        let by_key = self.by_key.read().expect("lock poisoned");
        let results = by_key
            .get(&key)
            .map(|registrations| {
                registrations
                    .iter()
                    .filter(|r| !r.is_expired() || !self.config.auto_expire)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_uri_attestation::{Issuer, SigningKey};
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

    #[test]
    fn register_and_lookup_exact() {
        let dht = unverified_dht();
        let uri = test_uri("2q");
        let registration = Registration::new(uri.clone(), vec![test_endpoint()]);

        dht.register(registration).unwrap();

        let results = dht
            .lookup_exact(
                &TrustRoot::parse("anthropic.com").unwrap(),
                &CapabilityPath::parse("assistant/chat").unwrap(),
            )
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_uri(), &uri);
    }

    #[test]
    fn register_empty_endpoints_fails() {
        let dht = unverified_dht();
        let uri = test_uri("2q");
        let registration = Registration::new(uri, vec![]);

        let result = dht.register(registration);

        assert!(matches!(result, Err(DhtError::NoEndpoints)));
    }

    #[test]
    fn double_registration_fails() {
        let dht = unverified_dht();
        let uri = test_uri("2q");

        dht.register(Registration::new(uri.clone(), vec![test_endpoint()]))
            .unwrap();

        let result = dht.register(Registration::new(uri, vec![test_endpoint()]));

        assert!(matches!(result, Err(DhtError::AlreadyRegistered { .. })));
    }

    #[test]
    fn deregister_removes_agent() {
        let dht = unverified_dht();
        let uri = test_uri("2q");

        dht.register(Registration::new(uri.clone(), vec![test_endpoint()]))
            .unwrap();
        dht.deregister(&uri).unwrap();

        let results = dht
            .lookup_exact(
                &TrustRoot::parse("anthropic.com").unwrap(),
                &CapabilityPath::parse("assistant/chat").unwrap(),
            )
            .unwrap();

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

        dht.register(Registration::new(uri1, vec![Endpoint::https("a.com")]))
            .unwrap();
        dht.register(Registration::new(uri2, vec![Endpoint::https("b.com")]))
            .unwrap();

        let results = dht
            .lookup_prefix(
                &TrustRoot::parse("anthropic.com").unwrap(),
                &CapabilityPath::parse("assistant").unwrap(),
            )
            .unwrap();

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

        dht.register(Registration::new(uri1, vec![Endpoint::https("a.com")]))
            .unwrap();
        dht.register(Registration::new(uri2, vec![Endpoint::https("b.com")]))
            .unwrap();

        // Identical capability paths under two authorities derive two distinct
        // keys, so neither lookup can observe the other's registration. This is
        // the cross-trust-root isolation that removing the global scan defends.
        let path = CapabilityPath::parse("assistant/chat").unwrap();
        let anthropic = dht
            .lookup_exact(&TrustRoot::parse("anthropic.com").unwrap(), &path)
            .unwrap();
        let openai = dht
            .lookup_exact(&TrustRoot::parse("openai.com").unwrap(), &path)
            .unwrap();

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

        dht.register(Registration::new(uri.clone(), vec![test_endpoint()]))
            .unwrap();

        let new_endpoint = Endpoint::grpc("agent.anthropic.com:50051");
        dht.update_endpoint(&uri, vec![new_endpoint.clone()])
            .unwrap();

        let results = dht
            .lookup_exact(
                &TrustRoot::parse("anthropic.com").unwrap(),
                &CapabilityPath::parse("assistant/chat").unwrap(),
            )
            .unwrap();

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

        dht.register(Registration::new(uri1, vec![test_endpoint()]))
            .unwrap();
        dht.register(Registration::new(uri2, vec![test_endpoint()]))
            .unwrap();

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

        dht.register(Registration::new(uri1, vec![test_endpoint()]))
            .unwrap();

        let result = dht.register(Registration::new(uri2, vec![test_endpoint()]));

        assert!(matches!(result, Err(DhtError::KeyCapacityExceeded { .. })));
    }

    #[test]
    fn clear_removes_all() {
        let dht = unverified_dht();
        let uri = test_uri("2q");

        dht.register(Registration::new(uri, vec![test_endpoint()]))
            .unwrap();

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

        let result = dht.register(Registration::new(uri, vec![test_endpoint()]));

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

        dht.register(Registration::new(uri.clone(), vec![test_endpoint()]).with_attestation(token))
            .unwrap();

        let results = dht
            .lookup_exact(uri.trust_root(), uri.capability_path())
            .unwrap();
        assert_eq!(results.len(), 1);
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
        dht.register(Registration::new(first, vec![test_endpoint()]))
            .unwrap();

        let result = dht.register(Registration::new(reclassified, vec![test_endpoint()]));

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
        dht.register(Registration::new(first, vec![test_endpoint()]))
            .unwrap();

        let result = dht.register(Registration::new(ancestor_reuse, vec![test_endpoint()]));

        assert!(matches!(
            result,
            Err(DhtError::IdentityCapabilityConflict { .. })
        ));
    }
}
