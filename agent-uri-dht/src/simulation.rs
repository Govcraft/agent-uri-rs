//! Simulated DHT implementation for evaluation.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

use agent_uri::{AgentUri, CapabilityPath, TrustRoot};

use crate::{
    Dht, DhtError, DhtKey, DhtStats, Endpoint, MigrationResult, PathTrie, Registration,
    SimulationConfig,
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
/// let dht = SimulatedDht::new(SimulationConfig::default());
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

    /// Secondary index: trust root string -> `PathTrie<Registration>`
    by_path: RwLock<HashMap<String, PathTrie<Registration>>>,

    /// Tertiary index: `AgentUri` string -> `DhtKey`
    by_uri: RwLock<HashMap<String, DhtKey>>,

    /// Configuration
    config: SimulationConfig,
}

impl SimulatedDht {
    /// Creates a new simulated DHT with the given configuration.
    #[must_use]
    pub fn new(config: SimulationConfig) -> Self {
        Self {
            by_key: RwLock::new(HashMap::new()),
            by_path: RwLock::new(HashMap::new()),
            by_uri: RwLock::new(HashMap::new()),
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
        let by_path = self.by_path.read().expect("lock poisoned");
        let by_uri = self.by_uri.read().expect("lock poisoned");

        let total_registrations = by_uri.len();
        let unique_keys = by_key.len();
        let unique_trust_roots = by_path.len();

        let max_registrations_per_key = by_key.values().map(Vec::len).max().unwrap_or(0);

        // Use f64::from for u32 to avoid precision loss; saturate for stats safety
        let total_u32 = u32::try_from(total_registrations).unwrap_or(u32::MAX);
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
        let uri_str = agent_uri.as_str().to_string();

        // Get old endpoints
        let old_endpoints = {
            let by_uri = self.by_uri.read().expect("lock poisoned");
            let key = by_uri
                .get(&uri_str)
                .ok_or_else(|| DhtError::not_found(&uri_str))?;

            let by_key = self.by_key.read().expect("lock poisoned");
            let registrations = by_key
                .get(key)
                .ok_or_else(|| DhtError::not_found(&uri_str))?;

            registrations
                .iter()
                .find(|r| r.agent_uri().as_str() == uri_str)
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
        let mut by_path = self.by_path.write().expect("lock poisoned");
        let mut by_uri = self.by_uri.write().expect("lock poisoned");

        by_key.clear();
        by_path.clear();
        by_uri.clear();
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
        let mut by_path = self.by_path.write().expect("lock poisoned");
        let mut by_uri = self.by_uri.write().expect("lock poisoned");

        let mut expired_uris: Vec<String> = Vec::new();

        // Find expired registrations
        for registrations in by_key.values() {
            for reg in registrations {
                if reg.is_expired() {
                    expired_uris.push(reg.agent_uri().as_str().to_string());
                }
            }
        }

        // Remove from all indices
        for uri_str in &expired_uris {
            if let Some(key) = by_uri.remove(uri_str)
                && let Some(registrations) = by_key.get_mut(&key)
            {
                registrations.retain(|r| r.agent_uri().as_str() != uri_str);
                if registrations.is_empty() {
                    by_key.remove(&key);
                }
            }
        }

        // Rebuild path index if there were expirations
        if !expired_uris.is_empty() {
            by_path.clear();
            for registrations in by_key.values() {
                for reg in registrations {
                    let trust_root_str = reg.agent_uri().trust_root().as_str().to_string();
                    let trie = by_path.entry(trust_root_str).or_default();
                    trie.insert(reg.agent_uri().capability_path(), reg.clone());
                }
            }
        }

        expired_uris.len()
    }

    fn estimate_memory_usage_inner(
        by_key: &HashMap<DhtKey, Vec<Registration>>,
        by_uri: &HashMap<String, DhtKey>,
    ) -> usize {
        // Rough estimate:
        // - Each DhtKey: 32 bytes
        // - Each Registration: ~500 bytes (URI + endpoints + attestation)
        // - HashMap overhead: ~64 bytes per entry
        // - PathTrie: ~100 bytes per node

        let key_bytes = by_key.len() * (32 + 64);
        let registration_bytes = by_uri.len() * 500;
        let uri_index_bytes = by_uri.len() * (100 + 32 + 64);

        key_bytes + registration_bytes + uri_index_bytes
    }
}

impl Dht for SimulatedDht {
    fn register(&self, registration: Registration) -> Result<(), DhtError> {
        // Validate
        if registration.endpoints().is_empty() {
            return Err(DhtError::NoEndpoints);
        }

        let uri_str = registration.agent_uri().as_str().to_string();
        let trust_root_str = registration.agent_uri().trust_root().as_str().to_string();
        let key = DhtKey::derive(
            registration.agent_uri().trust_root(),
            registration.agent_uri().capability_path(),
        );

        // Simulate delay if configured
        if let Some(delay) = self.config.simulated_delay {
            std::thread::sleep(delay);
        }

        // Check if already registered
        {
            let by_uri = self.by_uri.read().expect("lock poisoned");
            if by_uri.contains_key(&uri_str) {
                return Err(DhtError::already_registered(&uri_str));
            }
        }

        // Check key capacity
        {
            let by_key = self.by_key.read().expect("lock poisoned");
            if let Some(registrations) = by_key.get(&key)
                && registrations.len() >= self.config.max_registrations_per_key
            {
                return Err(DhtError::key_capacity_exceeded(
                    format!("{key}"),
                    self.config.max_registrations_per_key,
                ));
            }
        }

        // Insert into all indices
        {
            let mut by_key = self.by_key.write().expect("lock poisoned");
            let mut by_path = self.by_path.write().expect("lock poisoned");
            let mut by_uri = self.by_uri.write().expect("lock poisoned");

            // Secondary index (path trie) - must insert first since we need to borrow registration
            let trie = by_path.entry(trust_root_str).or_default();
            trie.insert(registration.agent_uri().capability_path(), registration.clone());

            // Primary index
            by_key.entry(key).or_default().push(registration);

            // Tertiary index
            by_uri.insert(uri_str, key);
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

        let uri_str = agent_uri.as_str();

        // Simulate delay if configured
        if let Some(delay) = self.config.simulated_delay {
            std::thread::sleep(delay);
        }

        // Get the key
        let key = {
            let by_uri = self.by_uri.read().expect("lock poisoned");
            *by_uri
                .get(uri_str)
                .ok_or_else(|| DhtError::not_found(uri_str))?
        };

        // Update in primary index
        let updated_registration = {
            let mut by_key = self.by_key.write().expect("lock poisoned");
            let registrations = by_key
                .get_mut(&key)
                .ok_or_else(|| DhtError::not_found(uri_str))?;

            let registration = registrations
                .iter_mut()
                .find(|r| r.agent_uri().as_str() == uri_str)
                .ok_or_else(|| DhtError::not_found(uri_str))?;

            if registration.is_expired() && self.config.auto_expire {
                return Err(DhtError::expired(uri_str));
            }

            registration.update_endpoints(new_endpoints);
            registration.clone()
        };

        // Update in path trie
        {
            let mut by_path = self.by_path.write().expect("lock poisoned");
            let trust_root_str = agent_uri.trust_root().as_str().to_string();

            if let Some(trie) = by_path.get_mut(&trust_root_str) {
                // Remove old and insert updated
                let capability_path = agent_uri.capability_path();
                let uri_str_owned = uri_str.to_string();
                trie.remove(capability_path, |r| {
                    r.agent_uri().as_str() == uri_str_owned
                });
                trie.insert(capability_path, updated_registration);
            }
        }

        Ok(())
    }

    fn deregister(&self, agent_uri: &AgentUri) -> Result<(), DhtError> {
        let uri_str = agent_uri.as_str();

        // Simulate delay if configured
        if let Some(delay) = self.config.simulated_delay {
            std::thread::sleep(delay);
        }

        // Get and remove from URI index
        let key = {
            let mut by_uri = self.by_uri.write().expect("lock poisoned");
            by_uri
                .remove(uri_str)
                .ok_or_else(|| DhtError::not_found(uri_str))?
        };

        // Remove from primary index
        {
            let mut by_key = self.by_key.write().expect("lock poisoned");
            if let Some(registrations) = by_key.get_mut(&key) {
                let uri_str_owned = uri_str.to_string();
                registrations.retain(|r| r.agent_uri().as_str() != uri_str_owned);
                if registrations.is_empty() {
                    by_key.remove(&key);
                }
            }
        }

        // Remove from path trie
        {
            let mut by_path = self.by_path.write().expect("lock poisoned");
            let trust_root_str = agent_uri.trust_root().as_str().to_string();

            if let Some(trie) = by_path.get_mut(&trust_root_str) {
                let uri_str_owned = uri_str.to_string();
                trie.remove(agent_uri.capability_path(), |r| {
                    r.agent_uri().as_str() == uri_str_owned
                });
            }
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

        let by_path = self.by_path.read().expect("lock poisoned");
        let trust_root_str = trust_root.as_str();

        let results = by_path
            .get(trust_root_str)
            .map(|trie| {
                trie.get_prefix(capability_path)
                    .into_iter()
                    .filter(|r| !r.is_expired() || !self.config.auto_expire)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        Ok(results)
    }

    fn lookup_global(
        &self,
        capability_path: &CapabilityPath,
    ) -> Result<Vec<Registration>, DhtError> {
        // Simulate delay if configured
        if let Some(delay) = self.config.simulated_delay {
            std::thread::sleep(delay);
        }

        let by_path = self.by_path.read().expect("lock poisoned");

        let mut results = Vec::new();

        for trie in by_path.values() {
            let matches: Vec<Registration> = trie
                .get_prefix(capability_path)
                .into_iter()
                .filter(|r| !r.is_expired() || !self.config.auto_expire)
                .cloned()
                .collect();
            results.extend(matches);
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let dht = SimulatedDht::with_defaults();
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
        let dht = SimulatedDht::with_defaults();
        let uri = test_uri("2q");
        let registration = Registration::new(uri, vec![]);

        let result = dht.register(registration);

        assert!(matches!(result, Err(DhtError::NoEndpoints)));
    }

    #[test]
    fn double_registration_fails() {
        let dht = SimulatedDht::with_defaults();
        let uri = test_uri("2q");

        dht.register(Registration::new(uri.clone(), vec![test_endpoint()]))
            .unwrap();

        let result = dht.register(Registration::new(uri, vec![test_endpoint()]));

        assert!(matches!(result, Err(DhtError::AlreadyRegistered { .. })));
    }

    #[test]
    fn deregister_removes_agent() {
        let dht = SimulatedDht::with_defaults();
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
        let dht = SimulatedDht::with_defaults();

        let uri1 = AgentUri::parse(
            "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q",
        )
        .unwrap();
        let uri2 = AgentUri::parse(
            "agent://anthropic.com/assistant/code/llm_01h455vb4pex5vsknk084sn02r",
        )
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
    fn lookup_global_finds_across_trust_roots() {
        let dht = SimulatedDht::with_defaults();

        let uri1 = AgentUri::parse(
            "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q",
        )
        .unwrap();
        let uri2 = AgentUri::parse(
            "agent://openai.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02r",
        )
        .unwrap();

        dht.register(Registration::new(uri1, vec![Endpoint::https("a.com")]))
            .unwrap();
        dht.register(Registration::new(uri2, vec![Endpoint::https("b.com")]))
            .unwrap();

        let results = dht
            .lookup_global(&CapabilityPath::parse("assistant/chat").unwrap())
            .unwrap();

        assert_eq!(results.len(), 2);
    }

    #[test]
    fn update_endpoint_changes_endpoints() {
        let dht = SimulatedDht::with_defaults();
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
        let dht = SimulatedDht::with_defaults();

        let uri1 = test_uri("2q");
        let uri2 = AgentUri::parse(
            "agent://anthropic.com/assistant/code/llm_01h455vb4pex5vsknk084sn02r",
        )
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
        let config = SimulationConfig::new().with_max_registrations_per_key(1);
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
        let dht = SimulatedDht::with_defaults();
        let uri = test_uri("2q");

        dht.register(Registration::new(uri, vec![test_endpoint()]))
            .unwrap();

        dht.clear();

        let stats = dht.stats();
        assert_eq!(stats.total_registrations(), 0);
    }

    #[test]
    fn register_batch_counts_successes() {
        let dht = SimulatedDht::with_defaults();

        let registrations = vec![
            Registration::new(test_uri("2q"), vec![test_endpoint()]),
            Registration::new(test_uri("2r"), vec![test_endpoint()]),
            Registration::new(test_uri("2s"), vec![]), // Will fail - no endpoints
        ];

        let count = dht.register_batch(registrations).unwrap();

        assert_eq!(count, 2);
    }
}
