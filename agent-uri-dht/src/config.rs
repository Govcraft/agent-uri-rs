//! Configuration for the simulated DHT.

use std::num::NonZeroUsize;
use std::time::Duration;

/// Configuration for the simulated DHT.
///
/// Controls behavior such as replication factor, TTL, paging, and verification.
#[derive(Debug, Clone)]
pub struct SimulationConfig {
    /// Maximum registrations at one capability path.
    ///
    /// This bounds the key an agent registers at, and only that key. A record
    /// is materialized at every ancestor key as well, but it appears there
    /// because of the path it chose rather than by choosing that key, so an
    /// ancestor's occupancy is not charged to it. Bounding ancestors instead
    /// would let whoever fills a popular top-level prefix decide whether an
    /// unrelated agent may register anywhere beneath it (issue #54).
    ///
    /// An ancestor key therefore holds whatever its subtree holds, which is
    /// the direct model's premise: it applies where one store owns the
    /// namespace and a stored value has no practical size bound. A store that
    /// does bound a value is required to shard instead, per SPECIFICATION.md
    /// §6.2.
    ///
    /// The default of 1000 is therefore a simulator affordance, not a figure a
    /// deployment can be sized against. A Kademlia overlay bounds a record at
    /// the wire size a peer will accept, which for `libp2p-kad` is 1 to 27
    /// registrations, which is exactly why `agent-uri-dht-libp2p` shards rather
    /// than storing a subtree at one key. Code that handles
    /// [`DhtError::KeyCapacityExceeded`] ports to it. A capacity chosen against
    /// this number does not.
    ///
    /// [`DhtError::KeyCapacityExceeded`]: crate::DhtError::KeyCapacityExceeded
    ///
    /// Default: 1000
    pub max_registrations_per_capability: usize,

    /// Default TTL for registrations.
    ///
    /// Default: 1 hour
    pub default_ttl: Duration,

    /// Whether to verify attestations on registration.
    ///
    /// Set to false only for isolated indexing evaluations.
    /// Default: true
    pub verify_attestations: bool,

    /// How many copies the simulator claims to hold.
    ///
    /// The simulator holds exactly one authoritative copy, so this is 1 and
    /// every [`crate::Quorum`] resolves to 1 against it. It exists so that
    /// quorum arithmetic is exercised rather than bypassed.
    /// Default: 1
    pub replication_factor: NonZeroUsize,

    /// Maximum registrations returned in one lookup page.
    ///
    /// The simulator could return every match at once, but a distributed
    /// backend cannot, so it pages deliberately. Callers written against an
    /// unpaged simulator break on a real backend.
    /// Default: 64
    pub page_size: NonZeroUsize,

    /// Whether expiry happens without being asked.
    ///
    /// When set, lookups omit lapsed records and writes evict them, so a store
    /// in use stays clean without anyone calling
    /// [`SimulatedDht::expire_stale`]. When clear, lapsed records stay visible
    /// and stay stored until that call, which is what an evaluation measuring
    /// how much of a namespace has gone stale needs.
    ///
    /// [`SimulatedDht::expire_stale`]: crate::SimulatedDht::expire_stale
    ///
    /// Default: true
    pub auto_expire: bool,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            max_registrations_per_capability: 1000,
            default_ttl: Duration::from_hours(1),
            verify_attestations: true,
            replication_factor: NonZeroUsize::new(1).unwrap(),
            page_size: NonZeroUsize::new(64).unwrap(),
            auto_expire: true,
        }
    }
}

impl SimulationConfig {
    /// Creates a new configuration with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum registrations at one capability path.
    #[must_use]
    pub const fn with_max_registrations_per_capability(mut self, max: usize) -> Self {
        self.max_registrations_per_capability = max;
        self
    }

    /// Sets the default TTL.
    #[must_use]
    pub const fn with_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = ttl;
        self
    }

    /// Enables or disables attestation verification.
    #[must_use]
    pub const fn with_verify_attestations(mut self, verify: bool) -> Self {
        self.verify_attestations = verify;
        self
    }

    /// Sets the number of copies the simulator claims to hold.
    #[must_use]
    pub const fn with_replication_factor(mut self, factor: NonZeroUsize) -> Self {
        self.replication_factor = factor;
        self
    }

    /// Sets the maximum number of registrations returned per lookup page.
    #[must_use]
    pub const fn with_page_size(mut self, page_size: NonZeroUsize) -> Self {
        self.page_size = page_size;
        self
    }

    /// Enables or disables automatic expiration.
    #[must_use]
    pub const fn with_auto_expire(mut self, auto_expire: bool) -> Self {
        self.auto_expire = auto_expire;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = SimulationConfig::default();
        assert_eq!(config.max_registrations_per_capability, 1000);
        assert_eq!(config.default_ttl, Duration::from_hours(1));
        assert!(config.verify_attestations);
        assert_eq!(config.replication_factor.get(), 1);
        assert_eq!(config.page_size.get(), 64);
        assert!(config.auto_expire);
    }

    #[test]
    fn builder_pattern() {
        let config = SimulationConfig::new()
            .with_max_registrations_per_capability(10)
            .with_default_ttl(Duration::from_mins(30))
            .with_verify_attestations(true)
            .with_page_size(NonZeroUsize::new(8).unwrap())
            .with_auto_expire(false);

        assert_eq!(config.max_registrations_per_capability, 10);
        assert_eq!(config.default_ttl, Duration::from_mins(30));
        assert!(config.verify_attestations);
        assert_eq!(config.page_size.get(), 8);
        assert!(!config.auto_expire);
    }
}
