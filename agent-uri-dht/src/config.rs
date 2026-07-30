//! Configuration for the simulated DHT.

use std::num::NonZeroUsize;
use std::time::Duration;

/// Configuration for the simulated DHT.
///
/// Controls behavior such as replication factor, TTL, paging, and verification.
#[derive(Debug, Clone)]
pub struct SimulationConfig {
    /// Maximum registrations per DHT key.
    ///
    /// In Kademlia, this corresponds to the replication factor k.
    /// Default: 1000
    pub max_registrations_per_key: usize,

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

    /// Whether to automatically remove expired registrations.
    ///
    /// Default: true
    pub auto_expire: bool,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            max_registrations_per_key: 1000,
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

    /// Sets the maximum registrations per key.
    #[must_use]
    pub const fn with_max_registrations_per_key(mut self, max: usize) -> Self {
        self.max_registrations_per_key = max;
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
        assert_eq!(config.max_registrations_per_key, 1000);
        assert_eq!(config.default_ttl, Duration::from_hours(1));
        assert!(config.verify_attestations);
        assert_eq!(config.replication_factor.get(), 1);
        assert_eq!(config.page_size.get(), 64);
        assert!(config.auto_expire);
    }

    #[test]
    fn builder_pattern() {
        let config = SimulationConfig::new()
            .with_max_registrations_per_key(10)
            .with_default_ttl(Duration::from_mins(30))
            .with_verify_attestations(true)
            .with_page_size(NonZeroUsize::new(8).unwrap())
            .with_auto_expire(false);

        assert_eq!(config.max_registrations_per_key, 10);
        assert_eq!(config.default_ttl, Duration::from_mins(30));
        assert!(config.verify_attestations);
        assert_eq!(config.page_size.get(), 8);
        assert!(!config.auto_expire);
    }
}
