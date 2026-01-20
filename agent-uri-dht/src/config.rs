//! Configuration for the simulated DHT.

use std::time::Duration;

/// Configuration for the simulated DHT.
///
/// Controls behavior such as replication factor, TTL, and verification.
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
    /// Set to false for evaluation without attestation infrastructure.
    /// Default: false
    pub verify_attestations: bool,

    /// Simulated network delay for operations.
    ///
    /// Used for latency experiments. None means no delay.
    /// Default: None
    pub simulated_delay: Option<Duration>,

    /// Whether to automatically remove expired registrations.
    ///
    /// Default: true
    pub auto_expire: bool,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            max_registrations_per_key: 1000,
            default_ttl: Duration::from_secs(3600),
            verify_attestations: false,
            simulated_delay: None,
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

    /// Sets the simulated network delay.
    #[must_use]
    pub const fn with_simulated_delay(mut self, delay: Duration) -> Self {
        self.simulated_delay = Some(delay);
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
        assert_eq!(config.default_ttl, Duration::from_secs(3600));
        assert!(!config.verify_attestations);
        assert!(config.simulated_delay.is_none());
        assert!(config.auto_expire);
    }

    #[test]
    fn builder_pattern() {
        let config = SimulationConfig::new()
            .with_max_registrations_per_key(10)
            .with_default_ttl(Duration::from_secs(1800))
            .with_verify_attestations(true)
            .with_simulated_delay(Duration::from_millis(50))
            .with_auto_expire(false);

        assert_eq!(config.max_registrations_per_key, 10);
        assert_eq!(config.default_ttl, Duration::from_secs(1800));
        assert!(config.verify_attestations);
        assert_eq!(config.simulated_delay, Some(Duration::from_millis(50)));
        assert!(!config.auto_expire);
    }
}
