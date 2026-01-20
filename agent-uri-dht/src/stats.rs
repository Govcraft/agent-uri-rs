//! Statistics and result types for DHT evaluation.

use std::time::Duration;

use crate::Endpoint;

/// Statistics about the DHT state.
///
/// Used for evaluation metrics and monitoring.
#[derive(Debug, Clone, Default)]
pub struct DhtStats {
    /// Total number of active registrations.
    pub total_registrations: usize,
    /// Number of unique DHT keys with registrations.
    pub unique_keys: usize,
    /// Number of unique trust roots.
    pub unique_trust_roots: usize,
    /// Maximum registrations at any single key.
    pub max_registrations_per_key: usize,
    /// Average registrations per key.
    pub avg_registrations_per_key: f64,
    /// Histogram of path depths.
    pub path_depth_histogram: Vec<usize>,
    /// Estimated memory usage in bytes.
    pub memory_bytes: usize,
}

impl DhtStats {
    /// Creates empty stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the total registrations.
    #[must_use]
    pub const fn total_registrations(&self) -> usize {
        self.total_registrations
    }

    /// Returns the unique keys count.
    #[must_use]
    pub const fn unique_keys(&self) -> usize {
        self.unique_keys
    }

    /// Returns the unique trust roots count.
    #[must_use]
    pub const fn unique_trust_roots(&self) -> usize {
        self.unique_trust_roots
    }

    /// Returns the maximum registrations at any key.
    #[must_use]
    pub const fn max_registrations_per_key(&self) -> usize {
        self.max_registrations_per_key
    }

    /// Returns the average registrations per key.
    #[must_use]
    pub const fn avg_registrations_per_key(&self) -> f64 {
        self.avg_registrations_per_key
    }

    /// Returns the memory usage estimate.
    #[must_use]
    pub const fn memory_bytes(&self) -> usize {
        self.memory_bytes
    }
}

/// Result of a simulated migration operation.
///
/// Captures the before/after state and performance metrics.
#[derive(Debug, Clone)]
pub struct MigrationResult {
    /// The agent URI that was migrated.
    pub agent_uri: String,
    /// The old endpoint(s).
    pub old_endpoints: Vec<Endpoint>,
    /// The new endpoint(s).
    pub new_endpoints: Vec<Endpoint>,
    /// Time taken to complete the update.
    pub update_latency: Duration,
    /// Whether the migration was successful.
    pub success: bool,
}

impl MigrationResult {
    /// Creates a successful migration result.
    #[must_use]
    pub fn success(
        agent_uri: impl Into<String>,
        old_endpoints: Vec<Endpoint>,
        new_endpoints: Vec<Endpoint>,
        update_latency: Duration,
    ) -> Self {
        Self {
            agent_uri: agent_uri.into(),
            old_endpoints,
            new_endpoints,
            update_latency,
            success: true,
        }
    }

    /// Creates a failed migration result.
    #[must_use]
    pub fn failure(
        agent_uri: impl Into<String>,
        old_endpoints: Vec<Endpoint>,
        new_endpoints: Vec<Endpoint>,
        update_latency: Duration,
    ) -> Self {
        Self {
            agent_uri: agent_uri.into(),
            old_endpoints,
            new_endpoints,
            update_latency,
            success: false,
        }
    }

    /// Returns true if the migration succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.success
    }

    /// Returns the agent URI.
    #[must_use]
    pub fn agent_uri(&self) -> &str {
        &self.agent_uri
    }

    /// Returns the old endpoints.
    #[must_use]
    pub fn old_endpoints(&self) -> &[Endpoint] {
        &self.old_endpoints
    }

    /// Returns the new endpoints.
    #[must_use]
    pub fn new_endpoints(&self) -> &[Endpoint] {
        &self.new_endpoints
    }

    /// Returns the update latency.
    #[must_use]
    pub const fn update_latency(&self) -> Duration {
        self.update_latency
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_stats() {
        let stats = DhtStats::default();
        assert_eq!(stats.total_registrations(), 0);
        assert_eq!(stats.unique_keys(), 0);
        assert_eq!(stats.unique_trust_roots(), 0);
        assert_eq!(stats.max_registrations_per_key(), 0);
        assert_eq!(stats.avg_registrations_per_key(), 0.0);
        assert_eq!(stats.memory_bytes(), 0);
    }

    #[test]
    fn successful_migration() {
        let old = vec![Endpoint::https("old.example.com")];
        let new = vec![Endpoint::https("new.example.com")];
        let result = MigrationResult::success(
            "agent://example.com/test/agent_123",
            old.clone(),
            new.clone(),
            Duration::from_millis(50),
        );

        assert!(result.is_success());
        assert_eq!(result.agent_uri(), "agent://example.com/test/agent_123");
        assert_eq!(result.old_endpoints(), &old);
        assert_eq!(result.new_endpoints(), &new);
        assert_eq!(result.update_latency(), Duration::from_millis(50));
    }

    #[test]
    fn failed_migration() {
        let old = vec![Endpoint::https("old.example.com")];
        let new = vec![Endpoint::https("new.example.com")];
        let result = MigrationResult::failure(
            "agent://example.com/test/agent_123",
            old,
            new,
            Duration::from_millis(100),
        );

        assert!(!result.is_success());
    }
}
