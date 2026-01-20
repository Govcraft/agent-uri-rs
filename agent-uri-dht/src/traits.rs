//! DHT trait definition for capability-based agent discovery.

use agent_uri::{AgentUri, CapabilityPath, TrustRoot};

use crate::{DhtError, Endpoint, Registration};

/// Abstract DHT operations.
///
/// This trait defines the interface for capability-based agent discovery.
/// Implementations may be in-memory (for testing/evaluation) or distributed
/// (using libp2p Kademlia, for example).
///
/// # Async Considerations
///
/// This trait uses synchronous methods for simplicity in the simulated
/// implementation. For async/distributed implementations, wrap in a
/// runtime-specific async layer.
pub trait Dht: Send + Sync {
    /// Registers an agent at its capability path.
    ///
    /// The agent is indexed by the DHT key derived from its trust root
    /// and capability path, enabling discovery by capability.
    ///
    /// # Arguments
    ///
    /// * `registration` - The registration record
    ///
    /// # Errors
    ///
    /// Returns `DhtError` if:
    /// - The agent is already registered (`AlreadyRegistered`)
    /// - The endpoints list is empty (`NoEndpoints`)
    /// - The DHT key is at capacity (`KeyCapacityExceeded`)
    /// - Attestation verification fails (`InvalidAttestation`)
    fn register(&self, registration: Registration) -> Result<(), DhtError>;

    /// Updates an existing registration's endpoints.
    ///
    /// Used for agent migration (changing network location without
    /// changing identity).
    ///
    /// # Arguments
    ///
    /// * `agent_uri` - The agent's URI
    /// * `new_endpoints` - The new network endpoints
    ///
    /// # Errors
    ///
    /// Returns `DhtError` if:
    /// - The agent is not registered (`NotFound`)
    /// - The registration has expired (`Expired`)
    /// - The endpoints list is empty (`NoEndpoints`)
    fn update_endpoint(
        &self,
        agent_uri: &AgentUri,
        new_endpoints: Vec<Endpoint>,
    ) -> Result<(), DhtError>;

    /// Removes a registration.
    ///
    /// # Arguments
    ///
    /// * `agent_uri` - The agent's URI
    ///
    /// # Errors
    ///
    /// Returns `DhtError::NotFound` if the agent is not registered.
    fn deregister(&self, agent_uri: &AgentUri) -> Result<(), DhtError>;

    /// Looks up agents at exact capability path.
    ///
    /// Returns only agents registered at exactly the specified path.
    ///
    /// # Arguments
    ///
    /// * `trust_root` - The trust root to search within
    /// * `capability_path` - The exact capability path
    ///
    /// # Returns
    ///
    /// A list of registrations matching the exact path. May be empty.
    ///
    /// # Errors
    ///
    /// Returns `DhtError` if an internal error occurs.
    fn lookup_exact(
        &self,
        trust_root: &TrustRoot,
        capability_path: &CapabilityPath,
    ) -> Result<Vec<Registration>, DhtError>;

    /// Looks up agents at capability path and all child paths.
    ///
    /// Returns agents registered at the specified path and any paths
    /// that start with it (prefix match).
    ///
    /// # Arguments
    ///
    /// * `trust_root` - The trust root to search within
    /// * `capability_path` - The capability path prefix
    ///
    /// # Returns
    ///
    /// A list of registrations whose paths start with the query path.
    ///
    /// # Errors
    ///
    /// Returns `DhtError` if an internal error occurs.
    fn lookup_prefix(
        &self,
        trust_root: &TrustRoot,
        capability_path: &CapabilityPath,
    ) -> Result<Vec<Registration>, DhtError>;

    /// Looks up agents across all trust roots (global discovery).
    ///
    /// # Arguments
    ///
    /// * `capability_path` - The capability path to search
    ///
    /// # Returns
    ///
    /// A list of registrations from any trust root with the specified path.
    ///
    /// # Errors
    ///
    /// Returns `DhtError` if an internal error occurs.
    fn lookup_global(&self, capability_path: &CapabilityPath)
        -> Result<Vec<Registration>, DhtError>;
}
