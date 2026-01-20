//! Registration records for DHT storage.

use std::time::{Duration, SystemTime};

use agent_uri::AgentUri;

use crate::Endpoint;

/// A registration record stored in the DHT.
///
/// Contains all information needed to contact an agent and verify its identity.
/// Registrations have a TTL and must be refreshed to remain active.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use agent_uri::AgentUri;
/// use agent_uri_dht::{Endpoint, Registration};
///
/// let uri = AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q").unwrap();
/// let endpoint = Endpoint::https("agent.anthropic.com:443");
///
/// let registration = Registration::new(uri, vec![endpoint])
///     .with_ttl(Duration::from_secs(3600));
/// ```
#[derive(Debug, Clone)]
pub struct Registration {
    /// The agent's URI (identity).
    agent_uri: AgentUri,
    /// Network endpoints where agent can be reached.
    endpoints: Vec<Endpoint>,
    /// Attestation token proving capability claims (PASETO).
    attestation: Option<String>,
    /// When this registration expires.
    expires_at: SystemTime,
    /// When this registration was created.
    registered_at: SystemTime,
}

impl Registration {
    /// Default TTL for registrations (1 hour).
    pub const DEFAULT_TTL: Duration = Duration::from_secs(3600);

    /// Creates a new registration with default TTL.
    ///
    /// # Arguments
    ///
    /// * `agent_uri` - The agent's identity URI
    /// * `endpoints` - Network endpoints for contacting the agent
    #[must_use]
    pub fn new(agent_uri: AgentUri, endpoints: Vec<Endpoint>) -> Self {
        let now = SystemTime::now();
        Self {
            agent_uri,
            endpoints,
            attestation: None,
            expires_at: now + Self::DEFAULT_TTL,
            registered_at: now,
        }
    }

    /// Sets the TTL for this registration.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.expires_at = self.registered_at + ttl;
        self
    }

    /// Sets the attestation token.
    #[must_use]
    pub fn with_attestation(mut self, attestation: impl Into<String>) -> Self {
        self.attestation = Some(attestation.into());
        self
    }

    /// Sets the expiration time directly.
    #[must_use]
    pub fn with_expires_at(mut self, expires_at: SystemTime) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Sets the registration time (for testing/simulation).
    #[must_use]
    pub fn with_registered_at(mut self, registered_at: SystemTime) -> Self {
        self.registered_at = registered_at;
        self
    }

    /// Returns the agent URI.
    #[must_use]
    pub fn agent_uri(&self) -> &AgentUri {
        &self.agent_uri
    }

    /// Returns the endpoints.
    #[must_use]
    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }

    /// Returns the attestation token, if any.
    #[must_use]
    pub fn attestation(&self) -> Option<&str> {
        self.attestation.as_deref()
    }

    /// Returns the expiration time.
    #[must_use]
    pub fn expires_at(&self) -> SystemTime {
        self.expires_at
    }

    /// Returns the registration time.
    #[must_use]
    pub fn registered_at(&self) -> SystemTime {
        self.registered_at
    }

    /// Returns true if this registration has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        SystemTime::now() >= self.expires_at
    }

    /// Returns the remaining TTL, or None if expired.
    #[must_use]
    pub fn remaining_ttl(&self) -> Option<Duration> {
        self.expires_at.duration_since(SystemTime::now()).ok()
    }

    /// Updates the endpoints for this registration.
    pub fn update_endpoints(&mut self, endpoints: Vec<Endpoint>) {
        self.endpoints = endpoints;
    }

    /// Refreshes the registration with a new TTL from now.
    pub fn refresh(&mut self, ttl: Duration) {
        let now = SystemTime::now();
        self.registered_at = now;
        self.expires_at = now + ttl;
    }
}

impl PartialEq for Registration {
    fn eq(&self, other: &Self) -> bool {
        // Equality based on agent URI (identity)
        self.agent_uri == other.agent_uri
    }
}

impl Eq for Registration {}

impl std::hash::Hash for Registration {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.agent_uri.as_str().hash(state);
    }
}

#[cfg(feature = "serde")]
fn system_time_to_millis(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(feature = "serde")]
fn millis_to_system_time(millis: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(millis)
}

#[cfg(feature = "serde")]
impl serde::Serialize for Registration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Registration", 5)?;
        state.serialize_field("agent_uri", self.agent_uri.as_str())?;
        state.serialize_field("endpoints", &self.endpoints)?;
        state.serialize_field("attestation", &self.attestation)?;
        state.serialize_field("expires_at", &system_time_to_millis(self.expires_at))?;
        state.serialize_field("registered_at", &system_time_to_millis(self.registered_at))?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Registration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Deserialize;

        #[derive(serde::Deserialize)]
        struct RegistrationData {
            agent_uri: String,
            endpoints: Vec<Endpoint>,
            attestation: Option<String>,
            expires_at: u64,
            registered_at: u64,
        }

        let data = RegistrationData::deserialize(deserializer)?;
        let agent_uri =
            AgentUri::parse(&data.agent_uri).map_err(serde::de::Error::custom)?;

        Ok(Self {
            agent_uri,
            endpoints: data.endpoints,
            attestation: data.attestation,
            expires_at: millis_to_system_time(data.expires_at),
            registered_at: millis_to_system_time(data.registered_at),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_uri() -> AgentUri {
        AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q")
            .unwrap()
    }

    fn test_endpoint() -> Endpoint {
        Endpoint::https("agent.anthropic.com:443")
    }

    #[test]
    fn new_registration_has_default_ttl() {
        let registration = Registration::new(test_uri(), vec![test_endpoint()]);
        assert!(!registration.is_expired());
        assert!(registration.remaining_ttl().is_some());
    }

    #[test]
    fn with_ttl_sets_expiration() {
        let registration = Registration::new(test_uri(), vec![test_endpoint()])
            .with_ttl(Duration::from_secs(60));
        let remaining = registration.remaining_ttl().unwrap();
        // Should be close to 60 seconds, allow for some test execution time
        assert!(remaining.as_secs() <= 60);
        assert!(remaining.as_secs() >= 59);
    }

    #[test]
    fn with_attestation_sets_attestation() {
        let registration = Registration::new(test_uri(), vec![test_endpoint()])
            .with_attestation("token123");
        assert_eq!(registration.attestation(), Some("token123"));
    }

    #[test]
    fn expired_registration() {
        let past = SystemTime::now() - Duration::from_secs(10);
        let registration = Registration::new(test_uri(), vec![test_endpoint()])
            .with_expires_at(past);
        assert!(registration.is_expired());
        assert!(registration.remaining_ttl().is_none());
    }

    #[test]
    fn update_endpoints() {
        let mut registration = Registration::new(test_uri(), vec![test_endpoint()]);
        let new_endpoint = Endpoint::grpc("agent.anthropic.com:50051");
        registration.update_endpoints(vec![new_endpoint.clone()]);
        assert_eq!(registration.endpoints(), &[new_endpoint]);
    }

    #[test]
    fn refresh_updates_times() {
        let past = SystemTime::now() - Duration::from_secs(3600);
        let mut registration = Registration::new(test_uri(), vec![test_endpoint()])
            .with_registered_at(past)
            .with_expires_at(past);

        assert!(registration.is_expired());

        registration.refresh(Duration::from_secs(60));

        assert!(!registration.is_expired());
        assert!(registration.remaining_ttl().is_some());
    }

    #[test]
    fn equality_based_on_uri() {
        let registration1 = Registration::new(test_uri(), vec![test_endpoint()]);
        let registration2 = Registration::new(test_uri(), vec![Endpoint::grpc("other.com:50051")]);
        assert_eq!(registration1, registration2);
    }

    #[test]
    fn different_uris_not_equal() {
        let uri1 = AgentUri::parse(
            "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q",
        )
        .unwrap();
        let uri2 = AgentUri::parse(
            "agent://anthropic.com/assistant/code/llm_01h455vb4pex5vsknk084sn02r",
        )
        .unwrap();
        let registration1 = Registration::new(uri1, vec![test_endpoint()]);
        let registration2 = Registration::new(uri2, vec![test_endpoint()]);
        assert_ne!(registration1, registration2);
    }
}
