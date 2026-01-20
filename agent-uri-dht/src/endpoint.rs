//! Network endpoint type for agent discovery.

use std::fmt;

/// Network endpoint for contacting an agent.
///
/// Represents a reachable address where an agent can be contacted.
/// Multiple endpoints may be provided for redundancy or protocol flexibility.
///
/// # Examples
///
/// ```
/// use agent_uri_dht::Endpoint;
///
/// let https = Endpoint::new("https", "agent.example.com:443", Some("/v1/agent"));
/// let grpc = Endpoint::new("grpc", "agent.example.com:50051", None::<&str>);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    /// Transport protocol (https, grpc, ws, etc.)
    protocol: String,
    /// Host and port (e.g., "agent.example.com:443")
    address: String,
    /// Optional path prefix for routing
    path: Option<String>,
}

impl Endpoint {
    /// Creates a new endpoint.
    ///
    /// # Arguments
    ///
    /// * `protocol` - Transport protocol (e.g., "https", "grpc", "ws")
    /// * `address` - Host and optional port (e.g., "example.com:443")
    /// * `path` - Optional path prefix (e.g., "/v1/agent")
    #[must_use]
    pub fn new(
        protocol: impl Into<String>,
        address: impl Into<String>,
        path: Option<impl Into<String>>,
    ) -> Self {
        Self {
            protocol: protocol.into(),
            address: address.into(),
            path: path.map(Into::into),
        }
    }

    /// Creates an HTTPS endpoint.
    #[must_use]
    pub fn https(address: impl Into<String>) -> Self {
        Self::new("https", address, None::<String>)
    }

    /// Creates an HTTPS endpoint with a path.
    #[must_use]
    pub fn https_with_path(address: impl Into<String>, path: impl Into<String>) -> Self {
        Self::new("https", address, Some(path))
    }

    /// Creates a gRPC endpoint.
    #[must_use]
    pub fn grpc(address: impl Into<String>) -> Self {
        Self::new("grpc", address, None::<String>)
    }

    /// Creates a WebSocket endpoint.
    #[must_use]
    pub fn websocket(address: impl Into<String>) -> Self {
        Self::new("ws", address, None::<String>)
    }

    /// Returns the protocol.
    #[must_use]
    pub fn protocol(&self) -> &str {
        &self.protocol
    }

    /// Returns the address.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns the path, if any.
    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    /// Returns the full URI representation.
    #[must_use]
    pub fn to_uri(&self) -> String {
        match &self.path {
            Some(p) => format!("{}://{}{}", self.protocol, self.address, p),
            None => format!("{}://{}", self.protocol, self.address),
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_uri())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Endpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Endpoint", 3)?;
        state.serialize_field("protocol", &self.protocol)?;
        state.serialize_field("address", &self.address)?;
        state.serialize_field("path", &self.path)?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Endpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Deserialize;

        #[derive(serde::Deserialize)]
        struct EndpointData {
            protocol: String,
            address: String,
            path: Option<String>,
        }

        let data = EndpointData::deserialize(deserializer)?;
        Ok(Self {
            protocol: data.protocol,
            address: data.address,
            path: data.path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_endpoint() {
        let endpoint = Endpoint::https("agent.example.com:443");
        assert_eq!(endpoint.protocol(), "https");
        assert_eq!(endpoint.address(), "agent.example.com:443");
        assert!(endpoint.path().is_none());
        assert_eq!(endpoint.to_uri(), "https://agent.example.com:443");
    }

    #[test]
    fn https_with_path_endpoint() {
        let endpoint = Endpoint::https_with_path("agent.example.com:443", "/v1/agent");
        assert_eq!(endpoint.protocol(), "https");
        assert_eq!(endpoint.address(), "agent.example.com:443");
        assert_eq!(endpoint.path(), Some("/v1/agent"));
        assert_eq!(endpoint.to_uri(), "https://agent.example.com:443/v1/agent");
    }

    #[test]
    fn grpc_endpoint() {
        let endpoint = Endpoint::grpc("agent.example.com:50051");
        assert_eq!(endpoint.protocol(), "grpc");
        assert_eq!(endpoint.to_uri(), "grpc://agent.example.com:50051");
    }

    #[test]
    fn websocket_endpoint() {
        let endpoint = Endpoint::websocket("agent.example.com:8080");
        assert_eq!(endpoint.protocol(), "ws");
        assert_eq!(endpoint.to_uri(), "ws://agent.example.com:8080");
    }

    #[test]
    fn custom_endpoint() {
        let endpoint = Endpoint::new("mqtt", "broker.example.com:1883", Some("/agents"));
        assert_eq!(endpoint.protocol(), "mqtt");
        assert_eq!(endpoint.address(), "broker.example.com:1883");
        assert_eq!(endpoint.path(), Some("/agents"));
        assert_eq!(endpoint.to_uri(), "mqtt://broker.example.com:1883/agents");
    }

    #[test]
    fn display_matches_to_uri() {
        let endpoint = Endpoint::https("agent.example.com:443");
        assert_eq!(format!("{endpoint}"), endpoint.to_uri());
    }

    #[test]
    fn endpoints_are_equal() {
        let endpoint1 = Endpoint::https("agent.example.com:443");
        let endpoint2 = Endpoint::https("agent.example.com:443");
        assert_eq!(endpoint1, endpoint2);
    }

    #[test]
    fn different_endpoints_are_not_equal() {
        let endpoint1 = Endpoint::https("agent1.example.com:443");
        let endpoint2 = Endpoint::https("agent2.example.com:443");
        assert_ne!(endpoint1, endpoint2);
    }
}
