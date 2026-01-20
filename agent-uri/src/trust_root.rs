//! Trust root type for agent authorities.
//!
//! # Grammar Reference
//!
//! The trust root grammar is defined in `grammar.abnf`:
//!
//! ```abnf
//! trust-root = host [ ":" port ]
//! host       = domain / ip-literal / ipv4-address
//! domain     = label *( "." label )
//! label      = 1*63( ALPHA / DIGIT / "-" )
//! ```
//!
//! Maximum trust root length: 128 characters (including port).

use std::cmp::Ordering;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::constants::{MAX_DNS_DOMAIN_LENGTH, MAX_DNS_LABEL_LENGTH, MAX_TRUST_ROOT_LENGTH};
use crate::error::TrustRootError;

/// The host portion of a trust root.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// A domain name (e.g., "anthropic.com")
    Domain(String),
    /// An IPv4 address (e.g., "192.168.1.1")
    Ipv4(Ipv4Addr),
    /// An IPv6 address (e.g., `::1`)
    Ipv6(Ipv6Addr),
}

/// A validated trust root (authority) from an agent URI.
///
/// The trust root identifies the authority that vouches for an agent's
/// identity and capabilities. It consists of a host (domain or IP) and
/// an optional port.
///
/// # Examples
///
/// ```
/// use agent_uri::TrustRoot;
///
/// let root = TrustRoot::parse("anthropic.com").unwrap();
/// assert_eq!(root.host_str(), "anthropic.com");
/// assert!(root.port().is_none());
///
/// let root = TrustRoot::parse("localhost:8472").unwrap();
/// assert_eq!(root.host_str(), "localhost");
/// assert_eq!(root.port(), Some(8472));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustRoot {
    host: Host,
    port: Option<u16>,
    /// Original string representation (normalized to lowercase)
    normalized: String,
}

impl TrustRoot {
    /// Parses a trust root from a string.
    ///
    /// # Errors
    ///
    /// Returns `TrustRootError` if:
    /// - The input is empty
    /// - The input exceeds 128 characters
    /// - The domain contains invalid characters or labels
    /// - The IP address is malformed
    /// - The port is invalid (not numeric or out of range)
    pub fn parse(input: &str) -> Result<Self, TrustRootError> {
        if input.is_empty() {
            return Err(TrustRootError::Empty);
        }

        if input.len() > MAX_TRUST_ROOT_LENGTH {
            return Err(TrustRootError::TooLong {
                max: MAX_TRUST_ROOT_LENGTH,
                actual: input.len(),
            });
        }

        // Handle IPv6 literals: [::1]:port
        if input.starts_with('[') {
            return Self::parse_ipv6_literal(input);
        }

        // Split host and port
        let (host_str, port) = Self::split_host_port(input)?;
        let host = Self::parse_host(host_str)?;
        let normalized = Self::normalize(&host, port);

        Ok(Self {
            host,
            port,
            normalized,
        })
    }

    /// Returns the host portion.
    #[must_use]
    pub const fn host(&self) -> &Host {
        &self.host
    }

    /// Returns the host as a string.
    #[must_use]
    pub fn host_str(&self) -> &str {
        match &self.host {
            Host::Domain(d) => d,
            Host::Ipv4(_) => {
                // Use the normalized form, split by colon
                self.normalized.split(':').next().unwrap_or(&self.normalized)
            }
            Host::Ipv6(_) => {
                // Extract from [addr] format
                let start = self.normalized.find('[').map_or(0, |i| i + 1);
                let end = self.normalized.find(']').unwrap_or(self.normalized.len());
                &self.normalized[start..end]
            }
        }
    }

    /// Returns the port, if specified.
    #[must_use]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    /// Returns true if this is a localhost address.
    #[must_use]
    pub fn is_localhost(&self) -> bool {
        match &self.host {
            Host::Domain(d) => d == "localhost",
            Host::Ipv4(ip) => ip.is_loopback(),
            Host::Ipv6(ip) => ip.is_loopback(),
        }
    }

    /// Returns the normalized string representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    /// Returns a new trust root with the given port.
    ///
    /// # Errors
    ///
    /// Returns `TrustRootError` if the resulting trust root would exceed
    /// the maximum length.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::TrustRoot;
    ///
    /// let root = TrustRoot::parse("localhost").unwrap();
    /// let with_port = root.with_port(8472).unwrap();
    /// assert_eq!(with_port.port(), Some(8472));
    /// ```
    pub fn with_port(&self, port: u16) -> Result<Self, TrustRootError> {
        let normalized = Self::normalize(&self.host, Some(port));
        if normalized.len() > MAX_TRUST_ROOT_LENGTH {
            return Err(TrustRootError::TooLong {
                max: MAX_TRUST_ROOT_LENGTH,
                actual: normalized.len(),
            });
        }
        Ok(Self {
            host: self.host.clone(),
            port: Some(port),
            normalized,
        })
    }

    /// Returns a new trust root without a port.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::TrustRoot;
    ///
    /// let root = TrustRoot::parse("localhost:8472").unwrap();
    /// let without_port = root.without_port();
    /// assert!(without_port.port().is_none());
    /// ```
    #[must_use]
    pub fn without_port(&self) -> Self {
        let normalized = Self::normalize(&self.host, None);
        Self {
            host: self.host.clone(),
            port: None,
            normalized,
        }
    }

    fn split_host_port(input: &str) -> Result<(&str, Option<u16>), TrustRootError> {
        if let Some(colon_idx) = input.rfind(':') {
            let host_part = &input[..colon_idx];
            let port_part = &input[colon_idx + 1..];

            // Check if this looks like a port (all digits)
            if !port_part.is_empty() && port_part.chars().all(|c| c.is_ascii_digit()) {
                let port: u16 = port_part.parse().map_err(|_| TrustRootError::InvalidPort {
                    value: port_part.to_string(),
                    reason: "port must be 0-65535",
                })?;
                return Ok((host_part, Some(port)));
            }
        }
        Ok((input, None))
    }

    fn parse_host(host_str: &str) -> Result<Host, TrustRootError> {
        // Try IPv4 first
        if let Ok(ip) = host_str.parse::<Ipv4Addr>() {
            return Ok(Host::Ipv4(ip));
        }

        // Must be a domain name
        Self::validate_domain(host_str)?;
        Ok(Host::Domain(host_str.to_lowercase()))
    }

    fn parse_ipv6_literal(input: &str) -> Result<Self, TrustRootError> {
        let closing_bracket = input.find(']').ok_or_else(|| TrustRootError::InvalidIpAddress {
            value: input.to_string(),
            reason: "missing closing bracket for IPv6 literal",
        })?;

        let ipv6_str = &input[1..closing_bracket];
        let ipv6: Ipv6Addr = ipv6_str.parse().map_err(|_| TrustRootError::InvalidIpAddress {
            value: ipv6_str.to_string(),
            reason: "invalid IPv6 address",
        })?;

        let port = if input.len() > closing_bracket + 1 {
            if input.as_bytes().get(closing_bracket + 1) != Some(&b':') {
                return Err(TrustRootError::InvalidPort {
                    value: input[closing_bracket + 1..].to_string(),
                    reason: "expected ':' after IPv6 closing bracket",
                });
            }
            let port_str = &input[closing_bracket + 2..];
            Some(port_str.parse::<u16>().map_err(|_| TrustRootError::InvalidPort {
                value: port_str.to_string(),
                reason: "port must be 0-65535",
            })?)
        } else {
            None
        };

        let normalized = Self::normalize(&Host::Ipv6(ipv6), port);
        Ok(Self {
            host: Host::Ipv6(ipv6),
            port,
            normalized,
        })
    }

    fn validate_domain(domain: &str) -> Result<(), TrustRootError> {
        if domain.len() > MAX_DNS_DOMAIN_LENGTH {
            return Err(TrustRootError::InvalidDomain {
                domain: domain.to_string(),
                reason: "domain exceeds 253 character limit",
            });
        }

        for label in domain.split('.') {
            if label.is_empty() {
                return Err(TrustRootError::InvalidDomain {
                    domain: domain.to_string(),
                    reason: "empty label (consecutive dots or leading/trailing dot)",
                });
            }

            if label.len() > MAX_DNS_LABEL_LENGTH {
                return Err(TrustRootError::LabelTooLong {
                    label: label.to_string(),
                    max: MAX_DNS_LABEL_LENGTH,
                    actual: label.len(),
                });
            }

            // Check characters (alphanumeric and hyphens)
            for (j, c) in label.chars().enumerate() {
                if !c.is_ascii_alphanumeric() && c != '-' {
                    return Err(TrustRootError::InvalidChar {
                        char: c,
                        position: domain.find(label).unwrap_or(0) + j,
                    });
                }
            }

            // Labels cannot start or end with hyphen
            if label.starts_with('-') || label.ends_with('-') {
                return Err(TrustRootError::InvalidDomain {
                    domain: domain.to_string(),
                    reason: "label cannot start or end with hyphen",
                });
            }
        }

        Ok(())
    }

    fn normalize(host: &Host, port: Option<u16>) -> String {
        let host_str = match host {
            Host::Domain(d) => d.clone(),
            Host::Ipv4(ip) => ip.to_string(),
            Host::Ipv6(ip) => format!("[{ip}]"),
        };

        match port {
            Some(p) => format!("{host_str}:{p}"),
            None => host_str,
        }
    }
}

impl fmt::Display for TrustRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.normalized)
    }
}

impl FromStr for TrustRoot {
    type Err = TrustRootError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<str> for TrustRoot {
    fn as_ref(&self) -> &str {
        &self.normalized
    }
}

impl TryFrom<&str> for TrustRoot {
    type Error = TrustRootError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl PartialOrd for TrustRoot {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TrustRoot {
    fn cmp(&self, other: &Self) -> Ordering {
        self.normalized.cmp(&other.normalized)
    }
}

impl PartialOrd for Host {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Host {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Domain(a), Self::Domain(b)) => a.cmp(b),
            (Self::Ipv4(a), Self::Ipv4(b)) => a.cmp(b),
            (Self::Ipv6(a), Self::Ipv6(b)) => a.cmp(b),
            (Self::Domain(_), _) | (Self::Ipv4(_), Self::Ipv6(_)) => Ordering::Less,
            (_, Self::Domain(_)) | (Self::Ipv6(_), Self::Ipv4(_)) => Ordering::Greater,
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for TrustRoot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.normalized)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for TrustRoot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Host {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Domain(d) => serializer.serialize_str(d),
            Self::Ipv4(ip) => serializer.serialize_str(&ip.to_string()),
            Self::Ipv6(ip) => serializer.serialize_str(&format!("[{ip}]")),
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Host {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let trust_root = TrustRoot::parse(&s).map_err(serde::de::Error::custom)?;
        Ok(trust_root.host.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_domain() {
        let root = TrustRoot::parse("anthropic.com").unwrap();
        assert_eq!(root.host_str(), "anthropic.com");
        assert!(root.port().is_none());
    }

    #[test]
    fn parse_domain_with_port() {
        let root = TrustRoot::parse("localhost:8472").unwrap();
        assert_eq!(root.host_str(), "localhost");
        assert_eq!(root.port(), Some(8472));
    }

    #[test]
    fn parse_ipv4() {
        let root = TrustRoot::parse("192.168.1.1").unwrap();
        assert!(matches!(root.host(), Host::Ipv4(_)));
    }

    #[test]
    fn parse_ipv4_with_port() {
        let root = TrustRoot::parse("192.168.1.1:8080").unwrap();
        assert!(matches!(root.host(), Host::Ipv4(_)));
        assert_eq!(root.port(), Some(8080));
    }

    #[test]
    fn parse_ipv6_literal() {
        let root = TrustRoot::parse("[::1]:8472").unwrap();
        assert!(matches!(root.host(), Host::Ipv6(_)));
        assert_eq!(root.port(), Some(8472));
    }

    #[test]
    fn parse_ipv6_without_port() {
        let root = TrustRoot::parse("[::1]").unwrap();
        assert!(matches!(root.host(), Host::Ipv6(_)));
        assert!(root.port().is_none());
    }

    #[test]
    fn normalizes_to_lowercase() {
        let root = TrustRoot::parse("ANTHROPIC.COM").unwrap();
        assert_eq!(root.as_str(), "anthropic.com");
    }

    #[test]
    fn is_localhost_domain() {
        let root = TrustRoot::parse("localhost").unwrap();
        assert!(root.is_localhost());
    }

    #[test]
    fn is_localhost_ipv4() {
        let root = TrustRoot::parse("127.0.0.1").unwrap();
        assert!(root.is_localhost());
    }

    #[test]
    fn is_localhost_ipv6() {
        let root = TrustRoot::parse("[::1]").unwrap();
        assert!(root.is_localhost());
    }

    #[test]
    fn is_not_localhost() {
        let root = TrustRoot::parse("anthropic.com").unwrap();
        assert!(!root.is_localhost());
    }

    #[test]
    fn parse_empty_fails() {
        let result = TrustRoot::parse("");
        assert!(matches!(result, Err(TrustRootError::Empty)));
    }

    #[test]
    fn parse_too_long_fails() {
        let long = "a".repeat(129);
        let result = TrustRoot::parse(&long);
        assert!(matches!(result, Err(TrustRootError::TooLong { .. })));
    }

    #[test]
    fn parse_invalid_domain_fails() {
        let result = TrustRoot::parse("invalid..domain");
        assert!(matches!(result, Err(TrustRootError::InvalidDomain { .. })));
    }

    #[test]
    fn parse_label_with_hyphen_start_fails() {
        let result = TrustRoot::parse("-invalid.com");
        assert!(matches!(result, Err(TrustRootError::InvalidDomain { .. })));
    }
}
