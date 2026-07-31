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
//! `ipv4-address` takes precedence over `domain` for hosts shaped as exactly four
//! dotted numeric labels.
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
///
/// # Internationalized names
///
/// **A trust root is ASCII. Converting an internationalized name to A-label
/// form is the caller's job, and this type will not tell you whether you did
/// it right.** Three consequences, none of them accidents:
///
/// 1. **A non-ASCII name is rejected, not converted.** `münchen.de` is an
///    error, not a synonym for `xn--mnchen-3ya.de`. Doing the conversion here
///    would mean shipping a Unicode normalization table and a version of
///    [UTS #46] inside an identity type, and two versions of that table
///    disagreeing would make one name two identities. Refusing is the smaller
///    surface.
/// 2. **An `xn--` label is opaque ASCII.** It is checked as a DNS label and
///    nothing more: no Punycode decode, no [IDNA] validity check, no
///    bidirectional or script rules. `xn--zzzzzz` is not valid Punycode and
///    parses anyway. If a name reaches here already broken, it stays broken.
/// 3. **Nothing here detects confusables.** `аpple.com` with a Cyrillic `а` is
///    rejected only because it is not ASCII; its A-label form,
///    `xn--pple-43d.com`, is accepted and is a different trust root than
///    `apple.com`. Two names that a person cannot tell apart are two
///    identities, and only the second ever reaches this type. Homograph
///    defence belongs where names are shown to people and where keys are
///    fetched, not in a parser that sees ASCII.
///
/// A trailing dot is rejected rather than stripped, so the DNS root-anchored
/// `example.com.` is not a spelling of `example.com`; only the latter names
/// that identity. ASCII case is folded, per RFC 4343.
///
/// ```
/// use agent_uri::TrustRoot;
///
/// // Convert before you get here.
/// assert!(TrustRoot::parse("münchen.de").is_err());
/// assert!(TrustRoot::parse("xn--mnchen-3ya.de").is_ok());
///
/// // Which means a name that was converted wrongly is accepted as written.
/// assert!(TrustRoot::parse("xn--zzzzzz").is_ok());
///
/// // And a trailing dot is a different string, so it is not a trust root.
/// assert!(TrustRoot::parse("example.com.").is_err());
/// ```
///
/// See [Section 8.11 of the specification][spec] for the threat this leaves
/// to the caller.
///
/// [UTS #46]: https://www.unicode.org/reports/tr46/
/// [IDNA]: https://datatracker.ietf.org/doc/html/rfc5891
/// [spec]: https://github.com/Govcraft/agent-uri-rs/blob/main/SPECIFICATION.md#811-internationalized-trust-root-names
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
    /// - A host of exactly four dotted numeric labels has an IPv4 octet outside
    ///   0-255 or an octet with a leading zero; this shape is parsed as IPv4 and
    ///   is never treated as a domain
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
                self.normalized
                    .split(':')
                    .next()
                    .unwrap_or(&self.normalized)
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
        if let Ok(ip) = host_str.parse::<Ipv4Addr>() {
            return Ok(Host::Ipv4(ip));
        }

        // Four dotted numeric labels are an ipv4-address by grammar shape;
        // they must not fall through to domain validation (issue #24).
        if Self::is_ipv4_shaped(host_str) {
            return Err(TrustRootError::InvalidIpAddress {
                value: host_str.to_string(),
                reason: Self::ipv4_rejection_reason(host_str),
            });
        }

        Self::validate_domain(host_str)?;
        Ok(Host::Domain(host_str.to_lowercase()))
    }

    /// Returns `true` if the host is syntactically four dot-separated,
    /// non-empty, all-ASCII-digit labels — the shape of `ipv4-address`
    /// in the grammar, regardless of whether the octet values are valid.
    fn is_ipv4_shaped(host: &str) -> bool {
        let mut labels = 0usize;
        for label in host.split('.') {
            labels += 1;
            if labels > 4 || label.is_empty() || !label.bytes().all(|b| b.is_ascii_digit()) {
                return false;
            }
        }
        labels == 4
    }

    /// Explains why an IPv4-shaped host is not a valid dotted-decimal address.
    ///
    /// Callers must only invoke this for hosts that satisfy `is_ipv4_shaped`
    /// and that `Ipv4Addr` rejected; for such hosts the only failure modes are
    /// an out-of-range octet and a leading zero.
    fn ipv4_rejection_reason(host: &str) -> &'static str {
        for label in host.split('.') {
            match label.parse::<u64>() {
                Ok(value) if value <= 255 => {}
                _ => return "IPv4 octets must be 0-255",
            }
        }
        "IPv4 octets must not have leading zeros"
    }

    fn parse_ipv6_literal(input: &str) -> Result<Self, TrustRootError> {
        let closing_bracket = input
            .find(']')
            .ok_or_else(|| TrustRootError::InvalidIpAddress {
                value: input.to_string(),
                reason: "missing closing bracket for IPv6 literal",
            })?;

        let ipv6_str = &input[1..closing_bracket];
        let ipv6: Ipv6Addr = ipv6_str
            .parse()
            .map_err(|_| TrustRootError::InvalidIpAddress {
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
            Some(
                port_str
                    .parse::<u16>()
                    .map_err(|_| TrustRootError::InvalidPort {
                        value: port_str.to_string(),
                        reason: "port must be 0-65535",
                    })?,
            )
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

    #[test]
    fn ipv4_shaped_host_with_out_of_range_octet_is_rejected() {
        let result = TrustRoot::parse("256.1.1.1");

        assert!(matches!(
            result,
            Err(TrustRootError::InvalidIpAddress {
                reason: "IPv4 octets must be 0-255",
                ..
            })
        ));
    }

    #[test]
    fn ipv4_shaped_host_with_port_and_out_of_range_octet_is_rejected() {
        let result = TrustRoot::parse("256.1.1.1:8080");

        assert!(matches!(
            result,
            Err(TrustRootError::InvalidIpAddress {
                reason: "IPv4 octets must be 0-255",
                ..
            })
        ));
    }

    #[test]
    fn ipv4_shaped_host_with_leading_zero_is_rejected() {
        let result = TrustRoot::parse("192.168.001.1");

        assert!(matches!(
            result,
            Err(TrustRootError::InvalidIpAddress { .. })
        ));
    }

    #[test]
    fn ipv4_shaped_host_with_large_octet_is_rejected() {
        let result = TrustRoot::parse("1.2.3.99999");

        assert!(matches!(
            result,
            Err(TrustRootError::InvalidIpAddress { .. })
        ));
    }

    #[test]
    fn ipv4_shaped_host_with_all_octets_out_of_range_is_rejected() {
        let result = TrustRoot::parse("999.999.999.999");

        assert!(matches!(
            result,
            Err(TrustRootError::InvalidIpAddress { .. })
        ));
    }

    #[test]
    fn valid_ipv4_hosts_parse_as_ipv4() {
        for input in ["192.168.1.1", "127.0.0.1", "0.0.0.0", "255.255.255.255"] {
            let root = TrustRoot::parse(input).unwrap();

            assert!(matches!(root.host(), Host::Ipv4(_)));
        }
    }

    #[test]
    fn valid_ipv4_host_with_port_parses_as_ipv4() {
        let root = TrustRoot::parse("192.168.1.1:8080").unwrap();

        assert!(matches!(root.host(), Host::Ipv4(_)));
        assert_eq!(root.port(), Some(8080));
    }

    #[test]
    fn hosts_without_exactly_four_numeric_labels_parse_as_domains() {
        for input in ["1.2.3", "1.2.3.4.5", "1a.2.3.4", "256.1.1.1.example.com"] {
            let root = TrustRoot::parse(input).unwrap();

            assert!(matches!(root.host(), Host::Domain(domain) if domain == input));
        }
    }

    #[test]
    fn a_non_ascii_host_is_refused_and_not_converted() {
        // Section 8.11: converting here would put a Unicode version table on
        // the identity path, where two versions disagreeing make one name two
        // trust roots.
        for input in [
            "münchen.de",
            "\u{43f}\u{440}\u{438}\u{43c}\u{435}\u{440}.com",
            "café.fr",
        ] {
            let result = TrustRoot::parse(input);
            assert!(
                matches!(result, Err(TrustRootError::InvalidChar { .. })),
                "{input} was not refused as a non-ASCII host: {result:?}"
            );
        }
    }

    #[test]
    fn an_a_label_is_an_opaque_dns_label() {
        // `xn--` gets no Punycode decode and no IDNA check. The second of
        // these does not decode to anything, and parses anyway; documenting
        // that is the point of section 8.11, so it is pinned rather than
        // wished away.
        let converted = TrustRoot::parse("xn--mnchen-3ya.de").expect("an A-label is ASCII");
        assert_eq!(converted.host_str(), "xn--mnchen-3ya.de");

        let nonsense = TrustRoot::parse("xn--zzzzzz").expect("not decoded, so not refused");
        assert_eq!(nonsense.host_str(), "xn--zzzzzz");
    }

    #[test]
    fn a_homograph_is_a_different_trust_root_and_nothing_here_says_so() {
        // `xn--pple-43d.com` is the A-label form of `apple.com` spelled with
        // a Cyrillic first letter. Both parse, and they are unrelated.
        let latin = TrustRoot::parse("apple.com").expect("valid");
        let cyrillic = TrustRoot::parse("xn--pple-43d.com").expect("valid");

        assert_ne!(latin, cyrillic);
        assert_ne!(latin.host_str(), cyrillic.host_str());
    }

    #[test]
    fn a_root_anchored_name_is_not_a_second_spelling() {
        // Rejecting rather than stripping removes an equivalence question at
        // the cost of refusing a form DNS accepts (sections 4.1 and 8.11).
        assert!(TrustRoot::parse("example.com.").is_err());
        assert!(TrustRoot::parse("example.com").is_ok());
    }
}
