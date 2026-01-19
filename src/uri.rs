//! Main agent URI type.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use crate::agent_id::AgentId;
use crate::capability_path::CapabilityPath;
use crate::constants::{MAX_URI_LENGTH, SCHEME};
use crate::error::{ParseError, ParseErrorKind};
use crate::fragment::Fragment;
use crate::query::QueryParams;
use crate::trust_root::TrustRoot;

/// A parsed and validated agent URI.
///
/// Agent URIs provide topology-independent identity for agents with
/// capability-based discovery.
///
/// # Structure
///
/// ```text
/// agent://<trust-root>/<capability-path>/<agent-id>[?query][#fragment]
/// ```
///
/// # Examples
///
/// ```
/// use agent_uri::AgentUri;
///
/// let uri = AgentUri::parse("agent://anthropic.com/assistant/chat/llm_chat_01h455vb4pex5vsknk084sn02q").unwrap();
/// assert_eq!(uri.trust_root().host_str(), "anthropic.com");
/// assert_eq!(uri.capability_path().as_str(), "assistant/chat");
/// assert_eq!(uri.agent_id().prefix().as_str(), "llm_chat");
///
/// // With query and fragment
/// let uri = AgentUri::parse("agent://openai.com/tool/code/llm_01h455vb4pex5vsknk084sn02q?version=2.0#summarization").unwrap();
/// assert_eq!(uri.query().version(), Some("2.0"));
/// assert_eq!(uri.fragment().map(|f| f.as_str()), Some("summarization"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentUri {
    trust_root: TrustRoot,
    capability_path: CapabilityPath,
    agent_id: AgentId,
    query: QueryParams,
    fragment: Option<Fragment>,
    /// Normalized string representation
    normalized: String,
}

impl AgentUri {
    /// Parses an agent URI from a string.
    ///
    /// # Errors
    ///
    /// Returns `ParseError` if:
    /// - The URI is empty
    /// - The URI exceeds 512 characters
    /// - The scheme is not "agent://"
    /// - Any component (trust root, path, agent ID, query, fragment) is invalid
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        Self::parse_inner(input).map_err(|kind| ParseError {
            input: input.to_string(),
            kind,
        })
    }

    /// Creates a new agent URI from its components.
    ///
    /// # Errors
    ///
    /// Returns `ParseError` if the resulting URI would exceed the maximum length.
    pub fn new(
        trust_root: TrustRoot,
        capability_path: CapabilityPath,
        agent_id: AgentId,
        query: QueryParams,
        fragment: Option<Fragment>,
    ) -> Result<Self, ParseError> {
        let normalized = Self::normalize(&trust_root, &capability_path, &agent_id, &query, fragment.as_ref());
        let len = normalized.len();

        if len > MAX_URI_LENGTH {
            return Err(ParseError {
                input: normalized,
                kind: ParseErrorKind::TooLong {
                    max: MAX_URI_LENGTH,
                    actual: len,
                },
            });
        }

        Ok(Self {
            trust_root,
            capability_path,
            agent_id,
            query,
            fragment,
            normalized,
        })
    }

    /// Returns the trust root.
    #[must_use]
    pub const fn trust_root(&self) -> &TrustRoot {
        &self.trust_root
    }

    /// Returns the capability path.
    #[must_use]
    pub const fn capability_path(&self) -> &CapabilityPath {
        &self.capability_path
    }

    /// Returns the agent ID.
    #[must_use]
    pub const fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    /// Returns the query parameters.
    #[must_use]
    pub const fn query(&self) -> &QueryParams {
        &self.query
    }

    /// Returns the fragment, if present.
    #[must_use]
    pub const fn fragment(&self) -> Option<&Fragment> {
        self.fragment.as_ref()
    }

    /// Returns the normalized URI string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.normalized
    }

    /// Returns the canonical URI (without query and fragment).
    #[must_use]
    pub fn canonical(&self) -> String {
        format!(
            "{SCHEME}://{}/{}/{}",
            self.trust_root, self.capability_path, self.agent_id
        )
    }

    /// Returns true if this URI references a localhost agent.
    #[must_use]
    pub fn is_localhost(&self) -> bool {
        self.trust_root.is_localhost()
    }

    /// Returns a new URI with the given query parameters.
    ///
    /// # Errors
    ///
    /// Returns `ParseError` if the resulting URI would exceed the maximum length.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::{AgentUri, QueryParams};
    ///
    /// let uri = AgentUri::parse("agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q").unwrap();
    /// let query = QueryParams::parse("version=2.0").unwrap();
    /// let updated = uri.with_query(query).unwrap();
    /// assert_eq!(updated.query().version(), Some("2.0"));
    /// ```
    pub fn with_query(&self, query: QueryParams) -> Result<Self, ParseError> {
        Self::new(
            self.trust_root.clone(),
            self.capability_path.clone(),
            self.agent_id.clone(),
            query,
            self.fragment.clone(),
        )
    }

    /// Returns a new URI with query parameters parsed from a string.
    ///
    /// # Errors
    ///
    /// Returns `ParseError` if the query string is invalid or the resulting URI
    /// would exceed the maximum length.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentUri;
    ///
    /// let uri = AgentUri::parse("agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q").unwrap();
    /// let updated = uri.with_query_str("version=2.0&ttl=300").unwrap();
    /// assert_eq!(updated.query().version(), Some("2.0"));
    /// assert_eq!(updated.query().ttl(), Some(300));
    /// ```
    pub fn with_query_str(&self, s: &str) -> Result<Self, ParseError> {
        let query = QueryParams::parse(s).map_err(|e| ParseError {
            input: s.to_string(),
            kind: ParseErrorKind::InvalidQuery(e),
        })?;
        self.with_query(query)
    }

    /// Returns a new URI without query parameters.
    ///
    /// # Errors
    ///
    /// Returns `ParseError` if the resulting URI would exceed the maximum length.
    /// (This is unlikely but possible in edge cases.)
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentUri;
    ///
    /// let uri = AgentUri::parse("agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q?version=2.0").unwrap();
    /// let updated = uri.without_query().unwrap();
    /// assert!(updated.query().is_empty());
    /// ```
    pub fn without_query(&self) -> Result<Self, ParseError> {
        self.with_query(QueryParams::new())
    }

    /// Returns a new URI with the given fragment.
    ///
    /// # Errors
    ///
    /// Returns `ParseError` if the resulting URI would exceed the maximum length.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::{AgentUri, Fragment};
    ///
    /// let uri = AgentUri::parse("agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q").unwrap();
    /// let fragment = Fragment::parse("summarization").unwrap();
    /// let updated = uri.with_fragment(fragment).unwrap();
    /// assert_eq!(updated.fragment().map(|f| f.as_str()), Some("summarization"));
    /// ```
    pub fn with_fragment(&self, fragment: Fragment) -> Result<Self, ParseError> {
        Self::new(
            self.trust_root.clone(),
            self.capability_path.clone(),
            self.agent_id.clone(),
            self.query.clone(),
            Some(fragment),
        )
    }

    /// Returns a new URI with a fragment parsed from a string.
    ///
    /// # Errors
    ///
    /// Returns `ParseError` if the fragment is invalid or the resulting URI
    /// would exceed the maximum length.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentUri;
    ///
    /// let uri = AgentUri::parse("agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q").unwrap();
    /// let updated = uri.with_fragment_str("summarization").unwrap();
    /// assert_eq!(updated.fragment().map(|f| f.as_str()), Some("summarization"));
    /// ```
    pub fn with_fragment_str(&self, s: &str) -> Result<Self, ParseError> {
        let fragment = Fragment::parse(s).map_err(|e| ParseError {
            input: s.to_string(),
            kind: ParseErrorKind::InvalidFragment(e),
        })?;
        self.with_fragment(fragment)
    }

    /// Returns a new URI without a fragment.
    ///
    /// # Errors
    ///
    /// Returns `ParseError` if the resulting URI would exceed the maximum length.
    /// (This is unlikely but possible in edge cases.)
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentUri;
    ///
    /// let uri = AgentUri::parse("agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q#test").unwrap();
    /// let updated = uri.without_fragment().unwrap();
    /// assert!(updated.fragment().is_none());
    /// ```
    pub fn without_fragment(&self) -> Result<Self, ParseError> {
        Self::new(
            self.trust_root.clone(),
            self.capability_path.clone(),
            self.agent_id.clone(),
            self.query.clone(),
            None,
        )
    }

    fn parse_inner(input: &str) -> Result<Self, ParseErrorKind> {
        if input.is_empty() {
            return Err(ParseErrorKind::Empty);
        }

        if input.len() > MAX_URI_LENGTH {
            return Err(ParseErrorKind::TooLong {
                max: MAX_URI_LENGTH,
                actual: input.len(),
            });
        }

        // Check and strip scheme
        let scheme_prefix = format!("{SCHEME}://");
        if !input.starts_with(&scheme_prefix) {
            let found = input.split("://").next().map(str::to_string);
            return Err(ParseErrorKind::InvalidScheme { found });
        }
        let rest = &input[scheme_prefix.len()..];

        // Split off fragment
        let (rest, fragment) = Self::split_fragment(rest)?;

        // Split off query
        let (rest, query) = Self::split_query(rest)?;

        // Split trust root from path
        let (trust_root_str, path_with_id) = Self::split_trust_root(rest)?;

        // Parse trust root
        let trust_root =
            TrustRoot::parse(trust_root_str).map_err(ParseErrorKind::InvalidTrustRoot)?;

        // Split capability path from agent ID (agent ID is always the last segment)
        let (cap_path_str, agent_id_str) = Self::split_path_and_id(path_with_id)?;

        // Parse capability path
        let capability_path =
            CapabilityPath::parse(cap_path_str).map_err(ParseErrorKind::InvalidCapabilityPath)?;

        // Parse agent ID
        let agent_id = AgentId::parse(agent_id_str).map_err(ParseErrorKind::InvalidAgentId)?;

        let normalized =
            Self::normalize(&trust_root, &capability_path, &agent_id, &query, fragment.as_ref());

        Ok(Self {
            trust_root,
            capability_path,
            agent_id,
            query,
            fragment,
            normalized,
        })
    }

    fn split_fragment(input: &str) -> Result<(&str, Option<Fragment>), ParseErrorKind> {
        if let Some(hash_idx) = input.find('#') {
            let rest = &input[..hash_idx];
            let frag_str = &input[hash_idx + 1..];
            if frag_str.is_empty() {
                Ok((rest, None)) // Empty fragment is stripped
            } else {
                let fragment =
                    Fragment::parse(frag_str).map_err(ParseErrorKind::InvalidFragment)?;
                Ok((rest, Some(fragment)))
            }
        } else {
            Ok((input, None))
        }
    }

    fn split_query(input: &str) -> Result<(&str, QueryParams), ParseErrorKind> {
        if let Some(q_idx) = input.find('?') {
            let rest = &input[..q_idx];
            let query_str = &input[q_idx + 1..];
            if query_str.is_empty() {
                Ok((rest, QueryParams::new())) // Empty query is stripped
            } else {
                let query = QueryParams::parse(query_str).map_err(ParseErrorKind::InvalidQuery)?;
                Ok((rest, query))
            }
        } else {
            Ok((input, QueryParams::new()))
        }
    }

    fn split_trust_root(input: &str) -> Result<(&str, &str), ParseErrorKind> {
        // Find the first '/' which separates trust root from path
        let slash_idx = input.find('/').ok_or(ParseErrorKind::MissingComponent {
            component: "capability path",
        })?;

        let trust_root = &input[..slash_idx];
        let path = &input[slash_idx + 1..];

        if trust_root.is_empty() {
            return Err(ParseErrorKind::MissingComponent {
                component: "trust root",
            });
        }

        if path.is_empty() {
            return Err(ParseErrorKind::MissingComponent {
                component: "capability path",
            });
        }

        Ok((trust_root, path))
    }

    fn split_path_and_id(input: &str) -> Result<(&str, &str), ParseErrorKind> {
        // The agent ID is the last segment
        let last_slash_idx = input.rfind('/').ok_or(ParseErrorKind::MissingComponent {
            component: "agent ID",
        })?;

        let path = &input[..last_slash_idx];
        let agent_id = &input[last_slash_idx + 1..];

        if path.is_empty() {
            return Err(ParseErrorKind::MissingComponent {
                component: "capability path",
            });
        }

        if agent_id.is_empty() {
            return Err(ParseErrorKind::MissingComponent {
                component: "agent ID",
            });
        }

        Ok((path, agent_id))
    }

    fn normalize(
        trust_root: &TrustRoot,
        capability_path: &CapabilityPath,
        agent_id: &AgentId,
        query: &QueryParams,
        fragment: Option<&Fragment>,
    ) -> String {
        let mut result = format!("{SCHEME}://{trust_root}/{capability_path}/{agent_id}");

        if !query.is_empty() {
            result.push('?');
            result.push_str(&query.to_string());
        }

        if let Some(frag) = fragment {
            result.push('#');
            result.push_str(frag.as_str());
        }

        result
    }
}

impl fmt::Display for AgentUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.normalized)
    }
}

impl FromStr for AgentUri {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<str> for AgentUri {
    fn as_ref(&self) -> &str {
        &self.normalized
    }
}

impl TryFrom<&str> for AgentUri {
    type Error = ParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl PartialOrd for AgentUri {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AgentUri {
    fn cmp(&self, other: &Self) -> Ordering {
        self.normalized.cmp(&other.normalized)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for AgentUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.normalized)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AgentUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_uri() {
        let input = "agent://anthropic.com/assistant/chat/llm_chat_01h455vb4pex5vsknk084sn02q";
        let uri = AgentUri::parse(input).unwrap();

        assert_eq!(uri.trust_root().host_str(), "anthropic.com");
        assert_eq!(uri.capability_path().as_str(), "assistant/chat");
        assert_eq!(uri.agent_id().prefix().as_str(), "llm_chat");
    }

    #[test]
    fn parse_empty_returns_error() {
        let result = AgentUri::parse("");
        assert!(matches!(
            result,
            Err(ParseError {
                kind: ParseErrorKind::Empty,
                ..
            })
        ));
    }

    #[test]
    fn parse_too_long_returns_error() {
        let long_path = "a".repeat(500);
        let input = format!("agent://x.com/{long_path}/llm_01h455vb4pex5vsknk084sn02q");
        let result = AgentUri::parse(&input);
        assert!(matches!(
            result,
            Err(ParseError {
                kind: ParseErrorKind::TooLong { .. },
                ..
            })
        ));
    }

    #[test]
    fn parse_wrong_scheme_returns_error() {
        let result =
            AgentUri::parse("http://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q");
        assert!(matches!(
            result,
            Err(ParseError {
                kind: ParseErrorKind::InvalidScheme { .. },
                ..
            })
        ));
    }

    #[test]
    fn parse_with_query_params() {
        let input =
            "agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q?version=2.0&ttl=300";
        let uri = AgentUri::parse(input).unwrap();

        assert_eq!(uri.query().version(), Some("2.0"));
        assert_eq!(uri.query().ttl(), Some(300));
    }

    #[test]
    fn parse_with_fragment() {
        let input = "agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q#summarization";
        let uri = AgentUri::parse(input).unwrap();

        assert_eq!(uri.fragment().map(|f| f.as_str()), Some("summarization"));
    }

    #[test]
    fn empty_query_is_stripped() {
        let input = "agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q?";
        let uri = AgentUri::parse(input).unwrap();
        assert!(uri.query().is_empty());
    }

    #[test]
    fn empty_fragment_is_stripped() {
        let input = "agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q#";
        let uri = AgentUri::parse(input).unwrap();
        assert!(uri.fragment().is_none());
    }

    #[test]
    fn canonical_strips_query_and_fragment() {
        let input =
            "agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q?version=2.0#test";
        let uri = AgentUri::parse(input).unwrap();
        let canonical = uri.canonical();

        assert!(!canonical.contains('?'));
        assert!(!canonical.contains('#'));
    }

    #[test]
    fn is_localhost() {
        let uri = AgentUri::parse(
            "agent://localhost:8472/test/llm_01h455vb4pex5vsknk084sn02q",
        )
        .unwrap();
        assert!(uri.is_localhost());

        let uri =
            AgentUri::parse("agent://127.0.0.1/test/llm_01h455vb4pex5vsknk084sn02q").unwrap();
        assert!(uri.is_localhost());

        let uri =
            AgentUri::parse("agent://anthropic.com/test/llm_01h455vb4pex5vsknk084sn02q").unwrap();
        assert!(!uri.is_localhost());
    }

    #[test]
    fn parse_missing_capability_path() {
        let result = AgentUri::parse("agent://anthropic.com/llm_01h455vb4pex5vsknk084sn02q");
        assert!(matches!(
            result,
            Err(ParseError {
                kind: ParseErrorKind::MissingComponent { component: "agent ID" },
                ..
            })
        ));
    }

    #[test]
    fn display_roundtrip() {
        let input = "agent://anthropic.com/assistant/chat/llm_chat_01h455vb4pex5vsknk084sn02q";
        let uri = AgentUri::parse(input).unwrap();
        assert_eq!(uri.to_string(), input);
    }

    #[test]
    fn new_from_components() {
        let trust_root = TrustRoot::parse("anthropic.com").unwrap();
        let cap_path = CapabilityPath::parse("assistant/chat").unwrap();
        let agent_id = AgentId::parse("llm_01h455vb4pex5vsknk084sn02q").unwrap();

        let uri = AgentUri::new(
            trust_root,
            cap_path,
            agent_id,
            QueryParams::new(),
            None,
        )
        .unwrap();

        assert_eq!(uri.trust_root().host_str(), "anthropic.com");
        assert_eq!(uri.capability_path().as_str(), "assistant/chat");
    }
}
