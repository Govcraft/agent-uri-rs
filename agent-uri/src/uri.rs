//! Main agent URI type.
//!
//! # Grammar Reference
//!
//! The URI grammar is defined in `grammar.abnf` at the crate root:
//!
//! ```abnf
//! agent-uri = scheme "://" trust-root "/" capability-path "/" agent-id
//!             [ "?" query ] [ "#" fragment ]
//! scheme    = "agent"
//! ```
//!
//! Maximum URI length: 512 characters.

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
///
/// # Identity
///
/// **Two `AgentUri` values are equal when they name the same agent, which is a
/// weaker condition than being the same string.** Equality, ordering, and
/// hashing compare the trust root, the capability path, and the agent ID —
/// the canonical form. The query and the fragment are excluded: a query
/// carries resolution hints and a fragment names a sub-capability, and neither
/// changes which agent is being addressed. This is [Section 5.2 of the
/// specification][spec], and it is what makes `?version=2.0` a request about an
/// agent rather than a different agent.
///
/// A value that is not part of identity is still part of the string.
/// [`Display`](std::fmt::Display), [`as_str`](Self::as_str), and serde all
/// preserve the query and the fragment exactly as parsed. Only
/// [`canonical`](Self::canonical) drops them.
///
/// ```
/// use agent_uri::AgentUri;
///
/// let plain = AgentUri::parse(
///     "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q"
/// ).unwrap();
/// let hinted = AgentUri::parse(
///     "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q?ttl=300#invoice"
/// ).unwrap();
///
/// // Equal as identities...
/// assert_eq!(plain, hinted);
/// assert_eq!(plain.canonical(), hinted.canonical());
///
/// // ...and not as strings.
/// assert_ne!(plain.as_str(), hinted.as_str());
/// assert_eq!(hinted.query().ttl(), Some(300));
/// assert_eq!(hinted.fragment().map(|f| f.as_str()), Some("invoice"));
/// ```
///
/// ## What this means for collections
///
/// A `HashSet` or `HashMap` keyed by `AgentUri` deduplicates by identity, so
/// inserting a decorated URI where an undecorated one is already present keeps
/// the first and discards the second — including its query and fragment. That
/// is the intent for caches, registries, and DHT keys, where one agent must
/// have one entry. It is a defect if the query is data you meant to keep, so
/// key those by [`as_str`](Self::as_str) instead.
///
/// ```
/// use std::collections::HashSet;
/// use agent_uri::AgentUri;
///
/// let plain = AgentUri::parse(
///     "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q"
/// ).unwrap();
/// let hinted = AgentUri::parse(
///     "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q?ttl=300"
/// ).unwrap();
///
/// let mut agents = HashSet::new();
/// assert!(agents.insert(plain));
/// assert!(!agents.insert(hinted)); // same agent, so not a second entry
/// assert_eq!(agents.len(), 1);
/// ```
///
/// [spec]: https://github.com/Govcraft/agent-uri-rs/blob/main/SPECIFICATION.md#52-comparison-algorithm
#[derive(Debug, Clone)]
pub struct AgentUri {
    trust_root: TrustRoot,
    capability_path: CapabilityPath,
    agent_id: AgentId,
    query: QueryParams,
    fragment: Option<Fragment>,
    /// Normalized string representation
    normalized: String,
}

/// Identity equality: see the `Identity` section on [`AgentUri`].
///
/// The three fields compared here are the three fields [`Hash`] hashes and the
/// three fields [`Ord`] orders by. All three impls sit together so that a
/// change to one is a visible omission in the others.
impl PartialEq for AgentUri {
    fn eq(&self, other: &Self) -> bool {
        self.trust_root == other.trust_root
            && self.capability_path == other.capability_path
            && self.agent_id == other.agent_id
    }
}

impl Eq for AgentUri {}

/// Hashes exactly what [`PartialEq`] compares, as the `Hash`/`Eq` contract
/// requires: equal URIs hash equally, so a decorated URI and its plain form
/// land in the same bucket rather than in two.
impl std::hash::Hash for AgentUri {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.trust_root.hash(state);
        self.capability_path.hash(state);
        self.agent_id.hash(state);
    }
}

impl AgentUri {
    /// Parses an agent URI from a string.
    ///
    /// # Case
    ///
    /// Case is folded exactly where a standard makes a component
    /// case-insensitive: the scheme (RFC 3986 section 3.1) and the trust root's
    /// DNS name (RFC 4343). The capability path and the agent ID are identity
    /// material that the grammar fixes as lowercase, so an uppercase letter in
    /// either is rejected rather than folded.
    ///
    /// ```
    /// use agent_uri::AgentUri;
    ///
    /// let uri = AgentUri::parse("AGENT://Anthropic.COM/chat/llm_01h455vb4pex5vsknk084sn02q").unwrap();
    /// assert_eq!(
    ///     uri.as_str(),
    ///     "agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q"
    /// );
    ///
    /// assert!(AgentUri::parse("agent://anthropic.com/Chat/llm_01h455vb4pex5vsknk084sn02q").is_err());
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ParseError` if:
    /// - The URI is empty
    /// - The URI exceeds 512 characters
    /// - The scheme is not "agent" (compared case-insensitively)
    /// - Any component (trust root, path, agent ID, query, fragment) is invalid
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        Self::parse_inner(input).map_err(|kind| ParseError::new(input, kind))
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
        let normalized = Self::normalize(
            &trust_root,
            &capability_path,
            &agent_id,
            &query,
            fragment.as_ref(),
        );
        let len = normalized.len();

        if len > MAX_URI_LENGTH {
            return Err(ParseError::new(
                &normalized,
                ParseErrorKind::TooLong {
                    max: MAX_URI_LENGTH,
                    actual: len,
                },
            ));
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
        let query = QueryParams::parse(s)
            .map_err(|e| ParseError::new(s, ParseErrorKind::InvalidQuery(e)))?;
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
        let fragment = Fragment::parse(s)
            .map_err(|e| ParseError::new(s, ParseErrorKind::InvalidFragment(e)))?;
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

        // Check and strip scheme. RFC 3986 section 3.1 makes the scheme
        // case-insensitive with lowercase as the canonical form, so `AGENT://`
        // is accepted and folded. Nothing after it is: the trust root is
        // case-insensitive by DNS, and every remaining component is identity
        // material the grammar fixes as lowercase.
        let scheme_prefix = format!("{SCHEME}://");
        let scheme_matches = input
            .get(..scheme_prefix.len())
            .is_some_and(|found| found.eq_ignore_ascii_case(&scheme_prefix));
        if !scheme_matches {
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

        let normalized = Self::normalize(
            &trust_root,
            &capability_path,
            &agent_id,
            &query,
            fragment.as_ref(),
        );

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
                // Handle this case here because `Fragment::parse` rejects an empty fragment.
                Ok((rest, None))
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

/// Identity ordering: the same three fields [`PartialEq`] compares and [`Hash`]
/// hashes, in the order they appear in a URI.
///
/// This used to render both sides with [`canonical`](AgentUri::canonical) and
/// compare the strings, which allocated twice per comparison — a `BTreeMap`
/// keyed by `AgentUri` paid that on every probe. The order is the same except
/// where one component is a prefix of another, because the rendered form has a
/// `/` between components and `/` sorts after `.` and after every letter:
/// string order put `acme.com.br` before `acme.com`, and this puts `acme.com`
/// first. Ordering by the components is the order the type's own identity
/// implies; the old one was an artifact of the separator.
impl Ord for AgentUri {
    fn cmp(&self, other: &Self) -> Ordering {
        self.trust_root
            .cmp(&other.trust_root)
            .then_with(|| self.capability_path.cmp(&other.capability_path))
            .then_with(|| self.agent_id.cmp(&other.agent_id))
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
    use crate::error::{FragmentError, TrustRootError};

    /// Parses a URI the test asserts is well formed.
    fn uri(input: &str) -> AgentUri {
        AgentUri::parse(input).unwrap_or_else(|e| panic!("{input} should parse: {e}"))
    }

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
    fn scheme_case_is_folded() {
        // Vectors norm-001 and norm-002 (issue #19). RFC 3986 section 3.1.
        for input in [
            "AGENT://example.com/chat/llm_01h455vb4pex5vsknk084sn02q",
            "AgEnT://example.com/chat/llm_01h455vb4pex5vsknk084sn02q",
            "Agent://example.com/chat/llm_01h455vb4pex5vsknk084sn02q",
        ] {
            let uri = AgentUri::parse(input).unwrap();
            assert_eq!(
                uri.as_str(),
                "agent://example.com/chat/llm_01h455vb4pex5vsknk084sn02q"
            );
        }
    }

    #[test]
    fn folding_the_scheme_does_not_fold_anything_after_it() {
        // The trust root folds by DNS; the path and the agent ID do not fold at
        // all, whatever the scheme's case was (issue #19).
        let uri =
            AgentUri::parse("AGENT://Anthropic.COM/chat/llm_01h455vb4pex5vsknk084sn02q").unwrap();
        assert_eq!(
            uri.as_str(),
            "agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q"
        );

        assert!(
            AgentUri::parse("AGENT://example.com/Chat/llm_01h455vb4pex5vsknk084sn02q").is_err()
        );
        assert!(
            AgentUri::parse("AGENT://example.com/chat/LLM_01H455VB4PEX5VSKNK084SN02Q").is_err()
        );
    }

    #[test]
    fn a_scheme_shorter_than_the_prefix_is_an_invalid_scheme() {
        // `input.get(..8)` is None both for a short input and for one whose
        // eighth byte falls inside a character; neither is `agent://`.
        assert!(matches!(
            AgentUri::parse("agent:/"),
            Err(ParseError {
                kind: ParseErrorKind::InvalidScheme { .. },
                ..
            })
        ));
        assert!(matches!(
            AgentUri::parse("agent:/\u{00e9}x/y/llm_01h455vb4pex5vsknk084sn02q"),
            Err(ParseError {
                kind: ParseErrorKind::InvalidScheme { .. },
                ..
            })
        ));
    }

    #[test]
    fn parse_wrong_scheme_returns_error() {
        let result = AgentUri::parse("http://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q");
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
        let input = "agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q?version=2.0&ttl=300";
        let uri = AgentUri::parse(input).unwrap();

        assert_eq!(uri.query().version(), Some("2.0"));
        assert_eq!(uri.query().ttl(), Some(300));
    }

    #[test]
    fn parse_with_fragment() {
        let input = "agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q#summarization";
        let uri = AgentUri::parse(input).unwrap();

        assert_eq!(
            uri.fragment().map(crate::Fragment::as_str),
            Some("summarization")
        );
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
    fn with_fragment_str_rejects_empty_fragment() {
        let uri =
            AgentUri::parse("agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q").unwrap();

        let result = uri.with_fragment_str("");

        assert!(matches!(
            result,
            Err(ParseError {
                kind: ParseErrorKind::InvalidFragment(FragmentError::Empty),
                ..
            })
        ));
    }

    #[test]
    fn uri_with_fragment_round_trips_through_as_str() {
        let uri = AgentUri::parse("agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q")
            .unwrap()
            .with_fragment_str("sub/task:v2")
            .unwrap();

        assert!(uri.as_str().ends_with("#sub/task:v2"));

        let reparsed = AgentUri::parse(uri.as_str()).unwrap();
        assert_eq!(
            reparsed.fragment().map(Fragment::as_str),
            Some("sub/task:v2")
        );
        assert_eq!(reparsed.as_str(), uri.as_str());
    }

    #[test]
    fn parsed_uri_never_renders_a_bare_hash() {
        let uri =
            AgentUri::parse("agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q#").unwrap();

        assert!(uri.fragment().is_none());
        assert!(!uri.as_str().ends_with('#'));

        let reparsed = AgentUri::parse(uri.as_str()).unwrap();
        assert_eq!(reparsed.as_str(), uri.as_str());
    }

    #[test]
    fn canonical_strips_query_and_fragment() {
        let input = "agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q?version=2.0#test";
        let uri = AgentUri::parse(input).unwrap();
        let canonical = uri.canonical();

        assert!(!canonical.contains('?'));
        assert!(!canonical.contains('#'));
    }

    #[test]
    fn query_and_fragment_do_not_change_identity_equality() {
        let base =
            AgentUri::parse("agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q").unwrap();
        let decorated = AgentUri::parse(
            "agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q?version=2.0#task",
        )
        .unwrap();

        assert_eq!(base, decorated);
        assert_eq!(base.cmp(&decorated), Ordering::Equal);
        assert_eq!(hash_of(&base), hash_of(&decorated));
    }

    fn hash_of(uri: &AgentUri) -> u64 {
        use std::hash::{Hash, Hasher};

        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        uri.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn equal_uris_hash_equally_and_key_one_entry() {
        use std::collections::HashSet;

        let base =
            AgentUri::parse("agent://acme.com/workflow/rule_01h455vb4pex5vsknk084sn02q").unwrap();
        let decorated =
            AgentUri::parse("agent://acme.com/workflow/rule_01h455vb4pex5vsknk084sn02q?ttl=300")
                .unwrap();

        let mut set = HashSet::new();
        assert!(set.insert(base.clone()));
        assert!(!set.insert(decorated));
        assert!(set.contains(&base));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn different_agents_do_not_share_a_hash_bucket_entry() {
        use std::collections::HashSet;

        let one =
            AgentUri::parse("agent://acme.com/workflow/rule_01h455vb4pex5vsknk084sn02q").unwrap();
        let other =
            AgentUri::parse("agent://acme.com/workflow/rule_01h455vb4pex5vsknk084sn02r").unwrap();
        let elsewhere =
            AgentUri::parse("agent://other.com/workflow/rule_01h455vb4pex5vsknk084sn02q").unwrap();

        assert_ne!(one, other);
        assert_ne!(one, elsewhere);

        let set: HashSet<_> = [one, other, elsewhere].into_iter().collect();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn hashing_ignores_exactly_what_equality_ignores() {
        // If a field is added to one impl and not the other, the Hash/Eq
        // contract breaks silently. This checks the pair rather than either.
        let base =
            AgentUri::parse("agent://acme.com/workflow/rule_01h455vb4pex5vsknk084sn02q").unwrap();

        for variant in [
            "agent://acme.com/workflow/rule_01h455vb4pex5vsknk084sn02q?ttl=300",
            "agent://acme.com/workflow/rule_01h455vb4pex5vsknk084sn02q#invoice",
            "agent://acme.com/workflow/rule_01h455vb4pex5vsknk084sn02q?v=1&ttl=9#x",
            "agent://ACME.COM/workflow/rule_01h455vb4pex5vsknk084sn02q",
        ] {
            let variant = AgentUri::parse(variant).unwrap();
            assert_eq!(base, variant, "{variant} should be the same identity");
            assert_eq!(
                hash_of(&base),
                hash_of(&variant),
                "{variant} is equal, so it must hash equally"
            );
        }
    }

    #[test]
    fn is_localhost() {
        let uri =
            AgentUri::parse("agent://localhost:8472/test/llm_01h455vb4pex5vsknk084sn02q").unwrap();
        assert!(uri.is_localhost());

        let uri = AgentUri::parse("agent://127.0.0.1/test/llm_01h455vb4pex5vsknk084sn02q").unwrap();
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
                kind: ParseErrorKind::MissingComponent {
                    component: "agent ID"
                },
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

        let uri = AgentUri::new(trust_root, cap_path, agent_id, QueryParams::new(), None).unwrap();

        assert_eq!(uri.trust_root().host_str(), "anthropic.com");
        assert_eq!(uri.capability_path().as_str(), "assistant/chat");
    }

    #[test]
    fn ipv4_shaped_trust_root_with_out_of_range_octet_is_rejected() {
        let result = AgentUri::parse("agent://256.1.1.1/test/llm_01h455vb4pex5vsknk084sn02q");

        assert!(matches!(
            result,
            Err(ParseError {
                kind: ParseErrorKind::InvalidTrustRoot(TrustRootError::InvalidIpAddress { .. }),
                ..
            })
        ));
    }

    #[test]
    fn ordering_agrees_with_identity_equality() {
        // `Ord` and `PartialEq` must not disagree about which URIs are the
        // same one, and the query and fragment are outside identity for both.
        let plain = uri("agent://acme.com/chat/llm_01h455vb4pex5vsknk084sn02q");
        let hinted = uri("agent://acme.com/chat/llm_01h455vb4pex5vsknk084sn02q?ttl=300#part");

        assert_eq!(plain.cmp(&hinted), Ordering::Equal);
        assert_eq!(plain, hinted);
    }

    #[test]
    fn ordering_walks_the_components_in_the_order_a_uri_writes_them() {
        let by_root = uri("agent://b.com/chat/llm_01h455vb4pex5vsknk084sn02q");
        let by_path = uri("agent://a.com/zeta/llm_01h455vb4pex5vsknk084sn02q");
        let by_id = uri("agent://a.com/chat/rule_01h455vb4pex5vsknk084sn02q");
        let first = uri("agent://a.com/chat/llm_01h455vb4pex5vsknk084sn02q");

        // The trust root decides before the path, and the path before the ID.
        assert!(first < by_id);
        assert!(by_id < by_path);
        assert!(by_path < by_root);
    }

    #[test]
    fn ordering_is_by_component_and_not_by_the_rendered_string() {
        // The two differ exactly here: rendered, `acme.com` is followed by
        // `/`, and `/` sorts after the `.` that continues `acme.com.br`, so
        // comparing the strings put the longer name first. Comparing trust
        // roots puts the shorter one first, which is what a reader sorting a
        // list of hosts expects.
        let shorter = uri("agent://acme.com/chat/llm_01h455vb4pex5vsknk084sn02q");
        let longer = uri("agent://acme.com.br/chat/llm_01h455vb4pex5vsknk084sn02q");

        assert!(shorter < longer);
        assert!(longer.canonical() < shorter.canonical());
    }

    #[test]
    fn ordering_is_a_total_order() {
        let uris = [
            uri("agent://a.com/chat/llm_01h455vb4pex5vsknk084sn02q"),
            uri("agent://a.com.br/chat/llm_01h455vb4pex5vsknk084sn02q"),
            uri("agent://a.com/chat/rule_01h455vb4pex5vsknk084sn02q"),
            uri("agent://b.com/zeta/deep/human_01h455vb4pex5vsknk084sn02q"),
        ];

        for left in &uris {
            for right in &uris {
                assert_eq!(
                    left.cmp(right).reverse(),
                    right.cmp(left),
                    "{left} vs {right} is not antisymmetric"
                );
                assert_eq!(left.cmp(right) == Ordering::Equal, left == right);
            }
        }
    }

    #[test]
    fn a_rejected_input_too_large_to_be_a_uri_is_not_copied_into_the_error() {
        // `parse` used to clone whatever it was handed, so rejecting a
        // megabyte cost a megabyte.
        let hostile = format!("agent://{}", "a".repeat(2 * 1024 * 1024));

        let Err(error) = AgentUri::parse(&hostile) else {
            panic!("a two-megabyte input must not parse");
        };

        assert!(error.input.len() < 1024, "the error kept the whole input");
        assert!(matches!(error.kind, ParseErrorKind::TooLong { .. }));
    }

    #[test]
    fn a_rejected_input_short_enough_to_have_been_a_uri_is_kept_whole() {
        let input = "agent://acme.com/Chat/llm_01h455vb4pex5vsknk084sn02q";

        let Err(error) = AgentUri::parse(input) else {
            panic!("an uppercase path segment must not parse");
        };

        assert_eq!(error.input, input);
    }
}
