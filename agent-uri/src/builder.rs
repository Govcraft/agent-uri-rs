//! Typestate builder for constructing [`AgentUri`] instances.
//!
//! This module provides a builder that uses phantom types to enforce
//! at compile-time that components are added in the correct order.

use std::marker::PhantomData;

use crate::agent_id::AgentId;
use crate::capability_path::CapabilityPath;
use crate::constants::MAX_URI_LENGTH;
use crate::error::{
    AgentIdError, BuilderError, CapabilityPathError, FragmentError, ParseErrorKind, QueryError,
    TrustRootError,
};
use crate::fragment::Fragment;
use crate::query::QueryParams;
use crate::trust_root::TrustRoot;
use crate::uri::AgentUri;

/// Marker: No components set yet.
#[derive(Debug, Clone, Copy, Default)]
pub struct Empty;

/// Marker: Trust root has been set.
#[derive(Debug, Clone, Copy, Default)]
pub struct HasTrustRoot;

/// Marker: Trust root and capability path have been set.
#[derive(Debug, Clone, Copy, Default)]
pub struct HasCapabilityPath;

/// Marker: All required components are set, ready to build.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ready;

/// A typestate builder for constructing [`AgentUri`] instances.
///
/// This builder enforces at compile-time that components are added
/// in the correct order: trust root, then capability path, then agent ID.
/// Query and fragment are optional and can be added at any point.
///
/// # Type State
///
/// The builder uses phantom types to track which components have been set:
/// - [`Empty`]: Initial state, no components set
/// - [`HasTrustRoot`]: Trust root has been set
/// - [`HasCapabilityPath`]: Trust root and capability path have been set
/// - [`Ready`]: All required components set, can call `build()`
///
/// # Examples
///
/// ```
/// use agent_uri::{AgentUriBuilder, TrustRoot, CapabilityPath, AgentId};
///
/// let uri = AgentUriBuilder::new()
///     .trust_root(TrustRoot::parse("anthropic.com").unwrap())
///     .capability_path(CapabilityPath::parse("assistant/chat").unwrap())
///     .agent_id(AgentId::new("llm_chat"))
///     .build()
///     .unwrap();
///
/// assert_eq!(uri.trust_root().host_str(), "anthropic.com");
/// ```
///
/// # Compile-Time Safety
///
/// Attempting to call methods out of order results in a compile error:
///
/// ```compile_fail
/// use agent_uri::{AgentUriBuilder, CapabilityPath};
///
/// // Error: cannot call capability_path() before trust_root()
/// let path = CapabilityPath::parse("chat").unwrap();
/// let builder = AgentUriBuilder::new()
///     .capability_path(path);  // Compile error!
/// ```
///
/// ```compile_fail
/// use agent_uri::{AgentUriBuilder, TrustRoot};
///
/// // Error: cannot call build() without all required components
/// let root = TrustRoot::parse("example.com").unwrap();
/// let uri = AgentUriBuilder::new()
///     .trust_root(root)
///     .build();  // Compile error!
/// ```
#[derive(Debug, Clone)]
pub struct AgentUriBuilder<State = Empty> {
    trust_root: Option<TrustRoot>,
    capability_path: Option<CapabilityPath>,
    agent_id: Option<AgentId>,
    query: QueryParams,
    fragment: Option<Fragment>,
    _state: PhantomData<State>,
}

impl AgentUriBuilder<Empty> {
    /// Creates a new builder in the initial state.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentUriBuilder;
    ///
    /// let builder = AgentUriBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            trust_root: None,
            capability_path: None,
            agent_id: None,
            query: QueryParams::new(),
            fragment: None,
            _state: PhantomData,
        }
    }

    /// Sets the trust root and advances to the [`HasTrustRoot`] state.
    ///
    /// This must be called first before setting other required components.
    ///
    /// # Arguments
    ///
    /// * `trust_root` - The validated trust root (authority) for the URI
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::{AgentUriBuilder, TrustRoot};
    ///
    /// let builder = AgentUriBuilder::new()
    ///     .trust_root(TrustRoot::parse("anthropic.com").unwrap());
    /// ```
    #[must_use]
    pub fn trust_root(self, trust_root: TrustRoot) -> AgentUriBuilder<HasTrustRoot> {
        AgentUriBuilder {
            trust_root: Some(trust_root),
            capability_path: self.capability_path,
            agent_id: self.agent_id,
            query: self.query,
            fragment: self.fragment,
            _state: PhantomData,
        }
    }

    /// Parses and sets the trust root from a string.
    ///
    /// This is a convenience method that combines parsing and setting the trust root.
    ///
    /// # Errors
    ///
    /// Returns [`TrustRootError`] if the string is not a valid trust root.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentUriBuilder;
    ///
    /// let builder = AgentUriBuilder::new()
    ///     .try_trust_root("anthropic.com")?;
    /// # Ok::<(), agent_uri::TrustRootError>(())
    /// ```
    pub fn try_trust_root(self, s: &str) -> Result<AgentUriBuilder<HasTrustRoot>, TrustRootError> {
        let trust_root = TrustRoot::parse(s)?;
        Ok(self.trust_root(trust_root))
    }
}

impl Default for AgentUriBuilder<Empty> {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentUriBuilder<HasTrustRoot> {
    /// Sets the capability path and advances to the [`HasCapabilityPath`] state.
    ///
    /// This must be called after `trust_root()` and before `agent_id()`.
    ///
    /// # Arguments
    ///
    /// * `capability_path` - The validated capability path describing the agent's function
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::{AgentUriBuilder, TrustRoot, CapabilityPath};
    ///
    /// let builder = AgentUriBuilder::new()
    ///     .trust_root(TrustRoot::parse("anthropic.com").unwrap())
    ///     .capability_path(CapabilityPath::parse("assistant/chat").unwrap());
    /// ```
    #[must_use]
    pub fn capability_path(
        self,
        capability_path: CapabilityPath,
    ) -> AgentUriBuilder<HasCapabilityPath> {
        AgentUriBuilder {
            trust_root: self.trust_root,
            capability_path: Some(capability_path),
            agent_id: self.agent_id,
            query: self.query,
            fragment: self.fragment,
            _state: PhantomData,
        }
    }

    /// Parses and sets the capability path from a string.
    ///
    /// This is a convenience method that combines parsing and setting the capability path.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityPathError`] if the string is not a valid capability path.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentUriBuilder;
    ///
    /// let builder = AgentUriBuilder::new()
    ///     .try_trust_root("anthropic.com")?
    ///     .try_capability_path("assistant/chat")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn try_capability_path(
        self,
        s: &str,
    ) -> Result<AgentUriBuilder<HasCapabilityPath>, CapabilityPathError> {
        let capability_path = CapabilityPath::parse(s)?;
        Ok(self.capability_path(capability_path))
    }
}

impl AgentUriBuilder<HasCapabilityPath> {
    /// Sets the agent ID and advances to the [`Ready`] state.
    ///
    /// After calling this, the builder is ready to call `build()`.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The validated agent identifier
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::{AgentUriBuilder, TrustRoot, CapabilityPath, AgentId};
    ///
    /// let builder = AgentUriBuilder::new()
    ///     .trust_root(TrustRoot::parse("anthropic.com").unwrap())
    ///     .capability_path(CapabilityPath::parse("assistant/chat").unwrap())
    ///     .agent_id(AgentId::new("llm_chat"));
    /// // Builder is now in Ready state and can call build()
    /// ```
    #[must_use]
    pub fn agent_id(self, agent_id: AgentId) -> AgentUriBuilder<Ready> {
        AgentUriBuilder {
            trust_root: self.trust_root,
            capability_path: self.capability_path,
            agent_id: Some(agent_id),
            query: self.query,
            fragment: self.fragment,
            _state: PhantomData,
        }
    }

    /// Parses and sets the agent ID from a string.
    ///
    /// This is a convenience method that combines parsing and setting the agent ID.
    ///
    /// # Errors
    ///
    /// Returns [`AgentIdError`] if the string is not a valid agent ID.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentUriBuilder;
    ///
    /// let builder = AgentUriBuilder::new()
    ///     .try_trust_root("anthropic.com")?
    ///     .try_capability_path("assistant/chat")?
    ///     .try_agent_id("llm_chat_01h455vb4pex5vsknk084sn02q")?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn try_agent_id(self, s: &str) -> Result<AgentUriBuilder<Ready>, AgentIdError> {
        let agent_id = AgentId::parse(s)?;
        Ok(self.agent_id(agent_id))
    }
}

impl AgentUriBuilder<Ready> {
    /// Builds the final [`AgentUri`].
    ///
    /// This method is only available when the builder is in the [`Ready`] state,
    /// meaning all required components (trust root, capability path, agent ID)
    /// have been set.
    ///
    /// # Errors
    ///
    /// Returns [`BuilderError::UriTooLong`] if the resulting URI would exceed
    /// the maximum allowed length of 512 characters.
    ///
    /// # Panics
    ///
    /// This method will not panic in practice because the typestate pattern
    /// guarantees all required fields are set before `build()` can be called.
    /// The internal `expect()` calls are for defense-in-depth only.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::{AgentUriBuilder, TrustRoot, CapabilityPath, AgentId};
    ///
    /// let uri = AgentUriBuilder::new()
    ///     .trust_root(TrustRoot::parse("anthropic.com").unwrap())
    ///     .capability_path(CapabilityPath::parse("assistant/chat").unwrap())
    ///     .agent_id(AgentId::new("llm_chat"))
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(uri.trust_root().host_str(), "anthropic.com");
    /// ```
    pub fn build(self) -> Result<AgentUri, BuilderError> {
        // SAFETY: These are guaranteed to be Some because the typestate
        // ensures all required fields are set when we reach the Ready state.
        // The only way to reach Ready is through the proper state transitions.
        let trust_root = self
            .trust_root
            .expect("trust_root set in HasTrustRoot state");
        let capability_path = self
            .capability_path
            .expect("capability_path set in HasCapabilityPath state");
        let agent_id = self.agent_id.expect("agent_id set in Ready state");

        AgentUri::new(
            trust_root,
            capability_path,
            agent_id,
            self.query,
            self.fragment,
        )
        .map_err(|e| match e.kind {
            ParseErrorKind::TooLong { max, actual } => BuilderError::UriTooLong { max, actual },
            // Other variants shouldn't occur with pre-validated components
            _ => BuilderError::UriTooLong {
                max: MAX_URI_LENGTH,
                actual: 0,
            },
        })
    }
}

/// Methods available in all states after Empty for optional components.
impl<State> AgentUriBuilder<State> {
    /// Sets optional query parameters.
    ///
    /// This can be called at any point in the builder chain.
    /// If called multiple times, the last value wins.
    ///
    /// # Arguments
    ///
    /// * `query` - The query parameters to include in the URI
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::{AgentUriBuilder, TrustRoot, CapabilityPath, AgentId, QueryParams};
    ///
    /// let uri = AgentUriBuilder::new()
    ///     .trust_root(TrustRoot::parse("anthropic.com").unwrap())
    ///     .query(QueryParams::parse("version=2.0").unwrap())
    ///     .capability_path(CapabilityPath::parse("chat").unwrap())
    ///     .agent_id(AgentId::new("llm"))
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(uri.query().version(), Some("2.0"));
    /// ```
    #[must_use]
    pub fn query(mut self, query: QueryParams) -> Self {
        self.query = query;
        self
    }

    /// Sets the optional fragment.
    ///
    /// This can be called at any point in the builder chain.
    /// If called multiple times, the last value wins.
    ///
    /// # Arguments
    ///
    /// * `fragment` - The fragment to include in the URI
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::{AgentUriBuilder, TrustRoot, CapabilityPath, AgentId, Fragment};
    ///
    /// let uri = AgentUriBuilder::new()
    ///     .trust_root(TrustRoot::parse("anthropic.com").unwrap())
    ///     .capability_path(CapabilityPath::parse("chat").unwrap())
    ///     .fragment(Fragment::parse("summarization").unwrap())
    ///     .agent_id(AgentId::new("llm"))
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(uri.fragment().map(|f| f.as_str()), Some("summarization"));
    /// ```
    #[must_use]
    pub fn fragment(mut self, fragment: Fragment) -> Self {
        self.fragment = Some(fragment);
        self
    }

    /// Parses and sets the query parameters from a string.
    ///
    /// This is a convenience method that combines parsing and setting query parameters.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError`] if the string is not a valid query string.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentUriBuilder;
    ///
    /// let builder = AgentUriBuilder::new()
    ///     .try_query("version=2.0&ttl=300")?;
    /// # Ok::<(), agent_uri::QueryError>(())
    /// ```
    pub fn try_query(self, s: &str) -> Result<Self, QueryError> {
        let query = QueryParams::parse(s)?;
        Ok(self.query(query))
    }

    /// Parses and sets the fragment from a string.
    ///
    /// This is a convenience method that combines parsing and setting the fragment.
    ///
    /// # Errors
    ///
    /// Returns [`FragmentError`] if the string is not a valid fragment.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentUriBuilder;
    ///
    /// let builder = AgentUriBuilder::new()
    ///     .try_fragment("summarization")?;
    /// # Ok::<(), agent_uri::FragmentError>(())
    /// ```
    pub fn try_fragment(self, s: &str) -> Result<Self, FragmentError> {
        let fragment = Fragment::parse(s)?;
        Ok(self.fragment(fragment))
    }

    /// Sets the query if provided, otherwise leaves it unchanged.
    ///
    /// This is useful when the query is optional and may be `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::{AgentUriBuilder, QueryParams};
    ///
    /// let query = Some(QueryParams::parse("version=2.0").unwrap());
    /// let builder = AgentUriBuilder::new()
    ///     .maybe_query(query);
    /// ```
    #[must_use]
    pub fn maybe_query(self, query: Option<QueryParams>) -> Self {
        match query {
            Some(q) => self.query(q),
            None => self,
        }
    }

    /// Sets the fragment if provided, otherwise leaves it unchanged.
    ///
    /// This is useful when the fragment is optional and may be `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::{AgentUriBuilder, Fragment};
    ///
    /// let fragment = Some(Fragment::parse("test").unwrap());
    /// let builder = AgentUriBuilder::new()
    ///     .maybe_fragment(fragment);
    /// ```
    #[must_use]
    pub fn maybe_fragment(self, fragment: Option<Fragment>) -> Self {
        match fragment {
            Some(f) => self.fragment(f),
            None => self,
        }
    }

    /// Parses and sets the query from a string if provided.
    ///
    /// This is useful when the query string is optional and may be `None`.
    ///
    /// # Errors
    ///
    /// Returns [`QueryError`] if the provided string is not a valid query string.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentUriBuilder;
    ///
    /// let query_str = Some("version=2.0");
    /// let builder = AgentUriBuilder::new()
    ///     .maybe_query_str(query_str)?;
    /// # Ok::<(), agent_uri::QueryError>(())
    /// ```
    pub fn maybe_query_str(self, s: Option<&str>) -> Result<Self, QueryError> {
        match s {
            Some(s) => self.try_query(s),
            None => Ok(self),
        }
    }

    /// Parses and sets the fragment from a string if provided.
    ///
    /// This is useful when the fragment string is optional and may be `None`.
    ///
    /// # Errors
    ///
    /// Returns [`FragmentError`] if the provided string is not a valid fragment.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentUriBuilder;
    ///
    /// let fragment_str = Some("summarization");
    /// let builder = AgentUriBuilder::new()
    ///     .maybe_fragment_str(fragment_str)?;
    /// # Ok::<(), agent_uri::FragmentError>(())
    /// ```
    pub fn maybe_fragment_str(self, s: Option<&str>) -> Result<Self, FragmentError> {
        match s {
            Some(s) => self.try_fragment(s),
            None => Ok(self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_trust_root() -> TrustRoot {
        TrustRoot::parse("anthropic.com").unwrap()
    }

    fn sample_capability_path() -> CapabilityPath {
        CapabilityPath::parse("assistant/chat").unwrap()
    }

    fn sample_agent_id() -> AgentId {
        AgentId::new("llm_chat")
    }

    #[test]
    fn new_creates_empty_builder() {
        let builder = AgentUriBuilder::new();
        assert!(builder.trust_root.is_none());
        assert!(builder.capability_path.is_none());
        assert!(builder.agent_id.is_none());
    }

    #[test]
    fn trust_root_transitions_to_has_trust_root() {
        let builder = AgentUriBuilder::new().trust_root(sample_trust_root());
        assert!(builder.trust_root.is_some());
        assert!(builder.capability_path.is_none());
    }

    #[test]
    fn capability_path_transitions_to_has_capability_path() {
        let builder = AgentUriBuilder::new()
            .trust_root(sample_trust_root())
            .capability_path(sample_capability_path());
        assert!(builder.trust_root.is_some());
        assert!(builder.capability_path.is_some());
        assert!(builder.agent_id.is_none());
    }

    #[test]
    fn agent_id_transitions_to_ready() {
        let builder = AgentUriBuilder::new()
            .trust_root(sample_trust_root())
            .capability_path(sample_capability_path())
            .agent_id(sample_agent_id());
        assert!(builder.trust_root.is_some());
        assert!(builder.capability_path.is_some());
        assert!(builder.agent_id.is_some());
    }

    #[test]
    fn build_creates_valid_uri() {
        let uri = AgentUriBuilder::new()
            .trust_root(sample_trust_root())
            .capability_path(sample_capability_path())
            .agent_id(sample_agent_id())
            .build()
            .unwrap();

        assert_eq!(uri.trust_root().host_str(), "anthropic.com");
        assert_eq!(uri.capability_path().as_str(), "assistant/chat");
        assert_eq!(uri.agent_id().prefix().as_str(), "llm_chat");
    }

    #[test]
    fn build_with_query_includes_query() {
        let query = QueryParams::parse("version=2.0&ttl=300").unwrap();

        let uri = AgentUriBuilder::new()
            .trust_root(sample_trust_root())
            .query(query)
            .capability_path(sample_capability_path())
            .agent_id(sample_agent_id())
            .build()
            .unwrap();

        assert_eq!(uri.query().version(), Some("2.0"));
        assert_eq!(uri.query().ttl(), Some(300));
    }

    #[test]
    fn build_with_fragment_includes_fragment() {
        let fragment = Fragment::parse("summarization").unwrap();

        let uri = AgentUriBuilder::new()
            .trust_root(sample_trust_root())
            .capability_path(sample_capability_path())
            .fragment(fragment)
            .agent_id(sample_agent_id())
            .build()
            .unwrap();

        assert_eq!(
            uri.fragment().map(Fragment::as_str),
            Some("summarization")
        );
    }

    #[test]
    fn build_with_all_optionals() {
        let query = QueryParams::parse("version=2.0").unwrap();
        let fragment = Fragment::parse("test").unwrap();

        let uri = AgentUriBuilder::new()
            .trust_root(sample_trust_root())
            .capability_path(sample_capability_path())
            .agent_id(sample_agent_id())
            .query(query)
            .fragment(fragment)
            .build()
            .unwrap();

        assert_eq!(uri.query().version(), Some("2.0"));
        assert_eq!(uri.fragment().map(Fragment::as_str), Some("test"));
    }

    #[test]
    fn build_too_long_returns_error() {
        // Create components that are individually valid but together exceed 512 chars.
        // The basic components (scheme + trust_root + path + agent_id) max out at ~484,
        // so we need a long query string to push over 512.

        // Trust root: ~115 chars (55 + 1 + 55 + 4)
        let long_domain = format!("{}.{}.com", "a".repeat(55), "b".repeat(55));
        let trust_root = TrustRoot::parse(&long_domain).unwrap();

        // Capability path: ~251 chars (28 segments × 8 chars + 27 slashes = 224 + 27)
        let long_path = (0..28).map(|_| "abcdefgh").collect::<Vec<_>>().join("/");
        let capability_path = CapabilityPath::parse(&long_path).unwrap();

        // Agent ID: ~63 chars (prefix + underscore + 26 char suffix)
        let agent_id = AgentId::new("very_long_prefix_name_for_this_test");

        // Long query parameter to push over 512
        // Current components total 506 chars, need 7+ more to exceed 512
        let long_query = format!("custom={}", "x".repeat(70));
        let query = QueryParams::parse(&long_query).unwrap();

        let result = AgentUriBuilder::new()
            .trust_root(trust_root)
            .capability_path(capability_path)
            .agent_id(agent_id)
            .query(query)
            .build();

        assert!(matches!(result, Err(BuilderError::UriTooLong { .. })));
    }

    #[test]
    fn query_can_be_set_at_any_state() {
        let query = QueryParams::parse("version=1.0").unwrap();

        // Set query after trust_root
        let builder1 = AgentUriBuilder::new()
            .trust_root(sample_trust_root())
            .query(query.clone());
        assert!(!builder1.query.is_empty());

        // Set query after capability_path
        let builder2 = AgentUriBuilder::new()
            .trust_root(sample_trust_root())
            .capability_path(sample_capability_path())
            .query(query.clone());
        assert!(!builder2.query.is_empty());

        // Set query after agent_id (in Ready state)
        let builder3 = AgentUriBuilder::new()
            .trust_root(sample_trust_root())
            .capability_path(sample_capability_path())
            .agent_id(sample_agent_id())
            .query(query);
        assert!(!builder3.query.is_empty());
    }

    #[test]
    fn fragment_can_be_set_at_any_state() {
        let fragment = Fragment::parse("test").unwrap();

        // Set fragment after trust_root
        let builder1 = AgentUriBuilder::new()
            .trust_root(sample_trust_root())
            .fragment(fragment.clone());
        assert!(builder1.fragment.is_some());

        // Set fragment after capability_path
        let builder2 = AgentUriBuilder::new()
            .trust_root(sample_trust_root())
            .capability_path(sample_capability_path())
            .fragment(fragment.clone());
        assert!(builder2.fragment.is_some());

        // Set fragment after agent_id (in Ready state)
        let builder3 = AgentUriBuilder::new()
            .trust_root(sample_trust_root())
            .capability_path(sample_capability_path())
            .agent_id(sample_agent_id())
            .fragment(fragment);
        assert!(builder3.fragment.is_some());
    }

    #[test]
    fn default_creates_empty_builder() {
        let builder: AgentUriBuilder<Empty> = AgentUriBuilder::default();
        assert!(builder.trust_root.is_none());
    }

    #[test]
    fn clone_preserves_state() {
        let builder = AgentUriBuilder::new()
            .trust_root(sample_trust_root())
            .capability_path(sample_capability_path());

        let cloned = builder.clone();
        assert!(cloned.trust_root.is_some());
        assert!(cloned.capability_path.is_some());
    }

    #[test]
    fn debug_output_is_useful() {
        let builder = AgentUriBuilder::new().trust_root(sample_trust_root());

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("AgentUriBuilder"));
        assert!(debug_str.contains("trust_root"));
    }
}
