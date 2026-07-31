//! Fetching, caching, and refreshing the keys a trust root publishes.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use agent_uri::TrustRoot;
use agent_uri_attestation::key_document::MAX_DOCUMENT_LENGTH;
use agent_uri_attestation::{AcceptAll, KeyDocument, TrustStore, Verifier};

use crate::error::DiscoveryError;

/// The path section 7.2 puts the document at.
pub const WELL_KNOWN_PATH: &str = "/.well-known/agent-keys.json";

/// How long a fetched document is served from cache before it is fetched again.
///
/// A rotation is announced by the document changing, so this is also the
/// longest a verifier can go on not knowing that a key was withdrawn or added.
/// An hour matches the default token lifetime: no token outlives the staleness
/// of the key list that would have refused it by more than one lifetime.
pub const DEFAULT_TTL: Duration = Duration::from_hours(1);

/// How long a single fetch may take before it is given up on.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Fetches and caches the key documents of trust roots.
///
/// Cloning shares the cache and the underlying HTTP client, so one of these
/// per process is enough and passing it around costs nothing.
///
/// # Example
///
/// ```no_run
/// use agent_uri_attestation_wellknown::KeyDiscovery;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let discovery = KeyDiscovery::new();
///
/// // Trust a root this process has never exchanged a key with.
/// let verifier = discovery.verifier_for("acme.com").await?;
/// # let token = String::new();
/// let claims = verifier.verify(&token)?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct KeyDiscovery {
    client: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, Cached>>>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct Cached {
    document: Arc<KeyDocument>,
    fetched_at: Instant,
}

impl Default for KeyDiscovery {
    fn default() -> Self {
        Self::with_timeout(DEFAULT_TIMEOUT)
    }
}

impl KeyDiscovery {
    /// A discovery client with the default timeout and cache lifetime.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A discovery client whose requests give up after `timeout`.
    ///
    /// The client is built to refuse redirects. A redirect from a trust root's
    /// own endpoint is an instruction to go and ask something else, and this
    /// crate's whole claim about a document is that the authority it names is
    /// the authority that served it. Following a redirect would hand that
    /// decision to whoever wrote the `Location` header.
    ///
    /// # Panics
    ///
    /// Panics if the HTTP client cannot be built, which means the process has
    /// no usable TLS backend. There is nothing a caller could do with that as
    /// an error except stop.
    #[must_use]
    pub fn with_timeout(timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .use_preconfigured_tls(tls_config())
            .build()
            .expect("a TLS backend is required to fetch key documents");

        Self {
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
            ttl: DEFAULT_TTL,
        }
    }

    /// Serves a cached document for this long before fetching again.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// How long a fetched document is served from cache.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The cached document for a root, if one was fetched within the TTL.
    ///
    /// Does no I/O and never blocks on the network, which is what makes it
    /// usable from somewhere that cannot await.
    #[must_use]
    pub fn cached(&self, trust_root: &str) -> Option<Arc<KeyDocument>> {
        let cache = self.cache.read().ok()?;
        let entry = cache.get(trust_root)?;
        (entry.fetched_at.elapsed() < self.ttl).then(|| Arc::clone(&entry.document))
    }

    /// The document for a root, fetched only if the cache has none that is fresh.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError`] when the root is unusable, the endpoint
    /// cannot be reached or answers with anything but success, the response is
    /// too large, or the document does not say what a key document must.
    pub async fn document(&self, trust_root: &str) -> Result<Arc<KeyDocument>, DiscoveryError> {
        if let Some(cached) = self.cached(trust_root) {
            return Ok(cached);
        }
        self.refresh(trust_root).await
    }

    /// Fetches a root's document, ignoring and then replacing the cache.
    ///
    /// What to call when a root announces a rotation out of band, rather than
    /// waiting out the TTL.
    ///
    /// # Errors
    ///
    /// As [`Self::document`]. A failed refresh leaves whatever was cached
    /// before in place: a root that is briefly unreachable should not cost a
    /// verifier the keys it already had, and the entry ages out on its own.
    pub async fn refresh(&self, trust_root: &str) -> Result<Arc<KeyDocument>, DiscoveryError> {
        let url = Self::endpoint(trust_root)?;
        let body = self.get(trust_root, &url).await?;

        let document = KeyDocument::parse(&body).map_err(|source| DiscoveryError::Document {
            trust_root: trust_root.to_string(),
            source,
        })?;
        // The document is only evidence about the authority that served it.
        document
            .check_belongs_to(trust_root)
            .map_err(|source| DiscoveryError::Document {
                trust_root: trust_root.to_string(),
                source,
            })?;

        let document = Arc::new(document);
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                trust_root.to_string(),
                Cached {
                    document: Arc::clone(&document),
                    fetched_at: Instant::now(),
                },
            );
        }

        Ok(document)
    }

    /// The trust store a root's published keys describe.
    ///
    /// # Errors
    ///
    /// As [`Self::document`], plus the document being unusable as a store: no
    /// key this crate can verify with, a key that does not decode, or a window
    /// that ends before it starts.
    pub async fn trust_store(&self, trust_root: &str) -> Result<TrustStore, DiscoveryError> {
        self.document(trust_root)
            .await?
            .trust_store()
            .map_err(|source| DiscoveryError::Document {
                trust_root: trust_root.to_string(),
                source,
            })
    }

    /// A verifier that trusts one root, with that root's own revocations.
    ///
    /// This is the point of the crate: trust for a root nobody exchanged a key
    /// with by hand. The verifier's revocation source is the `revoked_keys` of
    /// the same document, so a key the root has withdrawn is refused without
    /// the caller assembling anything.
    ///
    /// A document with an empty `revoked_keys` produces a verifier that checks
    /// revocation and finds nothing revoked, which is different from one that
    /// does not check. Where a deployment has its own denylist as well, build
    /// the store with [`Self::trust_store`] and supply that instead.
    ///
    /// # Errors
    ///
    /// As [`Self::trust_store`], plus a `revoked_keys` entry that does not
    /// decode: a revocation that cannot be read cannot be enforced.
    pub async fn verifier_for(&self, trust_root: &str) -> Result<Verifier, DiscoveryError> {
        let document = self.document(trust_root).await?;
        let fault = |source| DiscoveryError::Document {
            trust_root: trust_root.to_string(),
            source,
        };

        let store = document.trust_store().map_err(fault)?;
        let denylist = document.denylist().map_err(fault)?;

        Ok(Verifier::new()
            .with_trust_store(store)
            .with_revocation(denylist))
    }

    /// Forgets everything cached for a root.
    ///
    /// Returns true if there was something to forget. Removal is local: it
    /// stops this process serving stale keys and says nothing to anyone else.
    #[must_use]
    pub fn forget(&self, trust_root: &str) -> bool {
        self.cache
            .write()
            .is_ok_and(|mut cache| cache.remove(trust_root).is_some())
    }

    /// The URL a root's document is published at.
    ///
    /// The trust root is parsed with the agent-uri grammar before it is put in
    /// a URL. That is not tidiness: this endpoint is built by concatenation, so
    /// a string carrying `/`, `@`, or a scheme would point the request at a
    /// host the caller did not name while still looking like a lookup of the
    /// one they did.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::InvalidTrustRoot`] when the grammar refuses
    /// the trust root.
    pub fn endpoint(trust_root: &str) -> Result<String, DiscoveryError> {
        let parsed =
            TrustRoot::parse(trust_root).map_err(|e| DiscoveryError::InvalidTrustRoot {
                trust_root: trust_root.to_string(),
                reason: e.to_string(),
            })?;

        Ok(format!("https://{parsed}{WELL_KNOWN_PATH}"))
    }

    /// Reads at most [`MAX_DOCUMENT_LENGTH`] bytes of the endpoint's answer.
    async fn get(&self, trust_root: &str, url: &str) -> Result<String, DiscoveryError> {
        let transport = |e: reqwest::Error| DiscoveryError::Transport {
            trust_root: trust_root.to_string(),
            reason: e.to_string(),
        };

        let response = self.client.get(url).send().await.map_err(transport)?;

        if !response.status().is_success() {
            return Err(DiscoveryError::Status {
                trust_root: trust_root.to_string(),
                status: response.status().as_u16(),
            });
        }

        // A declared length over the cap is refused before a byte is read, and
        // the body is measured again as it arrives because the header is the
        // server's claim rather than a fact.
        if response
            .content_length()
            .is_some_and(|declared| declared > MAX_DOCUMENT_LENGTH as u64)
        {
            return Err(too_large(trust_root));
        }

        let body = response.text().await.map_err(transport)?;
        if body.len() > MAX_DOCUMENT_LENGTH {
            return Err(too_large(trust_root));
        }

        Ok(body)
    }
}

/// The TLS configuration every fetch runs over.
///
/// Built here rather than left to the HTTP client's default for two reasons,
/// both of them about what this workspace ends up compiling:
///
/// - the crypto provider is **ring**, which `rusty_paseto` already puts in the
///   dependency graph. The alternative default drags in `aws-lc-sys`, and with
///   it a C toolchain and `cmake` as build requirements for a workspace that
///   otherwise needs neither;
/// - the trust anchors are the Mozilla root set, compiled in, rather than the
///   platform verifier. A trust root's key document has to be fetchable the
///   same way from a container with no system certificate store as from a
///   developer's laptop.
///
/// # Panics
///
/// Panics if the configuration cannot be built, which means the ring provider
/// does not support the protocol versions compiled in. That is a build-time
/// mismatch, not something a caller can handle.
fn tls_config() -> rustls::ClientConfig {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("the ring provider supports the protocol versions compiled in")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

fn too_large(trust_root: &str) -> DiscoveryError {
    DiscoveryError::TooLarge {
        trust_root: trust_root.to_string(),
        max: MAX_DOCUMENT_LENGTH,
    }
}

/// A verifier that trusts nothing and revokes nothing.
///
/// Handy as the starting point for one assembled from several roots:
///
/// ```
/// use agent_uri_attestation_wellknown::empty_verifier;
///
/// assert_eq!(empty_verifier().trusted_root_count(), 0);
/// assert!(empty_verifier().checks_revocation());
/// ```
#[must_use]
pub fn empty_verifier() -> Verifier {
    Verifier::new().with_revocation(AcceptAll)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_endpoint_is_the_path_specification_7_2_names() {
        assert_eq!(
            KeyDiscovery::endpoint("acme.com").unwrap(),
            "https://acme.com/.well-known/agent-keys.json"
        );
    }

    #[test]
    fn a_trust_root_with_a_port_keeps_it() {
        assert_eq!(
            KeyDiscovery::endpoint("localhost:8472").unwrap(),
            "https://localhost:8472/.well-known/agent-keys.json"
        );
    }

    #[test]
    fn a_trust_root_that_would_redirect_the_request_is_refused() {
        // Each of these, concatenated into "https://{}/.well-known/...",
        // produces a URL aimed somewhere other than where it reads as aimed.
        for hostile in [
            "acme.com/../evil.example",
            "acme.com@evil.example",
            "evil.example#acme.com",
            "evil.example?acme.com",
            "http://acme.com",
            "acme.com/.well-known",
            "",
        ] {
            assert!(
                KeyDiscovery::endpoint(hostile).is_err(),
                "'{hostile}' must not be turned into an endpoint"
            );
        }
    }

    #[test]
    fn a_cold_cache_serves_nothing() {
        let discovery = KeyDiscovery::new();

        assert!(discovery.cached("acme.com").is_none());
        assert!(!discovery.forget("acme.com"));
    }

    #[test]
    fn the_default_ttl_is_one_token_lifetime() {
        assert_eq!(KeyDiscovery::new().ttl(), DEFAULT_TTL);
        assert_eq!(
            KeyDiscovery::new().with_ttl(Duration::from_mins(1)).ttl(),
            Duration::from_mins(1)
        );
    }

    #[test]
    fn a_clone_shares_the_cache() {
        // Otherwise every clone would fetch its own copy of every document,
        // and the TTL would mean nothing.
        let discovery = KeyDiscovery::new();
        let clone = discovery.clone();

        assert!(Arc::ptr_eq(&discovery.cache, &clone.cache));
    }
}
