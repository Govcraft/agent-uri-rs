//! Fetching, caching, and refreshing the keys a trust root publishes.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use agent_uri::TrustRoot;
use agent_uri_attestation::key_document::MAX_DOCUMENT_LENGTH;
use agent_uri_attestation::{
    AcceptAll, DEFAULT_DOCUMENT_LEEWAY, DocumentVersion, KeyDocument, ServedDocument, TrustStore,
    Verifier, check_document_expiry,
};
use chrono::{DateTime, Utc};

use crate::error::DiscoveryError;
use crate::pinning::PinnedRootKeys;

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
    /// The newest version accepted from each root, whether or not it is still
    /// cached. Separate from the cache because it must outlive it: a rollback
    /// floor that a verifier forgot when a document went stale would be no
    /// floor at all, since waiting out the TTL is something an attacker holding
    /// the publication host can do.
    accepted_versions: Arc<RwLock<HashMap<String, DocumentVersion>>>,
    pins: Arc<HashMap<String, PinnedRootKeys>>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct Cached {
    document: Arc<KeyDocument>,
    fetched_at: Instant,
    /// When the document said it stops being evidence, if it said.
    ///
    /// A signed document carries its own lifetime, and it is shorter than the
    /// cache's job of being a cache. Serving one past its `expires` would let
    /// an attacker who can merely block the endpoint keep a revoked key alive
    /// for the rest of the TTL.
    expires: Option<DateTime<Utc>>,
}

/// A document that has passed whatever policy applies to the root it came from.
#[derive(Debug, Clone)]
struct Accepted {
    document: Arc<KeyDocument>,
    expires: Option<DateTime<Utc>>,
    /// The publication this document is, once a pinned key has vouched for it.
    version: Option<DocumentVersion>,
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
            accepted_versions: Arc::new(RwLock::new(HashMap::new())),
            pins: Arc::new(HashMap::new()),
            ttl: DEFAULT_TTL,
        }
    }

    /// Serves a cached document for this long before fetching again.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Requires this root's key document to be signed by one of `keys`.
    ///
    /// The keys arrive out of band, as section 7.2's "which trust roots matter"
    /// decision already does. From here on, this discovery client will not take
    /// the bare form from that root: a fallback an attacker can trigger by
    /// deleting a signature is not a defence.
    ///
    /// The root is matched exactly as written, against the string later passed
    /// to [`Self::document`] and its callers. Pins are fixed once the client is
    /// built, so a clone carries the pins the original had when it was cloned.
    ///
    /// # Example
    ///
    /// ```
    /// use agent_uri_attestation::SigningKey;
    /// use agent_uri_attestation_wellknown::{KeyDiscovery, PinnedRootKeys};
    ///
    /// # let root_key = SigningKey::generate().verifying_key();
    /// let discovery = KeyDiscovery::new().pin_root("acme.com", PinnedRootKeys::new(root_key));
    ///
    /// assert!(discovery.is_pinned("acme.com"));
    /// assert!(!discovery.is_pinned("example.com"));
    /// ```
    #[must_use]
    pub fn pin_root(mut self, trust_root: &str, keys: PinnedRootKeys) -> Self {
        Arc::make_mut(&mut self.pins).insert(trust_root.to_string(), keys);
        self
    }

    /// The keys pinned for a root, if any are.
    #[must_use]
    pub fn pinned_keys(&self, trust_root: &str) -> Option<&PinnedRootKeys> {
        self.pins.get(trust_root)
    }

    /// Whether this client requires a signed document from a root.
    #[must_use]
    pub fn is_pinned(&self, trust_root: &str) -> bool {
        self.pins.contains_key(trust_root)
    }

    /// The newest version accepted from a root, if one has been.
    ///
    /// The rollback floor: a document older than this is refused. Kept for the
    /// life of the process, and deliberately not cleared by [`Self::forget`].
    #[must_use]
    pub fn accepted_version(&self, trust_root: &str) -> Option<DocumentVersion> {
        self.accepted_versions.read().ok()?.get(trust_root).copied()
    }

    /// How long a fetched document is served from cache.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// The cached document for a root, if one is still good.
    ///
    /// Two things end a cache entry, and the earlier of them wins: the TTL this
    /// client was built with, and the `expires` a signed document carries. The
    /// second is what keeps an attacker who can block the endpoint — but not
    /// write to it — from stretching a revoked key's life to the TTL.
    ///
    /// Does no I/O and never blocks on the network, which is what makes it
    /// usable from somewhere that cannot await.
    #[must_use]
    pub fn cached(&self, trust_root: &str) -> Option<Arc<KeyDocument>> {
        let cache = self.cache.read().ok()?;
        let entry = cache.get(trust_root)?;

        if entry.fetched_at.elapsed() >= self.ttl {
            return None;
        }
        if let Some(expires) = entry.expires
            && check_document_expiry(expires, Utc::now(), DEFAULT_DOCUMENT_LEEWAY).is_err()
        {
            return None;
        }

        Some(Arc::clone(&entry.document))
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

        let accepted = self.accept(trust_root, &body, Utc::now())?;

        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                trust_root.to_string(),
                Cached {
                    document: Arc::clone(&accepted.document),
                    fetched_at: Instant::now(),
                    expires: accepted.expires,
                },
            );
        }

        Ok(accepted.document)
    }

    /// Applies this client's policy to a body, without touching the network.
    ///
    /// The whole of what discovery decides about a document lives here, so that
    /// all of it can be exercised against bytes rather than against a socket.
    ///
    /// | Root | Form served | Outcome |
    /// |---|---|---|
    /// | not pinned | bare | accepted on the terms of the TLS channel |
    /// | not pinned | signed | payload used, signature not checked |
    /// | pinned | bare | refused |
    /// | pinned | signed | signature, expiry, and version floor all checked |
    fn accept(
        &self,
        trust_root: &str,
        body: &str,
        now: DateTime<Utc>,
    ) -> Result<Accepted, DiscoveryError> {
        let fault = |source| DiscoveryError::Document {
            trust_root: trust_root.to_string(),
            source,
        };

        let served = ServedDocument::parse(body).map_err(fault)?;

        let accepted = match (self.pins.get(trust_root), &served) {
            // No pin: this is the channel-trust deployment, and both forms say
            // the same thing to it. Reading the payload of a signed document it
            // cannot check is what lets a root adopt signing without breaking
            // every verifier that has not pinned its key.
            (None, _) => Accepted {
                document: Arc::new(served.unverified_document().clone()),
                expires: None,
                version: None,
            },
            (Some(pinned), ServedDocument::Signed(signed)) => {
                let payload = signed
                    .verify_at(pinned.keys(), now, DEFAULT_DOCUMENT_LEEWAY)
                    .map_err(fault)?;
                let (version, expires) = (payload.version(), payload.expires());
                Accepted {
                    document: Arc::new(payload.into_document()),
                    expires: Some(expires),
                    version: Some(version),
                }
            }
            // The bare form to a pinned root, and any form a later revision of
            // section 7.2 adds that this crate cannot check. Both fail closed:
            // no pinned key vouched for what arrived.
            (Some(_), _) => {
                return Err(DiscoveryError::Unsigned {
                    trust_root: trust_root.to_string(),
                });
            }
        };

        // The document is only evidence about the authority that served it.
        accepted
            .document
            .check_belongs_to(trust_root)
            .map_err(fault)?;

        // Last, so that a document refused for any other reason never touches
        // the floor. Only a version a pinned key vouched for may raise it: an
        // unverified one is whatever the endpoint said, and honouring that
        // would let an attacker raise the floor out of reach of the root's own
        // publications.
        if let Some(version) = accepted.version {
            self.record_if_newer(trust_root, version)?;
        }

        Ok(accepted)
    }

    /// Refuses a document that would move this verifier backwards, and remembers
    /// one that moves it forwards.
    ///
    /// The signature on a replayed document is genuine — the root really did
    /// publish it, once. What makes it an attack is that it is behind: an
    /// attacker holding the publication host serves the last document from
    /// before a revocation, and the revocation is undone.
    ///
    /// Comparing and recording happen under one write lock. Split across two,
    /// two refreshes racing on the same root could each read the older floor and
    /// each conclude it was current.
    ///
    /// A poisoned lock is a refusal, not a shrug: a floor that cannot be
    /// consulted is a rollback check that did not happen, and this crate's
    /// answer to a check it cannot perform is everywhere else to reject.
    fn record_if_newer(
        &self,
        trust_root: &str,
        offered: DocumentVersion,
    ) -> Result<(), DiscoveryError> {
        let Ok(mut versions) = self.accepted_versions.write() else {
            return Err(DiscoveryError::VersionUnavailable {
                trust_root: trust_root.to_string(),
            });
        };

        match versions.get(trust_root) {
            Some(&held) if offered < held => Err(DiscoveryError::VersionRegression {
                trust_root: trust_root.to_string(),
                held: held.get(),
                offered: offered.get(),
            }),
            Some(&held) => {
                versions.insert(trust_root.to_string(), held.max(offered));
                Ok(())
            }
            None => {
                versions.insert(trust_root.to_string(), offered);
                Ok(())
            }
        }
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

    /// Forgets the cached document for a root.
    ///
    /// Returns true if there was something to forget. Removal is local: it
    /// stops this process serving stale keys and says nothing to anyone else.
    ///
    /// The rollback floor is *not* forgotten. It is what refuses a document
    /// older than one already accepted, and a floor that any cache-clearing
    /// call reset would be one an attacker could clear by making a fetch fail.
    /// Use [`Self::forget_publication_history`] to reset it, which is the right
    /// call only when a root has legitimately restarted its version counter.
    #[must_use]
    pub fn forget(&self, trust_root: &str) -> bool {
        self.cache
            .write()
            .is_ok_and(|mut cache| cache.remove(trust_root).is_some())
    }

    /// Forgets the newest version accepted from a root, lowering the floor.
    ///
    /// Returns true if there was a floor to forget. This gives up the rollback
    /// protection for that root until the next document is accepted, so call it
    /// only when the root itself has restarted its `version` counter — after a
    /// root-key ceremony, say — and never as part of clearing a cache.
    #[must_use]
    pub fn forget_publication_history(&self, trust_root: &str) -> bool {
        self.accepted_versions
            .write()
            .is_ok_and(|mut versions| versions.remove(trust_root).is_some())
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
    use agent_uri_attestation::{AttestationError, DocumentSigner, KeyDocumentPayload, SigningKey};

    use super::*;

    const TRUST_ROOT: &str = "acme.com";

    fn week_away() -> DateTime<Utc> {
        Utc::now() + chrono::Duration::days(7)
    }

    /// The bare document `acme.com` publishes.
    fn bare() -> String {
        let published = SigningKey::generate().verifying_key().to_base64();
        format!(
            r#"{{"trust_root": "{TRUST_ROOT}", "keys": [{{
                 "kid": "key-2026-01", "algorithm": "Ed25519", "public_key": "{published}",
                 "not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z"}}]}}"#
        )
    }

    /// The same document, signed by `root_key` as publication `version`.
    fn signed(root_key: &SigningKey, version: u64, expires: DateTime<Utc>) -> String {
        KeyDocumentPayload::new(
            KeyDocument::parse(&bare()).expect("the fixture document parses"),
            DocumentVersion::new(version),
            expires,
        )
        .to_signed_json(&[DocumentSigner::new(root_key).named("root-2026")])
        .expect("the fixture payload renders")
    }

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

    #[test]
    fn a_clone_shares_the_pins_and_the_rollback_floor() {
        // A clone that verified against different pins, or against a floor of
        // its own, would be a second policy nobody wrote down.
        let root_key = SigningKey::generate();
        let discovery =
            KeyDiscovery::new().pin_root(TRUST_ROOT, PinnedRootKeys::new(root_key.verifying_key()));
        let clone = discovery.clone();

        clone
            .accept(TRUST_ROOT, &signed(&root_key, 4, week_away()), Utc::now())
            .expect("the fixture document is acceptable");

        assert!(clone.is_pinned(TRUST_ROOT));
        assert_eq!(
            discovery.accepted_version(TRUST_ROOT),
            Some(DocumentVersion::new(4))
        );
    }

    #[test]
    fn an_unpinned_root_may_serve_either_form() {
        // What lets a trust root adopt signing without breaking the verifiers
        // that have not pinned its root key.
        let discovery = KeyDiscovery::new();
        let root_key = SigningKey::generate();

        let from_bare = discovery
            .accept(TRUST_ROOT, &bare(), Utc::now())
            .expect("the bare form is what this crate has always accepted");
        let from_signed = discovery
            .accept(TRUST_ROOT, &signed(&root_key, 1, week_away()), Utc::now())
            .expect("a signed document must still be readable without a pin");

        assert_eq!(from_signed.document.trust_root(), TRUST_ROOT);
        assert_eq!(from_bare.document.keys().len(), 1);
        // Nothing was verified, so nothing about the document binds this
        // verifier: no expiry to honour and no floor to raise.
        assert!(from_signed.expires.is_none());
        assert_eq!(discovery.accepted_version(TRUST_ROOT), None);
    }

    #[test]
    fn a_pinned_root_that_serves_the_bare_form_is_refused() {
        // The whole point of the pin. Accepting the bare form here would let
        // whoever served it decide that this deployment does not pin after all.
        let root_key = SigningKey::generate();
        let discovery =
            KeyDiscovery::new().pin_root(TRUST_ROOT, PinnedRootKeys::new(root_key.verifying_key()));

        let error = discovery
            .accept(TRUST_ROOT, &bare(), Utc::now())
            .expect_err("a pinned root must serve the signed form");

        assert!(
            matches!(&error, DiscoveryError::Unsigned { trust_root } if trust_root == TRUST_ROOT),
            "{error}"
        );
    }

    #[test]
    fn a_pinned_root_serving_a_document_signed_by_its_root_key_is_accepted() {
        let root_key = SigningKey::generate();
        let discovery =
            KeyDiscovery::new().pin_root(TRUST_ROOT, PinnedRootKeys::new(root_key.verifying_key()));

        let accepted = discovery
            .accept(TRUST_ROOT, &signed(&root_key, 7, week_away()), Utc::now())
            .expect("a document signed by the pinned key must be accepted");

        assert_eq!(accepted.document.trust_root(), TRUST_ROOT);
        assert!(accepted.expires.is_some());
        assert_eq!(
            discovery.accepted_version(TRUST_ROOT),
            Some(DocumentVersion::new(7))
        );
    }

    #[test]
    fn a_document_signed_by_anything_but_the_pinned_key_is_refused() {
        // The publication-host compromise this exists for: the attacker writes
        // a document naming keys they hold, and signs it with a key of theirs.
        let root_key = SigningKey::generate();
        let attacker_key = SigningKey::generate();
        let discovery =
            KeyDiscovery::new().pin_root(TRUST_ROOT, PinnedRootKeys::new(root_key.verifying_key()));

        let error = discovery
            .accept(
                TRUST_ROOT,
                &signed(&attacker_key, 8, week_away()),
                Utc::now(),
            )
            .expect_err("a document signed by an unpinned key must be refused");

        assert!(
            matches!(
                &error,
                DiscoveryError::Document {
                    source: AttestationError::InvalidSignature,
                    ..
                }
            ),
            "{error}"
        );
        assert_eq!(
            discovery.accepted_version(TRUST_ROOT),
            None,
            "a refused document must not raise the rollback floor"
        );
    }

    #[test]
    fn an_older_document_is_refused_however_genuinely_it_was_signed() {
        // Replay: the attacker serves the last document the root published
        // before it revoked a key. The signature is real; the version is not
        // current, and that is what refuses it.
        let root_key = SigningKey::generate();
        let discovery =
            KeyDiscovery::new().pin_root(TRUST_ROOT, PinnedRootKeys::new(root_key.verifying_key()));
        discovery
            .accept(TRUST_ROOT, &signed(&root_key, 9, week_away()), Utc::now())
            .expect("the current document is accepted");

        let error = discovery
            .accept(TRUST_ROOT, &signed(&root_key, 8, week_away()), Utc::now())
            .expect_err("a document behind the one already accepted must be refused");

        assert!(
            matches!(
                &error,
                DiscoveryError::VersionRegression {
                    held: 9,
                    offered: 8,
                    ..
                }
            ),
            "{error}"
        );
        assert_eq!(
            discovery.accepted_version(TRUST_ROOT),
            Some(DocumentVersion::new(9)),
            "a refused replay must not lower the floor it failed against"
        );
    }

    #[test]
    fn republishing_the_same_version_is_not_a_rollback() {
        // A verifier that re-fetches between publications sees the same version
        // twice, which is the ordinary case and not an attack.
        let root_key = SigningKey::generate();
        let discovery =
            KeyDiscovery::new().pin_root(TRUST_ROOT, PinnedRootKeys::new(root_key.verifying_key()));
        let document = signed(&root_key, 3, week_away());

        discovery.accept(TRUST_ROOT, &document, Utc::now()).unwrap();

        assert!(discovery.accept(TRUST_ROOT, &document, Utc::now()).is_ok());
    }

    #[test]
    fn a_newer_document_raises_the_floor() {
        let root_key = SigningKey::generate();
        let discovery =
            KeyDiscovery::new().pin_root(TRUST_ROOT, PinnedRootKeys::new(root_key.verifying_key()));

        discovery
            .accept(TRUST_ROOT, &signed(&root_key, 3, week_away()), Utc::now())
            .unwrap();
        discovery
            .accept(TRUST_ROOT, &signed(&root_key, 4, week_away()), Utc::now())
            .unwrap();

        assert_eq!(
            discovery.accepted_version(TRUST_ROOT),
            Some(DocumentVersion::new(4))
        );
        assert!(
            discovery
                .accept(TRUST_ROOT, &signed(&root_key, 3, week_away()), Utc::now())
                .is_err()
        );
    }

    #[test]
    fn an_expired_document_is_refused_even_though_the_root_signed_it() {
        let root_key = SigningKey::generate();
        let discovery =
            KeyDiscovery::new().pin_root(TRUST_ROOT, PinnedRootKeys::new(root_key.verifying_key()));
        let stale = signed(&root_key, 2, Utc::now() - chrono::Duration::days(1));

        let error = discovery
            .accept(TRUST_ROOT, &stale, Utc::now())
            .expect_err("a document past its own expiry must be refused");

        assert!(
            matches!(
                &error,
                DiscoveryError::Document {
                    source: AttestationError::DocumentExpired { .. },
                    ..
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn a_signed_document_naming_another_root_is_refused_however_it_is_signed() {
        // Signing says who wrote the document, not which namespace it is
        // evidence about. Both questions still have to be asked.
        let root_key = SigningKey::generate();
        let discovery = KeyDiscovery::new().pin_root(
            "evil.example",
            PinnedRootKeys::new(root_key.verifying_key()),
        );

        let error = discovery
            .accept(
                "evil.example",
                &signed(&root_key, 1, week_away()),
                Utc::now(),
            )
            .expect_err("a document naming another root must be refused");

        assert!(
            matches!(
                &error,
                DiscoveryError::Document {
                    source: AttestationError::TrustRootMismatch { .. },
                    ..
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn forgetting_a_cached_document_does_not_forget_how_far_the_root_has_published() {
        // Otherwise the rollback floor would be resettable by anything that
        // clears a cache, which includes an attacker who can make a fetch fail.
        let root_key = SigningKey::generate();
        let discovery =
            KeyDiscovery::new().pin_root(TRUST_ROOT, PinnedRootKeys::new(root_key.verifying_key()));
        discovery
            .accept(TRUST_ROOT, &signed(&root_key, 5, week_away()), Utc::now())
            .unwrap();

        let _ = discovery.forget(TRUST_ROOT);

        assert_eq!(
            discovery.accepted_version(TRUST_ROOT),
            Some(DocumentVersion::new(5))
        );
        assert!(discovery.forget_publication_history(TRUST_ROOT));
        assert_eq!(discovery.accepted_version(TRUST_ROOT), None);
    }

    #[test]
    fn a_rollback_check_that_cannot_be_made_refuses_rather_than_being_skipped() {
        // A poisoned lock means the record of what has already been accepted
        // cannot be read. Carrying on would accept a document having silently
        // dropped the one check that stops a replay.
        let root_key = SigningKey::generate();
        let discovery =
            KeyDiscovery::new().pin_root(TRUST_ROOT, PinnedRootKeys::new(root_key.verifying_key()));

        let versions = Arc::clone(&discovery.accepted_versions);
        let _ = std::thread::spawn(move || {
            let _held = versions.write().expect("the lock is not yet poisoned");
            panic!("poisoning the lock, deliberately");
        })
        .join();

        let error = discovery
            .accept(TRUST_ROOT, &signed(&root_key, 1, week_away()), Utc::now())
            .expect_err("a check that cannot be made must refuse");

        assert!(
            matches!(&error, DiscoveryError::VersionUnavailable { trust_root } if trust_root == TRUST_ROOT),
            "{error}"
        );
    }

    #[test]
    fn a_cached_signed_document_stops_being_served_at_its_own_expiry() {
        // The TTL is this crate's staleness budget; `expires` is the root's.
        // Whichever runs out first ends the entry, or an attacker who can only
        // block the endpoint would keep a revoked key alive to the TTL.
        let discovery = KeyDiscovery::new();
        let document = Arc::new(KeyDocument::parse(&bare()).unwrap());

        discovery.cache.write().unwrap().insert(
            TRUST_ROOT.to_string(),
            Cached {
                document: Arc::clone(&document),
                fetched_at: Instant::now(),
                expires: Some(Utc::now() + chrono::Duration::days(1)),
            },
        );
        assert!(discovery.cached(TRUST_ROOT).is_some());

        discovery.cache.write().unwrap().insert(
            TRUST_ROOT.to_string(),
            Cached {
                document,
                fetched_at: Instant::now(),
                expires: Some(Utc::now() - chrono::Duration::days(1)),
            },
        );

        assert!(
            discovery.cached(TRUST_ROOT).is_none(),
            "a document past its expiry must not be served, TTL or no TTL"
        );
    }
}
