//! Well-known key discovery for `agent://` attestation.
//!
//! [`agent-uri-attestation`](agent_uri_attestation) verifies a token against
//! the keys it is given, and until now those keys had to arrive by hand. That
//! is workable for the roots an operator already deals with and impossible for
//! the ones they do not: there was no way to bootstrap trust in a root nobody
//! had exchanged a key with out of band.
//!
//! [Specification](https://github.com/Govcraft/agent-uri-rs/blob/main/SPECIFICATION.md)
//! section 7.2 answers that by having every trust root publish its keys:
//!
//! ```text
//! GET https://{trust-root}/.well-known/agent-keys.json
//! ```
//!
//! This crate fetches that document, caches it, and turns it into a
//! [`Verifier`](agent_uri_attestation::Verifier).
//!
//! # Why this is a separate crate
//!
//! An HTTP client with a TLS stack is a large dependency, and the attestation
//! crate is useful without one. A caller that verifies tokens against keys from
//! a config file, a secrets manager, or a deployment artefact should not
//! inherit a networking stack to do it.
//!
//! The document *format* stays in the attestation crate, as
//! [`KeyDocument`](agent_uri_attestation::KeyDocument), because reading it is
//! arithmetic rather than I/O. This crate is the part that goes and gets it.
//!
//! # Example
//!
//! ```no_run
//! use agent_uri_attestation_wellknown::KeyDiscovery;
//!
//! # async fn example(token: &str) -> Result<(), Box<dyn std::error::Error>> {
//! let discovery = KeyDiscovery::new();
//!
//! // No key was exchanged with acme.com beforehand.
//! let verifier = discovery.verifier_for("acme.com").await?;
//! let claims = verifier.verify(token)?;
//! assert_eq!(claims.iss, "acme.com");
//! # Ok(())
//! # }
//! ```
//!
//! # What a fetched document does and does not establish
//!
//! It establishes which keys an authority stands behind, because it came from
//! that authority over TLS. Everything this crate refuses follows from
//! protecting that one claim:
//!
//! - **HTTPS only, and no redirects.** A redirect is an instruction to go and
//!   ask something else. Following one would let whoever wrote the `Location`
//!   header decide whose keys a caller ends up trusting.
//! - **The trust root is parsed before it is put in a URL.** The endpoint is
//!   built by concatenation, so a string carrying `/`, `@`, or a scheme would
//!   aim the request elsewhere while reading as a lookup of the named root.
//! - **The document must name the root whose endpoint served it.** Otherwise
//!   any authority could publish keys for anyone else's namespace.
//! - **The response is capped.** Both the declared length and what actually
//!   arrives, because the header is the server's claim rather than a fact.
//!
//! What it does **not** establish is that the authority deserves to be trusted.
//! Fetching `evil.example`'s keys tells you exactly which keys `evil.example`
//! signs with, and nothing about whether to believe anything it says. Deciding
//! which roots matter is the deployment's job and always was.
//!
//! # Staleness
//!
//! A cached document is served for [`DEFAULT_TTL`] before it is fetched again,
//! which is also the longest this crate can go on not knowing that a key was
//! added or withdrawn. It matches the default token lifetime: no token
//! outlives the staleness of the key list that would have refused it by more
//! than one lifetime. [`KeyDiscovery::refresh`] short-circuits the wait when a
//! rotation is announced some other way.
//!
//! A failed refresh keeps whatever was cached before. A root that is briefly
//! unreachable should not cost a verifier the keys it already had, and the
//! entry ages out on its own if the outage lasts.

#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]

mod discovery;
mod error;

pub use discovery::{DEFAULT_TIMEOUT, DEFAULT_TTL, KeyDiscovery, WELL_KNOWN_PATH, empty_verifier};
pub use error::DiscoveryError;
