//! PASETO v4.public attestation for agent-uri.
//!
//! This crate provides cryptographic attestation of agent URIs using
//! PASETO v4.public tokens (Ed25519 signatures). Attestations bind an
//! agent URI to a set of capabilities, signed by a trust root.
//!
//! # Overview
//!
//! Attestation tokens enable:
//! - Cryptographic binding of agent URIs to capabilities
//! - Prevention of spoofing and DHT poisoning
//! - Bearer token verification without callbacks
//!
//! # Example
//!
//! ```rust
//! use agent_uri_attestation::{Issuer, Verifier, SigningKey};
//! use agent_uri::AgentUri;
//! use std::time::Duration;
//!
//! // Issuer side: create attestation
//! let signing_key = SigningKey::generate();
//! let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(86400));
//!
//! let uri = AgentUri::parse(
//!     "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q"
//! ).unwrap();
//! let token = issuer.issue(&uri, vec!["workflow.approval.read".into()]).unwrap();
//!
//! // Verifier side: validate attestation
//! let mut verifier = Verifier::new();
//! verifier.add_trusted_root("acme.com", signing_key.verifying_key());
//!
//! let claims = verifier.verify(&token).unwrap();
//! assert_eq!(claims.agent_uri, uri.to_string());
//! assert_eq!(claims.capabilities, vec!["workflow.approval.read"]);
//! ```
//!
//! # Token Structure
//!
//! Attestation tokens are PASETO v4.public tokens containing:
//!
//! - `agent_uri`: The full agent URI being attested
//! - `capabilities`: Array of capability strings granted
//! - `iss`: Issuer (trust root) that created the attestation
//! - `iat`: Issued-at timestamp
//! - `exp`: Expiration timestamp
//! - `aud`: Optional audience restriction
//!
//! # Security Properties
//!
//! | Property | How Achieved |
//! |----------|--------------|
//! | No algorithm confusion | PASETO v4 is Ed25519-only |
//! | Replay protection | `exp` claim validated automatically |
//! | Trust root binding | `iss` must match trusted roots |
//! | URI binding | `agent_uri` claim verified against expected |
//! | Tamper detection | Ed25519 signature verification |

#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod claims;
mod error;
mod issuer;
mod keys;
mod verifier;

pub use claims::{AttestationClaims, AttestationClaimsBuilder};
pub use error::AttestationError;
pub use issuer::Issuer;
pub use keys::{SigningKey, VerifyingKey};
pub use verifier::Verifier;

/// A prelude module for convenient imports.
///
/// # Example
///
/// ```rust
/// use agent_uri_attestation::prelude::*;
/// ```
pub mod prelude {
    pub use crate::{
        AttestationClaims, AttestationClaimsBuilder, AttestationError, Issuer, SigningKey,
        VerifyingKey, Verifier,
    };
}
