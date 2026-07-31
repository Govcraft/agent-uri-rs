//! Revocation: deciding that an already-signed token should stop being honoured.
//!
//! A signature cannot be taken back. Once a trust root signs an attestation,
//! that token verifies under the root's key until its `exp` passes, and no
//! amount of regret at the issuing end changes it. Revocation is the mechanism
//! that lets a verifier decline a token the issuer would no longer stand
//! behind — a key that leaked, an agent that was decommissioned, a grant that
//! was issued in error.
//!
//! [Specification](https://github.com/Govcraft/agent-uri-rs/blob/main/SPECIFICATION.md)
//! section 8.2 makes this a MUST: verifiers check revocation before accepting.
//!
//! # Two things get revoked, not one
//!
//! - **A token**, by its [`jti`](crate::AttestationClaims::jti). Narrow: one
//!   attestation stops working and everything else the root issued is
//!   unaffected. This is the tool for a grant issued in error.
//! - **A key**, by its [`VerifyingKey`]. Wide: every token that key ever signed
//!   stops working at once, including ones nobody has enumerated. This is the
//!   tool for a compromise, where the set of bad tokens is exactly the set you
//!   cannot list.
//!
//! Key revocation is the one that matters under compromise. An attacker holding
//! a stolen signing key mints tokens whose `jti` values you have never seen, so
//! a per-token denylist can only ever name the tokens you already knew about.
//!
//! # There is no permissive default
//!
//! [`Verifier`](crate::Verifier) has no revocation source until one is given to
//! it, and until then it rejects every token. That is deliberate and it is the
//! opposite of convenient.
//!
//! The alternative — accept everything when unconfigured — makes the failure
//! mode silent. A deployment that forgot to wire up its denylist would verify
//! tokens exactly as if it had one, and would keep honouring a revoked token
//! with nothing anywhere reporting that revocation was not being enforced. The
//! cost of the strict default is one explicit line at construction; the cost of
//! the permissive one is paid once, during an incident, by someone who believed
//! revocation was on.
//!
//! A deployment that genuinely does not do revocation says so with
//! [`AcceptAll`], which is a claim in the code rather than an omission from it.
//!
//! # Example
//!
//! ```
//! use agent_uri_attestation::{Denylist, RevocationCheck, SigningKey};
//!
//! let compromised = SigningKey::generate().verifying_key();
//!
//! let denylist = Denylist::new()
//!     .revoke_token("01h455vb4pex5vsknk084sn02q")
//!     .revoke_key(&compromised);
//!
//! assert!(denylist.is_token_revoked("01h455vb4pex5vsknk084sn02q"));
//! assert!(denylist.is_key_revoked(&compromised));
//! assert!(!denylist.is_token_revoked("01h455vb4pex5vsknk084sn02r"));
//! ```

use std::collections::HashSet;

use crate::keys::VerifyingKey;

/// Decides whether a token or a signing key has been revoked.
///
/// Both methods answer "is this revoked?", so both fail closed by returning
/// `true` when the implementation cannot tell. An implementation that fetches a
/// list over the network and cannot reach it does not know that a token is
/// good; returning `false` there would turn every outage into a window in which
/// revoked tokens are honoured.
pub trait RevocationCheck: std::fmt::Debug + Send + Sync {
    /// Returns true if the token with this `jti` has been revoked.
    fn is_token_revoked(&self, jti: &str) -> bool;

    /// Returns true if this signing key has been revoked.
    ///
    /// A revoked key invalidates every token it signed, including tokens whose
    /// `jti` was never recorded anywhere — which under compromise is most of
    /// them.
    fn is_key_revoked(&self, key: &VerifyingKey) -> bool;
}

/// An in-memory denylist of revoked tokens and keys.
///
/// Suitable wherever the revoked set is known at startup or can be rebuilt in
/// process: a config file, a periodic fetch, an administrative API. It holds
/// only what it is told and never consults the network.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::{Denylist, RevocationCheck};
///
/// let denylist = Denylist::new().revoke_token("01h455vb4pex5vsknk084sn02q");
///
/// assert!(denylist.is_token_revoked("01h455vb4pex5vsknk084sn02q"));
/// assert_eq!(denylist.revoked_token_count(), 1);
/// ```
#[derive(Debug, Clone, Default)]
pub struct Denylist {
    tokens: HashSet<String>,
    keys: HashSet<[u8; 32]>,
}

impl Denylist {
    /// Creates an empty denylist, which revokes nothing.
    ///
    /// Note the difference from having no denylist at all: an empty `Denylist`
    /// is a verifier that checks revocation and finds nothing revoked, whereas
    /// a [`Verifier`](crate::Verifier) with no revocation source rejects
    /// everything. The first is a working deployment on a quiet day; the second
    /// is one that has not been configured.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Revokes a single token by its `jti`.
    #[must_use]
    pub fn revoke_token(mut self, jti: impl Into<String>) -> Self {
        self.tokens.insert(jti.into());
        self
    }

    /// Revokes a signing key, and with it every token that key signed.
    #[must_use]
    pub fn revoke_key(mut self, key: &VerifyingKey) -> Self {
        self.keys.insert(key.to_bytes());
        self
    }

    /// Revokes a token in place.
    pub fn insert_token(&mut self, jti: impl Into<String>) {
        self.tokens.insert(jti.into());
    }

    /// Revokes a key in place.
    pub fn insert_key(&mut self, key: &VerifyingKey) {
        self.keys.insert(key.to_bytes());
    }

    /// Returns the number of individually revoked tokens.
    #[must_use]
    pub fn revoked_token_count(&self) -> usize {
        self.tokens.len()
    }

    /// Returns the number of revoked keys.
    #[must_use]
    pub fn revoked_key_count(&self) -> usize {
        self.keys.len()
    }
}

impl RevocationCheck for Denylist {
    fn is_token_revoked(&self, jti: &str) -> bool {
        self.tokens.contains(jti)
    }

    fn is_key_revoked(&self, key: &VerifyingKey) -> bool {
        self.keys.contains(&key.to_bytes())
    }
}

/// A revocation check that revokes nothing, ever.
///
/// The explicit way to run without revocation. It exists so that "this
/// deployment does not do revocation" is a decision someone wrote down, rather
/// than the accident of never having configured a denylist — which is what a
/// permissive default would have made it indistinguishable from.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::{AcceptAll, RevocationCheck, SigningKey};
///
/// assert!(!AcceptAll.is_token_revoked("01h455vb4pex5vsknk084sn02q"));
/// assert!(!AcceptAll.is_key_revoked(&SigningKey::generate().verifying_key()));
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct AcceptAll;

impl RevocationCheck for AcceptAll {
    fn is_token_revoked(&self, _jti: &str) -> bool {
        false
    }

    fn is_key_revoked(&self, _key: &VerifyingKey) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;

    fn key() -> VerifyingKey {
        SigningKey::generate().verifying_key()
    }

    #[test]
    fn an_empty_denylist_revokes_nothing() {
        let denylist = Denylist::new();

        assert!(!denylist.is_token_revoked("01h455vb4pex5vsknk084sn02q"));
        assert!(!denylist.is_key_revoked(&key()));
        assert_eq!(denylist.revoked_token_count(), 0);
        assert_eq!(denylist.revoked_key_count(), 0);
    }

    #[test]
    fn a_revoked_token_is_revoked_and_its_neighbours_are_not() {
        let denylist = Denylist::new().revoke_token("01h455vb4pex5vsknk084sn02q");

        assert!(denylist.is_token_revoked("01h455vb4pex5vsknk084sn02q"));
        assert!(!denylist.is_token_revoked("01h455vb4pex5vsknk084sn02r"));
        assert!(!denylist.is_token_revoked(""));
    }

    #[test]
    fn a_revoked_key_is_revoked_and_another_key_is_not() {
        let compromised = key();
        let untouched = key();
        let denylist = Denylist::new().revoke_key(&compromised);

        assert!(denylist.is_key_revoked(&compromised));
        assert!(!denylist.is_key_revoked(&untouched));
    }

    #[test]
    fn revoking_a_token_does_not_revoke_the_key_that_signed_it() {
        // The two axes are independent, and conflating them would either make
        // one bad grant kill a whole trust root or make a compromised key keep
        // working. Both are the wrong blast radius.
        let signer = key();
        let denylist = Denylist::new().revoke_token("01h455vb4pex5vsknk084sn02q");

        assert!(denylist.is_token_revoked("01h455vb4pex5vsknk084sn02q"));
        assert!(!denylist.is_key_revoked(&signer));
    }

    #[test]
    fn revoking_a_key_does_not_name_any_particular_token() {
        // Key revocation has to work without enumerating tokens: under
        // compromise the attacker mints `jti` values nobody has ever seen.
        let compromised = key();
        let denylist = Denylist::new().revoke_key(&compromised);

        assert!(denylist.is_key_revoked(&compromised));
        assert!(!denylist.is_token_revoked("01h455vb4pex5vsknk084sn02q"));
        assert_eq!(denylist.revoked_token_count(), 0);
    }

    #[test]
    fn revoking_the_same_thing_twice_counts_once() {
        let repeated = key();
        let denylist = Denylist::new()
            .revoke_token("01h455vb4pex5vsknk084sn02q")
            .revoke_token("01h455vb4pex5vsknk084sn02q")
            .revoke_key(&repeated)
            .revoke_key(&repeated);

        assert_eq!(denylist.revoked_token_count(), 1);
        assert_eq!(denylist.revoked_key_count(), 1);
    }

    #[test]
    fn in_place_insertion_matches_the_builder() {
        let signer = key();
        let mut built_in_place = Denylist::new();
        built_in_place.insert_token("01h455vb4pex5vsknk084sn02q");
        built_in_place.insert_key(&signer);

        assert!(built_in_place.is_token_revoked("01h455vb4pex5vsknk084sn02q"));
        assert!(built_in_place.is_key_revoked(&signer));
    }

    #[test]
    fn accept_all_revokes_nothing_whatever_it_is_asked() {
        assert!(!AcceptAll.is_token_revoked("01h455vb4pex5vsknk084sn02q"));
        assert!(!AcceptAll.is_token_revoked(""));
        assert!(!AcceptAll.is_key_revoked(&key()));
    }
}
