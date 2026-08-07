//! The root keys a deployment pins, and what pinning one commits it to.
//!
//! Specification section 7.2 already makes "which trust roots matter" a
//! deployment decision: every verifier carries a list of root names it will
//! believe anything from. Pinning extends that entry by one field — the root
//! key — and in exchange the document that arrives has to have been written by
//! whoever holds that key, rather than by whoever can write to the web host.
//!
//! Pinning a root is a commitment as well as a protection. From then on this
//! crate will not accept the bare form from that root, so a root that stops
//! publishing signed documents stops being usable rather than quietly falling
//! back to channel trust. That is the point: a fallback an attacker can trigger
//! is not a defence.

use agent_uri_attestation::VerifyingKey;

use crate::error::DiscoveryError;

/// The root keys a verifier will accept a trust root's key document from.
///
/// Never empty. A pin with no keys would mean "refuse everything from this
/// root", which is a thing a deployment might want but never by accident, and
/// which an empty builder call would produce silently.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::SigningKey;
/// use agent_uri_attestation_wellknown::PinnedRootKeys;
///
/// let outgoing = SigningKey::generate().verifying_key();
/// let incoming = SigningKey::generate().verifying_key();
///
/// // During a root-key rotation, pin both: the root publishes signed by each
/// // for the overlap, and this verifier keeps working across it.
/// let pinned = PinnedRootKeys::new(outgoing).and(incoming);
///
/// assert_eq!(pinned.keys().len(), 2);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedRootKeys {
    keys: Vec<VerifyingKey>,
}

impl PinnedRootKeys {
    /// Pins one root key.
    #[must_use]
    pub fn new(key: VerifyingKey) -> Self {
        Self { keys: vec![key] }
    }

    /// Pins another, for a root key that is itself rotating.
    ///
    /// A key already pinned is not added twice, so repeating a key cannot
    /// inflate the work a served document costs.
    #[must_use]
    pub fn and(mut self, key: VerifyingKey) -> Self {
        if !self.keys.contains(&key) {
            self.keys.push(key);
        }
        self
    }

    /// Pins a root key written the way an operator holds one: base64.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryError::InvalidRootKey`] when the string is not the
    /// base64 of a valid Ed25519 public key. A pinned key that does not decode
    /// is a configuration mistake that must surface where it was made, not one
    /// that quietly leaves a root unverifiable.
    pub fn from_base64(encoded: &str) -> Result<Self, DiscoveryError> {
        VerifyingKey::from_base64(encoded)
            .map(Self::new)
            .map_err(|source| DiscoveryError::InvalidRootKey {
                reason: source.to_string(),
            })
    }

    /// The keys, in the order they were pinned.
    #[must_use]
    pub fn keys(&self) -> &[VerifyingKey] {
        &self.keys
    }
}

#[cfg(test)]
mod tests {
    use agent_uri_attestation::SigningKey;

    use super::*;

    fn key() -> VerifyingKey {
        SigningKey::generate().verifying_key()
    }

    #[test]
    fn a_pin_holds_every_key_it_was_given() {
        let first = key();
        let second = key();

        let pinned = PinnedRootKeys::new(first.clone()).and(second.clone());

        assert_eq!(pinned.keys(), [first, second]);
    }

    #[test]
    fn pinning_the_same_key_twice_pins_it_once() {
        // Each pinned key costs a signature verification per signature served,
        // so a duplicated line in a config file must not double the work.
        let repeated = key();

        let pinned = PinnedRootKeys::new(repeated.clone()).and(repeated);

        assert_eq!(pinned.keys().len(), 1);
    }

    #[test]
    fn a_pin_can_be_read_from_the_base64_an_operator_holds() {
        let root_key = key();

        let pinned = PinnedRootKeys::from_base64(&root_key.to_base64()).unwrap();

        assert_eq!(pinned.keys(), [root_key]);
    }

    #[test]
    fn a_pinned_key_that_does_not_decode_is_refused_where_it_was_written() {
        let error = PinnedRootKeys::from_base64("not a key")
            .expect_err("a pin that does not decode must be refused");

        assert!(
            matches!(error, DiscoveryError::InvalidRootKey { .. }),
            "{error}"
        );
    }
}
