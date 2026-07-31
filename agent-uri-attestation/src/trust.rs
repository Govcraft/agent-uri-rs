//! The keys a verifier trusts, and the window in which each one is trusted.
//!
//! A trust root does not have one key forever. Keys are rotated on a schedule,
//! and they are rotated in a hurry after a compromise, and neither is possible
//! if a verifier can only hold a single key per root: the moment the new key is
//! installed, every token still in flight under the old one stops verifying.
//!
//! [Specification](https://github.com/Govcraft/agent-uri-rs/blob/main/SPECIFICATION.md)
//! section 7.2 models this directly. A trust root publishes a *list* of keys,
//! each with a `kid`, a `not_before`, and a `not_after`, so that during a
//! rotation both the outgoing and incoming key are published at once and the
//! changeover costs nothing.
//!
//! # A window is checked at verification time
//!
//! [`TrustedKey::validity_at`] asks whether a key may be used *now*, not
//! whether it was usable when the token was signed.
//!
//! Judging by the token's `iat` would be the more forgiving rule, and it is the
//! wrong one: it makes `not_after` advisory. A root that withdrew a key at noon
//! would keep honouring anything that key signed at 11:59 for as long as that
//! token's `exp` allowed, which is exactly the outcome withdrawing a key is
//! meant to prevent. Checking against the current instant means a retired key
//! retires.
//!
//! What that costs is an overlap: the outgoing key's `not_after` has to sit far
//! enough past the incoming key's `not_before` to cover the longest token still
//! in flight. With the default one-hour TTL that is an hour.
//!
//! # A window is not revocation
//!
//! A window is a schedule, published in advance, and a verifier that has the
//! key already knows the schedule. Revocation ([`RevocationCheck`]) is news: it
//! says a key stopped being trustworthy at a moment nobody planned for. A
//! compromised key needs both — removed from the store, and named on the
//! denylist for every verifier that still holds a stale copy.
//!
//! [`RevocationCheck`]: crate::RevocationCheck
//!
//! # Example
//!
//! ```
//! use agent_uri_attestation::{SigningKey, TrustStore, TrustedKey};
//! use chrono::{TimeZone, Utc};
//!
//! let outgoing = SigningKey::generate().verifying_key();
//! let incoming = SigningKey::generate().verifying_key();
//!
//! let changeover = Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap();
//! let overlap = chrono::Duration::hours(1);
//!
//! let mut store = TrustStore::new();
//! // The outgoing key stays usable for one token lifetime past the changeover.
//! store.add(
//!     "acme.com",
//!     TrustedKey::new(outgoing)
//!         .with_id("key-2026")
//!         .not_after(changeover + overlap),
//! );
//! store.add(
//!     "acme.com",
//!     TrustedKey::new(incoming).with_id("key-2027").not_before(changeover),
//! );
//!
//! assert_eq!(store.key_count(), 2);
//!
//! // Once the overlap has passed, the old key can go.
//! assert!(store.remove_key("acme.com", "key-2026"));
//! assert_eq!(store.key_count(), 1);
//! ```

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};

use crate::keys::VerifyingKey;

/// Where an instant falls relative to a key's publication window.
///
/// Returned by [`TrustedKey::validity_at`]. The variants carry the boundary
/// that was crossed so a caller can report *when* rather than merely *that*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyValidity {
    /// Inside the window, or the key has no window at all.
    Active,
    /// Before the key's `not_before`.
    NotYetValid {
        /// The instant the key becomes usable.
        not_before: DateTime<Utc>,
    },
    /// After the key's `not_after`.
    Expired {
        /// The instant the key stopped being usable.
        not_after: DateTime<Utc>,
    },
}

impl KeyValidity {
    /// Returns true for [`Self::Active`].
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// A verification key a trust root has published, with the window it applies in.
///
/// Both bounds are optional. A key with neither is trusted whenever it is in
/// the store, which is what [`Verifier::add_trusted_root`] produces and what
/// every deployment that does not rotate on a schedule wants. Section 7.2 of
/// the specification requires published keys to carry both, so a key built from
/// a fetched key document will have them.
///
/// [`Verifier::add_trusted_root`]: crate::Verifier::add_trusted_root
///
/// # Example
///
/// ```
/// use agent_uri_attestation::{KeyValidity, SigningKey, TrustedKey};
/// use chrono::{Duration, Utc};
///
/// let now = Utc::now();
/// let key = TrustedKey::new(SigningKey::generate().verifying_key())
///     .with_id("key-2026-01")
///     .not_before(now - Duration::days(1))
///     .not_after(now + Duration::days(1));
///
/// assert_eq!(key.id(), Some("key-2026-01"));
/// assert_eq!(key.validity_at(now, Duration::zero()), KeyValidity::Active);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    key: VerifyingKey,
    kid: Option<String>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
}

impl TrustedKey {
    /// A key with no identifier and no window: trusted for as long as it is held.
    #[must_use]
    pub fn new(key: VerifyingKey) -> Self {
        Self {
            key,
            kid: None,
            not_before: None,
            not_after: None,
        }
    }

    /// Names the key.
    ///
    /// The identifier is what [`TrustStore::remove_key`] takes and what a
    /// key-window rejection reports, and it is how re-reading a published key
    /// document updates a key in place rather than accumulating copies of it.
    #[must_use]
    pub fn with_id(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Sets the instant from which this key may be used.
    #[must_use]
    pub fn not_before(mut self, at: DateTime<Utc>) -> Self {
        self.not_before = Some(at);
        self
    }

    /// Sets the instant after which this key may no longer be used.
    #[must_use]
    pub fn not_after(mut self, at: DateTime<Utc>) -> Self {
        self.not_after = Some(at);
        self
    }

    /// The key itself.
    #[must_use]
    pub fn key(&self) -> &VerifyingKey {
        &self.key
    }

    /// The key's identifier, if it was given one.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The instant from which this key may be used, if it is bounded below.
    #[must_use]
    pub fn valid_from(&self) -> Option<DateTime<Utc>> {
        self.not_before
    }

    /// The instant after which this key may not be used, if it is bounded above.
    #[must_use]
    pub fn valid_until(&self) -> Option<DateTime<Utc>> {
        self.not_after
    }

    /// Pure function: where `now` falls in this key's window.
    ///
    /// `leeway` widens the window at both ends, for the same reason a token's
    /// validity window carries it: the root that published the schedule and the
    /// verifier reading it run different clocks, and a verifier a few seconds
    /// out of step should not open a gap in a rotation that was planned to have
    /// none.
    ///
    /// Both bounds are inclusive of the boundary instant, so a key is usable at
    /// exactly its `not_before` and at exactly its `not_after`.
    ///
    /// A key whose bounds are inverted (`not_after` before `not_before`) is
    /// never active: whichever bound `now` violates is reported, `not_before`
    /// first. Nothing prevents constructing one, and treating an incoherent
    /// window as permissive would be the wrong way to fail.
    #[must_use]
    pub fn validity_at(&self, now: DateTime<Utc>, leeway: Duration) -> KeyValidity {
        if let Some(not_before) = self.not_before
            && now < not_before - leeway
        {
            return KeyValidity::NotYetValid { not_before };
        }
        if let Some(not_after) = self.not_after
            && now > not_after + leeway
        {
            return KeyValidity::Expired { not_after };
        }
        KeyValidity::Active
    }
}

impl From<VerifyingKey> for TrustedKey {
    fn from(key: VerifyingKey) -> Self {
        Self::new(key)
    }
}

/// The set of trust roots a verifier trusts, and the keys held for each.
///
/// A root maps to a list rather than to a single key, which is what makes
/// rotation possible: the outgoing and incoming keys coexist for as long as the
/// overlap requires, and a token verifies under whichever one signed it.
///
/// # What a lookup costs
///
/// A token names its issuer in a claim, and a claim cannot be believed before
/// the signature that covers it has been checked. Verification therefore tries
/// keys until one works, so the store's total key count — not its root count —
/// bounds the Ed25519 operations an unverifiable token can buy. Keep retired
/// keys out of it.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::{SigningKey, TrustStore, TrustedKey};
///
/// let key = SigningKey::generate().verifying_key();
/// let mut store = TrustStore::new();
/// store.add("acme.com", TrustedKey::new(key));
///
/// assert!(store.contains_root("acme.com"));
/// assert_eq!(store.root_count(), 1);
///
/// assert_eq!(store.remove_root("acme.com"), 1);
/// assert!(store.is_empty());
/// ```
#[derive(Debug, Clone, Default)]
pub struct TrustStore {
    roots: HashMap<String, Vec<TrustedKey>>,
}

impl TrustStore {
    /// Creates an empty store, which trusts nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a key to a trust root, keeping the keys already held for it.
    ///
    /// Adding is idempotent: a key replaces one already present under the same
    /// root with the same identifier, or, for keys with no identifier, the same
    /// key material. Re-reading a published key document therefore updates the
    /// windows it carries rather than accumulating duplicates of every key in
    /// it.
    pub fn add(&mut self, trust_root: impl Into<String>, key: impl Into<TrustedKey>) {
        let key = key.into();
        let keys = self.roots.entry(trust_root.into()).or_default();
        match keys.iter_mut().find(|held| same_key(held, &key)) {
            Some(held) => *held = key,
            None => keys.push(key),
        }
    }

    /// [`Self::add`], as a builder step.
    #[must_use]
    pub fn with(mut self, trust_root: impl Into<String>, key: impl Into<TrustedKey>) -> Self {
        self.add(trust_root, key);
        self
    }

    /// Replaces every key held for a trust root with this one.
    ///
    /// The single-key operation, for a caller that is not rotating and wants
    /// the store to say exactly one thing about this root.
    pub fn set(&mut self, trust_root: impl Into<String>, key: impl Into<TrustedKey>) {
        self.roots.insert(trust_root.into(), vec![key.into()]);
    }

    /// Removes a trust root and every key held for it, returning how many keys
    /// that was.
    ///
    /// Returns 0 if the root was not present.
    pub fn remove_root(&mut self, trust_root: &str) -> usize {
        self.roots.remove(trust_root).map_or(0, |keys| keys.len())
    }

    /// Removes one key from a trust root by its identifier.
    ///
    /// Returns true if a key was removed. A root left with no keys is dropped,
    /// so a store never holds a root it would trust nothing for.
    pub fn remove_key(&mut self, trust_root: &str, kid: &str) -> bool {
        let Some(keys) = self.roots.get_mut(trust_root) else {
            return false;
        };
        let before = keys.len();
        keys.retain(|held| held.id() != Some(kid));
        let removed = keys.len() != before;
        if keys.is_empty() {
            self.roots.remove(trust_root);
        }
        removed
    }

    /// Returns true if any key is held for this trust root.
    ///
    /// Says nothing about whether those keys are inside their windows; see
    /// [`Self::has_active_key`].
    #[must_use]
    pub fn contains_root(&self, trust_root: &str) -> bool {
        self.roots.contains_key(trust_root)
    }

    /// Returns true if this trust root has at least one key usable at `now`.
    ///
    /// The question to ask before a rotation retires a key: a root with keys
    /// but none of them active verifies nothing.
    #[must_use]
    pub fn has_active_key(&self, trust_root: &str, now: DateTime<Utc>, leeway: Duration) -> bool {
        self.keys_for(trust_root)
            .iter()
            .any(|key| key.validity_at(now, leeway).is_active())
    }

    /// The keys held for a trust root, in the order they were added.
    ///
    /// Empty for a root that is not present.
    #[must_use]
    pub fn keys_for(&self, trust_root: &str) -> &[TrustedKey] {
        self.roots.get(trust_root).map_or(&[], Vec::as_slice)
    }

    /// The number of trust roots held.
    #[must_use]
    pub fn root_count(&self) -> usize {
        self.roots.len()
    }

    /// The number of keys held across every trust root.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.roots.values().map(Vec::len).sum()
    }

    /// Returns true if no trust root is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Every `(trust root, key)` pair held, in unspecified order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &TrustedKey)> {
        self.roots
            .iter()
            .flat_map(|(root, keys)| keys.iter().map(move |key| (root.as_str(), key)))
    }
}

/// Whether two keys occupy the same slot under a root.
///
/// Identity is the `kid` when there is one, because that is what a publisher
/// uses to say "this is the same key, with a corrected window". Keys without
/// one fall back to their material, which is the only thing left that
/// distinguishes them.
fn same_key(held: &TrustedKey, incoming: &TrustedKey) -> bool {
    match (held.id(), incoming.id()) {
        (Some(held_id), Some(incoming_id)) => held_id == incoming_id,
        (None, None) => held.key() == incoming.key(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::SigningKey;

    fn key() -> VerifyingKey {
        SigningKey::generate().verifying_key()
    }

    fn at(hour: u32) -> DateTime<Utc> {
        use chrono::TimeZone;
        Utc.with_ymd_and_hms(2026, 7, 31, hour, 0, 0).unwrap()
    }

    #[test]
    fn a_key_with_no_window_is_always_active() {
        let trusted = TrustedKey::new(key());

        assert_eq!(
            trusted.validity_at(at(0), Duration::zero()),
            KeyValidity::Active
        );
        assert_eq!(
            trusted.validity_at(DateTime::<Utc>::MAX_UTC, Duration::zero()),
            KeyValidity::Active
        );
    }

    #[test]
    fn a_key_before_its_window_reports_when_it_starts() {
        let trusted = TrustedKey::new(key()).not_before(at(12));

        assert_eq!(
            trusted.validity_at(at(11), Duration::zero()),
            KeyValidity::NotYetValid { not_before: at(12) }
        );
    }

    #[test]
    fn a_key_after_its_window_reports_when_it_ended() {
        let trusted = TrustedKey::new(key()).not_after(at(12));

        assert_eq!(
            trusted.validity_at(at(13), Duration::zero()),
            KeyValidity::Expired { not_after: at(12) }
        );
    }

    #[test]
    fn both_boundary_instants_are_inside_the_window() {
        let trusted = TrustedKey::new(key()).not_before(at(10)).not_after(at(12));

        assert_eq!(
            trusted.validity_at(at(10), Duration::zero()),
            KeyValidity::Active
        );
        assert_eq!(
            trusted.validity_at(at(12), Duration::zero()),
            KeyValidity::Active
        );
    }

    #[test]
    fn leeway_widens_the_window_at_both_ends() {
        let trusted = TrustedKey::new(key()).not_before(at(10)).not_after(at(12));
        let leeway = Duration::minutes(90);

        assert_eq!(
            trusted.validity_at(at(9), leeway),
            KeyValidity::Active,
            "a verifier an hour behind should not open a gap in a planned rotation"
        );
        assert_eq!(trusted.validity_at(at(13), leeway), KeyValidity::Active);
        assert!(!trusted.validity_at(at(8), leeway).is_active());
        assert!(!trusted.validity_at(at(14), leeway).is_active());
    }

    #[test]
    fn an_inverted_window_is_never_active() {
        let trusted = TrustedKey::new(key()).not_before(at(12)).not_after(at(10));

        for hour in 0..24 {
            assert!(
                !trusted.validity_at(at(hour), Duration::zero()).is_active(),
                "hour {hour} should not be inside an inverted window"
            );
        }
    }

    #[test]
    fn a_root_holds_more_than_one_key() {
        let mut store = TrustStore::new();
        store.add("acme.com", TrustedKey::new(key()).with_id("a"));
        store.add("acme.com", TrustedKey::new(key()).with_id("b"));

        assert_eq!(store.root_count(), 1);
        assert_eq!(store.key_count(), 2);
    }

    #[test]
    fn re_adding_a_key_by_id_updates_it_rather_than_duplicating_it() {
        let material = key();
        let mut store = TrustStore::new();
        store.add("acme.com", TrustedKey::new(material.clone()).with_id("a"));
        store.add(
            "acme.com",
            TrustedKey::new(material).with_id("a").not_after(at(12)),
        );

        assert_eq!(store.key_count(), 1);
        assert_eq!(store.keys_for("acme.com")[0].valid_until(), Some(at(12)));
    }

    #[test]
    fn re_adding_an_unnamed_key_matches_on_its_material() {
        let material = key();
        let mut store = TrustStore::new();
        store.add("acme.com", TrustedKey::new(material.clone()));
        store.add("acme.com", TrustedKey::new(material).not_after(at(12)));

        assert_eq!(store.key_count(), 1);
        assert_eq!(store.keys_for("acme.com")[0].valid_until(), Some(at(12)));
    }

    #[test]
    fn two_different_unnamed_keys_both_stay() {
        let mut store = TrustStore::new();
        store.add("acme.com", TrustedKey::new(key()));
        store.add("acme.com", TrustedKey::new(key()));

        assert_eq!(store.key_count(), 2);
    }

    #[test]
    fn setting_a_root_discards_the_keys_it_had() {
        let mut store = TrustStore::new();
        store.add("acme.com", TrustedKey::new(key()).with_id("a"));
        store.add("acme.com", TrustedKey::new(key()).with_id("b"));

        let replacement = key();
        store.set("acme.com", TrustedKey::new(replacement.clone()));

        assert_eq!(store.key_count(), 1);
        assert_eq!(store.keys_for("acme.com")[0].key(), &replacement);
    }

    #[test]
    fn removing_a_root_reports_how_many_keys_went_with_it() {
        let mut store = TrustStore::new();
        store.add("acme.com", TrustedKey::new(key()).with_id("a"));
        store.add("acme.com", TrustedKey::new(key()).with_id("b"));

        assert_eq!(store.remove_root("acme.com"), 2);
        assert_eq!(store.remove_root("acme.com"), 0);
        assert!(store.is_empty());
    }

    #[test]
    fn removing_the_last_key_removes_the_root_with_it() {
        let mut store = TrustStore::new();
        store.add("acme.com", TrustedKey::new(key()).with_id("a"));

        assert!(store.remove_key("acme.com", "a"));
        assert!(
            !store.contains_root("acme.com"),
            "a root with no keys trusts nothing and should not be reported as held"
        );
    }

    #[test]
    fn removing_a_key_leaves_its_siblings_alone() {
        let mut store = TrustStore::new();
        store.add("acme.com", TrustedKey::new(key()).with_id("a"));
        let kept = key();
        store.add("acme.com", TrustedKey::new(kept.clone()).with_id("b"));

        assert!(store.remove_key("acme.com", "a"));
        assert_eq!(store.key_count(), 1);
        assert_eq!(store.keys_for("acme.com")[0].key(), &kept);
    }

    #[test]
    fn removing_a_key_that_is_not_there_reports_it() {
        let mut store = TrustStore::new();
        store.add("acme.com", TrustedKey::new(key()).with_id("a"));

        assert!(!store.remove_key("acme.com", "b"));
        assert!(!store.remove_key("other.com", "a"));
        assert_eq!(store.key_count(), 1);
    }

    #[test]
    fn a_root_whose_keys_have_all_lapsed_still_counts_as_held() {
        let mut store = TrustStore::new();
        store.add("acme.com", TrustedKey::new(key()).not_after(at(10)));

        assert!(store.contains_root("acme.com"));
        assert!(!store.has_active_key("acme.com", at(11), Duration::zero()));
        assert!(store.has_active_key("acme.com", at(9), Duration::zero()));
    }

    #[test]
    fn an_absent_root_has_no_keys_and_no_active_key() {
        let store = TrustStore::new();

        assert!(store.keys_for("acme.com").is_empty());
        assert!(!store.has_active_key("acme.com", at(11), Duration::zero()));
    }

    #[test]
    fn iter_visits_every_key_under_every_root() {
        let mut store = TrustStore::new();
        store.add("acme.com", TrustedKey::new(key()).with_id("a"));
        store.add("acme.com", TrustedKey::new(key()).with_id("b"));
        store.add("other.com", TrustedKey::new(key()).with_id("c"));

        let mut ids: Vec<&str> = store.iter().filter_map(|(_, key)| key.id()).collect();
        ids.sort_unstable();

        assert_eq!(ids, ["a", "b", "c"]);
        assert_eq!(store.iter().count(), 3);
    }
}
