//! Tokens minted by an older `rusty_paseto` must still verify (issue #17).
//!
//! Attestations outlive the process that issued them: they sit in world-readable
//! DHT registration records for as long as their `exp` allows, and the verifier
//! that reads one is generally not the build that wrote it. So a `rusty_paseto`
//! upgrade is a wire-compatibility question, not just a dependency bump, and
//! nothing else in this crate's suite asks it — every other test mints and
//! verifies with the same build, which cannot detect a change that moves both
//! ends together.
//!
//! The token below was minted under `rusty_paseto` 0.9.0 from fixed key seeds
//! and is checked in verbatim. It is the only fixed token in the suite; the
//! canonical `test-vectors.json` carries claim sets rather than signed tokens,
//! so signature acceptance has no vector to check against.
//!
//! # Why this is not merely belt-and-braces
//!
//! 0.10 changed the v4.public verification path from ed25519-dalek's lenient
//! `verify()` to `verify_strict()`, which rejects signatures the old one
//! accepted: those over small-order public keys, and non-canonical encodings.
//! That is a deliberate tightening — it removes Ed25519 signature malleability —
//! but a tightening is exactly the kind of change that can also reject genuine
//! tokens. This test is the evidence that it does not.

use agent_uri_attestation::{AttestationError, Verifier, VerifyingKey};

/// Minted under `rusty_paseto` 0.9.0 with a trust-root seed of `[7u8; 32]`.
///
/// Claims: `iss` acme.com, `iat` 2026-01-01, `exp` 2126-01-01. The expiry is a
/// century out so the vector does not rot; a `TokenExpired` failure here means
/// the clock, not the token.
const TOKEN_FROM_0_9: &str = "v4.public.eyJhZ2VudF9rZXkiOiJHWDlySStGc2hUTEdxOGc0K3MxZXA0bStESGF5a2dNMEE1djZpejAyaldFPSIsImFnZW50X3VyaSI6ImFnZW50Oi8vYWNtZS5jb20vdGVzdC9hZ2VudF8wMWg0NTV2YjRwZXg1dnNrbmswODRzbjAycSIsImNhcGFiaWxpdGllcyI6WyJ0ZXN0L3JlYWQiXSwiZXhwIjoiMjEyNi0wMS0wMVQwMDowMDowMC4wMDBaIiwiaWF0IjoiMjAyNi0wMS0wMVQwMDowMDowMC4wMDBaIiwiaXNzIjoiYWNtZS5jb20iLCJuYmYiOiIyMDI2LTA3LTMxVDE3OjIwOjUzLjAwMjU3NzQ4MloifdVclS6K4TPzo_2DVQh7FrB7pPd4-qVXNyfQW1CgixP1QTTHcrKTxrn7njqp78TwgBnZOFWZuDxp4WFUkuxHCwQ";

/// The trust root's public key, from seed `[7u8; 32]`.
const ROOT_PUBLIC_KEY: &str = "6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=";

/// The attested agent's own public key, from seed `[42u8; 32]`.
const AGENT_PUBLIC_KEY: &str = "GX9rI+FshTLGq8g4+s1ep4m+DHaykgM0A5v6iz02jWE=";

fn verifier() -> Verifier {
    let key = VerifyingKey::from_base64(ROOT_PUBLIC_KEY).expect("the checked-in root key parses");
    let mut verifier = Verifier::new();
    verifier.add_trusted_root("acme.com", key);
    verifier
}

#[test]
fn a_token_minted_by_rusty_paseto_0_9_still_verifies() {
    let claims = verifier()
        .verify(TOKEN_FROM_0_9)
        .expect("a token minted under 0.9 must still verify");

    assert_eq!(claims.iss, "acme.com");
    assert_eq!(
        claims.agent_uri,
        "agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q"
    );
    assert_eq!(claims.capabilities, vec!["test/read"]);
    assert_eq!(claims.agent_key, AGENT_PUBLIC_KEY);
    assert_eq!(
        claims
            .agent_verifying_key()
            .expect("the attested agent key decodes")
            .to_base64(),
        AGENT_PUBLIC_KEY
    );
}

#[test]
fn the_checked_in_token_is_not_accepted_under_the_wrong_root_key() {
    // Guards the test above from passing vacuously. If `verify` were to accept
    // this token under a key that did not sign it, the first test would prove
    // nothing about signature verification at all.
    let other = VerifyingKey::from_base64(AGENT_PUBLIC_KEY).expect("a valid, unrelated key");
    let mut verifier = Verifier::new();
    verifier.add_trusted_root("acme.com", other);

    assert_eq!(
        verifier.verify(TOKEN_FROM_0_9),
        Err(AttestationError::InvalidSignature)
    );
}

#[test]
fn a_tampered_0_9_token_is_rejected() {
    // The payload is authenticated, so editing a claim inside it must break the
    // signature rather than change what the token says.
    let tampered = TOKEN_FROM_0_9.replace("eyJhZ2VudF9rZXki", "eyJhZ2VudF9rZXlx");

    assert_ne!(tampered, TOKEN_FROM_0_9, "the edit must actually change it");
    assert!(
        verifier().verify(&tampered).is_err(),
        "an edited token must not verify"
    );
}
