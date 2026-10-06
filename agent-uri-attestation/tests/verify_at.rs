//! Verifying and building at a supplied instant instead of the real clock.
//!
//! A caller that replays tokens it accepted earlier, or runs on a simulated
//! clock, has to ask "was this token valid at instant T", not "is it valid
//! now". These tests pin that every `_at` entry point judges both clock
//! dependent windows, the token's and the trusted key's, at the instant it is
//! given, in both directions, and changes nothing else about verification.

use std::time::Duration;

use agent_uri::{AgentUri, CapabilityPath};
use agent_uri_attestation::{
    AcceptAll, AttestationClaims, AttestationError, Denylist, Issuer, SigningKey, TrustedKey,
    Verifier,
};
use chrono::{DateTime, Duration as ChronoDuration, TimeZone, Utc};
use proptest::prelude::*;

const ROOT: &str = "acme.com";
const AUDIENCE: &str = "api.acme.com";

fn test_uri() -> AgentUri {
    AgentUri::parse("agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q").unwrap()
}

fn capability() -> CapabilityPath {
    CapabilityPath::parse("workflow/approval").unwrap()
}

/// A trust root's key and a verifier, at the default leeway, that trusts it.
fn trust() -> (SigningKey, Verifier) {
    let signing_key = SigningKey::generate();
    let mut verifier = Verifier::new().with_revocation(AcceptAll);
    verifier.add_trusted_root(ROOT, signing_key.verifying_key());
    (signing_key, verifier)
}

/// [`trust`] with no leeway, so the window's edges are exactly `iat` and `exp`.
fn strict_trust() -> (SigningKey, Verifier) {
    let signing_key = SigningKey::generate();
    let mut verifier = Verifier::with_leeway(Duration::ZERO).with_revocation(AcceptAll);
    verifier.add_trusted_root(ROOT, signing_key.verifying_key());
    (signing_key, verifier)
}

/// The claims of a token issued at `issued` that lives for `ttl`, restricted
/// to `audience` when one is given.
fn claims_issued_at(
    issued: DateTime<Utc>,
    ttl: Duration,
    audience: Option<&str>,
) -> AttestationClaims {
    let mut builder = AttestationClaims::builder()
        .agent_uri(test_uri().canonical())
        .agent_key(&SigningKey::generate().verifying_key())
        .issuer(ROOT)
        .add_capability("workflow/approval")
        .ttl(ttl);
    if let Some(audience) = audience {
        builder = builder.audience(audience);
    }
    builder.build_at(issued).unwrap()
}

fn sign(signing_key: &SigningKey, claims: &AttestationClaims) -> String {
    Issuer::new(ROOT, signing_key.clone(), Duration::from_hours(1))
        .issue_claims(claims)
        .unwrap()
}

/// Signs a token issued at `issued` that lives for `ttl`.
fn token_issued_at(
    signing_key: &SigningKey,
    issued: DateTime<Utc>,
    ttl: Duration,
    audience: Option<&str>,
) -> String {
    sign(signing_key, &claims_issued_at(issued, ttl, audience))
}

/// An unrestricted and an [`AUDIENCE`]-restricted token with the same window.
fn tokens_issued_at(
    signing_key: &SigningKey,
    issued: DateTime<Utc>,
    ttl: Duration,
) -> (String, String) {
    (
        token_issued_at(signing_key, issued, ttl, None),
        token_issued_at(signing_key, issued, ttl, Some(AUDIENCE)),
    )
}

/// `t` truncated to the millisecond: a token carries `iat` and `exp` at that
/// precision, so claims read back from one compare equal only to such an instant.
fn whole_millis(t: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_millis(t.timestamp_millis()).unwrap()
}

/// Corrupts a token's payload so that its decoded bytes definitely change.
fn tamper(token: &str) -> String {
    let mut parts: Vec<String> = token.split('.').map(String::from).collect();
    let payload = &mut parts[2];
    let midpoint = payload.len() / 2;
    let original = payload.as_bytes()[midpoint] as char;
    let replacement = if original == 'a' { 'b' } else { 'a' };
    payload.replace_range(midpoint..=midpoint, &replacement.to_string());
    parts.join(".")
}

/// Every `_at` entry point, run against one instant. The audience-free ones
/// get the unrestricted token, the audience-bound ones the restricted token.
fn every_entry_point_at(
    verifier: &Verifier,
    unrestricted: &str,
    restricted: &str,
    at: DateTime<Utc>,
) -> Vec<(&'static str, Result<AttestationClaims, AttestationError>)> {
    let uri = test_uri();
    let required = capability();
    vec![
        ("verify_at", verifier.verify_at(unrestricted, at)),
        (
            "verify_for_audience_at",
            verifier.verify_for_audience_at(restricted, AUDIENCE, at),
        ),
        (
            "verify_for_uri_at",
            verifier.verify_for_uri_at(unrestricted, &uri, at),
        ),
        (
            "verify_for_uri_and_audience_at",
            verifier.verify_for_uri_and_audience_at(restricted, &uri, AUDIENCE, at),
        ),
        (
            "verify_for_capability_at",
            verifier.verify_for_capability_at(unrestricted, &uri, &required, at),
        ),
        (
            "verify_for_capability_and_audience_at",
            verifier
                .verify_for_capability_and_audience_at(restricted, &uri, &required, AUDIENCE, at),
        ),
    ]
}

#[test]
fn a_token_verified_inside_its_window_passes_after_its_real_expiry() {
    let (signing_key, verifier) = trust();
    // Issued a day ago for one minute: long expired by the real clock.
    let issued = whole_millis(Utc::now() - ChronoDuration::days(1));
    let ttl = Duration::from_secs(60);
    let (unrestricted, restricted) = tokens_issued_at(&signing_key, issued, ttl);

    assert!(
        matches!(
            verifier.verify(&unrestricted),
            Err(AttestationError::TokenExpired { .. })
        ),
        "the real clock must still see the token as expired"
    );

    let inside = issued + ChronoDuration::seconds(30);
    for (entry_point, result) in every_entry_point_at(&verifier, &unrestricted, &restricted, inside)
    {
        let claims = result.unwrap_or_else(|error| {
            panic!("{entry_point} at an instant inside the window must pass, got {error:?}")
        });
        assert_eq!(claims.iat, issued, "{entry_point}");
        assert_eq!(
            claims.exp,
            issued + ChronoDuration::seconds(60),
            "{entry_point}"
        );
    }
}

#[test]
fn a_token_verified_past_its_exp_fails_before_its_real_expiry() {
    let (signing_key, verifier) = trust();
    // Issued now for an hour: valid by the real clock.
    let issued = Utc::now();
    let ttl = Duration::from_hours(1);
    let (unrestricted, restricted) = tokens_issued_at(&signing_key, issued, ttl);
    let exp = issued + ChronoDuration::hours(1);

    assert!(
        verifier.verify(&unrestricted).is_ok(),
        "the real clock must still see the token as valid"
    );

    // Past exp by more than the leeway the verifier grants.
    let past =
        exp + ChronoDuration::from_std(verifier.leeway()).unwrap() + ChronoDuration::seconds(1);
    for (entry_point, result) in every_entry_point_at(&verifier, &unrestricted, &restricted, past) {
        match result {
            Err(AttestationError::TokenExpired { expired_at }) => {
                let reported = DateTime::parse_from_rfc3339(&expired_at)
                    .expect("expired_at must be RFC 3339")
                    .with_timezone(&Utc);
                assert_eq!(
                    reported.timestamp_millis(),
                    exp.timestamp_millis(),
                    "{entry_point} must report the token's own exp"
                );
            }
            other => panic!("{entry_point} past exp must be TokenExpired, got {other:?}"),
        }
    }
}

#[test]
fn a_token_verified_before_its_iat_is_not_yet_valid_at_that_instant() {
    let (signing_key, verifier) = trust();
    // Valid by the real clock, but not yet issued an hour before it was.
    let issued = Utc::now();
    let (unrestricted, restricted) =
        tokens_issued_at(&signing_key, issued, Duration::from_hours(2));
    let before = issued - ChronoDuration::hours(1);

    for (entry_point, result) in every_entry_point_at(&verifier, &unrestricted, &restricted, before)
    {
        assert!(
            matches!(result, Err(AttestationError::TokenNotYetValid { .. })),
            "{entry_point} before iat must be TokenNotYetValid, got {result:?}"
        );
    }
}

#[test]
fn the_window_is_iat_inclusive_and_exp_exclusive_at_the_supplied_instant() {
    // Without leeway the window is exactly [iat, exp), the same edges the real
    // clock sees.
    let (signing_key, verifier) = strict_trust();
    let issued = Utc.with_ymd_and_hms(2030, 6, 1, 12, 0, 0).unwrap();
    let token = token_issued_at(&signing_key, issued, Duration::from_secs(60), None);
    let exp = issued + ChronoDuration::seconds(60);
    let one_milli = ChronoDuration::milliseconds(1);

    assert!(matches!(
        verifier.verify_at(&token, issued - one_milli),
        Err(AttestationError::TokenNotYetValid { .. })
    ));
    assert!(verifier.verify_at(&token, issued).is_ok());
    assert!(verifier.verify_at(&token, exp - one_milli).is_ok());
    assert!(matches!(
        verifier.verify_at(&token, exp),
        Err(AttestationError::TokenExpired { .. })
    ));
}

#[test]
fn the_leeway_widens_the_window_around_the_supplied_instant() {
    let (signing_key, verifier) = trust();
    let leeway = ChronoDuration::from_std(verifier.leeway()).unwrap();
    let issued = Utc.with_ymd_and_hms(2030, 6, 1, 12, 0, 0).unwrap();
    let token = token_issued_at(&signing_key, issued, Duration::from_secs(60), None);
    let exp = issued + ChronoDuration::seconds(60);
    let one_milli = ChronoDuration::milliseconds(1);

    assert!(verifier.verify_at(&token, issued - leeway).is_ok());
    assert!(matches!(
        verifier.verify_at(&token, issued - leeway - one_milli),
        Err(AttestationError::TokenNotYetValid { .. })
    ));
    assert!(verifier.verify_at(&token, exp + leeway - one_milli).is_ok());
    assert!(matches!(
        verifier.verify_at(&token, exp + leeway),
        Err(AttestationError::TokenExpired { .. })
    ));
}

#[test]
fn a_retired_key_verifies_a_token_at_an_instant_inside_its_window() {
    // The key's window and the token's are judged at the same supplied instant:
    // a key retired since the token was signed still vouches for it then.
    let signing_key = SigningKey::generate();
    let issued = whole_millis(Utc::now() - ChronoDuration::days(30));
    let retired = issued + ChronoDuration::days(1);
    let mut verifier = Verifier::with_leeway(Duration::ZERO).with_revocation(AcceptAll);
    verifier.add_trusted_key(
        ROOT,
        TrustedKey::new(signing_key.verifying_key())
            .with_id("2030-a")
            .not_before(issued - ChronoDuration::days(1))
            .not_after(retired),
    );
    // Still inside its own window by the real clock: only the key has lapsed.
    let token = token_issued_at(&signing_key, issued, Duration::from_hours(24 * 60), None);

    assert!(
        matches!(
            verifier.verify(&token),
            Err(AttestationError::KeyExpired { .. })
        ),
        "by the real clock the retired key must not vouch"
    );
    assert!(matches!(
        verifier.verify_at(&token, retired + ChronoDuration::hours(1)),
        Err(AttestationError::KeyExpired { .. })
    ));
    let claims = verifier
        .verify_at(&token, issued + ChronoDuration::hours(1))
        .unwrap();
    assert_eq!(claims.iat, issued);
}

#[test]
fn a_key_not_yet_in_service_at_the_supplied_instant_does_not_vouch() {
    let signing_key = SigningKey::generate();
    let issued = Utc.with_ymd_and_hms(2030, 6, 1, 12, 0, 0).unwrap();
    let in_service = issued + ChronoDuration::days(1);
    let mut verifier = Verifier::with_leeway(Duration::ZERO).with_revocation(AcceptAll);
    verifier.add_trusted_key(
        ROOT,
        TrustedKey::new(signing_key.verifying_key()).not_before(in_service),
    );
    let token = token_issued_at(&signing_key, issued, Duration::from_hours(48), None);

    assert!(matches!(
        verifier.verify_at(&token, issued + ChronoDuration::hours(1)),
        Err(AttestationError::KeyNotYetValid { .. })
    ));
    assert!(
        verifier
            .verify_at(&token, in_service + ChronoDuration::hours(1))
            .is_ok()
    );
}

#[test]
fn the_real_clock_entry_points_are_the_at_entry_points_at_now() {
    let (signing_key, verifier) = trust();
    let (unrestricted, restricted) =
        tokens_issued_at(&signing_key, Utc::now(), Duration::from_hours(1));
    let uri = test_uri();
    let required = capability();

    assert_eq!(
        verifier.verify(&unrestricted),
        verifier.verify_at(&unrestricted, Utc::now())
    );
    assert_eq!(
        verifier.verify_for_audience(&restricted, AUDIENCE),
        verifier.verify_for_audience_at(&restricted, AUDIENCE, Utc::now())
    );
    assert_eq!(
        verifier.verify_for_uri(&unrestricted, &uri),
        verifier.verify_for_uri_at(&unrestricted, &uri, Utc::now())
    );
    assert_eq!(
        verifier.verify_for_uri_and_audience(&restricted, &uri, AUDIENCE),
        verifier.verify_for_uri_and_audience_at(&restricted, &uri, AUDIENCE, Utc::now())
    );
    assert_eq!(
        verifier.verify_for_capability(&unrestricted, &uri, &required),
        verifier.verify_for_capability_at(&unrestricted, &uri, &required, Utc::now())
    );
    assert_eq!(
        verifier.verify_for_capability_and_audience(&restricted, &uri, &required, AUDIENCE),
        verifier.verify_for_capability_and_audience_at(
            &restricted,
            &uri,
            &required,
            AUDIENCE,
            Utc::now()
        )
    );
}

#[test]
fn a_supplied_instant_never_rescues_a_bad_signature() {
    // The signature is still checked first: a tampered token is a signature
    // failure at any instant, inside its window or not.
    let (signing_key, verifier) = trust();
    let issued = Utc::now() - ChronoDuration::days(1);
    let token = token_issued_at(&signing_key, issued, Duration::from_secs(60), None);
    let tampered = tamper(&token);

    for at in [
        issued + ChronoDuration::seconds(30),
        issued + ChronoDuration::days(2),
    ] {
        assert_eq!(
            verifier.verify_at(&tampered, at),
            Err(AttestationError::InvalidSignature)
        );
    }
}

#[test]
fn a_supplied_instant_never_rescues_a_revoked_token_or_key() {
    // Revocation is not a function of time: it is the verifier's current
    // denylist that decides, whatever instant the window is judged at.
    let signing_key = SigningKey::generate();
    let issued = Utc::now() - ChronoDuration::days(1);
    let inside = issued + ChronoDuration::seconds(30);
    let claims = claims_issued_at(issued, Duration::from_secs(60), None);
    let token = sign(&signing_key, &claims);

    let mut by_jti =
        Verifier::new().with_revocation(Denylist::new().revoke_token(claims.jti.clone()));
    by_jti.add_trusted_root(ROOT, signing_key.verifying_key());
    assert!(matches!(
        by_jti.verify_at(&token, inside),
        Err(AttestationError::TokenRevoked { .. })
    ));

    // Revoking the trust-root key that signed it refuses every token it signed.
    let mut by_key =
        Verifier::new().with_revocation(Denylist::new().revoke_key(&signing_key.verifying_key()));
    by_key.add_trusted_root(ROOT, signing_key.verifying_key());
    assert!(matches!(
        by_key.verify_at(&token, inside),
        Err(AttestationError::KeyRevoked { .. })
    ));
}

#[test]
fn a_supplied_instant_needs_a_revocation_source_like_the_real_clock() {
    let signing_key = SigningKey::generate();
    let issued = Utc::now() - ChronoDuration::days(1);
    let token = token_issued_at(&signing_key, issued, Duration::from_secs(60), None);
    let mut verifier = Verifier::new();
    verifier.add_trusted_root(ROOT, signing_key.verifying_key());

    assert_eq!(
        verifier.verify_at(&token, issued + ChronoDuration::seconds(30)),
        Err(AttestationError::RevocationUnavailable)
    );
}

#[test]
fn a_supplied_instant_changes_no_other_check() {
    let (signing_key, verifier) = trust();
    let issued = Utc::now() - ChronoDuration::days(1);
    let inside = issued + ChronoDuration::seconds(30);
    let (unrestricted, restricted) =
        tokens_issued_at(&signing_key, issued, Duration::from_secs(60));
    let other_uri =
        AgentUri::parse("agent://acme.com/workflow/review/rule_01h455vb4pex5vsknk084sn02q")
            .unwrap();

    // Untrusted: a verifier that trusts another key for the same root.
    let mut stranger = Verifier::new().with_revocation(AcceptAll);
    stranger.add_trusted_root(ROOT, SigningKey::generate().verifying_key());
    assert_eq!(
        stranger.verify_at(&unrestricted, inside),
        Err(AttestationError::InvalidSignature)
    );

    // Subject mismatch.
    assert!(matches!(
        verifier.verify_for_uri_at(&unrestricted, &other_uri, inside),
        Err(AttestationError::UriMismatch { .. })
    ));

    // Audience mismatch.
    assert!(matches!(
        verifier.verify_at(&restricted, inside),
        Err(AttestationError::AudienceMismatch { .. })
    ));
    assert!(matches!(
        verifier.verify_for_audience_at(&restricted, "api.evil.com", inside),
        Err(AttestationError::AudienceMismatch { .. })
    ));

    // Capability outside the attested identity, and one inside it.
    let narrower = CapabilityPath::parse("workflow/approval/invoice/delete").unwrap();
    assert!(matches!(
        verifier.verify_for_capability_at(
            &unrestricted,
            &test_uri(),
            &CapabilityPath::parse("workflow/review").unwrap(),
            inside
        ),
        Err(AttestationError::CapabilityOutsideIdentity { .. })
    ));
    assert!(
        verifier
            .verify_for_capability_at(&unrestricted, &test_uri(), &narrower, inside)
            .is_ok(),
        "a narrower path under an attested capability is covered"
    );
}

#[test]
fn build_at_places_the_window_at_the_supplied_instant() {
    let issued = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
    let claims = claims_issued_at(issued, Duration::from_secs(90), None);

    assert_eq!(claims.iat, issued);
    assert_eq!(claims.exp, issued + ChronoDuration::seconds(90));
}

#[test]
fn build_at_keeps_a_supplied_jti_and_mints_a_fresh_one_otherwise() {
    let issued = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
    let builder = || {
        AttestationClaims::builder()
            .agent_uri(test_uri().canonical())
            .agent_key(&SigningKey::generate().verifying_key())
            .issuer(ROOT)
            .ttl(Duration::from_secs(90))
    };

    let named = builder()
        .jti("01h455vb4pex5vsknk084sn02q")
        .build_at(issued)
        .unwrap();
    assert_eq!(named.jti, "01h455vb4pex5vsknk084sn02q");

    let first = builder().build_at(issued).unwrap();
    let second = builder().build_at(issued).unwrap();
    assert_ne!(
        first.jti, second.jti,
        "two tokens built at one instant are still two tokens"
    );
}

#[test]
fn build_is_build_at_the_real_clock() {
    let before = Utc::now();
    let claims = AttestationClaims::builder()
        .agent_uri(test_uri().canonical())
        .agent_key(&SigningKey::generate().verifying_key())
        .issuer(ROOT)
        .ttl(Duration::from_secs(90))
        .build()
        .unwrap();
    let after = Utc::now();

    assert!(before <= claims.iat && claims.iat <= after);
    assert_eq!(claims.exp, claims.iat + ChronoDuration::seconds(90));
}

#[test]
fn build_at_reports_an_unrepresentable_expiry_instead_of_panicking() {
    let result = AttestationClaims::builder()
        .agent_uri(test_uri().canonical())
        .agent_key(&SigningKey::generate().verifying_key())
        .issuer(ROOT)
        .ttl(Duration::from_hours(1))
        .build_at(DateTime::<Utc>::MAX_UTC);

    assert_eq!(result, Err(AttestationError::InvalidTtl));
}

#[test]
fn build_at_still_requires_every_field_build_requires() {
    let issued = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
    let without_key = AttestationClaims::builder()
        .agent_uri(test_uri().canonical())
        .issuer(ROOT)
        .build_at(issued);

    assert!(matches!(
        without_key,
        Err(AttestationError::MissingField { .. })
    ));
}

proptest! {
    // Each case signs and verifies, so keep the count modest.
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Verified at any instant without leeway, a token passes exactly when
    /// that instant lies in `[iat, exp)`, whatever the real clock says.
    #[test]
    fn verify_at_passes_exactly_inside_the_window(
        issued_offset_secs in -5_000_000_i64..5_000_000,
        ttl_secs in 1_u64..1_000_000,
        probe_secs in -1_000_000_i64..2_000_000,
    ) {
        let (signing_key, verifier) = strict_trust();
        let issued = whole_millis(Utc::now() + ChronoDuration::seconds(issued_offset_secs));
        let token = token_issued_at(&signing_key, issued, Duration::from_secs(ttl_secs), None);
        let probe = issued + ChronoDuration::seconds(probe_secs);

        let result = verifier.verify_at(&token, probe);
        let ttl = i64::try_from(ttl_secs).unwrap();
        if probe_secs < 0 {
            let is_early = matches!(result, Err(AttestationError::TokenNotYetValid { .. }));
            prop_assert!(is_early, "before iat: {result:?}");
        } else if probe_secs < ttl {
            prop_assert!(result.is_ok(), "inside the window: {result:?}");
        } else {
            let is_expired = matches!(result, Err(AttestationError::TokenExpired { .. }));
            prop_assert!(is_expired, "at or past exp: {result:?}");
        }
    }
}
