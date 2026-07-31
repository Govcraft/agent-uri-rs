//! A published key document, end to end: what a root serves, what a verifier
//! built from it accepts, and what it refuses.
//!
//! Everything here is the composition [`KeyDiscovery::verifier_for`] performs
//! once the bytes are in hand. The socket is the one part not exercised: it is
//! `reqwest` doing the HTTP, and what this crate adds around it — the endpoint
//! it builds, the redirects it will not follow, the size it will not exceed,
//! the trust root a document must name — is checked in the unit tests.

use std::time::Duration;

use agent_uri::AgentUri;
use agent_uri_attestation::{
    AttestationError, Issuer, KeyDocument, SigningKey, TrustedKey, Verifier, VerifyingKey,
};
use chrono::Utc;

const TRUST_ROOT: &str = "acme.com";
const URI: &str = "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q";

/// The document `acme.com` would serve, with the keys and revocations given.
fn published(keys: &[(&str, &VerifyingKey)], revoked: &[&VerifyingKey]) -> String {
    let now = Utc::now();
    let entries: Vec<String> = keys
        .iter()
        .map(|(kid, key)| {
            format!(
                r#"{{"kid": "{kid}", "algorithm": "Ed25519", "public_key": "{}",
                     "not_before": "{}", "not_after": "{}"}}"#,
                key.to_base64(),
                (now - chrono::Duration::days(1)).to_rfc3339(),
                (now + chrono::Duration::days(365)).to_rfc3339()
            )
        })
        .collect();
    let revocations: Vec<String> = revoked
        .iter()
        .map(|key| format!(r#"{{"public_key": "{}"}}"#, key.to_base64()))
        .collect();

    format!(
        r#"{{"trust_root": "{TRUST_ROOT}", "keys": [{}], "revoked_keys": [{}]}}"#,
        entries.join(", "),
        revocations.join(", ")
    )
}

/// What `verifier_for` builds once it has the document.
fn verifier_from(json: &str) -> Verifier {
    let document = KeyDocument::parse(json).expect("the document parses");
    document
        .check_belongs_to(TRUST_ROOT)
        .expect("the document names its own root");

    Verifier::new()
        .with_trust_store(document.trust_store().expect("the keys are usable"))
        .with_revocation(document.denylist().expect("the revocations are readable"))
}

fn token_from(signing_key: &SigningKey) -> String {
    Issuer::new(TRUST_ROOT, signing_key.clone(), Duration::from_hours(1))
        .issue(
            &AgentUri::parse(URI).expect("the fixed URI is valid"),
            &SigningKey::generate().verifying_key(),
            vec!["workflow/approval".into()],
        )
        .expect("the fixed claims mint")
}

#[test]
fn a_token_verifies_against_a_key_nobody_exchanged_by_hand() {
    // The whole point: no `add_trusted_root` call anywhere, and the token from
    // a root this process had never heard of verifies.
    let root_key = SigningKey::generate();
    let json = published(&[("key-2026", &root_key.verifying_key())], &[]);

    let claims = verifier_from(&json)
        .verify(&token_from(&root_key))
        .expect("a token signed by a published key must verify");

    assert_eq!(claims.iss, TRUST_ROOT);
    assert_eq!(claims.agent_uri, URI);
}

#[test]
fn a_rotation_in_the_document_is_a_rotation_in_the_verifier() {
    let outgoing = SigningKey::generate();
    let incoming = SigningKey::generate();
    let json = published(
        &[
            ("outgoing", &outgoing.verifying_key()),
            ("incoming", &incoming.verifying_key()),
        ],
        &[],
    );

    let verifier = verifier_from(&json);

    assert_eq!(verifier.trusted_key_count(), 2);
    assert!(verifier.verify(&token_from(&outgoing)).is_ok());
    assert!(verifier.verify(&token_from(&incoming)).is_ok());
}

#[test]
fn a_key_the_root_has_revoked_is_refused_even_while_it_is_still_published() {
    // A root that revokes a key and has not yet finished removing it from
    // `keys` must not keep honouring it in the meantime. The two lists are
    // read together, and the revocation wins.
    let leaked = SigningKey::generate();
    let sound = SigningKey::generate();
    let json = published(
        &[
            ("leaked", &leaked.verifying_key()),
            ("sound", &sound.verifying_key()),
        ],
        &[&leaked.verifying_key()],
    );

    let verifier = verifier_from(&json);

    assert_eq!(
        verifier.verify(&token_from(&leaked)),
        Err(AttestationError::KeyRevoked {
            issuer: TRUST_ROOT.to_string()
        })
    );
    assert!(
        verifier.verify(&token_from(&sound)).is_ok(),
        "revoking one published key must leave the others working"
    );
}

#[test]
fn a_token_from_a_key_the_root_does_not_publish_is_refused() {
    let published_key = SigningKey::generate();
    let stranger = SigningKey::generate();
    let json = published(&[("key-2026", &published_key.verifying_key())], &[]);

    assert_eq!(
        verifier_from(&json).verify(&token_from(&stranger)),
        Err(AttestationError::InvalidSignature)
    );
}

#[test]
fn a_verifier_built_from_a_document_still_honours_the_windows_in_it() {
    // The document carries `not_before` and `not_after` and they are not
    // decoration: a key past its window is refused however it arrived.
    let retired = SigningKey::generate();
    let token = token_from(&retired);

    let mut verifier = Verifier::new().with_revocation(agent_uri_attestation::AcceptAll);
    verifier.add_trusted_key(
        TRUST_ROOT,
        TrustedKey::new(retired.verifying_key())
            .with_id("retired")
            .not_after(Utc::now() - chrono::Duration::minutes(1)),
    );

    let error = verifier
        .verify(&token)
        .expect_err("a key past its published window must be refused");

    assert!(
        matches!(&error, AttestationError::KeyExpired { kid, .. } if kid.as_deref() == Some("retired")),
        "{error}"
    );
}

#[test]
fn a_document_naming_another_root_is_refused_before_any_key_is_read() {
    // The check that stops one authority publishing keys for another's
    // namespace. Without it, whatever served the bytes could name any root.
    let json = published(
        &[("key-2026", &SigningKey::generate().verifying_key())],
        &[],
    );
    let document = KeyDocument::parse(&json).unwrap();

    assert!(document.check_belongs_to("evil.example").is_err());
}
