//! A publication host compromise, end to end, against a verifier that pins the
//! trust root's offline root key.
//!
//! Specification section 8.12 is the threat: an attacker who can write to
//! whatever serves `/.well-known/agent-keys.json` replaces the document with
//! one listing keys they hold. Every channel check still passes, because the
//! bytes really did come from the right host over a real certificate. What
//! follows is what the signed form of section 7.2 changes about the outcome.
//!
//! The socket is the one part not exercised, as in `published_keys.rs`: these
//! tests hand the verifier the bytes the attacker would have served.

use std::time::Duration;

use agent_uri::AgentUri;
use agent_uri_attestation::{
    AttestationError, DocumentSigner, DocumentVersion, Issuer, KeyDocument, KeyDocumentPayload,
    SignedKeyDocument, SigningKey, Verifier, VerifyingKey,
};
use agent_uri_attestation_wellknown::PinnedRootKeys;
use chrono::{Duration as ChronoDuration, Utc};

const TRUST_ROOT: &str = "acme.com";
const URI: &str = "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q";

/// The bare document a root publishes for the signing keys given.
fn document(keys: &[(&str, &VerifyingKey)]) -> KeyDocument {
    let now = Utc::now();
    let entries: Vec<String> = keys
        .iter()
        .map(|(kid, key)| {
            format!(
                r#"{{"kid": "{kid}", "algorithm": "Ed25519", "public_key": "{}",
                     "not_before": "{}", "not_after": "{}"}}"#,
                key.to_base64(),
                (now - ChronoDuration::days(1)).to_rfc3339(),
                (now + ChronoDuration::days(365)).to_rfc3339()
            )
        })
        .collect();

    KeyDocument::parse(&format!(
        r#"{{"trust_root": "{TRUST_ROOT}", "keys": [{}]}}"#,
        entries.join(", ")
    ))
    .expect("the fixture document parses")
}

/// What the root serves: the document, signed by its offline root key.
fn publish(root_key: &SigningKey, document: KeyDocument, version: u64) -> String {
    KeyDocumentPayload::new(
        document,
        DocumentVersion::new(version),
        Utc::now() + ChronoDuration::days(7),
    )
    .to_signed_json(&[DocumentSigner::new(root_key).named("root-2026")])
    .expect("the fixture payload renders")
}

/// The verifier a pinning deployment builds from an accepted document.
fn verifier_from(document: &KeyDocument) -> Verifier {
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
fn a_document_the_root_signed_offline_produces_a_working_verifier() {
    let root_key = SigningKey::generate();
    let signing_key = SigningKey::generate();
    let pinned = PinnedRootKeys::new(root_key.verifying_key());

    let served = publish(
        &root_key,
        document(&[("key-2026", &signing_key.verifying_key())]),
        1,
    );

    let payload = SignedKeyDocument::parse(&served)
        .expect("the document parses")
        .verify(pinned.keys())
        .expect("the pinned root key signed it");

    let claims = verifier_from(payload.document())
        .verify(&token_from(&signing_key))
        .expect("a token signed by a published key must verify");

    assert_eq!(claims.iss, TRUST_ROOT);
    assert_eq!(claims.agent_uri, URI);
}

#[test]
fn an_attacker_who_owns_the_web_host_cannot_swap_in_keys_of_their_own() {
    // Section 8.12's threat, with the mitigation in place. The attacker writes
    // a perfectly well-formed document naming a key they hold and signs it with
    // the best key they have, which is not the one that was pinned.
    let root_key = SigningKey::generate();
    let attacker_root = SigningKey::generate();
    let attacker_signing = SigningKey::generate();
    let pinned = PinnedRootKeys::new(root_key.verifying_key());

    let forged = publish(
        &attacker_root,
        document(&[("key-2026", &attacker_signing.verifying_key())]),
        2,
    );

    assert_eq!(
        SignedKeyDocument::parse(&forged)
            .expect("the forged document is well-formed; that is the point")
            .verify(pinned.keys()),
        Err(AttestationError::InvalidSignature)
    );
}

#[test]
fn an_attacker_cannot_keep_the_root_signature_and_change_what_it_covers() {
    // The other shape of the same attack: take the document the root really
    // signed, edit the key it publishes, and serve it with the real signature.
    let root_key = SigningKey::generate();
    let honest_key = SigningKey::generate().verifying_key();
    let attacker_key = SigningKey::generate().verifying_key();
    let pinned = PinnedRootKeys::new(root_key.verifying_key());

    let served = publish(&root_key, document(&[("key-2026", &honest_key)]), 3);
    let tampered = served.replace(&honest_key.to_base64(), &attacker_key.to_base64());
    assert_ne!(
        tampered, served,
        "the fixture must actually have been edited"
    );

    assert_eq!(
        SignedKeyDocument::parse(&tampered)
            .expect("the tampered document is still well-formed")
            .verify(pinned.keys()),
        Err(AttestationError::InvalidSignature)
    );
}

#[test]
fn the_signed_form_still_carries_the_revocations_a_verifier_acts_on() {
    // Signing changes who may write the document, not what it says. A key the
    // root has revoked is still refused, and now the revocation cannot be
    // deleted by whoever holds the host.
    let root_key = SigningKey::generate();
    let leaked = SigningKey::generate();
    let sound = SigningKey::generate();
    let pinned = PinnedRootKeys::new(root_key.verifying_key());

    let with_revocation = KeyDocument::parse(&format!(
        r#"{{"trust_root": "{TRUST_ROOT}",
             "keys": {},
             "revoked_keys": [{{"public_key": "{}"}}]}}"#,
        serde_json::to_string(
            document(&[
                ("leaked", &leaked.verifying_key()),
                ("sound", &sound.verifying_key())
            ])
            .keys()
        )
        .unwrap(),
        leaked.verifying_key().to_base64()
    ))
    .expect("the fixture document parses");

    let served = publish(&root_key, with_revocation, 4);
    let payload = SignedKeyDocument::parse(&served)
        .unwrap()
        .verify(pinned.keys())
        .expect("the pinned root key signed it");
    let verifier = verifier_from(payload.document());

    assert_eq!(
        verifier.verify(&token_from(&leaked)),
        Err(AttestationError::KeyRevoked {
            issuer: TRUST_ROOT.to_string()
        })
    );
    assert!(verifier.verify(&token_from(&sound)).is_ok());
}

#[test]
fn a_stale_signed_document_stops_being_accepted_at_its_expiry() {
    // The bound on what replay buys an attacker who cannot forge a signature:
    // they can serve old bytes the root really signed, but not indefinitely.
    let root_key = SigningKey::generate();
    let signing_key = SigningKey::generate();
    let pinned = PinnedRootKeys::new(root_key.verifying_key());

    let expired = KeyDocumentPayload::new(
        document(&[("key-2026", &signing_key.verifying_key())]),
        DocumentVersion::FIRST,
        Utc::now() - ChronoDuration::days(1),
    )
    .to_signed_json(&[DocumentSigner::new(&root_key)])
    .expect("the fixture payload renders");

    let error = SignedKeyDocument::parse(&expired)
        .unwrap()
        .verify(pinned.keys())
        .expect_err("a document past its expiry must be refused");

    assert!(
        matches!(error, AttestationError::DocumentExpired { .. }),
        "{error}"
    );
}

#[test]
fn a_root_key_rotation_keeps_verifiers_pinning_either_key_working() {
    // Section 7.2 requirement 5. The root publishes signed by both keys for the
    // overlap window; a verifier that has updated its pin and one that has not
    // both accept the same document.
    let outgoing = SigningKey::generate();
    let incoming = SigningKey::generate();
    let signing_key = SigningKey::generate();

    let served = KeyDocumentPayload::new(
        document(&[("key-2026", &signing_key.verifying_key())]),
        DocumentVersion::new(5),
        Utc::now() + ChronoDuration::days(7),
    )
    .to_signed_json(&[
        DocumentSigner::new(&outgoing).named("root-2026"),
        DocumentSigner::new(&incoming).named("root-2027"),
    ])
    .expect("the fixture payload renders");

    let document = SignedKeyDocument::parse(&served).unwrap();

    assert!(
        document
            .verify(PinnedRootKeys::new(outgoing.verifying_key()).keys())
            .is_ok()
    );
    assert!(
        document
            .verify(PinnedRootKeys::new(incoming.verifying_key()).keys())
            .is_ok()
    );
    assert!(
        document
            .verify(PinnedRootKeys::new(SigningKey::generate().verifying_key()).keys())
            .is_err()
    );
}
