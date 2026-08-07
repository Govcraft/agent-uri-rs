//! Fuzzes the key-document parsers and the signed form's verification.
//!
//! A key document arrives from whatever answers a trust root's well-known
//! endpoint, which under specification section 8.12 is exactly the party a
//! pinning deployment has decided not to believe. A panic in this path is a
//! denial of service in every verifier that refreshes its keys, and it is
//! reachable by anyone who can serve bytes at that URL.
//!
//! Two assertions, both about the same boundary:
//!
//! - a document must never verify against a pinned root key that did not sign
//!   it, which is the whole of what pinning buys;
//! - a document must never verify after its `expires`, which is what bounds
//!   replay of a document the root really did sign.

#![no_main]

use agent_uri_attestation::{ServedDocument, SignedKeyDocument};
use agent_uri_attestation_fuzz as harness;
use chrono::Utc;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    // Whatever form the bytes are in, reading them must return rather than panic.
    let _ = ServedDocument::parse(input);
    let _ = agent_uri_attestation::KeyDocument::parse(input);

    let Ok(document) = SignedKeyDocument::parse(input) else {
        return;
    };

    // The fixed pinned key never signed anything in the corpus, and cannot: the
    // seeds carry broken signatures, and forging one is what Ed25519 rests on
    // not being possible.
    let pinned = [harness::untrusted_signer().verifying_key()];

    assert!(
        document.verify(&pinned).is_err(),
        "a document verified against a root key that did not sign it"
    );

    // A document past its expiry must be refused whoever signed it, so checking
    // it against every key in the harness must still fail once time has passed.
    let far_future = Utc::now() + chrono::Duration::days(365 * 100);
    let every_key: Vec<_> = (0..=9u8)
        .map(|seed| harness::signer(seed).verifying_key())
        .collect();

    assert!(
        document
            .verify_at(&every_key, far_future, std::time::Duration::ZERO)
            .is_err(),
        "a document was accepted a century after it expired"
    );
});
