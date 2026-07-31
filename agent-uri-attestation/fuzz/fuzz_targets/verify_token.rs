//! Fuzzes the verifier's outer surface: an arbitrary string must be refused,
//! and must be refused by returning rather than by panicking.
//!
//! An attestation token arrives from whoever is presenting it, so this is the
//! function that reads attacker-controlled bytes first. A panic here is a
//! denial of service in every service that verifies one.
//!
//! What this target reaches is the structural path: length cap, PASETO framing,
//! base64, signature. It will not get past the signature, because forging
//! Ed25519 is what the whole scheme rests on not being possible. Reaching the
//! claims logic needs a *signed* payload, which is what `verify_signed_claims`
//! does.
//!
//! No seed in this target's corpus is a token that verifies, and none may
//! become one. The seeds are structurally real — full PASETO framing, real
//! base64, a real claims payload — with the signature broken, so they hand the
//! mutator the shape of a token without ever satisfying the assertion below. A
//! genuinely valid seed would also stop being valid at its `exp`, which is the
//! opposite of the reproducibility the fixed keys in the harness exist for.

#![no_main]

use agent_uri::{AgentUri, CapabilityPath};
use agent_uri_attestation_fuzz as harness;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &str| {
    let verifier = harness::verifier();

    // Every entry point, because each one runs its own checks after the shared
    // ones and a panic in any of them is the same denial of service.
    let accepted = verifier.verify(input).is_ok()
        || verifier.verify_for_audience(input, "api.acme.com").is_ok();

    assert!(
        !accepted,
        "an unsigned string verified; that would mean a forged token is acceptable"
    );

    let uri = AgentUri::parse("agent://acme.com/test/llm_01h455vb4pex5vsknk084sn02q")
        .expect("the fixed URI is valid");
    let capability = CapabilityPath::parse("test").expect("the fixed capability is valid");

    assert!(verifier.verify_for_uri(input, &uri).is_err());
    assert!(
        verifier
            .verify_for_uri_and_audience(input, &uri, "api.acme.com")
            .is_err()
    );
    assert!(
        verifier
            .verify_for_capability(input, &uri, &capability)
            .is_err()
    );
    assert!(
        verifier
            .verify_for_capability_and_audience(input, &uri, &capability, "api.acme.com")
            .is_err()
    );
});
