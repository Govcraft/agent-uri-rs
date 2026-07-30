//! What an attacker who can reach a node cannot do.
//!
//! The unit tests in `validate` prove the rules in isolation. These prove the
//! rules are actually on the path a record travels: published from one node,
//! stored on several, read back by a third.

mod support;

use std::time::Duration;

use agent_uri::AgentUri;
use agent_uri_attestation::SigningKey;
use agent_uri_dht::{Dht, DhtError, Endpoint, Mutation, MutationProof, Registration, WriteOptions};
use support::{
    Overlay, TRUST_ROOT, exact, lookup, lookup_until_found, proof_for, register, write_options,
};

/// The write options an attacker would use: whatever gets the record furthest.
fn attacker_options() -> WriteOptions {
    write_options()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registration_signed_by_the_wrong_key_never_reaches_the_overlay() {
    // #50 over the network. The attacker holds a valid token for the URI and
    // signs with a key that token does not name.
    let overlay = Overlay::start(3).await;
    let (uri, _, registration) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "a.example:443",
    );
    let attacker = SigningKey::generate();

    let result = register(&overlay.nodes[0], registration, &attacker).await;

    assert!(
        matches!(result, Err(DhtError::Unauthorized { .. })),
        "expected the write to be refused, got {result:?}"
    );
    assert!(lookup(&overlay.nodes[2], &exact(&uri)).await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lifted_token_cannot_be_used_to_claim_an_agents_uri() {
    // #51 over the network. The attacker has the victim's token, from a lookup,
    // and signs correctly, with their own key.
    let overlay = Overlay::start(3).await;
    let (uri, victim, victim_registration) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "honest.example:443",
    );
    register(&overlay.nodes[0], victim_registration.clone(), &victim)
        .await
        .unwrap();
    let _ = lookup_until_found(&overlay.nodes[2], &exact(&uri)).await;

    let token = victim_registration
        .attestation()
        .expect("the victim published a token")
        .to_string();
    let attacker = SigningKey::generate();
    let forged = Registration::new(
        uri.clone(),
        attacker.verifying_key(),
        vec![Endpoint::https("attacker.example:443")],
    )
    .with_attestation(token);

    let result = register(&overlay.nodes[1], forged, &attacker).await;

    assert!(
        matches!(result, Err(DhtError::AgentKeyMismatch { .. })),
        "expected the token to be refused for another key, got {result:?}"
    );
    let found = lookup(&overlay.nodes[2], &exact(&uri)).await;
    assert_eq!(found[0].endpoints()[0].address(), "honest.example:443");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_attacker_cannot_repoint_an_agent_they_did_not_register() {
    let overlay = Overlay::start(3).await;
    let (uri, agent, registration) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "honest.example:443",
    );
    register(&overlay.nodes[0], registration, &agent)
        .await
        .unwrap();
    let _ = lookup_until_found(&overlay.nodes[2], &exact(&uri)).await;

    let attacker = SigningKey::generate();
    let stolen = vec![Endpoint::https("attacker.example:443")];
    let proof = proof_for(
        &overlay.nodes[1],
        &uri,
        &attacker,
        &Mutation::UpdateEndpoint { endpoints: &stolen },
    )
    .await;

    let result = overlay.nodes[1]
        .update_endpoint(&uri, stolen, &proof, attacker_options())
        .await;

    assert!(
        matches!(result, Err(DhtError::Unauthorized { .. })),
        "expected the migration to be refused, got {result:?}"
    );
    let found = lookup(&overlay.nodes[2], &exact(&uri)).await;
    assert_eq!(found[0].endpoints()[0].address(), "honest.example:443");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_attacker_cannot_evict_an_agent_they_did_not_register() {
    let overlay = Overlay::start(3).await;
    let (uri, agent, registration) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "honest.example:443",
    );
    register(&overlay.nodes[0], registration, &agent)
        .await
        .unwrap();
    let _ = lookup_until_found(&overlay.nodes[2], &exact(&uri)).await;

    let attacker = SigningKey::generate();
    let proof = proof_for(&overlay.nodes[1], &uri, &attacker, &Mutation::Deregister).await;

    let result = overlay.nodes[1]
        .deregister(&uri, &proof, attacker_options())
        .await;

    assert!(matches!(result, Err(DhtError::Unauthorized { .. })));
    assert_eq!(lookup(&overlay.nodes[2], &exact(&uri)).await.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replayed_write_does_not_apply_twice() {
    // A proof travels in the clear beside the operation it authorizes. Applying
    // one twice has to be refused by the record's own sequence, because
    // nothing stops a node on the path keeping a copy.
    let overlay = Overlay::start(3).await;
    let (uri, agent, registration) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "first.example:443",
    );
    register(&overlay.nodes[0], registration, &agent)
        .await
        .unwrap();
    let _ = lookup_until_found(&overlay.nodes[2], &exact(&uri)).await;

    let second = vec![Endpoint::https("second.example:443")];
    let proof = proof_for(
        &overlay.nodes[0],
        &uri,
        &agent,
        &Mutation::UpdateEndpoint { endpoints: &second },
    )
    .await;
    overlay.nodes[0]
        .update_endpoint(&uri, second.clone(), &proof, write_options())
        .await
        .unwrap();

    // Wait for the first application to be the record everyone holds.
    for _ in 0..20 {
        let found = lookup(&overlay.nodes[0], &exact(&uri)).await;
        if found
            .first()
            .is_some_and(|r| r.endpoints()[0].address() == "second.example:443")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let replayed = overlay.nodes[0]
        .update_endpoint(&uri, second, &proof, write_options())
        .await;

    assert!(
        matches!(replayed, Err(DhtError::Rejected { .. })),
        "expected the replay to be refused, got {replayed:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_cannot_register_under_a_trust_root_it_has_no_token_for() {
    // Cross-namespace issuance, SPECIFICATION.md §8.9: a token from one
    // authority must not place an agent under another's.
    let overlay = Overlay::start(3).await;
    let agent = SigningKey::generate();
    let foreign =
        AgentUri::parse("agent://openai.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q")
            .unwrap();
    let token = overlay
        .issuer
        .issue(
            &AgentUri::parse(&format!(
                "agent://{TRUST_ROOT}/assistant/chat/llm_01h455vb4pex5vsknk084sn02q"
            ))
            .unwrap(),
            &agent.verifying_key(),
            vec![],
        )
        .unwrap();
    let registration = Registration::new(
        foreign.clone(),
        agent.verifying_key(),
        vec![Endpoint::https("a.example:443")],
    )
    .with_attestation(token);

    // The nodes do not know openai.com, so under the default policy they store
    // the record without verifying it. What must not happen is the record
    // appearing under anthropic.com, whose key derivation it never touches.
    let _ = register(&overlay.nodes[0], registration, &agent).await;

    let under_anthropic = lookup(&overlay.nodes[2], &support::prefix("assistant")).await;
    assert!(
        under_anthropic.is_empty(),
        "a foreign agent surfaced under this trust root"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_holding_the_wrong_key_for_a_trust_root_serves_nothing_from_it() {
    // The failure that partitions an overlay by misconfiguration rather than by
    // network. It is worth a test because the symptom, an empty lookup, looks
    // identical to an agent that was never registered.
    let left = Overlay::start(2).await;
    let (uri, key, registration) = left.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "a.example:443",
    );
    register(&left.nodes[0], registration, &key).await.unwrap();
    assert!(
        !lookup_until_found(&left.nodes[1], &exact(&uri))
            .await
            .is_empty()
    );

    // Same trust root name, different key. This overlay is a different
    // authority wearing the same name.
    let impostor = Overlay::start(2).await;
    impostor.connect_to(&left).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        lookup(&impostor.nodes[0], &exact(&uri)).await.is_empty(),
        "a node verified a record against a key it does not hold"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registration_whose_lifetime_exceeds_the_nodes_ceiling_is_refused() {
    let overlay = Overlay::start(3).await;
    let (uri, key, registration) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "a.example:443",
    );
    // The default ceiling is 24 hours, and the record is refused rather than
    // clamped: clamping would alter bytes the signature covers.
    let greedy = registration.with_ttl(Duration::from_hours(48));

    let result = register(&overlay.nodes[0], greedy, &key).await;

    assert!(
        matches!(result, Err(DhtError::Rejected { .. })),
        "expected the lifetime to be refused, got {result:?}"
    );
    assert!(lookup(&overlay.nodes[2], &exact(&uri)).await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_re_registration_after_deregistration_is_not_evicted_by_the_old_tombstone() {
    // The defect that broke the first version of the mutation proofs: a record
    // that starts its sequence over sits below every proof its previous
    // incarnation handed out.
    let overlay = Overlay::start(3).await;
    let (uri, key, registration) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "first.example:443",
    );
    register(&overlay.nodes[0], registration, &key)
        .await
        .unwrap();
    let _ = lookup_until_found(&overlay.nodes[2], &exact(&uri)).await;

    let proof = proof_for(&overlay.nodes[0], &uri, &key, &Mutation::Deregister).await;
    overlay.nodes[0]
        .deregister(&uri, &proof, write_options())
        .await
        .unwrap();

    // Return under a later registration time, continuing the sequence rather
    // than restarting it, which is what `with_sequence` is for.
    let token = overlay
        .issuer
        .issue(&uri, &key.verifying_key(), vec![])
        .unwrap();
    let returning = Registration::new(
        uri.clone(),
        key.verifying_key(),
        vec![Endpoint::https("second.example:443")],
    )
    .with_attestation(token)
    .with_sequence(100);
    let returning_proof = MutationProof::sign_registration(&key, &returning);
    overlay.nodes[0]
        .register(returning, &returning_proof, write_options())
        .await
        .unwrap();

    for _ in 0..20 {
        let found = lookup(&overlay.nodes[2], &exact(&uri)).await;
        if found
            .first()
            .is_some_and(|r| r.endpoints()[0].address() == "second.example:443")
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("the returning agent never displaced its own tombstone");
}
