//! Publishing and finding agents across a real multi-node overlay.

mod support;

use std::time::Duration;

use agent_uri_dht::{Dht, Mutation};
use support::{
    Overlay, exact, lookup, lookup_until_found, prefix, proof_for, register, write_options,
};

#[tokio::test(flavor = "multi_thread")]
async fn a_registration_published_on_one_node_is_found_from_another() {
    let overlay = Overlay::start(4).await;
    let (uri, key, registration) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "a.example:443",
    );

    register(&overlay.nodes[0], registration, &key)
        .await
        .unwrap();

    let found = lookup_until_found(&overlay.nodes[3], &exact(&uri)).await;
    assert_eq!(found.len(), 1, "the record did not reach the far node");
    assert_eq!(found[0].agent_uri(), &uri);
    assert_eq!(found[0].endpoints()[0].address(), "a.example:443");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_prefix_lookup_reaches_agents_registered_deeper() {
    // The ancestor materialization of SPECIFICATION.md §6.2, with the pointer
    // indirection the wire limit forces.
    let overlay = Overlay::start(4).await;
    let (uri, key, registration) = overlay.agent(
        "assistant/chat/streaming",
        "llm_01h455vb4pex5vsknk084sn02q",
        "a.example:443",
    );

    register(&overlay.nodes[0], registration, &key)
        .await
        .unwrap();

    let found = lookup_until_found(&overlay.nodes[2], &prefix("assistant")).await;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].agent_uri(), &uri);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_exact_lookup_does_not_return_descendants() {
    let overlay = Overlay::start(4).await;
    let (_, key, registration) = overlay.agent(
        "assistant/chat/streaming",
        "llm_01h455vb4pex5vsknk084sn02q",
        "a.example:443",
    );
    register(&overlay.nodes[0], registration, &key)
        .await
        .unwrap();

    // The pointer sits on the "assistant" page too, because that is how prefix
    // lookup works. Exact mode has to filter it out on the URI it dereferences.
    let _ = lookup_until_found(&overlay.nodes[1], &prefix("assistant")).await;
    let exact_hits = lookup(
        &overlay.nodes[1],
        &agent_uri_dht::Query::exact(
            agent_uri::TrustRoot::parse(support::TRUST_ROOT).unwrap(),
            agent_uri::CapabilityPath::parse("assistant").unwrap(),
        ),
    )
    .await;
    assert!(exact_hits.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn several_agents_under_one_path_are_all_found() {
    let overlay = Overlay::start(4).await;
    for n in 0..5u32 {
        let (_, key, registration) = overlay.agent(
            "assistant/chat",
            &format!("llm_01h455vb4pex5vsknk084sn0{n:02}"),
            &format!("node{n}.example:443"),
        );
        register(
            &overlay.nodes[usize::try_from(n).unwrap() % 4],
            registration,
            &key,
        )
        .await
        .unwrap();
    }

    for _ in 0..20 {
        let found = lookup(&overlay.nodes[1], &prefix("assistant")).await;
        if found.len() == 5 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("not every agent under the path was discovered");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_migration_is_visible_across_the_overlay() {
    let overlay = Overlay::start(4).await;
    let (uri, key, registration) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "us-east.example:443",
    );
    register(&overlay.nodes[0], registration, &key)
        .await
        .unwrap();
    let _ = lookup_until_found(&overlay.nodes[3], &exact(&uri)).await;

    let moved = vec![agent_uri_dht::Endpoint::https("eu-west.example:443")];
    let proof = proof_for(
        &overlay.nodes[0],
        &uri,
        &key,
        &Mutation::UpdateEndpoint { endpoints: &moved },
    )
    .await;
    overlay.nodes[0]
        .update_endpoint(&uri, moved, &proof, write_options())
        .await
        .unwrap();

    for _ in 0..20 {
        let found = lookup(&overlay.nodes[3], &exact(&uri)).await;
        if found
            .first()
            .is_some_and(|record| record.endpoints()[0].address() == "eu-west.example:443")
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("the migration never became visible");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_extends_the_registration() {
    let overlay = Overlay::start(4).await;
    let (uri, key, registration) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "a.example:443",
    );
    let original_expiry = registration.expires_at();
    register(&overlay.nodes[0], registration, &key)
        .await
        .unwrap();
    let _ = lookup_until_found(&overlay.nodes[2], &exact(&uri)).await;

    let ttl = Duration::from_hours(4);
    let proof = proof_for(&overlay.nodes[0], &uri, &key, &Mutation::Refresh { ttl }).await;
    overlay.nodes[0]
        .refresh(&uri, ttl, &proof, write_options())
        .await
        .unwrap();

    for _ in 0..20 {
        let found = lookup(&overlay.nodes[2], &exact(&uri)).await;
        if found
            .first()
            .is_some_and(|record| record.expires_at() > original_expiry)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("the refreshed lifetime never became visible");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deregistered_agent_stops_being_returned() {
    // Kademlia has no delete. Removal is a tombstone that outranks the record
    // it replaces and then expires on the same schedule.
    let overlay = Overlay::start(4).await;
    let (uri, key, registration) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "a.example:443",
    );
    register(&overlay.nodes[0], registration, &key)
        .await
        .unwrap();
    let _ = lookup_until_found(&overlay.nodes[3], &exact(&uri)).await;

    let proof = proof_for(&overlay.nodes[0], &uri, &key, &Mutation::Deregister).await;
    overlay.nodes[0]
        .deregister(&uri, &proof, write_options())
        .await
        .unwrap();

    for _ in 0..20 {
        if lookup(&overlay.nodes[3], &exact(&uri)).await.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("the deregistered agent is still being returned");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lookup_pages_rather_than_returning_everything() {
    let overlay = Overlay::start(4).await;
    for n in 0..4u32 {
        let (_, key, registration) = overlay.agent(
            "assistant/chat",
            &format!("llm_01h455vb4pex5vsknk084sn0{n:02}"),
            "a.example:443",
        );
        register(&overlay.nodes[0], registration, &key)
            .await
            .unwrap();
    }
    // Wait for all four to be visible before bounding the read.
    for _ in 0..20 {
        if lookup(&overlay.nodes[0], &prefix("assistant")).await.len() == 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // One key for the descriptor, one for the page, one per agent: a budget of
    // four can dereference two of them.
    let options = support::read_options().with_max_keys(4);
    let page = overlay.nodes[0]
        .lookup(&prefix("assistant"), &options)
        .await
        .unwrap();

    assert!(page.has_more(), "a truncated read must report a cursor");
    assert!(page.len() < 4);

    let resumed = overlay.nodes[0]
        .lookup(
            &prefix("assistant"),
            &support::read_options().with_cursor(page.next_cursor().unwrap()),
        )
        .await
        .unwrap();
    assert!(
        !resumed.is_empty(),
        "resuming from the cursor found nothing"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unregistered_agent_is_simply_absent() {
    let overlay = Overlay::start(3).await;
    let uri = agent_uri::AgentUri::parse(
        "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn09z",
    )
    .unwrap();

    assert!(lookup(&overlay.nodes[0], &exact(&uri)).await.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_reports_its_own_identity() {
    let overlay = Overlay::start(2).await;
    assert_ne!(overlay.nodes[0].local_id(), overlay.nodes[1].local_id());
    assert!(!overlay.nodes[0].local_id().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn bootstrapping_against_nothing_reports_no_peers() {
    let overlay = Overlay::start(1).await;
    let result = overlay.nodes[0].bootstrap(&[]).await;
    assert!(matches!(result, Err(agent_uri_dht::DhtError::NoPeers)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mutation_against_an_unregistered_agent_is_not_found() {
    let overlay = Overlay::start(3).await;
    let (uri, key, registration) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "a.example:443",
    );
    let proof = agent_uri_dht::MutationProof::sign_registration(&key, &registration);

    let result = overlay.nodes[0]
        .deregister(&uri, &proof, write_options())
        .await;
    assert!(matches!(
        result,
        Err(agent_uri_dht::DhtError::NotFound { .. })
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_registration_without_endpoints_is_refused_before_it_reaches_the_network() {
    let overlay = Overlay::start(2).await;
    let (_, key, _) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "a.example:443",
    );
    let uri = agent_uri::AgentUri::parse(
        "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q",
    )
    .unwrap();
    let empty = agent_uri_dht::Registration::new(uri, key.verifying_key(), vec![]);

    let result = register(&overlay.nodes[0], empty, &key).await;
    assert!(matches!(result, Err(agent_uri_dht::DhtError::NoEndpoints)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_record_survives_the_node_that_published_it_leaving() {
    // Churn. Every node in the overlay replicates every record, so the question
    // is whether the record outlives its publisher, not which replica held it.
    let mut overlay = Overlay::start(5).await;
    let (uri, key, registration) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "a.example:443",
    );
    register(&overlay.nodes[0], registration, &key)
        .await
        .unwrap();

    let survivor = overlay.nodes[4].clone();
    assert!(!lookup_until_found(&survivor, &exact(&uri)).await.is_empty());

    // Dropping a handle stops its node: the worker exits when the last sender
    // to it is gone.
    overlay.nodes.drain(0..2);
    tokio::time::sleep(Duration::from_millis(500)).await;

    let found = lookup_until_found(&survivor, &exact(&uri)).await;
    assert_eq!(found.len(), 1, "the record died with its publisher");
    assert_eq!(found[0].agent_uri(), &uri);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_partitioned_overlay_does_not_see_the_others_records_until_it_heals() {
    let left = Overlay::start(3).await;
    let (uri, key, registration) = left.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "a.example:443",
    );
    register(&left.nodes[0], registration, &key).await.unwrap();
    assert!(
        !lookup_until_found(&left.nodes[2], &exact(&uri))
            .await
            .is_empty()
    );

    // A second overlay that has never met the first, under the same trust root
    // so that the two really are halves of one namespace. Two nodes rather than
    // one, so a failed lookup means the partition holds nothing rather than
    // that the node has no peers.
    let right = Overlay::start_under(left.root_key(), 2).await;
    assert!(
        lookup(&right.nodes[0], &exact(&uri)).await.is_empty(),
        "a partition returned a record it cannot have seen"
    );

    right.connect_to(&left).await;

    let found = lookup_until_found(&right.nodes[0], &exact(&uri)).await;
    assert_eq!(found.len(), 1, "the healed partition never saw the record");
    assert_eq!(found[0].agent_uri(), &uri);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_joining_late_can_still_find_what_it_missed() {
    let mut overlay = Overlay::start(3).await;
    let (uri, key, registration) = overlay.agent(
        "assistant/chat",
        "llm_01h455vb4pex5vsknk084sn02q",
        "a.example:443",
    );
    register(&overlay.nodes[0], registration, &key)
        .await
        .unwrap();

    let latecomer = overlay.add_node().await;
    let found = lookup_until_found(&latecomer, &exact(&uri)).await;
    assert_eq!(found.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_full_page_widens_and_every_agent_is_still_found() {
    // The property the whole sharding scheme exists for: a capability path
    // outgrows one record, and nothing registered before the split becomes
    // unreachable. Growth is a doubling precisely so that a pointer already
    // written stays on a page the wider reader still visits.
    let overlay = Overlay::start_with(agent_uri_attestation::SigningKey::generate(), 3, 2).await;

    for n in 0..6u32 {
        let (_, key, registration) = overlay.agent(
            "assistant/chat",
            &format!("llm_01h455vb4pex5vsknk084sn0{n:02}"),
            "a.example:443",
        );
        register(&overlay.nodes[0], registration, &key)
            .await
            .unwrap();
    }

    for _ in 0..25 {
        let found = lookup(&overlay.nodes[2], &prefix("assistant")).await;
        if found.len() == 6 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let found = lookup(&overlay.nodes[2], &prefix("assistant")).await;
    panic!("only {} of 6 agents survived the shard split", found.len());
}
