//! Starting a node.

use std::sync::Arc;
use std::time::Duration;

use agent_uri_attestation::Verifier;
use agent_uri_dht::DhtError;
use futures::StreamExt;
use libp2p::kad::store::MemoryStore;
use libp2p::swarm::SwarmEvent;
use libp2p::{Swarm, identify, identity, kad, noise, tcp, yamux};
use tokio::sync::mpsc;

use crate::config::Libp2pConfig;
use crate::dht::Libp2pDht;
use crate::worker::{Behaviour, Worker};

/// How long `start` waits for the operating system to assign listen addresses.
const LISTEN_READY_TIMEOUT: Duration = Duration::from_secs(10);

/// How many commands may be queued before a caller waits for the worker.
///
/// Small on purpose. A deep queue would let a caller pile up work the node
/// cannot get through and turn a slow overlay into unbounded memory.
const COMMAND_QUEUE: usize = 64;

/// Builds a node and starts it.
///
/// The identity keypair is the node's identity in the overlay, and has nothing
/// to do with the agent keys that sign registrations. One process running many
/// agents is still one node.
///
/// The verifier supplies the trust roots this node checks attestations against,
/// both for records it is asked to store and for records it reads. A verifier
/// with no roots, under the default policy, stores what it is given and
/// verifies nothing.
///
/// # Errors
///
/// Returns [`DhtError::Unavailable`] if the transport cannot be built, a
/// configured address cannot be listened on, or no listen address becomes ready
/// within ten seconds.
pub async fn start(
    config: Libp2pConfig,
    verifier: Verifier,
    keypair: identity::Keypair,
) -> Result<Libp2pDht, DhtError> {
    let local_peer = libp2p::PeerId::from(keypair.public());
    let mut swarm = build_swarm(&config, keypair)?;

    let expected = config.listen_addresses.len();
    for address in &config.listen_addresses {
        swarm.listen_on(address.clone()).map_err(|error| {
            DhtError::unavailable(format!("cannot listen on {address}: {error}"))
        })?;
    }
    if expected > 0 {
        await_listeners(&mut swarm, expected).await?;
        // Until a node knows it is reachable, Kademlia keeps it in client mode
        // and it answers no queries. On a loopback overlay that detection never
        // fires, so a node that was asked to listen is told it is a server.
        swarm.behaviour_mut().kad.set_mode(Some(kad::Mode::Server));
    }

    let verifier = Arc::new(verifier);
    let (commands, receiver) = mpsc::channel(COMMAND_QUEUE);
    let worker = Worker::new(swarm, receiver, Arc::clone(&verifier), config.clone());
    tokio::spawn(worker.run());

    Ok(Libp2pDht::new(commands, local_peer, verifier, config))
}

fn build_swarm(
    config: &Libp2pConfig,
    keypair: identity::Keypair,
) -> Result<Swarm<Behaviour>, DhtError> {
    let kad_config = kademlia_config(config);

    let builder = libp2p::SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|error| DhtError::unavailable(format!("cannot build transport: {error}")))?
        .with_behaviour(|key| {
            let peer = libp2p::PeerId::from(key.public());
            Behaviour {
                kad: kad::Behaviour::with_config(peer, MemoryStore::new(peer), kad_config),
                identify: identify::Behaviour::new(identify::Config::new(
                    "/agent-uri/id/1.0.0".to_string(),
                    key.public(),
                )),
            }
        })
        .map_err(|error| DhtError::unavailable(format!("cannot build behaviour: {error}")))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_mins(1)));

    Ok(builder.build())
}

fn kademlia_config(config: &Libp2pConfig) -> kad::Config {
    let mut kad_config = kad::Config::new(config.protocol.clone());
    kad_config
        // Every value that enters this node's store is validated first. This
        // is the setting that makes that possible, and without it a peer could
        // put anything at any key.
        .set_record_filtering(kad::StoreInserts::FilterBoth)
        .set_replication_factor(config.replication_factor)
        .set_query_timeout(config.query_timeout)
        // Kademlia's own expiry is a backstop. A registration's real lifetime
        // is inside its value, signed, and enforced wherever the record is read.
        .set_record_ttl(Some(config.max_record_ttl))
        .set_publication_interval(Some(config.republication_interval))
        .set_replication_interval(Some(config.republication_interval));
    kad_config
}

/// Waits until the operating system has assigned every requested listener.
///
/// A configuration asking for port zero does not know its own address until
/// this completes, and a node that returned before then would advertise
/// nothing to bootstrap against.
async fn await_listeners(swarm: &mut Swarm<Behaviour>, expected: usize) -> Result<(), DhtError> {
    let ready = async {
        let mut seen = 0usize;
        while seen < expected {
            if let SwarmEvent::NewListenAddr { .. } = swarm.select_next_some().await {
                seen += 1;
            }
        }
    };

    tokio::time::timeout(LISTEN_READY_TIMEOUT, ready)
        .await
        .map_err(|_| DhtError::unavailable("no listen address became ready"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_node_reports_the_port_the_os_gave_it() {
        let node = start(
            Libp2pConfig::default().listening_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
            Verifier::new(),
            identity::Keypair::generate_ed25519(),
        )
        .await
        .unwrap();

        let addresses = node.listen_addresses().await.unwrap();
        assert_eq!(addresses.len(), 1);
        assert!(!addresses[0].to_string().ends_with("/tcp/0"));
    }

    #[tokio::test]
    async fn a_dial_address_carries_the_peer_identity() {
        // A bare listen address cannot be bootstrapped against, because
        // Kademlia routes to peer identities.
        let node = start(
            Libp2pConfig::default().listening_on("/ip4/127.0.0.1/tcp/0".parse().unwrap()),
            Verifier::new(),
            identity::Keypair::generate_ed25519(),
        )
        .await
        .unwrap();

        let dial = node.dial_addresses().await.unwrap();
        assert!(dial[0].as_str().contains("/p2p/"));
    }

    #[tokio::test]
    async fn a_client_node_needs_no_listen_address() {
        let node = start(
            Libp2pConfig::default(),
            Verifier::new(),
            identity::Keypair::generate_ed25519(),
        )
        .await
        .unwrap();
        assert!(node.listen_addresses().await.unwrap().is_empty());
    }
}
