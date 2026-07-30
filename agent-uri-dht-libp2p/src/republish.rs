//! Keeping a registration alive.
//!
//! Two different things have to keep happening for an agent to stay
//! discoverable, and only one of them is Kademlia's job.
//!
//! **Surviving churn** is Kademlia's. Nodes leave, the set of peers closest to
//! a key changes, and the overlay copies records to the new ones on its own
//! replication schedule. Nothing here is needed for that.
//!
//! **Surviving expiry** is the agent's. A registration carries its own
//! `expires_at`, signed, and no node can extend it: extending is a write, and a
//! write needs the agent's key. A backend that renewed records on its own would
//! be forging the agent's intent to stay reachable, which is exactly the thing
//! the signature exists to prevent.
//!
//! So renewal lives here, in something that holds the agent's signing key and
//! does openly what the node cannot do at all.

use std::time::{Duration, SystemTime};

use agent_uri::AgentUri;
use agent_uri_attestation::SigningKey;
use agent_uri_dht::{Dht, DhtError, Mutation, MutationProof, Query, WriteOptions};

use crate::Libp2pDht;

/// The fraction of a registration's lifetime after which it is renewed.
///
/// Halfway leaves a full second half to retry in. Renewing at the last moment
/// would make a single failed write the difference between reachable and gone.
const RENEW_AT: u32 = 2;

/// Extends a registration's lifetime by `ttl`, signing the write.
///
/// Reads the record as it currently stands, because a refresh signs against the
/// version it found, and publishes the extension along with fresh pointers at
/// every ancestor path.
///
/// # Errors
///
/// Returns [`DhtError::NotFound`] if the agent is not registered, or a network
/// error if the overlay could not be reached.
pub async fn renew(
    dht: &Libp2pDht,
    agent_uri: &AgentUri,
    key: &SigningKey,
    ttl: Duration,
    options: WriteOptions,
) -> Result<(), DhtError> {
    let query = Query::exact(
        agent_uri.trust_root().clone(),
        agent_uri.capability_path().clone(),
    );
    let current = dht
        .lookup(&query, &agent_uri_dht::ReadOptions::default())
        .await?
        .into_items()
        .into_iter()
        .find(|record| record.agent_uri() == agent_uri)
        .ok_or_else(|| DhtError::not_found(agent_uri.canonical()))?;

    // The expiry is computed here, once, and both signed and submitted. The
    // node applies what it is given rather than deriving an instant of its
    // own, so this is the only clock reading that matters.
    let expires_at = SystemTime::now() + ttl;
    let proof = MutationProof::sign_next(key, &current, &Mutation::Refresh { ttl, expires_at });
    dht.refresh(agent_uri, ttl, expires_at, &proof, options)
        .await?;
    Ok(())
}

/// Renews a registration for as long as the returned handle is held.
///
/// The interval is half the TTL, so a renewal that fails has the other half to
/// succeed in. Dropping the handle stops the renewals; the registration then
/// expires on its own schedule, which is the correct behaviour for a process
/// that has gone away.
///
/// # Example
///
/// ```no_run
/// # use std::time::Duration;
/// # use agent_uri::AgentUri;
/// # use agent_uri_attestation::SigningKey;
/// # use agent_uri_dht_libp2p::{Libp2pDht, keep_alive};
/// # async fn example(dht: Libp2pDht, uri: AgentUri, key: SigningKey) {
/// // Held for as long as the agent intends to stay reachable.
/// let _renewal = keep_alive(dht, uri, key, Duration::from_hours(1));
/// # }
/// ```
#[must_use]
pub fn keep_alive(dht: Libp2pDht, agent_uri: AgentUri, key: SigningKey, ttl: Duration) -> Renewal {
    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(ttl / RENEW_AT);
        // The first tick fires immediately, and the registration was just
        // written, so it is consumed rather than acted on.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if let Err(error) = renew(&dht, &agent_uri, &key, ttl, WriteOptions::default()).await {
                tracing::warn!(agent = %agent_uri, %error, "could not renew registration");
            }
        }
    });

    Renewal { handle }
}

/// Keeps a registration alive until it is dropped.
#[derive(Debug)]
pub struct Renewal {
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for Renewal {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_happens_with_a_full_ttl_left_to_retry_in() {
        // The property, not the constant: a renewal interval at or beyond the
        // TTL would make one failed write enough to lose the registration.
        let ttl = Duration::from_hours(1);
        assert!(ttl / RENEW_AT < ttl);
        assert_eq!(ttl / RENEW_AT, Duration::from_mins(30));
    }
}
