# agent-uri-dht-libp2p

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/Govcraft/agent-uri-rs)

The networked Kademlia backend for `agent://` discovery, over `libp2p-kad`.

[`agent-uri-dht`](../agent-uri-dht) defines what discovery means and ships an in-process index that implements it. This crate implements the same `Dht` trait against a real overlay: records live on other people's machines, reads cross the network, and every node that stores a record decides for itself whether it should.

It is a separate crate because `libp2p` is a large dependency and the core crate is useful without it. A caller that only derives DHT keys should not inherit a networking stack.

```toml
[dependencies]
agent-uri-dht-libp2p = "0.1"
```

## Starting a node

```rust,no_run
use agent_uri_attestation::Verifier;
use agent_uri_dht::{Dht, PeerAddr, Query, ReadOptions, WriteOptions};
use agent_uri_dht_libp2p::Libp2pConfig;
use libp2p::identity;

# async fn example(trust_root_key: agent_uri_attestation::VerifyingKey)
# -> Result<(), Box<dyn std::error::Error>> {
// A node verifies attestations against the trust roots it is given.
let mut verifier = Verifier::new();
verifier.add_trusted_root("anthropic.com", trust_root_key);

let node = agent_uri_dht_libp2p::start(
    Libp2pConfig::default().listening_on("/ip4/0.0.0.0/tcp/4001".parse()?),
    verifier,
    identity::Keypair::generate_ed25519(),
)
.await?;

node.bootstrap(&[PeerAddr::new("/ip4/198.51.100.7/tcp/4001/p2p/12D3KooWExample")])
    .await?;
# Ok(())
# }
```

Registration, migration, refresh, deregistration, and lookup are the `Dht` trait's, unchanged from the simulator. Code written against `SimulatedDht` runs here.

## How a registration is stored

This crate implements the **sharded** record model of `SPECIFICATION.md` §6.2, which every Kademlia deployment is required to use. The alternative, materializing a registration at its exact path and every ancestor so that a prefix query is one exact-key read, does not survive contact with a real overlay: `libp2p-kad`'s wire limit is 16 KiB, which the spike in [#72](https://github.com/Govcraft/agent-uri-rs/issues/72) measured at 1 to 27 registrations, against a broad ancestor key meant to hold an entire subtree.

The sharded model splits the two jobs one record was doing:

| key | holds | written by |
|---|---|---|
| identity | the agent's signed registration | the agent, once per write |
| page | pointers to agents beneath a path | every agent, at every ancestor |
| descriptor | how many pages a path is spread over | whoever widens it |

A pointer is about 74 bytes against a registration's 600, so a page holds roughly 220 agents rather than 27. That moves the ceiling; it does not remove one. Sharding does: a path's pointers spread across `2^level` pages, and whichever publisher finds a full page raises the level for everyone.

The level is a power of two on purpose, and §6.1.1 requirement 5 makes that normative. With `page = hash mod P`, raising `P` moves nearly every existing publisher to a different page and every pointer already written becomes unreadable until its publisher happens to rewrite it. With `page = hash & (2^level - 1)`, raising the level splits each page in two and leaves every existing pointer where a wider reader still looks. Growth is backward compatible, and a stale level costs coverage rather than correctness.

The key derivations are in §6.1.1 and their test vectors in Appendix B.4.1; `keys.rs` asserts them, because an implementation that derives one key differently sees none of this one's registrations and the failure looks like an empty namespace rather than a disagreement.

**Cost of a lookup:** one descriptor read, one page read per shard, and one read per agent found, which is what §6.4 costs the sharded model at. Each is one exact-key read, so each is still `O(log N)` hops.

## What makes this safe under replication

Kademlia copies records between nodes verbatim, on its own schedule, in whichever direction fires first. A backend whose nodes edited what they stored, or preferred whatever arrived last, would have replication undoing writes.

Every value here is instead reconciled by a rule that does not depend on arrival order, and no node ever rewrites a value it accepts:

- **identity records** are immutable and signed; the later `(registered_at, sequence)` wins
- **pointer pages** union, keeping the later expiry per URI
- **shard descriptors** take the greater level

All three are commutative, associative, and idempotent, so replication is anti-entropy rather than a race. The same rules run on both sides of a read: a node applies them when a record arrives, and a reader applies them across every copy the overlay returned, which makes a lookup as fresh as the best-informed peer that replied.

## What a node refuses to store

§6.2 requirement 4 says DHT nodes MUST verify attestations before storing records. Every value entering a node's store passes validation, via Kademlia's `StoreInserts::FilterBoth`, including values the node publishes itself. A node will not store a record whose signature does not cover it, whose key does not match its URI, or whose attestation names a different key than the record does.

The one place that requirement cannot be met literally is a trust root the node has no key for, and a node holds records for keys near it in the overlay, which is every trust root. `AttestationPolicy` is where that is decided rather than assumed:

| policy | unknown trust roots |
|---|---|
| `RequireVerified` | refused; the node serves only roots it was configured with |
| `VerifyKnownRoots` (default) | stored, but never a key change the node could not verify |
| `Unverified` | stored; for isolated tests |

## Keeping a registration alive

Two things have to keep happening, and only one is Kademlia's job.

**Surviving churn** is the overlay's: nodes leave, the closest set changes, and records are copied to the new nodes automatically.

**Surviving expiry** is the agent's. A registration carries its own signed `expires_at`, and no node can extend it, because extending is a write and a write needs the agent's key. `keep_alive` holds the signing key and renews at half the TTL, which leaves the other half to retry in.

## Known limits

- **A node with no peers cannot publish.** Kademlia counts remote acknowledgements, and a local store write is not one. Bootstrap first.
- **Pointer pages are unauthenticated.** Anyone can put any URI on any page. A lookup dereferences each pointer and checks the agent's own URI against the path queried, so an injected pointer costs a wasted read and nothing more.
- **Shard growth is opportunistic.** A page over its high-water mark is widened by whoever notices; until then it keeps accepting pointers.

## Testing

Integration tests run a real multi-node overlay in one process, over loopback TCP with noise and yamux, covering discovery, migration, deregistration, paging, shard growth, churn, partition, and the attacks that [#50](https://github.com/Govcraft/agent-uri-rs/issues/50) and [#51](https://github.com/Govcraft/agent-uri-rs/issues/51) closed.

```sh
cargo nextest run -p agent-uri-dht-libp2p
```

## License

MIT OR Apache-2.0
