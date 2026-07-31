# agent-uri-dht

[![Crates.io](https://img.shields.io/crates/v/agent-uri-dht.svg)](https://crates.io/crates/agent-uri-dht)
[![Documentation](https://docs.rs/agent-uri-dht/badge.svg)](https://docs.rs/agent-uri-dht)
[![License](https://img.shields.io/crates/l/agent-uri-dht.svg)](../LICENSE-MIT)

Capability-based discovery for the [`agent://`](https://crates.io/crates/agent-uri) URI scheme: the `Dht` trait every backend implements, plus an in-process reference implementation to develop and test against.

## Overview

An agent URI says who an agent is. Discovery answers the other question: *find me an agent at `anthropic.com` that can do `assistant/chat`*. Records are keyed by trust root and capability path,

```text
key = SHA256(trust_root || "/" || capability_path)
```

so a prefix lookup is an exact-key read rather than a scan.

| Piece | What it is |
|-------|------------|
| `Dht` | The async trait a backend implements |
| `DhtKey` | Kademlia-style key derivation, specification §6.1 |
| `Registration` | A record: URI, agent key, endpoints, optional attestation |
| `MutationProof` | The signature that authorizes a write |
| `SimulatedDht` | In-process reference implementation and test double |
| `PathTrie` | A standalone local hierarchical index, for callers who want one |

## Installation

```toml
[dependencies]
agent-uri-dht = "0.12"
```

## Quick Start

```rust
use agent_uri::{AgentUri, CapabilityPath, TrustRoot};
use agent_uri_attestation::SigningKey;
use agent_uri_dht::{
    Dht, Endpoint, MutationProof, Query, ReadOptions, Registration, SimulatedDht,
    SimulationConfig, WriteOptions,
};

// Verification is disabled only for this isolated indexing example; it is on
// by default, and production registration keeps it on with a configured
// `Verifier`.
let dht = SimulatedDht::new(
    SimulationConfig::default().with_verify_attestations(false)
);

// Register an agent. The key named here is the only one that can change or
// remove the record later.
let uri = AgentUri::parse(
    "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q"
)?;
let agent_key = SigningKey::generate();
let registration = Registration::new(
    uri,
    agent_key.verifying_key(),
    vec![Endpoint::https("agent.anthropic.com:443")],
);
let proof = MutationProof::sign_registration(&agent_key, &registration);
dht.register(registration, &proof, WriteOptions::default()).await?;

// Discover by capability prefix. Results are paged.
let query = Query::prefix(
    TrustRoot::parse("anthropic.com")?,
    CapabilityPath::parse("assistant")?,
);
let page = dht.lookup(&query, &ReadOptions::default()).await?;
```

## Operating Against a Network

`Dht` describes a distributed store, not a map, and its shape reflects that even when the backend is in-process:

- **Every operation is async and takes a deadline.** A call that does not finish returns `DhtError::Timeout`, which does not mean the write failed to apply.
- **Writes name a `Quorum`.** How many replicas must acknowledge is the caller's latency-versus-durability trade; `WriteReceipt` reports what was actually reached.
- **Lookups are paged.** Follow `Page::next_cursor` until it is `None`, unless you are sampling rather than enumerating.
- **Failures are distinguishable.** `DhtError::is_transient` separates a slow or partitioned network from a rejected request. Collapsing the two turns a partition into an apparently empty namespace.
- **Writes are authorized, not merely addressed.** An agent URI is public and so is the attestation stored beside it, so every write carries a `MutationProof` signed by the agent's own key. Without it, reaching a replica would be enough to repoint an agent.

## What `SimulatedDht` Is and Is Not

It is the reference implementation and the test double: one in-process index holding one authoritative copy, which is what you want to develop, test, and benchmark against. It is not a deployment.

**Its limits are its own.** `SimulationConfig` bounds a key at 1000 registrations by default and bounds a stored value not at all. A Kademlia overlay bounds a record at the wire size a peer will accept — for `libp2p-kad`, 1 to 27 registrations — so it stores pointers at ancestor keys and sharded pages behind them. Code that checks whether a write succeeded and pages through a lookup ports unchanged; configuration tuned against these numbers does not.

**A measurement taken against it measures indexing.** Nothing here partitions, replicates, retries, or loses a peer, so a lookup returns exactly what was written. That makes it a clean way to ask whether this crate indexes and pages correctly, and no way at all to ask what a distributed store returns under load or partition.

For a real overlay, see [`agent-uri-dht-libp2p`](https://crates.io/crates/agent-uri-dht-libp2p), which implements the same `Dht` trait over `libp2p-kad`.

## Features

| Feature | Description |
|---------|-------------|
| `default` | Key derivation, records, the trait, and the simulated backend |
| `serde` | Serialize/deserialize records and queries |

## License

MIT OR Apache-2.0
