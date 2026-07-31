# agent-uri-rs

[![Crates.io](https://img.shields.io/crates/v/agent-uri.svg)](https://crates.io/crates/agent-uri)
[![Documentation](https://docs.rs/agent-uri/badge.svg)](https://docs.rs/agent-uri)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

Rust implementation of the `agent://` URI scheme for topology-independent agent identity.

## Why

**Agent URIs remain stable as agents migrate across infrastructure.** When an agent moves between cloud regions, scales across replicas, or switches providers, its `agent://` URI stays the same. Clients resolve the URI through a distributed hash table to find the current network location. No hardcoded endpoints, no broken references.

The scheme separates identity from location: a trust root anchors the agent to an organization, a capability path describes what it does, and a TypeID suffix uniquely identifies the instance. This provides DNS-like stability with built-in capability semantics and cryptographic attestation.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
agent-uri = "0.5"
```

Parse an existing URI:

```rust
use agent_uri::AgentUri;

let uri = AgentUri::parse(
    "agent://anthropic.com/assistant/chat/llm_chat_01h455vb4pex5vsknk084sn02q"
).unwrap();

assert_eq!(uri.trust_root().host_str(), "anthropic.com");
assert_eq!(uri.capability_path().as_str(), "assistant/chat");
assert_eq!(uri.agent_id().prefix().as_str(), "llm_chat");
```

Build a new URI with compile-time enforcement:

```rust
use agent_uri::{AgentUriBuilder, TrustRoot, CapabilityPath, AgentId};

let uri = AgentUriBuilder::new()
    .trust_root(TrustRoot::parse("anthropic.com").unwrap())
    .capability_path(CapabilityPath::parse("assistant/chat").unwrap())
    .agent_id(AgentId::new("llm_chat"))  // generates fresh UUIDv7
    .build()
    .unwrap();

println!("{}", uri);
// agent://anthropic.com/assistant/chat/llm_chat_01jk8m3v...
```

The typestate builder catches missing components at compile time, not runtime.

## Crate Architecture

```
                    ┌─────────────────────────────┐
                    │        your application     │
                    └─────────────────────────────┘
                                  │
            ┌─────────────────────┼─────────────────────┐
            │                     │                     │
            ▼                     ▼                     ▼
┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐
│    agent-uri      │ │ agent-uri-        │ │   agent-uri-dht   │
│                   │ │ attestation       │ │                   │
│  parse, validate, │ │                   │ │ discover agents   │
│  construct URIs   │ │ verify identity   │ │ by capability     │
└───────────────────┘ └───────────────────┘ └───────────────────┘
         ▲                     │                     │
         │                     │                     ▼
         │                     │         ┌───────────────────┐
         │                     │         │ agent-uri-dht-    │
         │                     │         │ libp2p            │
         │                     │         │                   │
         │                     │         │ the same, over a  │
         │                     │         │ Kademlia overlay  │
         │                     │         └───────────────────┘
         │                     │                     │
         └─────────────────────┴─────────────────────┘
                         depends on
```

Use `agent-uri` alone for parsing and validation. Add `agent-uri-attestation` when you need cryptographic proof of identity. Add `agent-uri-dht` when you need to discover agents by capability, and `agent-uri-dht-libp2p` when that discovery has to cross a network rather than a process.

## Crates

### agent-uri

**Validates URIs against the formal ABNF grammar and prevents invalid construction.**

```toml
[dependencies]
agent-uri = "0.5"
```

```rust
use agent_uri::{AgentUri, TrustRoot, CapabilityPath, AgentId};

// Parse and extract components
let uri = AgentUri::parse(
    "agent://acme.corp/workflow/approval/rule_fsm_01h5fsk..."
).unwrap();

println!("Trust root: {}", uri.trust_root());        // acme.corp
println!("Capability: {}", uri.capability_path());   // workflow/approval
println!("Agent type: {}", uri.agent_id().prefix()); // rule_fsm

// Check capability hierarchy
let path = CapabilityPath::parse("workflow/approval/invoice").unwrap();
assert!(path.starts_with(&CapabilityPath::parse("workflow").unwrap()));
```

Agent IDs use [TypeID](https://github.com/jetify-com/typeid) format: a semantic prefix plus a 26-character Crockford Base32 UUIDv7 suffix. The UUIDv7 provides time-ordering for distributed systems.

**Feature flags:**
- `serde` - Serialize and deserialize all types

### agent-uri-attestation

**Proves an agent's identity and capabilities without contacting the issuer.**

```toml
[dependencies]
agent-uri-attestation = "0.5"
```

```rust
use agent_uri::AgentUri;
use agent_uri_attestation::{AcceptAll, Issuer, Verifier, SigningKey};
use std::time::Duration;

// Trust root issues attestation
let uri = AgentUri::parse(
    "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q"
).unwrap();

let signing_key = SigningKey::generate();
let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(86400));

// The token binds the agent's own key, not just its URI.
let agent_key = SigningKey::generate();
let token = issuer
    .issue(&uri, &agent_key.verifying_key(), vec!["workflow/approval".into()])
    .unwrap();

// Verifier checks token without callback
let mut verifier = Verifier::new().with_revocation(AcceptAll);
verifier.add_trusted_root("acme.com", signing_key.verifying_key());
let claims = verifier.verify(&token).unwrap();
assert_eq!(claims.agent_uri, uri.to_string());
assert_eq!(claims.agent_verifying_key().unwrap(), agent_key.verifying_key());
```

Tokens use PASETO v4.public (Ed25519 signatures). The URI path is identity-defining: every attested capability must equal that path or be its descendant. Changing the path creates a different agent identity and requires a new Agent ID and attestation.

The `agent_key` claim is what keeps a token from being a bearer credential. Registration records are world-readable and carry their token inline, so without it anyone who performed a lookup would hold a credential naming a URI and its capabilities and nothing about who may present it.

### agent-uri-dht

**Finds agents by what they do, not where they are.**

```toml
[dependencies]
agent-uri-dht = "0.9"
```

```rust
use agent_uri::{AgentUri, TrustRoot, CapabilityPath};
use agent_uri_attestation::{AcceptAll, Issuer, SigningKey, Verifier};
use agent_uri_dht::{
    Dht, Endpoint, MutationProof, Query, ReadOptions, Registration, SimulatedDht, SimulationConfig,
    WriteOptions,
};
use futures::executor::block_on;
use std::time::Duration;

// Agent registers its current location
let uri = AgentUri::parse(
    "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q"
).unwrap();

let signing_key = SigningKey::generate();
let issuer = Issuer::new(
    "anthropic.com",
    signing_key.clone(),
    Duration::from_secs(3600),
);
let agent_key = SigningKey::generate();
let token = issuer
    .issue(&uri, &agent_key.verifying_key(), vec!["assistant/chat".into()])
    .unwrap();
let mut verifier = Verifier::new().with_revocation(AcceptAll);
verifier.add_trusted_root("anthropic.com", signing_key.verifying_key());
let dht = SimulatedDht::with_verifier(SimulationConfig::default(), verifier);
let registration = Registration::new(
    uri.clone(),
    agent_key.verifying_key(),
    vec![Endpoint::https("us-east-1.agent.anthropic.com")]
).with_attestation(token);

// Every write is signed by the agent's own key: the token says the trust root
// vouched for that key, the proof says this party holds it.
let proof = MutationProof::sign_registration(&agent_key, &registration);

// Every operation is async and takes a deadline and a quorum.
block_on(dht.register(registration, &proof, WriteOptions::default())).unwrap();

// Client discovers by capability prefix. Results are paged: follow
// `next_cursor()` until it is None, or you are sampling rather than enumerating.
let query = Query::prefix(
    TrustRoot::parse("anthropic.com").unwrap(),
    CapabilityPath::parse("assistant").unwrap(),
);
let page = block_on(dht.lookup(&query, &ReadOptions::default())).unwrap();
assert!(!page.is_empty());
```

DHT keys are derived as `SHA-256(trust_root || "/" || capability_path)`. This crate implements the **direct** record model of `SPECIFICATION.md` §6.2: a registration is replicated to its exact path key and every ancestor key, so a prefix query reads one exact key and gets that subtree. That works where one store owns the namespace and a stored value has no practical size bound. It costs O(path depth) writes and can make broad ancestor keys hot.

Every query is scoped to one trust root, because every key is derived from one. There is deliberately no cross-trust-root lookup: cross-trust-root isolation bounds the blast radius of a trust-root key compromise.

`SimulatedDht` runs in one process and is the reference implementation and test double. It honors the full async, quorum, and paging surface, so code written against it behaves the same way against the networked backend below.

Its limits do not carry over, and neither do measurements taken against it. It bounds a key at 1000 registrations by default and a stored value not at all, which no overlay can honor: `libp2p-kad` caps a record at 1 to 27 registrations. And nothing in it partitions, replicates, or loses a peer, so a lookup returns exactly what was written to it. That makes it the right place to check that registrations are indexed and paged correctly, which is what `agent-uri-eval`'s discovery precision and recall figures check. Those figures are not a retrieval-quality result and not evidence about distributed deployment; see that crate's docs.

**Feature flags:**
- `serde` - Serialize and deserialize types (enables `agent-uri/serde`)

### agent-uri-dht-libp2p

**The same discovery, over a real Kademlia overlay.**

```toml
[dependencies]
agent-uri-dht-libp2p = "0.2"
```

```rust,no_run
use agent_uri_attestation::{AcceptAll, Verifier};
use agent_uri_dht::{Dht, PeerAddr};
use agent_uri_dht_libp2p::Libp2pConfig;
use libp2p::identity;

# async fn example(trust_root_key: agent_uri_attestation::VerifyingKey)
# -> Result<(), Box<dyn std::error::Error>> {
let mut verifier = Verifier::new().with_revocation(AcceptAll);
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

A separate crate because `libp2p` is a large dependency and the core crate is useful without it.

The storage layout differs from `agent-uri-dht`'s, because a broad ancestor key cannot hold its subtree on a real overlay: `libp2p-kad`'s wire limit caps a record at 1 to 27 registrations. This crate therefore implements the **sharded** record model of `SPECIFICATION.md` §6.2, which every Kademlia deployment is required to use. Ancestor keys hold pointers rather than records, sharded across pages that double as they fill, and a prefix lookup dereferences them. Every node validates what it is asked to store, and every reader validates what it is given.

See [its README](agent-uri-dht-libp2p/README.md) for the record model, the reconciliation rules that make replication safe, and the limits that remain.

## URI Format

```
agent://trust-root/capability/path/prefix_01h455vb4pex5vsknk084sn02q
       └────┬────┘└────┬─────┘└──────────────┬──────────────────┘
         authority   capability            agent id
```

| Component | Constraint | Example |
|-----------|------------|---------|
| Trust root | Max 128 chars; domain, IPv4, or IPv6 with optional port | `anthropic.com`, `192.168.1.1:8080` |
| Capability path | Max 256 chars, max 32 segments of 1-64 chars each | `assistant/chat`, `workflow/approval/invoice` |
| Agent ID | Max 90 chars; prefix + `_` + 26-char Base32 suffix | `llm_chat_01h455vb4pex5vsknk084sn02q` |
| Full URI | Max 512 chars | |

Query strings and fragments are supported but stripped for identity comparison and DHT key derivation.

## Specification

See [SPECIFICATION.md](SPECIFICATION.md) for the complete formal specification, including ABNF grammar, normalization rules, DHT key derivation algorithm, attestation claims structure, and security considerations.

Conformance vectors for the current lowercase-by-grammar behavior are in
[`test-vectors.json`](test-vectors.json) (v0.5). The published v0.4 behavior,
which permitted implementations to normalize some uppercase path and Agent ID
inputs, remains archived in [`test-vectors-v0.4.json`](test-vectors-v0.4.json)
for reproducibility. Version 0.5 rejects those inputs so identity material is
never silently rewritten.

Every machine-checkable vector runs in CI, against the crate that implements it:
parsing and identity vectors in `agent-uri`, `dht_keys` in `agent-uri-dht`, and
the capability and attestation vectors in `agent-uri-attestation`.

## Testing

`task ci` runs what CI runs: formatting, clippy at `-D warnings`, the test
suite, and doctests. Beyond that:

| Command | What it does |
|---------|--------------|
| `task test` | Unit, integration, conformance, and property tests |
| `task fuzz` | libFuzzer over every parser entry point, a minute each (needs nightly and `cargo-fuzz`) |
| `task kani` | Kani model-checking proofs |
| `task miri` | Miri, for undefined behavior |
| `task bench` | Criterion benchmarks |

The parser takes untrusted input, so a panic in it is a denial of service in
every service that parses a URI. Two harnesses guard that: adversarial property
tests (`agent-uri/tests/no_panic_proptest.rs`) run on every commit over mutated
valid URIs, near-misses, and arbitrary bytes; the fuzz targets
(`agent-uri/fuzz/fuzz_targets/`) run on the weekly schedule and can be run
locally against the seed corpus at any time.

## Paper

This implementation is based on the research paper:

> **Agent URI: A Topology-Independent Identity Scheme for Agentic Systems**
> [arXiv:2601.14567](https://arxiv.org/abs/2601.14567)

## License

MIT OR Apache-2.0
