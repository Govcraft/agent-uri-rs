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
agent-uri = "0.4"
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
         │                     │                     │
         └─────────────────────┴─────────────────────┘
                         depends on
```

Use `agent-uri` alone for parsing and validation. Add `agent-uri-attestation` when you need cryptographic proof of identity. Add `agent-uri-dht` when you need to discover agents by capability.

## Crates

### agent-uri

**Validates URIs against the formal ABNF grammar and prevents invalid construction.**

```toml
[dependencies]
agent-uri = "0.4"
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
agent-uri-attestation = "0.2"
```

```rust
use agent_uri::AgentUri;
use agent_uri_attestation::{Issuer, Verifier, SigningKey};
use std::time::Duration;

// Trust root issues attestation
let uri = AgentUri::parse(
    "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q"
).unwrap();

let signing_key = SigningKey::generate();
let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(86400));
let token = issuer.issue(&uri, vec!["workflow.approval".into()]).unwrap();

// Verifier checks token without callback
let mut verifier = Verifier::new();
verifier.add_trusted_root("acme.com", signing_key.verifying_key());
let claims = verifier.verify(&token).unwrap();
assert_eq!(claims.agent_uri, uri.to_string());
```

Tokens use PASETO v4.public (Ed25519 signatures). Capability claims support hierarchical coverage: an attestation for `workflow` covers `workflow/approval` and `workflow/approval/invoice`.

### agent-uri-dht

**Finds agents by what they do, not where they are.**

```toml
[dependencies]
agent-uri-dht = "0.1"
```

```rust
use agent_uri::{AgentUri, TrustRoot, CapabilityPath};
use agent_uri_dht::{Dht, SimulatedDht, Registration, Endpoint};

// Agent registers its current location
let uri = AgentUri::parse(
    "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q"
).unwrap();

let dht = SimulatedDht::with_defaults();
let registration = Registration::new(
    uri.clone(),
    vec![Endpoint::https("us-east-1.agent.anthropic.com")]
);
dht.register(registration).unwrap();

// Client discovers by capability prefix
let results = dht.lookup_prefix(
    &TrustRoot::parse("anthropic.com").unwrap(),
    &CapabilityPath::parse("assistant").unwrap(),
).unwrap();
assert!(!results.is_empty());
```

DHT keys are derived as `SHA-256(trust_root || "/" || capability_path)`. The `lookup_prefix` function finds all agents under a capability subtree: query `assistant` to discover agents at `assistant/chat`, `assistant/code`, and `assistant/vision`.

**Feature flags:**
- `serde` - Serialize and deserialize types (enables `agent-uri/serde`)

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

## Paper

This implementation is based on the research paper:

> **Agent URI: A Topology-Independent Identity Scheme for Agentic Systems**
> [arXiv:2601.14567](https://arxiv.org/abs/2601.14567)

## License

MIT OR Apache-2.0
