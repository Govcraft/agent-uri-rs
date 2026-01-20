# agent-uri

[![Crates.io](https://img.shields.io/crates/v/agent-uri.svg)](https://crates.io/crates/agent-uri)
[![Documentation](https://docs.rs/agent-uri/badge.svg)](https://docs.rs/agent-uri)
[![License](https://img.shields.io/crates/l/agent-uri.svg)](LICENSE)

Parser and validator for the `agent://` URI scheme, providing topology-independent identity for agents in multi-agent systems.

## Overview

Multi-agent systems need a standard way to identify agents that works regardless of where they're deployed. agent-uri solves this by encoding identity, authority, and capabilities into a single URI.

Each URI contains a trust root (who issued it), a capability path (what it can do), and an agent ID using TypeID format (who it is, when it was created). The typestate builder catches construction errors at compile time, and all components validate against the specification on parse.

## URI Format

```
agent://example.com/assistant/chat/llm_chat_01h455vb4pex5vsknk084sn02q?version=1.0#task
       └─ trust root ─┘└─ capability path ─┘└───────── agent id ────────┘└─ query ─┘└frag┘
```

| Component | Description |
|-----------|-------------|
| **Trust Root** | Domain or IP identifying the issuing authority |
| **Capability Path** | Hierarchical path describing agent capabilities |
| **Agent ID** | TypeID with semantic prefix + UUIDv7 suffix |
| **Query** | Optional metadata (version, ttl, attestation) |
| **Fragment** | Optional semantic annotation |

## Installation

```toml
[dependencies]
agent-uri = "0.3"
```

For JSON serialization support:

```toml
[dependencies]
agent-uri = { version = "0.3", features = ["serde"] }
```

## Quick Start

```rust
use agent_uri::prelude::*;

// Parse an existing URI
let uri = AgentUri::parse(
    "agent://anthropic.com/assistant/chat/llm_chat_01h455vb4pex5vsknk084sn02q"
).unwrap();

// Access components
println!("Trust root: {}", uri.trust_root());           // anthropic.com
println!("Capability: {}", uri.capability_path());       // assistant/chat
println!("Agent ID: {}", uri.agent_id());               // llm_chat_01h455vb4pex5vsknk084sn02q
println!("ID prefix: {}", uri.agent_id().prefix());     // llm_chat
```

## Building URIs

The typestate builder enforces correct construction order at compile time:

```rust
use agent_uri::prelude::*;

let uri = AgentUriBuilder::new()
    .try_trust_root("openai.com")?
    .try_capability_path("tool/code")?
    .agent_id(AgentId::new("code_assist"))  // generates fresh UUIDv7
    .try_query("version=2.0")?
    .try_fragment("streaming")?
    .build()?;

println!("{uri}");
// agent://openai.com/tool/code/code_assist_01jj0t8yv4ex3vsknk084sn92a?version=2.0#streaming
```

The builder requires trust root, capability path, and agent ID in order. Query and fragment are optional at any stage.

## Working with Components

### Trust Root

```rust
let root = TrustRoot::parse("api.example.com:8080")?;
assert_eq!(root.host_str(), "api.example.com");
assert_eq!(root.port(), Some(8080));

// Modify port
let without_port = root.without_port();
```

### Capability Path

```rust
let path = CapabilityPath::parse("workflow/approval/invoice")?;
assert_eq!(path.depth(), 3);
assert!(path.starts_with(&CapabilityPath::parse("workflow")?));

// Navigate hierarchy
for segment in path.iter() {
    println!("{segment}");
}
```

### Agent ID

Agent IDs use TypeID format: a semantic prefix plus a base32-encoded UUIDv7.

```rust
// Create new ID (generates UUIDv7 automatically)
let id = AgentId::new("llm_chat");
println!("{id}");  // llm_chat_01h455vb4pex5vsknk084sn02q

// Parse existing
let parsed = AgentId::parse("task_runner_01h455vb4pex5vsknk084sn02q")?;
println!("Prefix: {}", parsed.prefix());  // task_runner
println!("UUID: {}", parsed.uuid());      // extracts the UUIDv7
```

### Query and Fragment

```rust
let uri = AgentUri::parse(
    "agent://example.com/agent/test/bot_01abc?version=1.0&ttl=3600#summary"
)?;

// Access query parameters
if let Some(version) = uri.query().version() {
    println!("Version: {version}");
}

// Access fragment
if let Some(frag) = uri.fragment() {
    println!("Fragment: {}", frag.as_str());
}

// Create modified URI
let updated = uri.with_query(QueryParams::new().with_param("version", "2.0")?);
```

## Features

| Feature | Description |
|---------|-------------|
| `default` | Core parsing and validation |
| `serde` | Serialize/deserialize all types |

## License

MIT OR Apache-2.0
