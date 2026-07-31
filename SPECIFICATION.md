# Agent URI Scheme Specification

**Version:** 0.8.3
**Status:** Draft
**Last Updated:** 2026-07-31
**Authors:** Roland R. Rodriguez, Jr. <rrrodzilla@proton.me>

## Abstract

This document specifies the `agent://` URI scheme for topology-independent agent identity in multi-agent systems. The scheme enables capability-based discovery through DHT key derivation, organizational scoping through trust roots, and cryptographic verification through PASETO attestation tokens.

## Status of This Document

This is a draft specification intended for community review and feedback. The specification is implemented by the reference implementation at https://crates.io/crates/agent-uri.

Feedback is welcome via GitHub issues or direct contact with the authors. Specific areas where feedback is requested:

- DHT participation incentive models
- Capability mapping service design
- Integration patterns with A2A protocol

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [URI Syntax](#3-uri-syntax)
4. [Component Semantics](#4-component-semantics)
5. [Normalization and Equivalence](#5-normalization-and-equivalence)
6. [Discovery and Resolution](#6-discovery-and-resolution)
7. [Attestation](#7-attestation)
8. [Security Considerations](#8-security-considerations)
9. [IANA Considerations](#9-iana-considerations)
10. [References](#10-references)

Appendix A: [ABNF Grammar](#appendix-a-abnf-grammar)
Appendix B: [Test Vectors](#appendix-b-test-vectors)
Appendix C: [Length Constraints](#appendix-c-length-constraints)

---

## 1. Introduction

### 1.1 Problem Statement

Multi-agent systems require stable agent identity that survives infrastructure changes. Current approaches bind agent identity to network location—when agents migrate between providers, scale across instances, or federate across organizations, URI-based identity schemes break references, fragment audit trails, and require centralized coordination.

### 1.2 Solution Overview

The `agent://` URI scheme decouples identity from topology through three components:

- **Trust root**: Organizational authority vouching for the agent
- **Capability path**: Hierarchical, identity-defining description of agent capabilities
- **Agent identifier**: Globally unique, time-sortable reference

### 1.3 Design Goals

1. **Topology independence**: Agent identity MUST NOT change when the agent migrates between hosts, cloud providers, or geographic regions.

2. **Capability semantics**: The scheme MUST support discovery by capability ("find agents that can approve invoices").

3. **Decentralized resolution**: No single registry SHOULD be required for resolution.

4. **Organizational scoping**: Queries MUST be scopable to trust boundaries.

5. **Verifiable claims**: Capability claims MUST be cryptographically verifiable.

---

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119].

**Agent**: A software entity capable of autonomous action in a multi-agent system.

**Trust root**: An organizational authority that vouches for agents' existence and capabilities by issuing attestation tokens.

**Capability path**: A hierarchical path describing what an agent can do.

The capability path is constitutive identity material. Moving the same
implementation to a different capability path denotes a different agent and
requires a newly minted Agent ID and attestation.

**Agent identifier**: A TypeID combining a semantic prefix with a UUIDv7 suffix.

**Attestation**: A cryptographically signed token binding an agent URI to capability claims.

**DHT**: Distributed Hash Table used for decentralized agent discovery.

**Pointer**: A small record naming an agent URI registered beneath a capability
path. A pointer is a discovery hint. The agent's own registration record is the
authority for everything about that agent.

**Pointer page**: One stored value holding a set of pointers for one capability
path.

**Shard level**: The exponent `L` for which a capability path's pointers occupy
`2^L` pointer pages.

---

## 3. URI Syntax

### 3.1 Structure

An agent URI follows RFC 3986 generic syntax with agent-specific constraints:

```
agent://trust-root/capability-path/agent-id[?query][#fragment]
```

**Examples:**

```
agent://anthropic.com/assistant/chat/llm_chat_01h455vb4pex5vsknk084sn02q
agent://acme.corp/workflow/approval/invoice/rule_fsm_01h5fskfsk4fpeqwnsyz5hj55t
agent://localhost:8472/debug/test/llm_01h455vb4pex5vsknk084sn02q
```

### 3.2 ABNF Grammar

The complete grammar is provided in [Appendix A](#appendix-a-abnf-grammar). The top-level rule is:

```abnf
agent-uri = scheme "://" trust-root "/" capability-path "/" agent-id
            [ "?" query ] [ "#" fragment ]

scheme    = "agent"
```

### 3.3 Length Constraints

| Component | Maximum Length | Notes |
|-----------|---------------|-------|
| Total URI | 512 characters | Hard limit |
| Trust root | 128 characters | Including port |
| Capability path | 256 characters | All segments combined |
| Path segments | 32 count | Maximum number of segments |
| Each segment | 64 characters | Individual segment |
| Agent ID prefix | 63 characters | TypeID specification limit |
| Agent ID suffix | 26 characters | Fixed (UUIDv7 in Crockford Base32) |

Implementations MUST reject URIs exceeding these limits.

The component maxima bind before the total does: the longest constructible URI is
8 (`agent://`) + 128 + 1 + 256 + 1 + 90 = 484 characters, so the 512-character
cap is never the limit that refuses a well-formed URI. It is checked first
regardless, so that a hostile input is refused on its length before any component
is parsed. Vector `len-002` carries the 484-character case.

---

## 4. Component Semantics

### 4.1 Trust Root

The trust root identifies the organizational authority vouching for the agent.

**Syntax:**

```abnf
trust-root = host [ ":" port ]
host       = domain / ip-literal / ipv4-address
domain     = label *( "." label )
label      = 1*63( ALPHA / DIGIT / "-" )
```

**Requirements:**

1. The trust root MUST follow DNS hostname syntax or be a valid IP address.
2. Domain labels MUST NOT start or end with a hyphen.
3. The trust root MUST publish verification keys at a well-known endpoint (see [Section 7.2](#72-key-publication)).
4. DNS trust roots are case-insensitive and MUST be normalized to lowercase. IPv4 addresses use dotted-decimal form and IPv6 literals use RFC 5952 canonical text in brackets. An explicit port is preserved; no default port is inferred or stripped.
   A trailing dot MUST be rejected rather than stripped: `example.com.` is not a valid trust root, and only `example.com` names that identity.
5. A trust root is ASCII. A host containing a non-ASCII character MUST be rejected rather than converted; a label beginning `xn--` is treated as an opaque DNS label and is not decoded or validated as Punycode. Converting an internationalized name to A-label form is the responsibility of whatever accepts it from a person, and [Section 8.11](#811-internationalized-trust-root-names) states what this leaves undetected.
6. A host consisting of exactly four dot-separated labels that each contain only digits MUST be parsed as an `ipv4-address`, never as a `domain`. Such a host MUST be rejected when it is not a valid dotted-decimal address: every octet MUST be in the range 0-255 and MUST NOT carry a leading zero, per the `dec-octet` rule in [Appendix A](#appendix-a-abnf-grammar). Hosts with any other number of labels, or with a non-numeric label, remain subject to the `domain` rule.

**Examples:**

```
anthropic.com
agents.us-west-2.prod.acme.corp
localhost:8472
[::1]:8472
192.168.1.1:8080
```

### 4.2 Capability Path

The capability path describes what the agent does using hierarchical segments.

**Syntax:**

```abnf
capability-path = segment *( "/" segment )
segment         = 1*64( LOWER / DIGIT / "-" )
```

**Requirements:**

1. Capability paths MUST contain at least one segment.
2. Capability paths MUST NOT exceed 32 segments.
3. Each segment MUST be lowercase alphanumeric with hyphens permitted. Uppercase input MUST be rejected, not folded, and a segment MUST NOT carry percent-encoding: `ch%61t` is rejected rather than decoded to `chat`.
4. Segments MUST NOT be empty (no consecutive slashes).
5. Capability paths support prefix matching for discovery.
6. An agent's capability path is immutable. A capability-path change MUST use a
   new Agent ID; implementations MUST reject reuse of a trust-root/Agent-ID pair
   under another path.

**Examples:**

```
assistant/chat
workflow/approval/invoice
tool/code-interpreter
financial/trading/equity/market-orders
```

**Semantics:**

Capability paths form a hierarchy. A query for `/workflow/approval` returns agents registered at:
- `/workflow/approval` (exact match)
- `/workflow/approval/invoice` (child)
- `/workflow/approval/expense` (child)

But not:
- `/workflow` (parent)
- `/workflow/review` (sibling)

### 4.3 Agent Identifier

The agent identifier is a TypeID providing globally unique, time-sortable reference.

**Syntax:**

```abnf
agent-id     = prefix "_" suffix
prefix       = LOWER *( LOWER / "_" ) LOWER / LOWER
suffix       = first-char 25base32char
first-char   = "0" / "1" / "2" / "3" / "4" / "5" / "6" / "7"
base32char   = DIGIT / "a" / "b" / "c" / "d" / "e" / "f" / "g" / "h"
             / "j" / "k" / "m" / "n" / "p" / "q" / "r" / "s" / "t"
             / "v" / "w" / "x" / "y" / "z"
```

The suffix uses Crockford Base32 encoding with the alphabet `0123456789abcdefghjkmnpqrstvwxyz` (excludes i, l, o, u to avoid ambiguity). The first character is constrained to 0-7 to ensure the 128-bit UUIDv7 value fits in 26 characters (3 + 25×5 = 128 bits).

**Requirements:**

1. The prefix MUST contain only lowercase letters and underscores.
2. The prefix MUST start and end with a letter.
3. The suffix MUST be exactly 26 characters of Crockford Base32.
4. The suffix's first character MUST be in the range 0-7 (ensures 128-bit value fits).
5. The suffix encodes a UUIDv7, providing time-ordering and uniqueness.
6. The alphabet excludes i, l, o, u to avoid visual ambiguity with 1, 1, 0, v.

**Prefix Semantics:**

The prefix encodes the agent's implementation type:

| Prefix | Description |
|--------|-------------|
| `llm` | Large language model agent |
| `llm_chat` | LLM specialized for conversation |
| `rule` | Rule-based agent |
| `rule_fsm` | Finite state machine agent |
| `hybrid` | Combined approaches |

Custom prefixes SHOULD follow the pattern `type_modifier_modifier`.

That pattern is a naming convention and not part of the syntax above. A prefix that does not read as a class followed by non-empty modifiers is still well formed: the `prefix` rule permits any arrangement of lowercase letters and underscores between the first and last letter, including consecutive underscores, exactly as the TypeID specification does. An implementation MUST accept `llm__chat`. Refusing it would reject identifiers that conforming TypeID implementations mint. An implementation that exposes the class and modifiers separately MUST NOT report a modifier for the empty run between consecutive underscores.

**Examples:**

```
llm_01h455vb4pex5vsknk084sn02q
llm_chat_streaming_01h5fskfsk4fpeqwnsyz5hj55t
rule_fsm_01h455vb4pex5vsknk084sn02q
```

### 4.4 Query String

The query string provides optional parameters for version negotiation and metadata.

**Syntax:**

```abnf
query = *( pchar / "/" / "?" )
```

**Standard Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `version` | string | Capability version constraint |
| `ttl` | integer | Time-to-live hint in seconds |
| `attestation` | string | Inline PASETO token (discouraged; use headers) |

**Requirements:**

1. Query parameters are NOT part of agent identity.
2. Two URIs differing only in query string reference the same agent.
3. Query parameters MUST be stripped for normalization and DHT key derivation.
4. Percent-encoded octets in a query parameter value MUST be decoded as a byte sequence, and the decoded byte sequence MUST be valid UTF-8.
5. A value whose decoded octets are not valid UTF-8 MUST be rejected. Implementations MUST NOT substitute U+FFFD, decode lossily, or interpret the octets as Latin-1.
6. When serializing a query parameter value, any octet outside the unreserved set (`ALPHA` / `DIGIT` / `-` / `_` / `.`) MUST be rendered as `%` followed by two uppercase hexadecimal digits.

### 4.5 Fragment

The fragment provides optional sub-agent reference.

**Syntax:**

```abnf
fragment = *( pchar / "/" / "?" )
```

**Requirements:**

1. Fragments are NOT part of agent identity.
2. Fragments are reserved for future use in composite agent scenarios.
3. Fragments MUST be stripped for normalization and DHT key derivation.

---

## 5. Normalization and Equivalence

### 5.1 Canonical Form

Two URIs denote the same agent if and only if their canonical forms are byte-equal.

An agent URI is identity material, so normalization is deliberately narrow: an
implementation folds case only where a standard makes a component
case-insensitive, and rejects every other departure from canonical form rather
than repairing it. A repair maps two spellings onto one identity, and each such
mapping is a place where two parties can disagree about which agent a string
names. Rejection leaves exactly one spelling per identity.

**Normalization Rules:**

1. **Scheme**: Compared case-insensitively, written lowercase (`agent`).
   `AGENT://` is accepted and folded, per RFC 3986 Section 3.1.
2. **Trust root**: DNS names compared case-insensitively, written lowercase, per
   RFC 4343. IP addresses in canonical text form — for IPv6 that is RFC 5952,
   which drops leading zeros and compresses the longest run of zero groups.
   Explicit ports preserved.
3. **Capability path**: Lowercase by grammar, with no trailing slash. Uppercase
   input is rejected, not folded.
4. **Agent ID**: Lowercase by grammar. Uppercase input is rejected, not folded.
5. **Query and fragment**: Stripped entirely. Where a query is preserved rather
   than stripped, its parameters serialize sorted by name.

**Rejected rather than normalized:**

| Input | Disposition | Why |
|-------|-------------|-----|
| `AGENT://example.com/chat/llm_01h4...` | Accepted, folded | Scheme is case-insensitive by RFC 3986 |
| `agent://Example.COM/chat/llm_01h4...` | Accepted, folded | DNS is case-insensitive by RFC 4343 |
| `agent://example.com./chat/llm_01h4...` | **Rejected** | A trailing dot is a different spelling, not a case difference |
| `agent://example.com/Chat/llm_01h4...` | **Rejected** | Capability segments are lowercase identity material |
| `agent://example.com/chat/LLM_01H4...` | **Rejected** | Agent IDs are lowercase identity material |
| `agent://example.com/ch%61t/llm_01h4...` | **Rejected** | Percent-encoding appears in the grammar only in query parameter values |

Rules 3 and 4 took effect in version 0.5; earlier revisions normalized uppercase
input in those components. The 0.4 vectors are preserved as
`test-vectors-v0.4.json` so prior references stay checkable.

**Example:**

```
Input:  AGENT://Anthropic.COM/assistant/chat/llm_01h455vb4pex5vsknk084sn02q?version=1.0#task
Output: agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q
```

### 5.2 Comparison Algorithm

To compare two agent URIs for equivalence:

1. Parse both URIs according to [Section 3](#3-uri-syntax).
2. Apply normalization rules from [Section 5.1](#51-canonical-form).
3. Compare the resulting strings byte-by-byte.
4. URIs are equivalent if and only if the comparison returns equal.

Implementations MUST use the canonical form for:
- DHT key derivation
- Attestation subject matching
- Cache keys
- Audit log references

---

## 6. Discovery and Resolution

### 6.1 DHT Key Derivation

Every DHT key in this specification is a SHA-256 digest, and all of them are
computed over one canonical input string:

```
path_input = canonical(trust_root) || "/" || canonical(capability_path)
```

The key naming a capability path is the digest of that string on its own:

```
capability_key = SHA-256(path_input)
```

**Properties:**

1. **Trust-root scoping**: Different trust roots produce different keys for the same capability path, preventing cross-organization pollution.

2. **Deterministic lookup**: Any node can compute the key and query directly without metadata lookup.

**Example:**

```
Trust root: anthropic.com
Capability path: assistant/chat
Input string: "anthropic.com/assistant/chat"
Key: SHA-256("anthropic.com/assistant/chat")
   = ee7f343128163eec1164fb5afc0a019df215fc73decb14bc58fef1a4966e8262
```

#### 6.1.1 Sharded Keys

A store that bounds the size of one stored value cannot hold a capability path's
subtree at `capability_key`; [Section 6.2](#62-registration-protocol)
requirement 6 gives the measured limit. A backend on such a store spreads a
capability path over a family of keys instead, derived from the same
`path_input` under distinct domain separators. Each separator below is the
literal ASCII string shown followed by one `0x00` octet.

| Key | Holds | Derivation |
|-----|-------|------------|
| Identity | one agent's registration | `SHA-256("agent-uri/dht/identity/v1" 0x00 \|\| canonical(agent_uri))` |
| Shard descriptor | a path's shard level | `SHA-256("agent-uri/dht/shard-descriptor/v1" 0x00 \|\| path_input)` |
| Pointer page `n` | pointers beneath a path | `SHA-256("agent-uri/dht/shard-page/v1" 0x00 \|\| path_input \|\| "#" \|\| uint32be(n))` |

A publisher's page index at shard level `L` is derived from its Agent ID:

```
placement            = uint32be(SHA-256("agent-uri/dht/shard-placement/v1" 0x00 || agent_id)[0..4])
page_for(agent_id, L) = placement AND (2^L - 1)
```

**Requirements:**

1. A sharded backend MUST use these derivations byte for byte. Two
   implementations that disagree on a key do not merely perform differently;
   they cannot see each other's registrations.

2. Domain separation is REQUIRED, not an optimization. Without it a pointer page
   and a registration can be made to land on the same key, and a node handed a
   value has nothing to tell it which of the two the value was written as.

3. The identity key MUST be derived from the canonical agent URI per
   [Section 5.1](#51-canonical-form). A reference carrying a query string or a
   fragment names a view of an agent rather than another agent, and MUST resolve
   to the same record.

4. Placement MUST be computed from the Agent ID alone and not from the full URI.
   An agent then occupies the same page index at its exact path and at every
   ancestor path, so a reader fanning out over one level sees each agent exactly
   once per path.

5. The page count MUST be a power of two and placement MUST be by bitwise mask.
   This is normative rather than an implementation preference. Under
   `page = placement mod P` for arbitrary `P`, raising `P` moves nearly every
   publisher to a different page, and every pointer already written becomes
   unreadable until its publisher happens to rewrite it. Under a mask, raising
   `L` by one splits each page in two: an agent either stays on the page it was
   on or moves to a page index that did not exist at the lower level, and a
   reader at the higher level visits both. Growth is therefore backward
   compatible. A specification that said only "spread over `P` pages" would
   admit an implementation that silently loses registrations every time a path
   grows.

6. Implementations MUST impose a maximum shard level; 16 is RECOMMENDED, which
   is 65 536 pages under one path. A shard descriptor is unauthenticated
   (requirement 14 of [Section 6.2](#62-registration-protocol)), so without a
   cap a forged level directs every reader of that path to derive an unbounded
   number of keys.

7. A reader SHOULD bound the number of keys one lookup reads, independently of
   the level it read. The cap in requirement 6 bounds a forged descriptor; a
   per-lookup budget bounds the cost of an honest but very wide path.

### 6.2 Registration Protocol

An agent registers by publishing its record so that both an exact lookup by URI
and a prefix lookup by capability path can find it. Two record models satisfy
that, and which one applies is a property of the store rather than a free
choice.

**Direct model.** Where one store holds the namespace and a stored value has no
practical size bound, as in an in-process index or a database-backed registry,
the registration is written at the `capability_key` for its exact capability path
and at the key for every ancestor path. This ancestor-key materialization makes
a prefix query one ordinary exact-key lookup.

**Sharded model.** Where the store bounds the size of one value, which is every
Kademlia overlay, the registration is written once at its identity key, and each
ancestor key holds pointers to it spread over pages
([Section 6.1.1](#611-sharded-keys)). A prefix query reads the path's
descriptor, then its pages, then the registrations the pointers name.

The registration record is the same in both:

```rust
Registration {
    agent_uri: AgentUri,          // Full agent URI
    agent_key: PublicKey,         // Ed25519 key authorized to write this record
    endpoints: Vec<Endpoint>,     // Current network endpoints
    attestation: Option<String>,  // PASETO token
    expires_at: Timestamp,        // Registration TTL
    registered_at: Timestamp,     // Creation time; identifies the record instance
    sequence: u64,                // Position in this record's write history
}
```

The sharded model adds two auxiliary records. Neither carries authority, and
neither is signed:

```rust
Pointer {
    agent_uri: AgentUri,          // The agent this page points at
    expires_at: Timestamp,        // Not later than that agent's own expiry
}

ShardDescriptor {
    level: u8,                    // The path's pointers occupy 2^level pages
}
```

**Requirements:**

1. Agents MUST register at the capability path encoded in their URI.
2. Registration MUST include at least one endpoint.
3. Registration MUST include a valid attestation token covering the URI path.
4. DHT nodes MUST verify attestations before storing records.
5. In the direct model, an implementation MUST write the record atomically to
   the exact key and all ancestor keys. In the sharded model there is one
   authoritative copy, at the identity key, and the ancestor keys hold pointers
   that are written and expire independently of it; an implementation MUST
   tolerate transient divergence between them. This specification does not
   require cross-node multi-key atomicity in either model.
6. Registration write amplification is O(d), where d is path depth. A capability
   key cannot hold its subtree wherever the store bounds the size of one value,
   and that bound belongs to the protocol rather than to the deployment: on
   `libp2p-kad` the limit is 16 KiB per record, which this specification's
   reference workspace measured at 1 to 27 registrations. No amount of
   provisioning moves it, because the limit is enforced by the nodes that store
   the record and not by the one that writes it. A deployment on such a store
   MUST use the sharded model.
7. Registration MUST name an Ed25519 `agent_key`. That key, and only that key,
   is authorized to write the record.
8. Registration MUST carry a mutation proof over the record as submitted, and
   DHT nodes MUST verify it. The attestation says a trust root vouched for a
   key; the proof says the registering party holds it.
9. Where an attestation is required, DHT nodes MUST reject a registration whose
   `agent_key` differs from the attestation's `agent_key` claim. A token
   attests one agent's key and cannot be presented for another.
10. An agent that has previously held this URI SHOULD open the new record at a
    `sequence` above every sequence it has ever signed for that URI. See
    [Section 6.6](#66-write-authorization).
11. In the sharded model, a registration MUST be published at its identity key,
    and MUST place a pointer to itself on page `page_for(agent_id, L)` at its
    exact capability path and at every ancestor path, where `L` is the shard
    level read from that path's descriptor.
12. A pointer's `expires_at` MUST NOT be later than that of the registration it
    names. A stale pointer costs a reader one wasted dereference; one that
    outlives its registration costs that dereference on every lookup until it
    expires.
13. A publisher that finds a page at or above its capacity MAY raise that path's
    shard level. A raise MUST be by exactly one level, and an implementation
    MUST NOT lower a level it reads. Growth is opportunistic: a path over
    capacity keeps accepting pointers until some publisher widens it.
14. Pointers and shard descriptors are unauthenticated, and implementations MUST
    NOT treat either as evidence of anything about an agent. See requirement 3
    of [Section 6.3](#63-lookup-protocol) and
    [Section 8.10](#810-pointer-injection).
15. A node that bounds how many registrations a key may hold MUST charge a
    registration against the key derived from its own capability path, and MUST
    NOT refuse it for the occupancy of an ancestor key. In the direct model an
    ancestor holds its entire subtree, so charging it would make the population
    under a prefix decide whether an unrelated agent may register beneath it.
    See [Section 8.4](#84-capability-squatting).

### 6.3 Lookup Protocol

**Exact lookup by agent URI** is one read in either model: at the
`capability_key` for the agent's exact capability path in the direct model, at
the agent's identity key in the sharded model.

**Prefix lookup, and exact lookup by capability path,** proceed by model.

In the direct model:

1. **Key derivation**: Compute `capability_key` from trust root and capability
   path.

2. **DHT lookup**: Perform one ordinary lookup at that key. Ancestor-key
   materialization makes the returned bucket the prefix subtree.

3. **Result filtering**: Verify attestations on returned records; filter by
   query parameters.

In the sharded model:

1. **Descriptor read**: Read the path's shard descriptor to learn its level `L`.
   An absent descriptor means level 0, which is a single page.

2. **Page reads**: Read pages `0` through `2^L - 1` for that path and collect
   their pointers, discarding expired ones.

3. **Dereference**: Read the identity record named by each remaining pointer.

4. **Result filtering**: Verify attestations and mutation proofs on returned
   records; discard any record whose own capability path does not satisfy the
   query; filter by query parameters.

**Requirements:**

1. A reader MUST verify each returned record independently. Being handed a
   record by the overlay makes it neither authentic nor current.

2. Where several copies of one record are returned, a reader MUST resolve them
   by the ordering in [Section 6.6](#66-write-authorization), the greatest
   `(registered_at, sequence)`, and MUST NOT prefer whichever copy arrived
   last. Replication and caching decide arrival order; they say nothing about
   which copy is newer.

3. A reader MUST decide whether a record satisfies the query from the record's
   own `agent_uri`, and MUST NOT infer it from the page the pointer was found
   on. Nothing signs a pointer, so any page can name any URI.

4. A reader that truncates a lookup against a key budget (requirement 7 of
   [Section 6.1.1](#611-sharded-keys)) MUST report the result as incomplete. An
   empty page of results and an exhausted budget are different answers.

**Prefix Matching (direct model):**

A query for `/workflow/approval` reads only the depth-2 key:

```
Register: /workflow/approval/invoice
Writes:   SHA-256("acme.com/workflow")
          SHA-256("acme.com/workflow/approval")
          SHA-256("acme.com/workflow/approval/invoice")

Query:    /workflow/approval
Reads:    SHA-256("acme.com/workflow/approval")
```

**Prefix Matching (sharded model):**

The same registration writes one record and three pointers, and the same query
reads a descriptor, that path's pages, and one identity key per pointer:

```
Register: agent://acme.com/workflow/approval/invoice/llm_01h4...
Writes:   identity key for the canonical URI                       (the record)
          page_for(llm_01h4..., L) at "acme.com/workflow"          (a pointer)
          page_for(llm_01h4..., L) at "acme.com/workflow/approval" (a pointer)
          page_for(llm_01h4..., L) at "acme.com/workflow/approval/invoice"

Query:    /workflow/approval
Reads:    descriptor key for "acme.com/workflow/approval"    -> L
          page keys 0..2^L for "acme.com/workflow/approval"  -> pointers
          identity key per surviving pointer                 -> records
```

### 6.4 Resolution Guarantees

Under the standard Kademlia routing-table and connectivity assumptions, one
exact-key lookup is expected to require O(log N) overlay hops, where N is the
number of DHT nodes. Every read named below is one exact-key lookup and carries
that cost. What differs between operations is how many reads each one takes:

| Operation | Direct model | Sharded model |
|-----------|--------------|---------------|
| Exact lookup by agent URI | 1 read | 1 read |
| Exact lookup by capability path | 1 read | 1 + 2^L + m reads |
| Prefix lookup | 1 read | 1 + 2^L + m reads |

`L` is the queried path's shard level and `m` is the number of unexpired
pointers found. Result transfer remains proportional to the number and size of
returned records.

Two consequences are worth stating plainly. In the sharded model, exact lookup
*by capability path* costs exactly what a prefix lookup costs: both read the
same pointer pages, and they differ only in a local filter on the dereferenced
record's URI. What remains a single read is exact lookup *by agent URI*, which
is what a cached `agent://` reference resolves through.

The `2^L` page reads do not depend on each other and MAY be issued
concurrently, as MAY the `m` dereferences, so the expected latency of a sharded
lookup is nearer three sequential round trips than `1 + 2^L + m` of them.

An implementation MAY cache a path's shard descriptor, which removes the first
of those three from repeated lookups under one path. The cost of a stale cached
level falls on readers and not on publishers, and it is coverage rather than
correctness: a reader working from a level below the current one reads a subset
of the path's pages, and misses any agent whose pointer landed on a page the
higher level added. The cache lifetime bounds that window. A publisher working
from a stale level is unaffected, because the page it writes to is one a
higher-level reader still visits.

**Corollary:** Resolution cost is independent of migration history. An agent that has migrated 100 times has the same resolution cost as one that never migrated.

Propagation time after an update depends on the concrete DHT's replication,
retry, churn, and cache policies. This specification does not claim a fixed
upper bound.

### 6.5 Migration

Agent migration updates only the DHT record; the URI remains stable:

1. Agent reads its current record to learn its `registered_at` and `sequence`.
2. Agent signs a mutation proof over the new endpoint(s) at the next sequence.
3. Agent submits the update with that proof; nodes verify it per
   [Section 6.6](#66-write-authorization).
4. Kademlia replicates to k closest nodes.
5. After propagation, lookups return new endpoint.
6. Cached references continue to resolve correctly.

The agent's identity (URI) does not change for endpoint migration. A trust-root
or capability-path change creates a new identity and requires a new Agent ID and
attestation.

The record model does not change this sequence. In the sharded model a migration
rewrites the identity record and nothing else: a pointer names the agent's URI
and not its endpoints, so no ancestor key is touched and the write stays one
record regardless of path depth.

### 6.6 Write Authorization

Registration records are world-readable, so an agent URI identifies a record
but authorizes nothing. Every write that modifies or removes an existing
record MUST carry a **mutation proof**: an Ed25519 signature, made by the
record's `agent_key`, over the operation being requested.

**Signed payload.** The proof signs a domain-separated, length-prefixed
encoding of:

| Field | Purpose |
|-------|---------|
| Domain separator | Prevents a signature minted elsewhere from authorizing a DHT write |
| Operation kind | Prevents a refresh proof from acting as a deregistration, or a registration proof from acting as either |
| `registered_at` | Identifies the record instance |
| `sequence` | Identifies the position in that record's history |
| `agent_uri` | Binds the proof to one record |
| Operation arguments | Binds the proof to the endpoints or TTL requested |
| Resulting `expires_at` | Binds the proof to the record the write produces, not only to the request that produced it |

For registration, which creates the record rather than changing one, the proof
covers the record as submitted: its `agent_key`, endpoints, and `expires_at`,
at the `registered_at` and `sequence` the record opens with.

**Requirements:**

1. DHT nodes MUST reject a write whose proof does not verify under the record's
   `agent_key`: the stored record's for a modification or removal, the
   submitted record's for a registration.
2. DHT nodes MUST reject a write whose `sequence` does not exceed the stored
   record's `sequence`, and MUST record the accepted `sequence` on every
   ancestor-key copy.
3. The signature MUST be checked before the sequence. Reporting a sequence
   mismatch for an unsigned write discloses the record's position to a party
   that has proven nothing.
4. The encoding MUST be injective: every variable-length field length-prefixed,
   so that no two distinct operations produce the same signed bytes.
5. `registered_at` MUST NOT change over a record's lifetime. In particular,
   refreshing a registration extends `expires_at` only.
6. The proof MUST cover the `expires_at` the write results in, and a node MUST
   store that value rather than one it derives itself. A refreshing agent
   therefore states the instant its record will expire, not only the lifetime
   it asked for, because only the signer knows when it signed.

**Rationale.** The sequence number orders writes within one record's life, so a
captured proof cannot be applied twice. The registration time identifies the
record instance, so a proof captured before a deregistration cannot reach the
record that replaces it. Two registrations of the same URI within the
resolution of `registered_at` share an instance identity; requirement 10 of
[Section 6.2](#62-registration-protocol) removes that dependence on the clock
for agents that retain their sequence across re-registration.

Requirement 6 exists because a record that travels between nodes travels whole.
A field outside the signature is a field any node on the path may rewrite, and
`expires_at` is the field that decides how long a record outlives the agent's
intent to be found. Signing only the requested TTL, and letting each node
compute an instant from it, would leave an observer of a legitimate migration
free to republish the agent's own record with an expiry of their choosing.
Shortening one is the denial of service
[Section 8.1](#81-dht-eclipse-attacks) already scopes as a residual risk;
lengthening one holds a genuine, agent-signed record open past the
moment the agent chose to let it lapse. Requirement 6 makes both a signature
failure. It is also why a node that finds an expiry outside its acceptable
window MUST refuse the record rather than clamp it: clamping rewrites bytes the
signature covers, and the record would then fail to verify at the next hop.

---

## 7. Attestation

### 7.1 Token Format

Attestation tokens use PASETO v4.public (Ed25519 signatures):

```
v4.public.<payload>[.<footer>]
```

**Claims:**

| Claim | Type | Required | Description |
|-------|------|----------|-------------|
| `jti` | string | REQUIRED | Unique token identifier |
| `iss` | string | REQUIRED | Issuing trust root |
| `agent_uri` | string | REQUIRED | Canonical Agent URI being attested |
| `agent_key` | string | REQUIRED | Agent's own Ed25519 public key, base64-encoded |
| `iat` | datetime | REQUIRED | Issued-at timestamp |
| `exp` | datetime | REQUIRED | Expiration timestamp |
| `aud` | string | OPTIONAL | Audience restriction |
| `capabilities` | string[] | REQUIRED | Authorized capability paths |

**Example Claims:**

```json
{
  "jti": "01h455vb4pex5vsknk084sn02q",
  "iss": "acme.com",
  "agent_uri": "agent://acme.com/workflow/approval/invoice/rule_01h455vb4pex5vsknk084sn02q",
  "agent_key": "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
  "iat": "2026-01-20T00:00:00Z",
  "exp": "2026-02-19T00:00:00Z",
  "capabilities": ["workflow/approval/invoice"]
}
```

**Token Identifier:**

The `jti` claim names one token. Two attestations of the same URI with the same
capabilities are otherwise indistinguishable, which means neither can be spoken
about: not in a log, not in an incident report, and not in the revocation list
[Section 8.2](#82-trust-root-key-compromise) requires verifiers to consult. A
signature cannot be withdrawn, so an unnameable token is one that must be
honoured until it expires.

1. Trust roots MUST include `jti` in every issued token.
2. The value MUST be unique per token. It SHOULD be a UUIDv7 rendered as a
   26-character Crockford base32 string, which is the same encoding an
   `agent-id` suffix uses ([Section 3.5](#35-agent-id)); reusing it means an
   implementation needs one alphabet rather than two, and the v7 timestamp makes
   identifiers sort by issuance.
3. Verifiers MUST reject a token with no `jti`. Treating it as optional would
   place every such token permanently beyond the reach of revocation.

**Agent Key Binding:**

The `agent_key` claim names the agent's own key, distinct from the trust root's
signing key. Without it a token would be a bearer credential: registration
records are world-readable and carry their token inline, so any lookup would
hand the reader a credential naming a URI and its capabilities with nothing
about who is entitled to present it.

1. Trust roots MUST include `agent_key` in every issued token.
2. Trust roots SHOULD attest a key only after the agent has demonstrated
   possession of the matching private key. Attesting a key that was merely
   supplied vouches for whoever supplied it.
3. Verifiers MUST reject a token whose `agent_key` does not decode to a valid
   Ed25519 public key. Treating an unreadable key as absent would restore the
   bearer-credential behaviour this claim removes.

### 7.2 Key Publication

Trust roots MUST publish verification keys at a well-known endpoint:

```
GET https://{trust-root}/.well-known/agent-keys.json
```

**Response Format:**

```json
{
  "trust_root": "acme.com",
  "keys": [{
    "kid": "key-2026-01",
    "algorithm": "Ed25519",
    "public_key": "<base64-encoded public key>",
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2027-01-01T00:00:00Z"
  }],
  "revoked_keys": [{
    "public_key": "<base64-encoded public key>",
    "kid": "key-2025-07"
  }]
}
```

**Requirements:**

1. Trust roots MUST serve this endpoint over HTTPS.
2. Multiple keys MAY be published for rotation.
3. Keys MUST include validity periods (`not_before`, `not_after`).
4. Revoked keys SHOULD be listed in `revoked_keys`. Each entry MUST carry
   `public_key`, and MAY carry the `kid` the key had while it was published. It
   is the key material that a verifier can act on: a revocation is checked
   against the key that signed the token, and a verifier that has already
   dropped the key it is being told about cannot turn a name back into one.
5. Verifiers MUST reject a token whose signing key is outside its published
   validity period, evaluated against the verifier's current time rather than
   against the token's `iat`. Evaluating against `iat` would make `not_after`
   advisory: a key withdrawn at noon would keep producing acceptable tokens for
   as long as anything it signed beforehand had left to live.
6. Verifiers MAY apply their clock-skew tolerance to both bounds, for the same
   reason [Section 7.4](#74-verification-flow) applies it to `iat` and `exp`.
7. A verifier MUST reject a document that names a `trust_root` other than the
   one whose endpoint served it, and MUST NOT follow a redirect away from that
   endpoint. What makes a document evidence at all is the authority it was
   fetched from; without both of these, any authority could publish keys for
   anybody's namespace.
8. A verifier MUST bound what it will read from the endpoint, and SHOULD treat
   an unreachable endpoint as an absence of keys rather than as a reason to
   accept anything.

**What discovery does and does not establish:**

Fetching a document establishes which keys an authority stands behind. It does
not establish that the authority should be trusted. A verifier that fetches
`evil.example`'s keys learns exactly which keys `evil.example` signs with, and
nothing about whether to believe what it attests. Which trust roots matter is a
deployment decision, and this endpoint does not make it.

**Rotation:**

Requirement 5 is what makes the overlap in a published key list load-bearing
rather than decorative. A rotation that is safe for tokens already in flight
publishes the incoming key's `not_before` at or before the outgoing key's
`not_after`, with the gap between them at least as long as the longest token
lifetime the root issues:

```
outgoing:  not_after  = T + longest_ttl
incoming:  not_before = T
```

Every token signed before `T` expires by `T + longest_ttl`, so no token is ever
refused for naming a key that was current when it was minted. Trust roots
SHOULD retain a rotated-out key for that interval and SHOULD then remove it, so
that the number of keys a verifier must try stays bounded by the rotation
schedule rather than by the root's history.

A validity period is not revocation. It is a schedule, published in advance,
and a verifier that holds the key already holds the schedule. Revocation
([Section 8.2](#82-trust-root-key-compromise)) is unplanned news that has to
reach the verifier. A compromised key needs both: removal from what the root
publishes, and an entry on the revocation list for every verifier still holding
a stale copy of the key document.

### 7.3 Capability Binding

Every attested capability MUST first be constrained to the subject identity:

```
scoped(c, agent_uri) := c == uri_path || c.starts_with(uri_path + "/")
```

Within that scope, a grant may cover an equal or narrower requested operation:

```
covered(path, capabilities) := ∃c ∈ capabilities : path.starts_with(c)
```

**Example:**

For subject path `/workflow/approval`, an attestation with
`capabilities: ["workflow/approval"]` covers:
- `/workflow/approval` (exact match)
- `/workflow/approval/invoice` (descendant)

But NOT:
- `/workflow` (broader than the identity)
- `/workflow/review` (sibling)
- `/financial` (unrelated)

### 7.4 Verification Flow

Complete verification of an agent presenting URI and attestation:

1. Parse agent URI; extract `trust_root`, `capability_path`, `agent_id`.
2. Fetch/cache verification key from trust root's well-known endpoint.
3. Verify PASETO signature using the key, and reject if that key is outside the
   validity period the trust root published for it
   ([Section 7.2](#72-key-publication)).
4. Check `exp` > current time (not expired).
5. Check `iss` == `trust_root` from URI.
6. Check `agent_uri` == the canonical full agent URI.
7. Check `agent_key` decodes to a valid Ed25519 public key.
8. Check `jti` is present, and that neither it nor the verifying key appears in
   the revocation list of [Section 8.2](#82-trust-root-key-compromise). This
   step MUST follow step 3: `jti` and `iss` are claims, so consulting a list by
   them before the signature is checked lets the presenter choose which entry is
   looked up, and therefore choose one that is not listed.
9. Check every capability equals the URI path or is its descendant.
10. Check at least one capability covers the requested operation or registration path.
11. If `aud` is present, require an explicit, exact verifier audience match.
12. Where the presenter claims to *be* the agent, require proof of possession of
    `agent_key`. Steps 1 to 11 authenticate the token; only this authenticates
    the presenter. For registration that proof is the mutation proof of
    [Section 6.6](#66-write-authorization).

All checks MUST pass. Failure at any step MUST reject the attestation.

A verifier that has no revocation list available cannot perform step 8, and MUST
therefore reject rather than proceed. Accepting a token with a required check
skipped would report it as verified on evidence that was never gathered; a
deployment that does not revoke states that explicitly instead, which makes the
choice auditable rather than indistinguishable from an oversight.

### 7.5 Audience Restriction

The optional `aud` claim restricts attestation validity to specific verifiers:

**When to Use:**

- High-value transactions (financial approvals, contract signing)
- Sensitive data access (personal information, trade secrets)
- Compliance-driven interactions requiring specific authorization

**Verification Behavior:**

- If `aud` is present, the verifier MUST match.
- If `aud` is absent, any verifier MAY accept (subject to other checks).

**Multiple Parties:**

Agents interacting with multiple specific parties MAY hold multiple attestations with different `aud` values.

---

## 8. Security Considerations

### 8.1 DHT Eclipse Attacks

**Threat:** An adversary controlling nodes surrounding a capability key could return false registration records or suppress legitimate ones.

**Mitigations:**

1. **Multi-path verification**: Query from diverse network positions; consistent results across paths indicate authenticity.

2. **Attestation verification**: Signature verification against published keys rejects fraudulent attestations even if DHT returns attacker-controlled records.

3. **Kademlia redundancy**: Records are stored on k closest nodes; eclipsing requires controlling a significant fraction of the network.

**Residual Risk:** DHT manipulation can cause denial of service (hiding legitimate agents) but cannot cause acceptance of unauthorized agents.

### 8.2 Trust Root Key Compromise

**Threat:** A compromised signing key enables issuing fraudulent attestations for arbitrary agents under that trust root.

**Mitigations:**

1. **Key revocation**: Trust roots publish `revoked_keys` list; verifiers MUST check before accepting.

2. **Time-bounded attestations**: The `exp` claim limits blast radius.

3. **Key rotation with overlap**: Rotate periodically with overlapping validity windows.

4. **Hardware security modules**: Protect signing keys with HSMs.

**Revocation has two granularities, and both are needed:**

| Revoke | By | Effect |
|--------|-----|--------|
| One token | `jti` ([Section 7.1](#71-token-format)) | That attestation stops being honoured; everything else the root issued is unaffected |
| One key | The trust root's public key | Every token that key ever signed stops being honoured, including tokens never individually listed |

Per-token revocation is the tool for a grant issued in error. It is *not*
sufficient for compromise: an attacker holding a stolen signing key mints tokens
whose `jti` values the trust root has never seen, so a list of known token
identifiers can only ever name the attestations that were already known about.
Key revocation is what bounds that, because it does not require enumerating what
it refuses.

**Requirements:**

1. Verifiers MUST check both a token's `jti` and the key that verified its
   signature against the revocation list before accepting.
2. Verifiers MUST perform this check *after* signature verification. `jti` and
   `iss` are claims; consulting a list by them beforehand lets the presenter
   choose which entry is looked up.
3. A verifier with no revocation list available MUST reject. See
   [Section 7.4](#74-verification-flow).
4. Where both a token and its signing key are revoked, a verifier SHOULD report
   the key. It is the larger fact, and a caller told only that one token was
   withdrawn may reasonably request another from the same root — which is
   precisely what a compromised key benefits from.

**Residual Risk:** Revocation is only as current as the list a verifier holds.
Between a compromise and the list reaching every verifier, tokens minted with
the stolen key are honoured. The `exp` claim bounds that window from the other
end, which is why the default token lifetime is short.

**Scope Limitation:** Compromise affects only the compromised trust root's agents. Cross-trust-root isolation prevents lateral movement.

### 8.3 Trust Root Spoofing

**Threat:** An attacker claims a trust root domain they don't control.

**Mitigation:** Verifiers MUST fetch keys from the trust root's well-known endpoint over HTTPS. DNS and TLS provide domain authentication.

### 8.4 Capability Squatting

**Threat:** Early registrants claim broad capability paths, blocking legitimate agents.

**Mitigation:** Trust roots SHOULD implement governance for their namespace. DHT nodes MAY enforce attestation requirements before accepting registrations.

**Subtree lockout:** A node that bounds a key's occupancy turns squatting into
something cheaper and broader if it charges a registration against ancestor
keys. In the direct model an ancestor holds its whole subtree, so filling one
shallow prefix refuses every path beneath it, including paths nobody has
claimed and paths the squatter never named. The attacker does not have to guess
which capability a competitor will want; a top-level prefix covers all of them.
Requirement 15 of [Section 6.2](#62-registration-protocol) forbids the
accounting that allows this.

### 8.5 Query Privacy

**Threat:** DHT queries reveal requester interest in specific capabilities.

**Trade-offs:**

| Approach | Privacy | Latency | Bandwidth |
|----------|---------|---------|-----------|
| Onion routing | Strong | Higher | Normal |
| Query batching | Moderate | Normal | Higher |
| Local caching | Weak | Lower | Lower |

Deployments requiring query privacy SHOULD consider private information retrieval techniques.

### 8.6 Enumeration

**Threat:** Prefix-based discovery enables capability enumeration.

**Mitigation:** Trust roots MAY restrict prefix queries to authorized requesters.

**Note on the sharded model:** pointer pages list a path's agent URIs directly
and can be read without dereferencing anything, so enumeration there costs a
descriptor read and `2^L` page reads. A deployment that treated the cost of
enumeration as a protection has less of one than it appears to.

### 8.7 Registration Hijack

**Threat:** An agent URI is public, so any party that can reach a storing node
knows which record to write to. Without authorization on modification, that
party can repoint an agent's endpoints at infrastructure it controls, or evict
the agent entirely, without holding any key.

**Mitigation:** Every modification and removal carries a mutation proof signed
by the record's `agent_key`, per [Section 6.6](#66-write-authorization). The
proof covers the operation's arguments, so an intercepted migration cannot be
re-aimed at other endpoints while keeping the agent's signature.

**Residual Risk:** A captured proof that has already been applied cannot be
applied again, but an adversary who suppresses a legitimate write can delay it.
This is the denial of service described in
[Section 8.1](#81-dht-eclipse-attacks), not a hijack: producing a record that
points somewhere new requires a signature over those endpoints, which no
capture supplies.

### 8.8 Attestation Token Replay

**Threat:** Registration records are world-readable and carry their attestation
token inline, so any lookup returns one. A token that named only a URI and its
capabilities would be a bearer credential: whoever read a record could
re-register that URI, pointing at their own endpoints, for as long as the token
remained valid.

**Mitigations:**

1. **Agent key binding**: the `agent_key` claim names the key the trust root
   vouched for, and DHT nodes reject a registration whose record names a
   different one. A lifted token can only produce a record naming its rightful
   agent's key.

2. **Proof of possession**: registration carries a mutation proof signed by
   that key, so keeping the rightful key in the record does not help either.

3. **Endpoint binding in the proof, not the claims**: the proof covers the
   endpoints, so a lifted token cannot be paired with substituted ones. Binding
   endpoints into the *attestation* instead would force re-issuance from the
   trust root on every migration, which [Section 6.5](#65-migration) exists to
   avoid.

**Residual Risk:** A trust root that attests a key without first seeing the
agent prove possession of it vouches for whoever supplied that key. The binding
is only as good as the enrolment that precedes it.

### 8.9 Cross-Namespace Issuance

**Threat:** In a multi-root deployment, a verifier trusts several trust roots. A valid signing key for one authority (e.g. `marketing.acme.com`) mints an attestation whose `agent_uri` is rooted at a *different* authority (e.g. `finance.acme.com`). Authenticating `iss` alone proves only which trusted key signed the token, not that the signer owns the attested namespace.

**Mitigation:** Verifiers MUST reject an attestation whose `iss` claim differs from the trust root (authority) of the attested agent URI. If the attested URI's authority cannot be determined, verifiers MUST reject the attestation (fail closed). This binding makes `iss` authoritative for the URI's namespace and preserves the cross-trust-root isolation described in [Section 8.2](#82-trust-root-key-compromise): a key compromise or misuse cannot forge attestations for agents under a different trust root.

### 8.10 Pointer Injection

**Threat:** In the sharded model ([Section 6.1.1](#611-sharded-keys)), pointer
pages and shard descriptors carry no signature. There is nothing for one to be
signed *by*: a page is a set contributed to by every agent beneath a path, and
no single party owns it. Any party that can write to the overlay can therefore
put any agent URI on any page, or raise any path's shard level.

**Mitigations:**

1. **A pointer confers nothing.** A reader dereferences every pointer to the
   named agent's own registration and decides from that record's `agent_uri`
   whether it satisfies the query, per requirement 3 of
   [Section 6.3](#63-lookup-protocol). An injected pointer buys the attacker one
   wasted read on someone else's machine.

2. **Level capping.** A maximum shard level bounds how many keys a forged
   descriptor can make a reader derive, and a per-lookup key budget bounds it
   again independently.

3. **Union merge.** Pages merge by union rather than by replacement, so a write
   cannot remove a pointer another publisher placed.

**Residual Risk:** Pointer pages are a denial-of-service surface rather than an
authenticity one. Filling a page with pointers to agents that do not exist makes
every lookup under that path slower and can push a reader against its key
budget, hiding legitimate agents in the way
[Section 8.1](#81-dht-eclipse-attacks) describes. Raising a shard level is not
reversible by the same means, because descriptors take the greater level: a path
can be pushed wide and stays wide.

### 8.11 Internationalized Trust Root Names

**Threat:** A trust root is ASCII, and this specification performs no
[IDNA](#102-informative-references) processing. An implementation therefore
cannot distinguish a domain from one that merely looks like it, and two
spellings of one real-world name can be two identities or can be one identity
and one error.

Three distinct consequences follow, and they are consequences of the same
decision rather than three defects:

1. **Conversion is the caller's.** A non-ASCII name MUST be rejected, not
   converted: `münchen.de` is an error and not a synonym for
   `xn--mnchen-3ya.de`. Performing [UTS #46](#102-informative-references)
   ToASCII inside the identity type would place a Unicode version table on the
   identity path, where two implementations holding different table versions
   would map one name to two trust roots. Refusing is a smaller surface than
   disagreeing.

2. **An A-label is opaque.** A label beginning `xn--` is validated as a DNS
   label and no further: it is not decoded, and its Punycode is not checked.
   `xn--zzzzzz` is not valid Punycode and is a valid trust root under this
   specification. A name converted incorrectly upstream stays incorrect, and
   nothing downstream will say so.

3. **Confusables are not detected.** `apple.com` and the Cyrillic-`а`
   homograph, whose A-label form is `xn--pple-43d.com`, are two unrelated trust
   roots. Only the A-label form can ever reach a parser, and at that point the
   two strings are not similar.

**Mitigations:**

1. **Convert once, at the edge.** An implementation that accepts names from
   people SHOULD apply UTS #46 ToASCII at the point of entry, before the name
   becomes an identity, and SHOULD carry the A-label form from there on. A
   name converted twice, or converted in two places by two versions, is the
   failure this ordering prevents.

2. **Authentication does not depend on the name looking right.** A verifier
   fetches keys from the trust root's own well-known endpoint over HTTPS
   ([Section 7.2](#72-key-publication)). A homograph resolves to its own DNS
   name and its own keys, so it can impersonate a familiar name to a *reader*
   but cannot present the imitated root's attestations.

3. **Display is where confusability is decided.** An implementation that shows
   a trust root to a person SHOULD apply a confusable-detection policy there —
   mixed-script restriction, or displaying the A-label form — rather than
   relying on the parser, which by then has only ASCII to look at.

**Residual Risk:** A user who is shown a homograph and chooses to trust it has
been deceived before any part of this specification is reached. Nothing in the
URI syntax, the DHT, or attestation detects it, because at every one of those
layers the two names are simply different. Note also that a trailing dot is
rejected rather than stripped ([Section 4.1](#41-trust-root)), so a
root-anchored `example.com.` is not a second spelling of `example.com` but an
invalid trust root; this removes an equivalence question at the cost of
rejecting a form that DNS accepts.

---

## 9. IANA Considerations

### 9.1 URI Scheme Registration

This specification requests registration of the "agent" URI scheme in the "Uniform Resource Identifier (URI) Schemes" registry.

| Field | Value |
|-------|-------|
| Scheme name | agent |
| Status | Permanent |
| Applications/protocols | Multi-agent systems, A2A protocol |
| Contact | rrrodzilla@proton.me |
| Change controller | Govcraft |
| Reference | This specification |

### 9.2 Well-Known URI Registration

This specification requests registration of the following well-known URI:

| Field | Value |
|-------|-------|
| URI suffix | agent-keys.json |
| Change controller | Govcraft |
| Specification document | This specification, Section 7.2 |
| Related information | None |

---

## 10. References

### 10.1 Normative References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.

- [RFC 3986] Berners-Lee, T., Fielding, R., and L. Masinter, "Uniform Resource Identifier (URI): Generic Syntax", STD 66, RFC 3986, January 2005.

- [RFC 5234] Crocker, D. and P. Overell, "Augmented BNF for Syntax Specifications: ABNF", STD 68, RFC 5234, January 2008.

- [RFC 9562] Peabody, B. and K. Davis, "Universally Unique Identifiers (UUIDs)", RFC 9562, May 2024.

- [PASETO] Arciszewski, S., "Platform-Agnostic Security Tokens", https://paseto.io/, 2018.

- [TypeID] Jetify, "TypeID Specification", https://github.com/jetify-com/typeid, 2023.

### 10.2 Informative References

- [Kademlia] Maymounkov, P. and D. Mazières, "Kademlia: A Peer-to-Peer Information System Based on the XOR Metric", IPTPS 2002.

- [Saltzer1982] Saltzer, J., "On the Naming and Binding of Network Destinations", Proc. IEEE 70(9), 1982.

- [FIPA] Foundation for Intelligent Physical Agents, "FIPA Agent Management Specification", SC00023K, 2004.

- [A2A] Linux Foundation, "Agent-to-Agent (A2A) Protocol Specification", https://a2aprotocol.ai/, 2025.

- [DIDs] Sporny, M., et al., "Decentralized Identifiers (DIDs) v1.0", W3C Recommendation, 2022.

- [IDNA] Klensin, J., "Internationalized Domain Names in Applications (IDNA): Protocol", RFC 5891, August 2010.

- [UTS46] Davis, M. and M. Suignard, "Unicode IDNA Compatibility Processing", Unicode Technical Standard #46, https://www.unicode.org/reports/tr46/.

---

## Appendix A: ABNF Grammar

```abnf
; Agent URI Scheme - Complete ABNF Grammar
; RFC 5234 compliant

; ==========================================================================
; TOP-LEVEL RULE
; ==========================================================================

agent-uri       = scheme "://" trust-root "/" capability-path "/" agent-id
                  [ "?" query ] [ "#" fragment ]
                  ; Total length MUST NOT exceed 512 characters

scheme          = "agent"

; ==========================================================================
; TRUST ROOT
; ==========================================================================

trust-root      = host [ ":" port ]
                  ; Maximum 128 characters

host            = domain / ip-literal / ipv4-address

domain          = label *( "." label )
                  ; Maximum 253 characters (DNS limit)

label           = 1*63( ALPHA / DIGIT / "-" )
                  ; Labels cannot start or end with hyphen

ip-literal      = "[" ipv6-address "]"

ipv4-address    = dec-octet "." dec-octet "." dec-octet "." dec-octet

dec-octet       = DIGIT                 ; 0-9
                / %x31-39 DIGIT         ; 10-99
                / "1" 2DIGIT            ; 100-199
                / "2" %x30-34 DIGIT     ; 200-249
                / "25" %x30-35          ; 250-255

ipv6-address    = 6( h16 ":" ) ls32
                /                       "::" 5( h16 ":" ) ls32
                / [               h16 ] "::" 4( h16 ":" ) ls32
                / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
                / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
                / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
                / [ *4( h16 ":" ) h16 ] "::"              ls32
                / [ *5( h16 ":" ) h16 ] "::"              h16
                / [ *6( h16 ":" ) h16 ] "::"

h16             = 1*4HEXDIG
ls32            = ( h16 ":" h16 ) / ipv4-address

port            = 1*5DIGIT
                  ; 0-65535

; ==========================================================================
; CAPABILITY PATH
; ==========================================================================

capability-path = segment *( "/" segment )
                  ; Maximum 256 characters total
                  ; Maximum 32 segments

segment         = 1*64( LOWER / DIGIT / "-" )
                  ; Lowercase only; uppercase input is rejected

; ==========================================================================
; AGENT IDENTIFIER
; ==========================================================================

agent-id        = prefix "_" suffix

prefix          = LOWER *( LOWER / "_" ) LOWER / LOWER
                  ; Must start and end with ALPHA
                  ; Lowercase only

suffix          = first-char 25base32char
                  ; Encodes UUIDv7 (128 bits) in 26 base32 characters
                  ; 3 bits (first char) + 125 bits (25 chars × 5) = 128 bits

first-char      = "0" / "1" / "2" / "3" / "4" / "5" / "6" / "7"
                  ; First character limited to 0-7 (3 bits max value)
                  ; Ensures encoded value fits in 128 bits

base32char      = DIGIT / "a" / "b" / "c" / "d" / "e" / "f" / "g" / "h"
                / "j" / "k" / "m" / "n" / "p" / "q" / "r" / "s" / "t"
                / "v" / "w" / "x" / "y" / "z"
                  ; Crockford Base32 alphabet (lowercase canonical form)
                  ; Excludes: i, l, o, u (visually ambiguous)

; ==========================================================================
; QUERY AND FRAGMENT
; ==========================================================================

query           = *( pchar / "/" / "?" )

fragment        = *( pchar / "/" / "?" )

pchar           = unreserved / pct-encoded / sub-delims / ":" / "@"

unreserved      = ALPHA / DIGIT / "-" / "." / "_" / "~"

pct-encoded     = "%" HEXDIG HEXDIG

sub-delims      = "!" / "$" / "&" / "'" / "(" / ")"
                / "*" / "+" / "," / ";" / "="

; ==========================================================================
; CORE RULES (RFC 5234 Appendix B)
; ==========================================================================

ALPHA           = %x41-5A / %x61-7A    ; A-Z / a-z
DIGIT           = %x30-39              ; 0-9
HEXDIG          = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
                        / "a" / "b" / "c" / "d" / "e" / "f"
```

---

## Appendix B: Test Vectors

### B.1 Valid URIs

```
# Minimal valid URI
Input:  agent://a.co/x/llm_01h455vb4pex5vsknk084sn02q
Status: VALID
Trust root: a.co
Capability path: x
Agent ID: llm_01h455vb4pex5vsknk084sn02q

# Typical production URI
Input:  agent://anthropic.com/assistant/chat/llm_chat_01h455vb4pex5vsknk084sn02q
Status: VALID
Trust root: anthropic.com
Capability path: assistant/chat
Agent ID: llm_chat_01h455vb4pex5vsknk084sn02q

# Deep capability path
Input:  agent://acme.corp/workflow/approval/invoice/high-value/rule_fsm_01h5fskfsk4fpeqwnsyz5hj55t
Status: VALID
Trust root: acme.corp
Capability path: workflow/approval/invoice/high-value
Agent ID: rule_fsm_01h5fskfsk4fpeqwnsyz5hj55t

# With port
Input:  agent://localhost:8472/debug/test/llm_01h455vb4pex5vsknk084sn02q
Status: VALID
Trust root: localhost:8472
Capability path: debug/test
Agent ID: llm_01h455vb4pex5vsknk084sn02q

# IPv4 address
Input:  agent://192.168.1.1:8080/internal/agent_01h455vb4pex5vsknk084sn02q
Status: VALID
Trust root: 192.168.1.1:8080
Capability path: internal
Agent ID: agent_01h455vb4pex5vsknk084sn02q

# IPv6 address
Input:  agent://[::1]:8472/debug/llm_01h455vb4pex5vsknk084sn02q
Status: VALID
Trust root: [::1]:8472
Capability path: debug
Agent ID: llm_01h455vb4pex5vsknk084sn02q

# With query and fragment (stripped for identity)
Input:  agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q?version=2.0#streaming
Status: VALID
Trust root: anthropic.com
Capability path: assistant/chat
Agent ID: llm_01h455vb4pex5vsknk084sn02q
Canonical: agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q
```

### B.2 Invalid URIs

```
# Wrong scheme
Input:  http://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q
Status: INVALID
Reason: Scheme must be "agent"

# Missing agent ID
Input:  agent://anthropic.com/assistant/chat
Status: INVALID
Reason: Missing agent identifier

# Empty path segment
Input:  agent://anthropic.com//chat/llm_01h455vb4pex5vsknk084sn02q
Status: INVALID
Reason: Empty path segment not allowed

# Invalid agent ID (wrong suffix length)
Input:  agent://anthropic.com/chat/llm_01h455vb4pex
Status: INVALID
Reason: Agent ID suffix must be exactly 26 characters

# Invalid agent ID (missing prefix)
Input:  agent://anthropic.com/chat/01h455vb4pex5vsknk084sn02q
Status: INVALID
Reason: Agent ID must have prefix followed by underscore

# Trust root too long (>128 chars)
Input:  agent://a]
Status: INVALID
Reason: Trust root exceeds 128 character limit

# Uppercase in capability path
Input:  agent://anthropic.com/Assistant/Chat/llm_01h455vb4pex5vsknk084sn02q
Status: INVALID
Reason: Capability segments are lowercase by grammar
```

### B.3 Normalization Equivalence

```
# Authority normalization
URI A: agent://Anthropic.COM/assistant/chat/llm_01h455vb4pex5vsknk084sn02q
URI B: agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q
Equivalent: YES
Canonical: agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q

# Query string stripped
URI A: agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q?version=1.0
URI B: agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q?version=2.0
Equivalent: YES
Canonical: agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q

# Fragment stripped
URI A: agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q#task1
URI B: agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q#task2
Equivalent: YES
Canonical: agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q

# Different agents (not equivalent)
URI A: agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02q
URI B: agent://anthropic.com/chat/llm_01h455vb4pex5vsknk084sn02r
Equivalent: NO
```

### B.4 DHT Key Derivation

```
# Basic derivation
Trust root: anthropic.com
Capability path: assistant/chat
Input: "anthropic.com/assistant/chat"
capability_key = ee7f343128163eec1164fb5afc0a019df215fc73decb14bc58fef1a4966e8262

# Trust-root scoping (different keys)
Input A: "anthropic.com/assistant/chat"
       = ee7f343128163eec1164fb5afc0a019df215fc73decb14bc58fef1a4966e8262
Input B: "openai.com/assistant/chat"
       = c5a97797f98cc507b8604ebd16a27071e87056b047c8f2625182287d14b31f53

# Prefix key derivation
Trust root: acme.com
Path: workflow/approval/invoice
Keys at depths:
  Depth 1: SHA-256("acme.com/workflow")
         = 16889f14c0da9c42cae8063d495e33b4fa1b12cabfdd019c1491b217a56c857a
  Depth 2: SHA-256("acme.com/workflow/approval")
         = b15b22d3c95b3091743a071ed616d9715038a7afd559a7dc28f3d7a1f9eec03e
  Depth 3: SHA-256("acme.com/workflow/approval/invoice")
         = d9786664a610a9aaa2799a65c6bd3f9baa44a067f7511cb179c63041021f25f2
```

### B.4.1 Sharded Key Derivation

Every separator below is the ASCII string shown followed by one `0x00` octet.
See [Section 6.1.1](#611-sharded-keys).

```
# Identity key (from the canonical URI, so a query or fragment does not move it)
URI:   agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q
Input: "agent-uri/dht/identity/v1" 0x00 || that URI
Key:   90a4a81f9c9170054bb24aa43c96d6f228a4af6eb494af2deb9b01fe342f84e0

# Shard descriptor key
Input: "agent-uri/dht/shard-descriptor/v1" 0x00 || "anthropic.com/assistant/chat"
Key:   d40a062c6be6ecfdec023bb8b2de9c33ce438b1e1f9a3a1f5810dd692daa6d48

# Pointer page keys
Input: "agent-uri/dht/shard-page/v1" 0x00 || "anthropic.com/assistant/chat"
                                   || "#" || uint32be(0)
Key:   5f5cb6dbffabc05bcb29216212b86c4b1372881218406df99aeaebd944a81494

Input: ... || uint32be(1)
Key:   53e0301a0584471036c44b3a6fcc5c67d7c0308498a062f83dc1f7e51a29e5ea

# All four kinds of key for one path are distinct
capability_key != identity != descriptor != page (domain separators differ)

# Placement, from the Agent ID alone
Agent ID: llm_01h455vb4pex5vsknk084sn02q
Level 0: page 0    (one page; the mask is zero)
Level 1: page 1
Level 2: page 1
Level 3: page 1
Level 4: page 9

# Growth is backward compatible: raising the level either leaves an agent where
# it was or moves it to page (old + 2^L_old), which a wider reader also visits.
# Here, level 3 -> 4 moves this agent from page 1 to page 1 + 2^3 = 9.
```

### B.5 Capability Coverage

```
# Exact match
Capabilities: ["workflow/approval"]
Path: workflow/approval
Covered: YES

# Descendant coverage within the URI identity path
Subject path: workflow/approval
Capabilities: ["workflow/approval"]
Requested path: workflow/approval/invoice
Covered: YES

# No coverage (sibling)
Capabilities: ["workflow/approval"]
Path: workflow/review
Covered: NO

# No coverage (partial string)
Capabilities: ["work"]
Path: workflow
Covered: NO

# Multiple capabilities (any covers)
Subject path: workflow/approval
Capabilities: ["workflow/approval/read", "workflow/approval/write"]
Requested path: workflow/approval/write/invoice
Covered: YES (second capability covers)
```

---

## Appendix C: Length Constraints

### C.1 URI Components

| Component | Min | Max | Notes |
|-----------|-----|-----|-------|
| Total URI | 45 | 512 | Minimum assumes shortest valid URI |
| Scheme | 5 | 5 | Fixed: "agent" |
| Trust root | 4 | 128 | Minimum: "a.co" |
| Capability path | 1 | 256 | At least one segment required |
| Path segment | 1 | 64 | Per segment |
| Path segment count | 1 | 32 | Number of segments |
| Agent ID | 28 | 90 | prefix (1-63) + "_" + suffix (26) |
| Agent ID prefix | 1 | 63 | TypeID specification |
| Agent ID suffix | 26 | 26 | Fixed: UUIDv7 in Crockford Base32 |

### C.2 Attestation Components

| Component | Min | Max | Notes |
|-----------|-----|-----|-------|
| Total token | — | 8192 | PASETO practical limit |
| Payload (decoded) | — | 4096 | Bytes after base64url decode |
| agent_uri | 45 | 512 | Per URI constraints |
| capabilities array | 1 | 64 | Recommended practical item count |
| Each capability | 1 | 256 | Same grammar and limit as URI capability path |
| issuer | 4 | 128 | Matches trust root limit |
| audience | 1 | 128 | Optional |
| Timestamp | — | 30 | ISO 8601 with milliseconds |

### C.3 DHT Components

| Component | Size | Notes |
|-----------|------|-------|
| DHT key | 256 bits | SHA-256 output, every kind |
| Stored value | Backend-dependent | 16 KiB on `libp2p-kad`; see §6.2 requirement 6 |
| Registration record | Variable | Depends on endpoint count and attestation size |
| Endpoint | Variable | URL length |
| Pointer | ~74 bytes | At typical URI length; ~494 at the URI ceiling |
| Pointers per 16 KiB page | ~220 | At typical URI length; ~33 at the URI ceiling |
| Shard descriptor | 1 byte | The level; the record is its own key's whole value |
| Shard level | 0 to 16 | 16 RECOMMENDED as the maximum, per §6.1.1 requirement 6 |

The pointer figures are measured against this specification's reference
workspace and are informative, not normative. They are what makes the sharded
model necessary rather than merely tidy: pointers cut the per-agent cost by
roughly a factor of seven, which moves the ceiling but does not remove it. Only
sharding removes it, because only sharding adds keys.

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 0.8.3 | 2026-07-31 | §4.3 clarified: the `type_modifier_modifier` pattern stated to be a naming convention rather than syntax, consecutive underscores confirmed well formed as in the TypeID specification, and an implementation exposing the class and modifiers separately required not to report a modifier for the empty run between them |
| 0.8.2 | 2026-07-31 | §7.2 given the shape of a `revoked_keys` entry, which was named but never defined, and required to carry key material rather than only a name; the verifier-side obligations discovery implies added: refuse a document naming another trust root, do not follow redirects away from the endpoint, bound what is read, and treat an unreachable endpoint as an absence of keys; what a fetched document does and does not establish stated outright |
| 0.8.1 | 2026-07-31 | §7.2 given the verifier-side obligation its published validity periods implied: a key outside its window MUST be refused, judged at verification time rather than against the token's `iat`, with the rotation overlap that keeps in-flight tokens working stated as a schedule; §7.4 step 3 amended to carry the same check, and the distinction between a published schedule and unplanned revocation made explicit |
| 0.8.0 | 2026-07-31 | `jti` added to §7.1 as a REQUIRED claim, since §8.2 revocation cannot name a token that has no identifier; §7.4 given an explicit revocation step, placed after signature verification so the presenter cannot choose which list entry is consulted, and a verifier without a revocation list required to reject rather than skip it; §8.2 expanded with the two granularities of revocation and why per-token listing alone cannot bound a key compromise |
| 0.7.1 | 2026-07-31 | Trust root stated to be ASCII, with conversion of internationalized names placed on whatever accepts them from a person and `xn--` labels defined as opaque; the resulting confusability and mis-conversion exposure added as §8.11 |
| 0.7.0 | 2026-07-30 | Mutation proofs required to cover the `expires_at` the write results in, and nodes required to store that value rather than derive one, closing the rewritable expiry described in §6.6; per-key capacity required to be charged to the registering path's own key and not to an ancestor, with the resulting subtree lockout added to §8.4 |
| 0.6.0 | 2026-07-30 | Direct and sharded record models distinguished; sharded key derivation, pointer pages, and shard descriptors defined normatively; prefix lookup no longer claimed to be one exact-key read; §6.2 requirement 6 restated as a protocol ceiling rather than a provisioning matter; pointer injection added as §8.10; placeholder key vectors in B.4 replaced with computed digests |
| 0.5.2 | 2026-07-27 | Four dot-separated all-numeric host labels defined as an ipv4-address rather than a domain; hosts of that shape whose octets are outside 0-255 or carry a leading zero are rejected |
| 0.5.1 | 2026-07-27 | Query parameter percent-decoding defined as UTF-8 octet decoding; values whose decoded octets are not valid UTF-8 are rejected; serializing a query parameter value re-encodes non-unreserved octets as uppercase %XX |
| 0.5.0 | 2026-07-13 | Capability path made constitutive identity material; lowercase path and Agent ID inputs are rejected rather than normalized; URI-scoped capability claims and ancestor-key registration defined |
| 0.4.0 | 2026-01-20 | Initial draft specification |

---

*End of Specification*
