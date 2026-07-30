# Agent URI Scheme Specification

**Version:** 0.5.2
**Status:** Draft
**Last Updated:** 2026-07-27
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
5. A host consisting of exactly four dot-separated labels that each contain only digits MUST be parsed as an `ipv4-address`, never as a `domain`. Such a host MUST be rejected when it is not a valid dotted-decimal address: every octet MUST be in the range 0-255 and MUST NOT carry a leading zero, per the `dec-octet` rule in [Appendix A](#appendix-a-abnf-grammar). Hosts with any other number of labels, or with a non-numeric label, remain subject to the `domain` rule.

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
3. Each segment MUST be lowercase alphanumeric with hyphens permitted.
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

**Normalization Rules:**

1. **Scheme**: Lowercase (`agent`, not `AGENT`)
2. **Trust root**: DNS names lowercase with no trailing dot; IP addresses in canonical text form; explicit ports preserved
3. **Capability path**: Already lowercase by grammar, with no trailing slash
4. **Agent ID**: Already lowercase by grammar
5. **Query and fragment**: Stripped entirely

**Example:**

```
Input:  agent://Anthropic.COM/assistant/chat/llm_01h455vb4pex5vsknk084sn02q?version=1.0#task
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

DHT keys are derived by hashing the trust root and capability path:

```
key = SHA-256(canonical(trust_root) || "/" || canonical(capability_path))
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
   = 0x8a7f3c... (256-bit hash)
```

### 6.2 Registration Protocol

An agent registers by storing its record at the DHT key for its exact capability
path and at the key for every ancestor path. This ancestor-key materialization
makes a prefix query one ordinary exact-key DHT lookup.

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

**Requirements:**

1. Agents MUST register at the capability path encoded in their URI.
2. Registration MUST include at least one endpoint.
3. Registration MUST include a valid attestation token covering the URI path.
4. DHT nodes MUST verify attestations before storing records.
5. The reference in-memory index MUST write the record atomically to the exact key and all ancestor keys. A distributed backend MUST either tolerate transient divergence between these keys or define an additional coordination protocol; this specification does not require cross-node multi-key atomicity.
6. Registration write amplification is O(d), where d is path depth. Deployments
   MUST provision broad ancestor keys for higher load or impose capacity limits.
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

### 6.3 Lookup Protocol

Discovery proceeds in three steps:

1. **Key derivation**: Compute DHT key from trust root and capability path.

2. **DHT lookup**: Perform one ordinary lookup at that key. Ancestor-key
   materialization makes the returned bucket the prefix subtree.

3. **Result filtering**: Verify attestations on returned records; filter by query parameters.

**Prefix Matching:**

For registration, derive and write keys at each level. A query for
`/workflow/approval` reads only the depth-2 key:

```
Register: /workflow/approval/invoice
Writes:   SHA-256("acme.com/workflow")
          SHA-256("acme.com/workflow/approval")
          SHA-256("acme.com/workflow/approval/invoice")

Query:    /workflow/approval
Reads:    SHA-256("acme.com/workflow/approval")
```

### 6.4 Resolution Guarantees

Under the standard Kademlia routing-table and connectivity assumptions, one
exact-key lookup is expected to require O(log N) overlay hops, where N is the
number of DHT nodes. Prefix lookup has the same routing shape because it reads
one materialized ancestor key; result transfer remains proportional to the
number and size of returned records.

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

**Rationale.** The sequence number orders writes within one record's life, so a
captured proof cannot be applied twice. The registration time identifies the
record instance, so a proof captured before a deregistration cannot reach the
record that replaces it. Two registrations of the same URI within the
resolution of `registered_at` share an instance identity; requirement 10 of
[Section 6.2](#62-registration-protocol) removes that dependence on the clock
for agents that retain their sequence across re-registration.

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
  "iss": "acme.com",
  "agent_uri": "agent://acme.com/workflow/approval/invoice/rule_01h455vb4pex5vsknk084sn02q",
  "agent_key": "11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=",
  "iat": "2026-01-20T00:00:00Z",
  "exp": "2026-02-19T00:00:00Z",
  "capabilities": ["workflow/approval/invoice"]
}
```

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
  "revoked_keys": []
}
```

**Requirements:**

1. Trust roots MUST serve this endpoint over HTTPS.
2. Multiple keys MAY be published for rotation.
3. Keys MUST include validity periods (`not_before`, `not_after`).
4. Revoked keys SHOULD be listed in `revoked_keys`.

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
3. Verify PASETO signature using the key.
4. Check `exp` > current time (not expired).
5. Check `iss` == `trust_root` from URI.
6. Check `agent_uri` == the canonical full agent URI.
7. Check `agent_key` decodes to a valid Ed25519 public key.
8. Check every capability equals the URI path or is its descendant.
9. Check at least one capability covers the requested operation or registration path.
10. If `aud` is present, require an explicit, exact verifier audience match.
11. Where the presenter claims to *be* the agent, require proof of possession of
    `agent_key`. Steps 1 to 10 authenticate the token; only this authenticates
    the presenter. For registration that proof is the mutation proof of
    [Section 6.6](#66-write-authorization).

All checks MUST pass. Failure at any step MUST reject the attestation.

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

**Scope Limitation:** Compromise affects only the compromised trust root's agents. Cross-trust-root isolation prevents lateral movement.

### 8.3 Trust Root Spoofing

**Threat:** An attacker claims a trust root domain they don't control.

**Mitigation:** Verifiers MUST fetch keys from the trust root's well-known endpoint over HTTPS. DNS and TLS provide domain authentication.

### 8.4 Capability Squatting

**Threat:** Early registrants claim broad capability paths, blocking legitimate agents.

**Mitigation:** Trust roots SHOULD implement governance for their namespace. DHT nodes MAY enforce attestation requirements before accepting registrations.

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
Key: SHA-256("anthropic.com/assistant/chat")
   = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
   (Note: actual hash of this specific input)

# Trust-root scoping (different keys)
Input A: "anthropic.com/assistant/chat"
Input B: "openai.com/assistant/chat"
Keys: DIFFERENT (trust root is part of hash input)

# Prefix key derivation
Trust root: acme.com
Path: workflow/approval/invoice
Keys at depths:
  Depth 1: SHA-256("acme.com/workflow")
  Depth 2: SHA-256("acme.com/workflow/approval")
  Depth 3: SHA-256("acme.com/workflow/approval/invoice")
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
| DHT key | 256 bits | SHA-256 output |
| Registration record | Variable | Depends on endpoint count |
| Endpoint | Variable | URL length |

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 0.5.2 | 2026-07-27 | Four dot-separated all-numeric host labels defined as an ipv4-address rather than a domain; hosts of that shape whose octets are outside 0-255 or carry a leading zero are rejected |
| 0.5.1 | 2026-07-27 | Query parameter percent-decoding defined as UTF-8 octet decoding; values whose decoded octets are not valid UTF-8 are rejected; serializing a query parameter value re-encodes non-unreserved octets as uppercase %XX |
| 0.5.0 | 2026-07-13 | Capability path made constitutive identity material; lowercase path and Agent ID inputs are rejected rather than normalized; URI-scoped capability claims and ancestor-key registration defined |
| 0.4.0 | 2026-01-20 | Initial draft specification |

---

*End of Specification*
