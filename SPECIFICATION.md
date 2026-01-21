# Agent URI Scheme Specification

**Version:** 0.4.0
**Status:** Draft
**Last Updated:** 2026-01-20
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

The `agent://` URI scheme decouples identity from topology through three orthogonal components:

- **Trust root**: Organizational authority vouching for the agent
- **Capability path**: Hierarchical description of agent capabilities
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
4. The trust root is case-insensitive and MUST be normalized to lowercase.

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
segment         = 1*64( ALPHA / DIGIT / "-" )
```

**Requirements:**

1. Capability paths MUST contain at least one segment.
2. Capability paths MUST NOT exceed 32 segments.
3. Each segment MUST be lowercase alphanumeric with hyphens permitted.
4. Segments MUST NOT be empty (no consecutive slashes).
5. Capability paths support prefix matching for discovery.

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
prefix       = 1*63( ALPHA / "_" )
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
2. Two URIs differing only in query string MAY reference the same agent.
3. Query parameters MUST be stripped for normalization and DHT key derivation.

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
2. **Trust root**: Lowercase, no trailing dot
3. **Capability path**: Lowercase, no trailing slash, percent-decode unreserved characters
4. **Agent ID**: Lowercase (Base32 is case-insensitive)
5. **Query and fragment**: Stripped entirely

**Example:**

```
Input:  agent://Anthropic.COM/Assistant/Chat/LLM_01H455VB4PEX5VSKNK084SN02Q?version=1.0#task
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

An agent registers by storing a registration record at its capability path's DHT key:

```rust
Registration {
    agent_uri: AgentUri,          // Full agent URI
    endpoints: Vec<Endpoint>,     // Current network endpoints
    attestation: Option<String>,  // PASETO token
    expires_at: Timestamp,        // Registration TTL
    registered_at: Timestamp,     // Creation time
}
```

**Requirements:**

1. Agents MUST register at their most specific capability level.
2. Registration MUST include at least one endpoint.
3. Registration SHOULD include a valid attestation token.
4. DHT nodes SHOULD verify attestations before storing records.

### 6.3 Lookup Protocol

Discovery proceeds in three steps:

1. **Key derivation**: Compute DHT key from trust root and capability path.

2. **DHT lookup**: Query for records at that key (exact match) or keys in the subtree (prefix match).

3. **Result filtering**: Verify attestations on returned records; filter by query parameters.

**Prefix Matching:**

For prefix queries, derive keys at each level:

```
Query: /workflow/approval (prefix match)
Keys:  SHA-256("acme.com/workflow/approval")
       SHA-256("acme.com/workflow/approval/invoice")
       SHA-256("acme.com/workflow/approval/expense")
       ...
```

### 6.4 Resolution Guarantees

**Theorem (Bounded Resolution):** Resolution of any agent URI terminates in O(log N) DHT hops, where N is the number of DHT nodes.

**Corollary:** Resolution cost is independent of migration history. An agent that has migrated 100 times has the same resolution cost as one that never migrated.

**Theorem (Eventual Consistency):** After migration with DHT record update, all subsequent lookups return the new endpoint within time T_prop ≤ k × RTT_max, where k is the Kademlia replication factor.

### 6.5 Migration

Agent migration updates only the DHT record; the URI remains stable:

1. Agent updates its DHT record with new endpoint(s).
2. Kademlia replicates to k closest nodes.
3. After propagation, lookups return new endpoint.
4. Cached references continue to resolve correctly.

The agent's identity (URI) does not change. Trust root changes require re-attestation and result in a new identity.

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
| `sub` | string | REQUIRED | Agent URI being attested |
| `iat` | datetime | REQUIRED | Issued-at timestamp |
| `exp` | datetime | REQUIRED | Expiration timestamp |
| `aud` | string | OPTIONAL | Audience restriction |
| `capabilities` | string[] | REQUIRED | Authorized capability paths |

**Example Claims:**

```json
{
  "iss": "acme.com",
  "sub": "agent://acme.com/workflow/approval/invoice/rule_01h455vb4pex5vsknk084sn02q",
  "iat": "2026-01-20T00:00:00Z",
  "exp": "2026-02-19T00:00:00Z",
  "capabilities": ["workflow/approval"]
}
```

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

An attestation authorizes registration at capability paths covered by its `capabilities` claim:

```
covered(path, capabilities) := ∃c ∈ capabilities : path.starts_with(c)
```

**Example:**

Attestation with `capabilities: ["workflow"]` covers:
- `/workflow` (exact match)
- `/workflow/approval` (prefix match)
- `/workflow/approval/invoice` (prefix match)

But NOT:
- `/financial` (no prefix relationship)
- `/work` (partial string match insufficient)

### 7.4 Verification Flow

Complete verification of an agent presenting URI and attestation:

1. Parse agent URI; extract `trust_root`, `capability_path`, `agent_id`.
2. Fetch/cache verification key from trust root's well-known endpoint.
3. Verify PASETO signature using the key.
4. Check `exp` > current time (not expired).
5. Check `iss` == `trust_root` from URI.
6. Check `sub` == full agent URI.
7. Check `capabilities` covers the URI's `capability_path`.

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

segment         = 1*64( ALPHA / DIGIT / "-" )
                  ; Lowercase only; case-insensitive input normalized

; ==========================================================================
; AGENT IDENTIFIER
; ==========================================================================

agent-id        = prefix "_" suffix

prefix          = 1*63( ALPHA / "_" )
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

# Uppercase in capability path (valid but normalized)
Input:  agent://anthropic.com/Assistant/Chat/llm_01h455vb4pex5vsknk084sn02q
Status: VALID (normalized)
Canonical: agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q
```

### B.3 Normalization Equivalence

```
# Case normalization
URI A: agent://Anthropic.COM/Assistant/Chat/LLM_01H455VB4PEX5VSKNK084SN02Q
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

# Prefix coverage
Capabilities: ["workflow"]
Path: workflow/approval/invoice
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
Capabilities: ["financial", "workflow/approval"]
Path: workflow/approval/invoice
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
| capabilities array | 0 | 64 | Item count |
| Each capability | 1 | 128 | Characters |
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
| 0.4.0 | 2026-01-20 | Initial draft specification |

---

*End of Specification*
