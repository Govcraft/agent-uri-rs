# agent-uri-attestation

[![Crates.io](https://img.shields.io/crates/v/agent-uri-attestation.svg)](https://crates.io/crates/agent-uri-attestation)
[![Documentation](https://docs.rs/agent-uri-attestation/badge.svg)](https://docs.rs/agent-uri-attestation)
[![License](https://img.shields.io/crates/l/agent-uri-attestation.svg)](../LICENSE-MIT)

Cryptographic attestation for the [`agent://`](https://crates.io/crates/agent-uri) URI scheme, using PASETO v4.public tokens.

## Overview

An agent URI is public: anyone can write one down and claim it. An attestation is a trust root saying, over an Ed25519 signature, that a particular URI belongs to the holder of a particular key and may exercise a particular set of capabilities.

The token is not a bearer credential. It carries the agent's own public key in an `agent_key` claim, so possessing the token is not enough — the holder has to prove they hold the matching private key. Stealing the token gets an attacker a signed statement about somebody else.

## Installation

```toml
[dependencies]
agent-uri-attestation = "0.8"
```

## Quick Start

```rust
use agent_uri::AgentUri;
use agent_uri_attestation::{AcceptAll, Issuer, SigningKey, Verifier};
use std::time::Duration;

// Issuing side: the trust root attests a URI and the key its holder proved.
let root_key = SigningKey::generate();
let issuer = Issuer::new("acme.com", root_key.clone(), Duration::from_secs(3600));

let uri = AgentUri::parse(
    "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q"
)?;
let agent_key = SigningKey::generate();
let token = issuer.issue(
    &uri,
    &agent_key.verifying_key(),
    vec!["workflow/approval/read".into()],
)?;

// Verifying side. A verifier must say what it does about revocation before it
// accepts anything; `AcceptAll` states that this deployment does not revoke.
let mut verifier = Verifier::new().with_revocation(AcceptAll);
verifier.add_trusted_root("acme.com", root_key.verifying_key());

let claims = verifier.verify(&token)?;
assert_eq!(claims.iss, "acme.com");
assert_eq!(claims.agent_verifying_key()?, agent_key.verifying_key());
```

## Token Claims

| Claim | Meaning |
|-------|---------|
| `jti` | Unique token identifier, so this token can be revoked by name |
| `agent_uri` | The full agent URI being attested |
| `agent_key` | The agent's own Ed25519 public key, base64-encoded |
| `capabilities` | The capability paths granted |
| `iss` | The trust root that issued the attestation |
| `iat` / `exp` | Issued-at and expiry, both enforced with clock-skew leeway |
| `aud` | Optional audience restriction |

## Security Properties

| Property | How achieved |
|----------|--------------|
| No algorithm confusion | PASETO v4.public is Ed25519-only |
| Not a bearer credential | `agent_key` binds the token to a key the holder must possess |
| Replay protection | `exp` validated on every verification |
| Trust root binding | `iss` must be a trusted root |
| Issuer/namespace binding | `iss` must equal the `agent_uri` claim's authority |
| Tamper detection | Ed25519 signature over the whole payload |
| Withdrawal before expiry | `RevocationCheck`, by `jti` or by signing key |
| Key rotation without an outage | `TrustStore` holds several keys per root, each with its own window |

## Revocation

A verifier with no revocation source accepts nothing. There is no permissive default: a deployment that never wired up its denylist would otherwise behave exactly like one that had, right up until it honoured a revoked token.

```rust
use agent_uri_attestation::{AcceptAll, Denylist, Verifier};

// Checking against a real list, on either axis.
let checked = Verifier::new().with_revocation(
    Denylist::new()
        .revoke_token("01h455vb4pex5vsknk084sn02q")
        .revoke_key(compromised_key),
);

// Or stating outright that this deployment does not revoke.
let unchecked = Verifier::new().with_revocation(AcceptAll);
```

## Key Rotation

A trust root's key is not permanent, and replacing it must not break every token still in flight. Each root maps to a list of `TrustedKey`s rather than to one key, and each key carries an optional `not_before` and `not_after`:

```rust
use agent_uri_attestation::{TrustedKey, Verifier};
use chrono::{Duration, Utc};

// The outgoing key stays usable long enough to cover the longest token already
// issued under it — one hour, at the default TTL.
verifier.add_trusted_key(
    "acme.com",
    TrustedKey::new(outgoing)
        .with_id("key-2026")
        .not_after(Utc::now() + Duration::hours(1)),
);
verifier.add_trusted_key("acme.com", TrustedKey::new(incoming).with_id("key-2027"));

// Afterwards, retire it.
verifier.remove_trusted_key("acme.com", "key-2026");
```

A key's window is judged at verification time, not against the token's `iat`. The forgiving alternative would make `not_after` advisory: a root that withdrew a key at noon would keep honouring what that key signed at 11:59 for as long as those tokens lived.

## Where the Keys Come From

`KeyDocument` reads the key document specification §7.2 defines, so a caller holding one — from a config file, a secrets manager, a deployment artefact — can build a verifier from it without this crate touching the network.

Fetching it over HTTPS, with the caching and refreshing that implies, is [`agent-uri-attestation-wellknown`](https://crates.io/crates/agent-uri-attestation-wellknown). It is a separate crate because an HTTP client with a TLS stack is a large dependency and this one is useful without it.

### When the endpoint itself is the attacker

Everything about a fetched document authenticates the *channel* — HTTPS, no redirects, the document naming the root whose endpoint served it — and all of it is satisfied by someone who can write to the web host. Specification §8.12 is that threat; §7.2's signed document form is the answer.

`SignedKeyDocument` reads that form: the document wrapped in a signature by a **root key** the trust root holds offline and a verifier pins out of band, so publication becomes a file copy and the host never holds material whose theft mints trust.

```rust
// Publishing side, on a machine that is not the web server.
let served = KeyDocumentPayload::new(document, DocumentVersion::FIRST, Utc::now() + Duration::days(7))
    .to_signed_json(&[DocumentSigner::new(&root_key).named("root-2026")])?;

// Verifying side, holding the pinned root key.
let verified = SignedKeyDocument::parse(&served)?.verify(&[root_key.verifying_key()])?;
let store = verified.document().trust_store()?;
```

The signature covers `"agent-uri-key-document-v1\n"` followed by the exact octets of the `signed` member as served — no canonicalization, so a publisher and a verifier never have to agree on how to re-encode JSON.

A verifier that pins nothing keeps working against either form: `ServedDocument` tells them apart and hands over the payload on the terms of the bare one. Requiring the signed form, refusing a replayed older `version`, and refusing an expired document are policy, and policy needs the state of what has already been accepted, which is `agent-uri-attestation-wellknown`'s job.

## License

MIT OR Apache-2.0
