# agent-uri-attestation-wellknown

[![Crates.io](https://img.shields.io/crates/v/agent-uri-attestation-wellknown.svg)](https://crates.io/crates/agent-uri-attestation-wellknown)
[![Documentation](https://docs.rs/agent-uri-attestation-wellknown/badge.svg)](https://docs.rs/agent-uri-attestation-wellknown)
[![License](https://img.shields.io/crates/l/agent-uri-attestation-wellknown.svg)](../LICENSE-MIT)

Fetches a trust root's published verification keys over HTTPS and turns them into a ready-to-use `Verifier`.

## Overview

[`agent-uri-attestation`](https://crates.io/crates/agent-uri-attestation) verifies a token against the keys it is given, and those keys had to arrive by hand. That is workable for the roots an operator already deals with and impossible for the ones they do not: there was no way to bootstrap trust in a root nobody had exchanged a key with out of band.

Specification §7.2 answers that by having every trust root publish its keys:

```text
GET https://{trust-root}/.well-known/agent-keys.json
```

This crate fetches that document, caches it, and builds a verifier from it.

## Why a Separate Crate

An HTTP client with a TLS stack is a large dependency, and the attestation crate is useful without one. A caller verifying tokens against keys from a config file, a secrets manager, or a deployment artefact should not inherit a networking stack to do it.

The document *format* stays in the attestation crate, as `KeyDocument`, because reading it is arithmetic rather than I/O. This crate is the part that goes and gets it.

## Installation

```toml
[dependencies]
agent-uri-attestation-wellknown = "0.3"
```

## Quick Start

```rust
use agent_uri_attestation_wellknown::KeyDiscovery;

let discovery = KeyDiscovery::new();

// No key was exchanged with acme.com beforehand.
let verifier = discovery.verifier_for("acme.com").await?;
let claims = verifier.verify(token)?;
assert_eq!(claims.iss, "acme.com");
```

## What a Fetched Document Does and Does Not Establish

It establishes which keys an authority stands behind, because it came from that authority over TLS. Everything this crate refuses follows from protecting that one claim:

- **HTTPS only, and no redirects.** A redirect is an instruction to go and ask something else. Following one would let whoever wrote the `Location` header decide whose keys a caller ends up trusting.
- **The trust root is parsed before it is put in a URL.** The endpoint is built by concatenation, so a string carrying `/`, `@`, or a scheme would aim the request elsewhere while reading as a lookup of the named root.
- **The document must name the root whose endpoint served it.** Otherwise any authority could publish keys for anyone else's namespace.
- **The response is capped**, both the declared length and what actually arrives, because the header is the server's claim rather than a fact.

What it does **not** establish is that the authority deserves to be trusted. Fetching `evil.example`'s keys tells you exactly which keys `evil.example` signs with, and nothing about whether to believe anything it says. Deciding which roots matter is the deployment's job and always was.

## Pinning a Root Key

Nor does it establish that the *trust root* wrote the document. Every check above authenticates where the bytes came from, and every one of them is satisfied by an attacker who can write to the web host: they serve from the legitimate domain under a legitimate certificate, and the `revoked_keys` list a verifier would consult to learn better is the list they are serving. Specification §8.12 is that threat; §7.2's signed document form is the answer, and `PinnedRootKeys` is how this crate asks for it.

```rust
// The root key arrives out of band, the same way the decision to care about
// acme.com at all did.
let discovery = KeyDiscovery::new()
    .pin_root("acme.com", PinnedRootKeys::from_base64("<the root key>")?);

let verifier = discovery.verifier_for("acme.com").await?;
```

From then on, for that root:

- the bare form is **refused**. A fallback an attacker can trigger by deleting a signature is not a defence;
- the document must carry a valid signature by one of the pinned keys, so a root key can rotate by publishing signed with both for the overlap;
- a document past its own `expires` is refused, and one already cached stops being served at that instant rather than at the end of the TTL;
- a document whose `version` is behind the newest already accepted is refused. That floor outlives the cache and is not cleared by `forget`, because a rollback protection an attacker can reset by making one fetch fail protects nothing.

Together those bound a compromised host to serving documents the root really signed, only until they expire, and never one older than what this process has already seen. What remains is denial of service, which fails closed.

A root nobody pins keeps working exactly as before, in **either** form: the payload of a signed document is used without checking the signature, on the terms of the bare form. That is what lets a trust root adopt signing without breaking the verifiers that have not pinned it.

## Staleness

A cached document is served for `DEFAULT_TTL` before it is fetched again, which is also the longest this crate can go on not knowing that a key was added or withdrawn. It matches the default token lifetime: no token outlives the staleness of the key list that would have refused it by more than one lifetime. `KeyDiscovery::refresh` short-circuits the wait when a rotation is announced some other way.

A failed refresh keeps whatever was cached before. A root that is briefly unreachable should not cost a verifier the keys it already had, and the entry ages out on its own if the outage lasts. A signed document ages out at its own `expires` as well, whichever comes first.

## License

MIT OR Apache-2.0
