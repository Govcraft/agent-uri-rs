# agent-uri-cli

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](https://github.com/Govcraft/agent-uri-rs)

The command-line tool for the `agent://` identity scheme: key ceremony, attestation minting, verification, and inspection.

```console
$ agent-uri attest verify - --trust-root acme.com=29172969... < token.txt
VERIFIED
  checks passed: signature (ed25519), expiry, trust root, issuer/namespace binding

agent uri     agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q
issuer        acme.com
capabilities  workflow/approval
issued at     2026-07-12T01:14:20Z
expires at    2026-10-10T01:14:20Z (in 89 days)
```

## Install

```sh
cargo install agent-uri-cli
```

The binary is named `agent-uri`.

## What this is for

An `agent://` URI names an agent independently of where it runs:

```
agent://<trust-root>/<capability-path>/<agent-id>
```

The **trust root** is an authority that vouches for the agent, the **capability path** says what it does, and the **agent id** identifies the instance. An **attestation** is a PASETO v4.public token, signed by the trust root's Ed25519 key, that binds one such URI to a set of capabilities for a bounded time.

Holding a valid attestation is what lets a relying party believe an agent is who it claims to be, and is permitted to do what it is asking to do, without calling anybody back. This tool covers that whole lifecycle.

**A key may only attest URIs rooted at its own authority.** The issuer of a token must equal the authority in the URI it attests; a verifier rejects anything else as a cross-namespace forgery. This tool enforces that rule when *issuing*, so it will not mint a token that no verifier could ever accept.

## The ceremony

Four steps: generate the authority's key, publish its public half, mint attestations, verify them. Steps 1 and 2 happen once, at setup and at each rotation. Steps 3 and 4 are the daily loop.

### 1. Generate the trust root's key

```console
$ agent-uri key generate
Generated an Ed25519 signing key.

  key file      /home/you/.config/agent-uri/keys/issuer.key
  permissions   0600 (owner read/write only)

Register the public key with your trust-root registry. Relying parties verify with:
  agent-uri attest verify - --trust-root <your-authority>=29172969a481f7400956932052bbbb73ad9e36aff29b4c69c0be7217a68af8cc

public key  29172969a481f7400956932052bbbb73ad9e36aff29b4c69c0be7217a68af8cc
key file    /home/you/.config/agent-uri/keys/issuer.key
```

**Where the key lives.** `$XDG_CONFIG_HOME/agent-uri/keys/issuer.key` by default (falling back to `~/.config`), or wherever `--out` says. It holds 64 lowercase hex characters and nothing else: the 32-byte Ed25519 seed. The file is written at mode `0600` inside a directory at mode `0700`, and the tool **refuses to read a key that group or other can read** rather than quietly using a key the rest of the machine can see.

**Who holds it.** Whoever holds this key can mint an attestation for *any* agent under the authority. Treat it as the root of that authority's identity, not as a service credential: it belongs in a secret store or an HSM-backed host, held by the smallest group that can operate the authority, and it should never be copied onto developer laptops or into CI. Attestations are what you hand out; the key is what you never hand out.

To put the key straight into a secret store without it ever touching a disk:

```console
$ agent-uri key generate --stdout | vault kv put secret/acme/agent-uri key=-
```

The tradeoff is real, and `--help` says so: with `--stdout` the private key travels through a pipe rather than a `0600` file, so a careless redirect can land it in shell history, a scrollback buffer, or another process's logs. Prefer the default file path unless a secret store is consuming the key directly.

**Rotation.** Generate a new key, publish the new public key alongside the old one, and let relying parties trust both while attestations signed by the old key drain (at most one TTL). Then withdraw the old public key from the registry and delete the old private key. Replacing a key in place with `--force` invalidates every attestation it has issued the moment relying parties drop it, so it is a break-glass move, not a rotation:

```console
$ agent-uri key generate --out ./acme.key --force
```

Attestations cannot be revoked before they expire. The TTL *is* your revocation window, so keep it short.

### 2. Publish the public key

```console
$ agent-uri key public --key ./acme.key
29172969a481f7400956932052bbbb73ad9e36aff29b4c69c0be7217a68af8cc
```

Bare on stdout, so it composes:

```console
$ agent-uri key public --key ./acme.key > registry/acme.com.pub
```

This is the value you register with a trust-root registry, and the value relying parties pass to `--trust-root`. It verifies attestations; it cannot mint them. It is safe to publish.

### 3. Issue an attestation

```console
$ agent-uri attest issue \
    --key ./acme.key \
    --agent agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q \
    --capability workflow/approval \
    --ttl 90d
Issued an attestation.

  agent uri     agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q
  issuer        acme.com
  capabilities  workflow/approval
  expires at    2026-10-10T01:14:20Z (in 89 days)
  signing key   29172969a481f7400956932052bbbb73ad9e36aff29b4c69c0be7217a68af8cc

v4.public.eyJhZ2VudF91cmkiOiJhZ2VudDovL2FjbWUuY29tL3dvcmtmbG93...
```

**The token is the only thing on stdout.** Everything above it is prose on stderr. So this does what it looks like it does:

```console
$ agent-uri attest issue --key ./acme.key --agent agent://acme.com/... --capability chat/reply | pbcopy
```

The issuer is derived from the URI's authority. `--issuer` exists only so a mistake can be caught out loud:

```console
$ agent-uri attest issue --key ./acme.key --agent agent://acme.com/... --capability read --issuer evil.com
error: issuer 'evil.com' does not own the attested URI's authority 'acme.com'; a key may only attest agent URIs rooted at its own authority
  fix: drop --issuer to use 'acme.com', or attest a URI rooted at 'evil.com'; a token issued this way could never verify
```

**TTL.** `--ttl` takes humane durations: `30s`, `30m`, `12h`, `90d`, `2w`, `1h30m`. A bare number is rejected rather than guessed, because silent unit ambiguity is how a 30-second credential gets shipped in place of a 30-day one. The default is **24h**, and the maximum is 365d. Prefer short lifetimes and re-issue: an attestation cannot be revoked before it expires, so its TTL is the blast radius of a leak.

**Capabilities** are hierarchical, and cover their descendants. A token granting `workflow` satisfies a later check for `workflow/approval`. Grant the narrowest capability that works.

### 4. Verify an attestation

```console
$ agent-uri attest verify - \
    --trust-root acme.com=29172969a481f7400956932052bbbb73ad9e36aff29b4c69c0be7217a68af8cc \
    --agent agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q \
    --capability workflow/approval < token.txt
VERIFIED
  checks passed: signature (ed25519), expiry, trust root, issuer/namespace binding, subject, capability coverage

agent uri     agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q
issuer        acme.com
capabilities  workflow/approval
issued at     2026-07-12T01:14:20Z
expires at    2026-10-10T01:14:20Z (in 89 days)
```

Exit 0 means verified. Pass `-` to read the token from stdin; prefer that, since a token on the command line is visible to anyone who can run `ps`. Pass `--trust-root` more than once to accept several authorities.

Every refusal is exit 1, and says precisely what was wrong and what to do:

```console
$ agent-uri attest verify - --trust-root acme.com=2917... < expired.txt
error: token expired at 2026-07-09T01:14:34Z (3 days ago)
  fix: ask the issuer for a fresh attestation; an expired token cannot be renewed

$ agent-uri attest verify - --trust-root partner.io=91cd... < token.txt
error: token was issued by 'acme.com', which is not among the trust roots supplied (partner.io)
  fix: supply that authority's public key: --trust-root acme.com=<public-key-hex>

$ agent-uri attest verify - --trust-root acme.com=<wrong key> < token.txt
error: token signature does not verify against the trusted key for its issuer
  fix: the token was tampered with, or the public key you supplied for that authority is wrong; re-fetch the authority's public key and try again

$ agent-uri attest verify - --trust-root acme.com=2917... --agent agent://acme.com/... --capability workflow/approval < chat-token.txt
error: token does not cover the capability 'workflow/approval'; it grants chat/reply
  fix: obtain a token granting that capability, or one granting a prefix of it (granting 'workflow' covers 'workflow/approval')
```

Gate a script on the verdict:

```sh
if agent-uri attest verify - --trust-root acme.com="$PUBKEY" > /dev/null; then
    echo authorized
fi
```

## Inspecting a token

`attest inspect` decodes a token's claims and performs **no cryptography whatsoever**. Anyone can mint a token carrying any claims they like, so its output describes what a token *asserts*, never evidence that the assertion is true.

```console
$ agent-uri attest inspect - < token.txt
UNVERIFIED - claims decoded WITHOUT checking the signature
  anyone can mint a token carrying any claims; these prove nothing.
  run 'agent-uri attest verify' before trusting any of it.
  this token is expired: it lapsed 3 days ago.

agent uri     agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q
issuer        acme.com
capabilities  workflow/approval
issued at     2026-07-08T01:14:20Z
expires at    2026-07-09T01:14:20Z (3 days ago)
```

It exits 0 even for an expired or forged token, because describing an untrustworthy token is exactly its job. It is what you reach for the moment `verify` fails:

```console
$ agent-uri attest verify - --trust-root acme.com="$PUBKEY" < token.txt \
    || agent-uri attest inspect - < token.txt
```

In `--json` mode the output carries a literal `"verified": false`, so a machine can assert on its presence rather than on the absence of something:

```console
$ agent-uri --json attest inspect - < token.txt | jq -e '.verified == false'
```

## Validating a URI

```console
$ agent-uri uri validate agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q
VALID
  trust root    acme.com
  capability    workflow/approval
  agent id      rule_01h455vb4pex5vsknk084sn02q

agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q
```

The canonical form is the only thing on stdout, so it feeds straight back into a pipeline. Exit 0 is valid, exit 1 is not, and stderr says why.

## Output contract

**stdout carries data; stderr carries prose.** In both modes, without exception. That is what makes `attest issue | pbcopy` yield a token rather than a paragraph, and what lets `--json` be parsed without first being cleaned.

A failure never writes anything to stdout.

Human output is aligned and restrained. Colour appears only on verdict lines, and only when stderr is a terminal and `NO_COLOR` is unset. Timestamps are RFC 3339, always paired with a relative reading (`in 89 days`, `3 days ago`).

### `--json`

Every command emits a single JSON object on stdout. Errors are JSON too, on stderr:

```console
$ agent-uri --json uri validate not-a-uri
{"error":{"kind":"invalid_uri","message":"'not-a-uri' is not a valid agent:// URI: ...","remedy":"an agent URI looks like agent://<trust-root>/<capability-path>/<prefix>_<26-char-id>","exit_code":1}}
```

| Command | stdout |
|---|---|
| `key generate` | `{"public_key":"<64 hex>","path":"<path>"}` |
| `key generate --stdout` | `{"public_key":"<64 hex>","secret_key":"<64 hex>"}` |
| `key public` | `{"public_key":"<64 hex>"}` |
| `attest issue` | `{"token":"v4.public...","claims":{…}}` |
| `attest verify` | `{"verified":true,"checks":[…],"claims":{…}}` |
| `attest inspect` | `{"verified":false,"warning":"…","claims":{…}}` |
| `uri validate` | `{"valid":true,"uri":"…","trust_root":"…","capability_path":"…","agent_id":"…","agent_prefix":"…"}` |
| *any error* | *(stderr)* `{"error":{"kind":"…","message":"…","remedy":"…","exit_code":N}}` |

The `claims` object:

```json
{
  "agent_uri": "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q",
  "capabilities": ["workflow/approval"],
  "issuer": "acme.com",
  "issued_at": "2026-07-12T01:14:20Z",
  "expires_at": "2026-10-10T01:14:20Z",
  "audience": "api.acme.com",
  "expired": false,
  "not_yet_valid": false,
  "expires_in_seconds": 7689600
}
```

`audience` is omitted when the token carries none. There is no `nbf`: the not-before instant *is* `issued_at`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success; for `attest verify`, the token verified |
| `1` | Refused: an invalid URI, or a token that failed verification |
| `2` | Usage error: a malformed command line |
| `3` | I/O or key error: a missing, unreadable, or unsafely-permissioned key |

The line between 1 and 2: a malformed **knob** (`--ttl bogus`) is a usage error. Bad **content** that the command exists to judge (a URI, a token) is a refusal, and comes with a diagnosis.

Error `kind` slugs are stable, and safe to branch on in `--json` mode: `invalid_uri`, `invalid_capability`, `malformed_token`, `unsupported_token`, `invalid_claims`, `token_expired`, `token_not_yet_valid`, `invalid_signature`, `unknown_trust_root`, `subject_mismatch`, `capability_not_covered`, `issuer_namespace_mismatch`, `verification_failed`, `issue_failed`, `key_not_found`, `key_exists`, `malformed_key`, `insecure_key_permissions`, `no_config_dir`, `io_error`, `stdin_error`, `output_error`, `unsupported_format`.

## Shell completions and the man page

Both are hidden subcommands, so a single binary installs its own:

```sh
agent-uri completions bash > /usr/share/bash-completion/completions/agent-uri
agent-uri completions zsh  > /usr/local/share/zsh/site-functions/_agent-uri
agent-uri completions fish > ~/.config/fish/completions/agent-uri.fish

agent-uri man > /usr/share/man/man1/agent-uri.1
```

`bash`, `zsh`, `fish`, `powershell`, and `elvish` are supported.

## License

Licensed under either of [Apache License, Version 2.0](../LICENSE-APACHE) or [MIT license](../LICENSE-MIT) at your option.
