//! The command-line surface.
//!
//! This module holds argument types and their help text, and nothing else. The
//! behaviour lives in [`crate::commands`].

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use clap_complete::Shell;

use crate::trust::TrustedRoot;
use crate::ttl::Ttl;

/// The top-level overview, written to read like the opening of a man page.
const OVERVIEW: &str = "\
Key ceremony, attestation, and verification for the agent:// identity scheme.

An agent:// URI names an agent independently of where it runs:

    agent://<trust-root>/<capability-path>/<agent-id>

The trust root is an authority that vouches for the agent, the capability path
says what it does, and the agent id identifies the instance. An attestation is a
PASETO v4.public token, signed by the trust root's Ed25519 key, binding one such
URI to a set of capabilities for a bounded time. Holding a valid attestation is
what lets a relying party believe an agent is who it claims to be, and is
permitted to do what it is asking to do, without calling anybody back.

This tool covers the whole lifecycle: generate the trust root's key, publish its
public half, mint attestations, and verify or inspect them.

A key is only ever authorized to attest URIs rooted at its own authority: the
issuer of a token must equal the authority in the URI it attests. This tool
enforces that when issuing, so it will not mint a token that no verifier could
ever accept.";

/// The exit-code contract, appended to the top-level help.
const EXIT_CODES: &str = "\
Exit codes:
  0  success; for 'attest verify', the token verified
  1  refused: an invalid URI, or a token that failed verification
  2  usage error: a malformed command line
  3  I/O or key error: a missing, unreadable, or unsafely-permissioned key

Output:
  stdout carries data, stderr carries prose. With --json, stdout carries one
  JSON object and stderr carries nothing but errors (themselves JSON).

Examples:
  agent-uri key generate
  agent-uri attest issue --key issuer.key --agent agent://acme.com/chat/bot_01h4... \\
      --capability chat/reply --ttl 90d | pbcopy
  agent-uri attest verify - --trust-root acme.com=3b6a... < token.txt";

/// Command-line interface for the `agent://` identity scheme.
#[derive(Debug, Parser)]
#[command(
    name = "agent-uri",
    version,
    about = "Key ceremony, attestation, and verification for the agent:// identity scheme",
    long_about = OVERVIEW,
    after_long_help = EXIT_CODES,
    propagate_version = true
)]
pub struct Cli {
    /// Emit one stable JSON object on stdout instead of human-readable output.
    ///
    /// Diagnostics never mix with machine output: results go to stdout, errors
    /// go to stderr as `{"error":{"kind":...,"message":...,"remedy":...}}`.
    #[arg(long, global = true)]
    pub json: bool,

    /// The operation to perform.
    #[command(subcommand)]
    pub command: Command,
}

/// The top-level operations.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage the Ed25519 key a trust root signs attestations with.
    #[command(subcommand)]
    Key(KeyCommand),

    /// Mint, verify, and inspect attestation tokens.
    #[command(subcommand)]
    Attest(AttestCommand),

    /// Work with agent:// URIs.
    #[command(subcommand)]
    Uri(UriCommand),

    /// Print a shell completion script.
    #[command(hide = true)]
    Completions {
        /// The shell to generate completions for.
        shell: Shell,
    },

    /// Print this tool's man page, in roff, on stdout.
    ///
    /// Install it with: agent-uri man > /usr/share/man/man1/agent-uri.1
    #[command(hide = true)]
    Man,
}

/// Key ceremony.
#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Generate a new Ed25519 signing key.
    ///
    /// The key is written as 64 lowercase hex characters at mode 0600, inside a
    /// directory at mode 0700. Its public half is printed so you can register it
    /// with a trust-root registry; the private half is never printed unless you
    /// ask for it with --stdout.
    #[command(long_about = "\
Generate a new Ed25519 signing key.

This is the key that speaks for a trust root. Everything an authority ever
attests is signed by it, so treat it as the root of that authority's identity:
whoever holds it can mint an attestation for any agent under it.

The key is written as 64 lowercase hex characters, at mode 0600, in a directory
created at mode 0700. Its public half is printed to stdout together with the
path; the private half never touches stdout unless you pass --stdout.

Replacing a key invalidates every attestation it has issued, so this command
refuses to overwrite an existing key without --force.

EXAMPLES:
  Generate at the default path ($XDG_CONFIG_HOME/agent-uri/keys/issuer.key):
      agent-uri key generate

  Generate at an explicit path:
      agent-uri key generate --out ./acme.key

  Pipe the private key straight into a secret store, writing no file:
      agent-uri key generate --stdout | vault kv put secret/acme key=-

  Replace an existing key during a rotation:
      agent-uri key generate --out ./acme.key --force")]
    Generate {
        /// Where to write the private key.
        ///
        /// Defaults to $XDG_CONFIG_HOME/agent-uri/keys/issuer.key (falling back
        /// to ~/.config). Parent directories are created at mode 0700.
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,

        /// Replace an existing key file.
        ///
        /// Every attestation the old key issued stops verifying once relying
        /// parties drop its public key from their registry.
        #[arg(long)]
        force: bool,

        /// Print the private key to stdout instead of writing a file.
        ///
        /// The private key becomes the only thing on stdout, so it can be piped
        /// directly into a secret store. The tradeoff: the key passes through a
        /// pipe rather than a 0600 file, so it can land in shell history, a
        /// scrollback buffer, or another process's logs if you redirect it
        /// carelessly. Prefer the default file path unless a secret store is
        /// consuming the key.
        #[arg(long, conflicts_with_all = ["out", "force"])]
        stdout: bool,
    },

    /// Print the public key derived from a private key.
    ///
    /// This is what an operator registers with a trust-root registry, and what
    /// relying parties pass to `attest verify --trust-root <root>=<this>`.
    #[command(long_about = "\
Print the public key derived from a private key.

This is the value you publish. It is what an operator registers with a trust-root
registry, and what a relying party passes to:

    agent-uri attest verify --trust-root <root>=<public-key>

It is safe to share: it can verify attestations, but it cannot mint them.

EXAMPLES:
  Print the public key of the default key:
      agent-uri key public

  Print the public key of a specific key:
      agent-uri key public --key ./acme.key

  Publish it to a registry directory:
      agent-uri key public --key ./acme.key > registry/acme.com.pub")]
    Public {
        /// The private key to derive from.
        ///
        /// Defaults to $XDG_CONFIG_HOME/agent-uri/keys/issuer.key. The file is
        /// refused if group or other can read it.
        #[arg(long, value_name = "PATH")]
        key: Option<PathBuf>,
    },
}

/// Attestation minting, verification, and inspection.
#[derive(Debug, Subcommand)]
pub enum AttestCommand {
    /// Mint an attestation token for an agent URI.
    #[command(long_about = "\
Mint an attestation token for an agent URI.

The token is a PASETO v4.public credential: a set of claims, signed by the trust
root's Ed25519 key. It binds the agent URI to the capabilities you grant, for the
time you allow, and anyone holding the trust root's public key can check it
without calling you back.

The issuer is the authority in the agent URI. A key may only attest URIs rooted
at its own authority, so passing --issuer with anything else is refused here
rather than producing a token that every verifier would reject.

The token is the only thing written to stdout, so it pipes cleanly. The summary
of what you just signed goes to stderr, where a pipe will not swallow it.

Capabilities are hierarchical, but every grant must equal the URI capability
path or be its descendant. An identity-path grant covers its descendants.

EXAMPLES:
  Mint a token with the default 24h lifetime:
      agent-uri attest issue --key ./acme.key \\
          --agent agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q \\
          --capability workflow/approval/read

  Grant several capabilities, for 90 days, to one audience:
      agent-uri attest issue --key ./acme.key \\
          --agent agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q \\
          --capability workflow/approval/read \\
          --capability workflow/approval/execute \\
          --ttl 90d --audience api.acme.com

  Copy the token straight to the clipboard:
      agent-uri attest issue --key ./acme.key --agent agent://acme.com/... \\
          --capability chat/reply | pbcopy

  Emit the token and its claims as JSON:
      agent-uri --json attest issue --key ./acme.key --agent agent://acme.com/... \\
          --capability chat/reply")]
    Issue {
        /// The private key to sign with.
        #[arg(long, value_name = "PATH")]
        key: PathBuf,

        /// The agent URI to attest.
        #[arg(long, value_name = "URI")]
        agent: String,

        /// A capability to grant. Repeat to grant several.
        ///
        /// Each grant must equal the agent URI's capability path or be one of
        /// its descendants. A broader, sibling, or unrelated grant is refused.
        #[arg(long, value_name = "CAP", required = true)]
        capability: Vec<String>,

        /// How long the token stays valid: 90d, 12h, 30m, 1h30m.
        ///
        /// Defaults to 24h. The maximum is 365d; prefer short lifetimes and
        /// re-issue, since an attestation cannot be revoked before it expires.
        #[arg(long, value_name = "DURATION", default_value_t = Ttl::default())]
        ttl: Ttl,

        /// Restrict the token to one audience, e.g. api.acme.com.
        #[arg(long, value_name = "AUDIENCE")]
        audience: Option<String>,

        /// The issuing trust root. Defaults to the authority in --agent.
        ///
        /// Supplying an authority that differs from the one in --agent is
        /// refused: a key may only attest URIs rooted at its own authority.
        #[arg(long, value_name = "ROOT")]
        issuer: Option<String>,
    },

    /// Verify an attestation token against one or more trust roots.
    #[command(long_about = "\
Verify an attestation token against one or more trust roots.

This is the real check: the Ed25519 signature, the expiry, the issuer's presence
in the trust roots you supplied, and the binding between the issuer and the
authority of the URI it attests. Narrow it further with --agent to demand a
specific subject, and --capability to demand a specific permission.
Tokens restricted to an audience are accepted only when that audience is
supplied explicitly with --audience.

Exit 0 means the token verified, and its authenticated claims are on stdout.
Exit 1 means it was refused, and stderr says precisely why: expired at T, not yet
valid, unknown trust root, subject mismatch, capability not covered, or a
signature that does not check out.

Pass '-' to read the token from stdin. Prefer that: a token on the command line
is visible to anyone who can run 'ps'.

EXAMPLES:
  Verify a token from stdin:
      agent-uri attest verify - --trust-root acme.com=3b6a... < token.txt

  Verify a token given as an argument:
      agent-uri attest verify v4.public.eyJ... --trust-root acme.com=3b6a...

  Demand a specific agent and capability:
      agent-uri attest verify - --trust-root acme.com=3b6a... \\
          --agent agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q \\
          --capability workflow/approval

  Accept tokens from either of two authorities:
      agent-uri attest verify - --trust-root acme.com=3b6a... --trust-root partner.io=91cd...

  Gate a script on the verdict:
      if agent-uri attest verify - --trust-root acme.com=3b6a... > /dev/null; then
          echo authorized
      fi")]
    Verify {
        /// The token to verify, or '-' to read it from stdin.
        #[arg(value_name = "TOKEN")]
        token: String,

        /// A trusted root, as `<root>=<public-key-hex>`. Repeat to trust several.
        ///
        /// The public key is the 64 hex characters printed by 'agent-uri key public'.
        #[arg(long, value_name = "ROOT=HEX", required = true)]
        trust_root: Vec<TrustedRoot>,

        /// Require the token to attest exactly this agent URI.
        #[arg(long, value_name = "URI")]
        agent: Option<String>,

        /// Require the token to cover this capability path.
        ///
        /// Coverage is hierarchical: a token attesting 'workflow' covers a
        /// requirement of 'workflow/approval'.
        #[arg(long, value_name = "CAP", requires = "agent")]
        capability: Option<String>,

        /// Require this exact token audience.
        ///
        /// An audience-restricted token is refused unless this value is
        /// supplied and exactly matches its `aud` claim.
        #[arg(long, value_name = "AUDIENCE")]
        audience: Option<String>,
    },

    /// Decode a token's claims WITHOUT verifying them.
    #[command(long_about = "\
Decode a token's claims WITHOUT verifying them.

This performs no cryptography whatsoever. It reads the claims a token carries and
prints them, and anyone at all can mint a token carrying any claims they like.
Treat the output as a description of what a token *asserts*, never as evidence
that the assertion is true. Use 'agent-uri attest verify' for that.

It exists for the moment after a verification fails, when you need to see what
the token actually said: which authority it names, when it expired, what it
claimed to grant. It exits 0 even for an expired or forged token, because
describing an untrustworthy token is exactly its job.

In --json mode the output carries a literal \"verified\": false, so a machine can
assert on it: jq -e '.verified == false'.

EXAMPLES:
  Inspect a token from stdin:
      agent-uri attest inspect - < token.txt

  See why a token was refused:
      agent-uri attest verify - --trust-root acme.com=3b6a... < token.txt \\
          || agent-uri attest inspect - < token.txt

  Read its expiry as JSON:
      agent-uri --json attest inspect - < token.txt | jq -r .claims.expires_at")]
    Inspect {
        /// The token to decode, or '-' to read it from stdin.
        #[arg(value_name = "TOKEN")]
        token: String,
    },
}

/// URI operations.
#[derive(Debug, Subcommand)]
pub enum UriCommand {
    /// Validate an agent:// URI and print its canonical form.
    #[command(long_about = "\
Validate an agent:// URI and print its canonical form.

On success the canonical form is the only thing on stdout, so it can be fed
straight back into a pipeline, and the exit status is 0. On failure the exit
status is 1 and stderr says precisely what is wrong with it.

An agent URI has the shape:

    agent://<trust-root>/<capability-path>/<agent-id>

where the agent id is a TypeID: a semantic prefix, an underscore, and a
26-character UUIDv7 suffix.

EXAMPLES:
  Validate a URI:
      agent-uri uri validate agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q

  Break it into its parts:
      agent-uri --json uri validate agent://acme.com/chat/bot_01h455vb4pex5vsknk084sn02q

  Gate a script on validity:
      if agent-uri uri validate \"$uri\" > /dev/null 2>&1; then echo ok; fi")]
    Validate {
        /// The agent:// URI to validate.
        #[arg(value_name = "URI")]
        uri: String,
    },
}
