//! `agent-uri attest` — minting, verifying, and inspecting attestations.

use std::io::Write;

use agent_uri::{AgentUri, CapabilityPath};
use agent_uri_attestation::{AttestationClaims, AttestationError, Denylist, Issuer, Verifier};
use chrono::Utc;

use crate::cli::AttestCommand;
use crate::commands::resolve_token;
use crate::error::CliError;
use crate::keyfile;
use crate::output::Output;
use crate::reports::{ClaimsView, Inspected, TokenIssued, Verification};
use crate::token::decode_unverified;
use crate::trust::{self, TrustedRoot};
use crate::ttl::Ttl;

/// Runs an `attest` subcommand.
///
/// # Errors
///
/// Returns [`CliError::Refused`] when a token or URI is rejected, or
/// [`CliError::Fault`] on a key or I/O failure.
pub fn run<O: Write, E: Write>(
    command: &AttestCommand,
    out: &mut Output<O, E>,
) -> Result<(), CliError> {
    match command {
        AttestCommand::Issue {
            key,
            agent,
            agent_key,
            capability,
            ttl,
            audience,
            issuer,
        } => issue(
            &IssueRequest {
                key_path: key,
                agent,
                agent_key,
                capabilities: capability,
                ttl: *ttl,
                audience: audience.as_deref(),
                issuer: issuer.as_deref(),
            },
            out,
        ),
        AttestCommand::Verify {
            token,
            trust_root,
            agent,
            capability,
            audience,
            revoked_token,
            revoked_key,
        } => verify(
            &VerifyRequest {
                token,
                trust_roots: trust_root,
                agent: agent.as_deref(),
                capability: capability.as_deref(),
                audience: audience.as_deref(),
                revoked_tokens: revoked_token,
                revoked_keys: revoked_key,
            },
            out,
        ),
        AttestCommand::Inspect { token } => inspect(token, out),
    }
}

/// Everything `issue` needs, gathered so the signature stays legible.
struct IssueRequest<'a> {
    key_path: &'a std::path::Path,
    agent: &'a str,
    agent_key: &'a str,
    capabilities: &'a [String],
    ttl: Ttl,
    audience: Option<&'a str>,
    issuer: Option<&'a str>,
}

/// Everything `verify` needs.
struct VerifyRequest<'a> {
    token: &'a str,
    trust_roots: &'a [TrustedRoot],
    agent: Option<&'a str>,
    capability: Option<&'a str>,
    audience: Option<&'a str>,
    revoked_tokens: &'a [String],
    revoked_keys: &'a [String],
}

/// Resolves the issuing authority for a token, enforcing the issuer/namespace binding.
///
/// A key is only ever authorized to attest URIs rooted at its own authority: the
/// verifier requires the `iss` claim to equal the authority of the `agent_uri`
/// claim, and refuses the token otherwise. The issuing API does not enforce that,
/// so without this check the tool would happily mint a token that no verifier
/// anywhere could ever accept. Catching it here turns a silent, permanent
/// verification failure into an error at the moment of the mistake.
///
/// Pure, so the rule is testable without a key or a clock.
///
/// # Errors
///
/// Returns [`CliError::Refused`] when an explicit issuer disagrees with the
/// authority of the URI being attested.
fn resolve_issuer(uri: &AgentUri, requested: Option<&str>) -> Result<String, CliError> {
    let authority = uri.trust_root().as_str();

    match requested {
        None => Ok(authority.to_string()),
        Some(issuer) if issuer == authority => Ok(authority.to_string()),
        Some(issuer) => Err(CliError::refused(
            "issuer_namespace_mismatch",
            format!(
                "issuer '{issuer}' does not own the attested URI's authority '{authority}'; \
                 a key may only attest agent URIs rooted at its own authority"
            ),
            format!(
                "drop --issuer to use '{authority}', or attest a URI rooted at '{issuer}'; \
                 a token issued this way could never verify"
            ),
        )),
    }
}

/// Mints an attestation token.
fn issue<O: Write, E: Write>(
    request: &IssueRequest<'_>,
    out: &mut Output<O, E>,
) -> Result<(), CliError> {
    let uri = parse_agent_uri(request.agent)?;
    let issuer_root = resolve_issuer(&uri, request.issuer)?;
    let signing_key = keyfile::load(request.key_path)?;
    let public_key = trust::encode_public(&signing_key.verifying_key());
    let agent_key = trust::decode_public(request.agent_key).map_err(|source| {
        CliError::refused(
            "invalid_agent_key",
            format!("--agent-key is not a usable public key: {source}"),
            "pass the 64 hex characters printed by 'agent-uri key generate' \
             for the agent's own key, not the trust root's",
        )
    })?;

    let claims = AttestationClaims::builder()
        .agent_uri(uri.to_string())
        .agent_key(&agent_key)
        .capabilities(request.capabilities.to_vec())
        .issuer(&issuer_root)
        .ttl(request.ttl.as_duration());

    let claims = match request.audience {
        Some(audience) => claims.audience(audience),
        None => claims,
    };

    let claims = claims.build().map_err(|source| {
        CliError::refused(
            "invalid_claims",
            format!("cannot build the attestation claims: {source}"),
            "check --agent, --capability, and --ttl",
        )
    })?;

    let issuer = Issuer::new(&issuer_root, signing_key, request.ttl.as_duration());
    let token = issuer.issue_claims(&claims).map_err(|source| {
        CliError::refused(
            "issue_failed",
            format!("cannot sign the attestation: {source}"),
            "check the key file holds a valid Ed25519 key",
        )
    })?;

    let view = ClaimsView::new(&claims, Utc::now());

    // The summary is prose: it goes to stderr, so that `| pbcopy` gets a token
    // and not a paragraph.
    out.note("Issued an attestation.");
    out.blank();
    out.field("agent uri", &view.agent_uri);
    out.field("issuer", &view.issuer);
    out.field("capabilities", &view.capabilities.join(", "));
    if let Some(audience) = &view.audience {
        out.field("audience", audience);
    }
    out.field(
        "expires at",
        &crate::timefmt::absolute_and_relative(claims.exp, Utc::now()),
    );
    out.field("agent key", request.agent_key);
    out.field("signing key", &public_key);
    out.blank();

    out.emit(&TokenIssued {
        token,
        claims: view,
    })
}

/// Verifies a token against the supplied trust roots.
fn verify<O: Write, E: Write>(
    request: &VerifyRequest<'_>,
    out: &mut Output<O, E>,
) -> Result<(), CliError> {
    let token = resolve_token(request.token)?;

    let revoked = revocation_list(request)?;
    // Nothing revoked means nothing was checked against, and the report says so
    // rather than listing a check that did no work. A reader who sees
    // "revocation" in the list is entitled to believe a list was consulted.
    let checked_revocation = !request.revoked_tokens.is_empty() || !request.revoked_keys.is_empty();

    let mut verifier = Verifier::new().with_revocation(revoked);
    for root in request.trust_roots {
        verifier.add_trusted_root(root.root.clone(), root.key.clone());
    }

    let mut checks = vec![
        "signature (ed25519)".to_string(),
        "expiry".to_string(),
        "trust root".to_string(),
        "issuer/namespace binding".to_string(),
    ];

    if checked_revocation {
        checks.push(format!(
            "revocation ({} token(s), {} key(s))",
            request.revoked_tokens.len(),
            request.revoked_keys.len()
        ));
    }

    if request.audience.is_some() {
        checks.push("audience".to_string());
    }

    let claims = match (request.agent, request.capability, request.audience) {
        (Some(agent), Some(capability), Some(audience)) => {
            let uri = parse_agent_uri(agent)?;
            let required = parse_capability(capability)?;
            checks.push("subject".to_string());
            checks.push("capability coverage".to_string());
            verifier.verify_for_capability_and_audience(&token, &uri, &required, audience)
        }
        (Some(agent), Some(capability), None) => {
            let uri = parse_agent_uri(agent)?;
            let required = parse_capability(capability)?;
            checks.push("subject".to_string());
            checks.push("capability coverage".to_string());
            verifier.verify_for_capability(&token, &uri, &required)
        }
        (Some(agent), None, Some(audience)) => {
            let uri = parse_agent_uri(agent)?;
            checks.push("subject".to_string());
            verifier.verify_for_uri_and_audience(&token, &uri, audience)
        }
        (Some(agent), None, None) => {
            let uri = parse_agent_uri(agent)?;
            checks.push("subject".to_string());
            verifier.verify_for_uri(&token, &uri)
        }
        (None, _, Some(audience)) => verifier.verify_for_audience(&token, audience),
        (None, _, None) => verifier.verify(&token),
    }
    .map_err(|source| diagnose(&source, &token, request.trust_roots))?;

    let view = ClaimsView::new(&claims, Utc::now());

    out.verdict_good("VERIFIED");
    out.note(&format!("  checks passed: {}", checks.join(", ")));
    if !checked_revocation {
        // The verdict is real but narrower than it looks, and the gap is not
        // one a reader can infer from a word that says VERIFIED. A token whose
        // issuer withdrew it yesterday passes everything above.
        out.note("  revocation was NOT checked: no --revoked-token or --revoked-key was given.");
        out.note("  a token its issuer has since withdrawn would still pass the checks above.");
    }
    out.blank();

    out.emit(&Verification::new(view, checks))
}

/// Builds the denylist from the revocations named on the command line.
///
/// An empty list is not the same as no list: it says the caller supplied no
/// revocations, which the report above discloses rather than passing off as a
/// revocation check that found nothing.
fn revocation_list(request: &VerifyRequest<'_>) -> Result<Denylist, CliError> {
    let mut denylist = Denylist::new();

    for jti in request.revoked_tokens {
        denylist.insert_token(jti);
    }

    for hex_key in request.revoked_keys {
        let key = trust::decode_public(hex_key).map_err(|source| {
            CliError::refused(
                "invalid_revoked_key",
                format!("--revoked-key '{hex_key}' is not a public key: {source}"),
                "pass the 64 hex characters printed by 'agent-uri key public'",
            )
        })?;
        denylist.insert_key(&key);
    }

    Ok(denylist)
}

/// Decodes a token's claims without verifying them.
fn inspect<O: Write, E: Write>(token: &str, out: &mut Output<O, E>) -> Result<(), CliError> {
    let token = resolve_token(token)?;
    let claims = decode_unverified(&token)?;
    let view = ClaimsView::new(&claims, Utc::now());

    // The banner is unmissable, and it precedes the claims rather than trailing
    // them, so it cannot be mistaken for a verdict on what follows.
    out.verdict_caution("UNVERIFIED - claims decoded WITHOUT checking the signature");
    out.note("  anyone can mint a token carrying any claims; these prove nothing.");
    out.note("  run 'agent-uri attest verify' before trusting any of it.");

    if view.expired {
        out.note(&format!(
            "  this token is expired: it lapsed {}.",
            crate::timefmt::relative(view.expires_in_seconds)
        ));
    }
    if view.not_yet_valid {
        out.note("  this token is not yet valid: its issuance instant is in the future.");
    }
    out.blank();

    out.emit(&Inspected::new(view))
}

/// Parses an agent URI, refusing an invalid one with a precise diagnostic.
fn parse_agent_uri(input: &str) -> Result<AgentUri, CliError> {
    AgentUri::parse(input).map_err(|source| {
        CliError::refused(
            "invalid_uri",
            format!("'{input}' is not a valid agent:// URI: {source}"),
            "an agent URI looks like \
             agent://<trust-root>/<capability-path>/<prefix>_<26-char-id>",
        )
    })
}

/// Parses a required capability path.
fn parse_capability(input: &str) -> Result<CapabilityPath, CliError> {
    CapabilityPath::parse(input).map_err(|source| {
        CliError::refused(
            "invalid_capability",
            format!("'{input}' is not a valid capability path: {source}"),
            "a capability path is slash-separated, e.g. 'workflow/approval'",
        )
    })
}

/// Turns a verification failure into a precise, actionable refusal.
///
/// The verdict is always the verifier's, and so are the facts: the library
/// classifies its own failures and carries the instants it rejected on. This
/// only turns that into prose an operator can act on.
fn diagnose(error: &AttestationError, token: &str, roots: &[TrustedRoot]) -> CliError {
    match error {
        AttestationError::TokenExpired { expired_at } => expired(expired_at),
        AttestationError::TokenNotYetValid { valid_from } => not_yet_valid(valid_from),
        AttestationError::InvalidSignature => bad_signature(token, roots),
        AttestationError::InvalidTokenFormat { reason } => CliError::refused(
            "malformed_token",
            format!("token is not a well-formed attestation: {reason}"),
            "check the token was copied whole; inspect it with 'agent-uri attest inspect'",
        ),
        AttestationError::UntrustedIssuer { issuer }
        | AttestationError::MissingPublicKey { issuer } => unknown_root(issuer, roots),
        AttestationError::UriMismatch {
            token_uri,
            expected_uri,
        } => CliError::refused(
            "subject_mismatch",
            format!("token attests '{token_uri}', not the '{expected_uri}' you required"),
            "verify against the URI the token actually attests, or obtain a token for this one",
        ),
        AttestationError::InsufficientCapabilities { required, attested } => CliError::refused(
            "capability_not_covered",
            format!(
                "token does not cover the capability '{required}'; it grants {}",
                if attested.is_empty() {
                    "nothing".to_string()
                } else {
                    attested.join(", ")
                }
            ),
            "obtain a token granting that capability or an allowed prefix within the \
             agent URI's identity path",
        ),
        AttestationError::IssuerNamespaceMismatch {
            issuer,
            uri_trust_root,
        } => CliError::refused(
            "issuer_namespace_mismatch",
            format!(
                "token was issued by '{issuer}' but attests a URI rooted at '{uri_trust_root}'; \
                 a key may only attest URIs rooted at its own authority"
            ),
            "reject this token: it is a cross-namespace forgery, or was minted by a broken issuer",
        ),
        other => CliError::refused(
            "verification_failed",
            format!("token verification failed: {other}"),
            "inspect the token with 'agent-uri attest inspect' to see what it claims",
        ),
    }
}

/// Renders an instant the library rejected on, adding a relative reading.
///
/// The library reports these as RFC 3339, taken from claims it had already
/// authenticated. If one ever fails to parse, the raw value is shown rather than
/// swallowed: a timestamp the tool cannot read is still evidence.
fn instant(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339).map_or_else(
        |_| rfc3339.to_string(),
        |parsed| crate::timefmt::absolute_and_relative(parsed.with_timezone(&Utc), Utc::now()),
    )
}

/// Builds the refusal for an expired token, naming the instant it lapsed.
fn expired(expired_at: &str) -> CliError {
    CliError::refused(
        "token_expired",
        format!("token expired at {}", instant(expired_at)),
        "ask the issuer for a fresh attestation; an expired token cannot be renewed",
    )
}

/// Builds the refusal for a token whose validity has not begun.
fn not_yet_valid(valid_from: &str) -> CliError {
    CliError::refused(
        "token_not_yet_valid",
        format!(
            "token is not yet valid; it becomes valid at {}",
            instant(valid_from)
        ),
        "wait until it becomes valid, or check the clock on the issuing host",
    )
}

/// Builds the refusal for a signature that does not check out.
///
/// A token signed by an authority nobody supplied a key for also lands here,
/// because every trusted key was tried and none of them verified it. That is a
/// materially different problem for the operator, so it is named separately, and
/// naming it means reading the issuer the token *claims*. That claim is
/// unauthenticated, which is exactly why it is used only to choose the wording of
/// a refusal that has already been decided. It cannot turn a refusal into an
/// acceptance.
fn bad_signature(token: &str, roots: &[TrustedRoot]) -> CliError {
    if let Ok(claims) = decode_unverified(token)
        && !roots.iter().any(|root| root.root == claims.iss)
    {
        return unknown_root(&claims.iss, roots);
    }

    CliError::refused(
        "invalid_signature",
        "token signature does not verify against the trusted key for its issuer",
        "the token was tampered with, or the public key you supplied for that authority is wrong; \
         re-fetch the authority's public key and try again",
    )
}

/// Builds the refusal for an issuer nobody vouched for.
fn unknown_root(issuer: &str, roots: &[TrustedRoot]) -> CliError {
    let supplied = if roots.is_empty() {
        "none were supplied".to_string()
    } else {
        roots
            .iter()
            .map(|root| root.root.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };

    CliError::refused(
        "unknown_trust_root",
        format!(
            "token was issued by '{issuer}', which is not among the trust roots supplied ({supplied})"
        ),
        format!("supply that authority's public key: --trust-root {issuer}=<public-key-hex>"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q";

    fn uri() -> AgentUri {
        AgentUri::parse(URI).unwrap()
    }

    #[test]
    fn issuer_defaults_to_the_uri_authority() {
        assert_eq!(resolve_issuer(&uri(), None).unwrap(), "acme.com");
    }

    #[test]
    fn a_matching_issuer_is_accepted() {
        assert_eq!(
            resolve_issuer(&uri(), Some("acme.com")).unwrap(),
            "acme.com"
        );
    }

    #[test]
    fn a_foreign_issuer_is_refused_at_issue_time() {
        // Without this guard the tool would mint a token that the verifier's
        // issuer/namespace binding rejects forever.
        let error = resolve_issuer(&uri(), Some("evil.com")).unwrap_err();

        assert_eq!(error.diagnosis().kind, "issuer_namespace_mismatch");
        assert_eq!(error.exit_code(), 1);
        assert!(error.to_string().contains("evil.com"));
        assert!(error.to_string().contains("acme.com"));
    }

    #[test]
    fn an_authority_with_a_port_resolves_whole() {
        let uri =
            AgentUri::parse("agent://localhost:8472/chat/bot_01h455vb4pex5vsknk084sn02q").unwrap();

        assert_eq!(resolve_issuer(&uri, None).unwrap(), "localhost:8472");
        assert!(resolve_issuer(&uri, Some("localhost")).is_err());
    }

    #[test]
    fn an_invalid_uri_is_refused_with_guidance() {
        let error = parse_agent_uri("http://example.com").unwrap_err();

        assert_eq!(error.diagnosis().kind, "invalid_uri");
        assert_eq!(error.exit_code(), 1);
        assert!(error.diagnosis().remedy.contains("agent://"));
    }

    #[test]
    fn unknown_root_names_the_issuer_and_the_flag_to_fix_it() {
        let error = unknown_root("partner.io", &[]);

        assert_eq!(error.diagnosis().kind, "unknown_trust_root");
        assert!(error.to_string().contains("partner.io"));
        assert!(
            error
                .diagnosis()
                .remedy
                .contains("--trust-root partner.io=")
        );
    }

    #[test]
    fn expired_names_the_instant_and_how_long_ago() {
        let lapsed = Utc::now() - chrono::Duration::days(3);
        let error = expired(&lapsed.to_rfc3339());
        let message = error.to_string();

        assert_eq!(error.diagnosis().kind, "token_expired");
        assert_eq!(error.exit_code(), 1);
        assert!(message.contains("expired at"));
        assert!(message.contains(&crate::timefmt::rfc3339(lapsed)));
        assert!(message.contains("3 days ago"), "got: {message}");
    }

    #[test]
    fn an_unreadable_instant_is_shown_rather_than_swallowed() {
        // A timestamp the tool cannot parse is still evidence; never drop it.
        let error = expired("not-a-timestamp");

        assert!(error.to_string().contains("not-a-timestamp"));
    }

    #[test]
    fn not_yet_valid_names_the_instant_it_becomes_usable() {
        let starts = Utc::now() + chrono::Duration::hours(2);
        let error = not_yet_valid(&starts.to_rfc3339());

        assert_eq!(error.diagnosis().kind, "token_not_yet_valid");
        assert!(
            error.to_string().contains("in 1 hour") || error.to_string().contains("in 2 hours")
        );
    }

    #[test]
    fn capability_paths_are_validated() {
        assert!(parse_capability("workflow/approval").is_ok());

        let error = parse_capability("").unwrap_err();
        assert_eq!(error.diagnosis().kind, "invalid_capability");
    }
}
