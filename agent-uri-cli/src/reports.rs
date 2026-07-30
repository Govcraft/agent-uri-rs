//! What each command puts on stdout, in both formats.
//!
//! Each report is one stable JSON object under `--json`, and its human form is
//! the *data itself* (a token, a key, a canonical URI) so that the obvious pipe
//! does the obvious thing. Descriptions of the data live on stderr; see
//! [`crate::output`].

use std::io::{self, Write};

use agent_uri::AgentUri;
use agent_uri_attestation::AttestationClaims;
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::output::Report;
use crate::timefmt;

/// A claim set rendered for output, with the derived facts an operator needs.
///
/// The attestation claim set carries `iat`, `exp`, and optionally `aud`. There is
/// no `nbf`: the not-before instant *is* `iat`, which is what the library's own
/// not-yet-valid check compares against, so that is what is reported here rather
/// than inventing a field the wire format does not have.
#[derive(Debug, Clone, Serialize)]
pub struct ClaimsView {
    /// The agent URI being attested (the token's subject).
    pub agent_uri: String,
    /// The capabilities granted.
    pub capabilities: Vec<String>,
    /// The issuing trust root.
    pub issuer: String,
    /// When the token was issued; also its not-before instant.
    pub issued_at: String,
    /// When the token expires.
    pub expires_at: String,
    /// The audience restriction, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// Whether the token is past its expiry as of now.
    pub expired: bool,
    /// Whether the token's issuance instant is still in the future.
    pub not_yet_valid: bool,
    /// Seconds until expiry; negative once expired.
    pub expires_in_seconds: i64,
}

impl ClaimsView {
    /// Builds a view of the claims relative to a supplied `now`.
    ///
    /// Taking `now` as an argument keeps this pure, so expiry rendering is
    /// testable without waiting on a clock.
    pub fn new(claims: &AttestationClaims, now: DateTime<Utc>) -> Self {
        Self {
            agent_uri: claims.agent_uri.clone(),
            capabilities: claims.capabilities.clone(),
            issuer: claims.iss.clone(),
            issued_at: timefmt::rfc3339(claims.iat),
            expires_at: timefmt::rfc3339(claims.exp),
            audience: claims.aud.clone(),
            expired: now >= claims.exp,
            not_yet_valid: now < claims.iat,
            expires_in_seconds: (claims.exp - now).num_seconds(),
        }
    }
}

/// A freshly generated signing key.
#[derive(Debug, Clone, Serialize)]
pub struct KeyGenerated {
    /// The public key, as 64 lowercase hex characters. Safe to publish.
    pub public_key: String,
    /// Where the private key was written, when it was written to a file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The private key, present **only** when `--stdout` was requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
}

impl Report for KeyGenerated {
    fn render_human(&self, w: &mut dyn Write) -> io::Result<()> {
        // With --stdout the private key is the payload the operator asked to
        // pipe, so it is the only thing on the stream. Otherwise the private key
        // never appears: stdout carries the public key and where its private
        // half now lives.
        if let Some(secret) = &self.secret_key {
            return writeln!(w, "{secret}");
        }

        writeln!(w, "public key  {}", self.public_key)?;
        if let Some(path) = &self.path {
            writeln!(w, "key file    {path}")?;
        }
        Ok(())
    }
}

/// The public half of a stored key.
#[derive(Debug, Clone, Serialize)]
pub struct PublicKey {
    /// The public key, as 64 lowercase hex characters.
    pub public_key: String,
}

impl Report for PublicKey {
    fn render_human(&self, w: &mut dyn Write) -> io::Result<()> {
        // Bare, so it composes: agent-uri key public > registry/acme.com.pub
        writeln!(w, "{}", self.public_key)
    }
}

/// A newly minted attestation token.
#[derive(Debug, Clone, Serialize)]
pub struct TokenIssued {
    /// The PASETO v4.public token.
    pub token: String,
    /// The claims it carries.
    pub claims: ClaimsView,
}

impl Report for TokenIssued {
    fn render_human(&self, w: &mut dyn Write) -> io::Result<()> {
        // The token, and nothing else, so `| pbcopy` yields a usable credential.
        writeln!(w, "{}", self.token)
    }
}

/// The result of a successful verification.
#[derive(Debug, Clone, Serialize)]
pub struct Verification {
    /// Always `true`: this report is only ever built after the signature checked out.
    pub verified: bool,
    /// The checks that were performed, in the order they were applied.
    pub checks: Vec<String>,
    /// The authenticated claims.
    pub claims: ClaimsView,
}

impl Verification {
    /// Builds a verification report from authenticated claims.
    pub fn new(claims: ClaimsView, checks: Vec<String>) -> Self {
        Self {
            verified: true,
            checks,
            claims,
        }
    }
}

impl Report for Verification {
    fn render_human(&self, w: &mut dyn Write) -> io::Result<()> {
        render_claims(w, &self.claims)
    }
}

/// The result of decoding a token without verifying it.
#[derive(Debug, Clone, Serialize)]
pub struct Inspected {
    /// Always `false`. Present as a literal field, not merely omitted, so a
    /// machine reading this can assert on it: `jq -e '.verified == false'`.
    pub verified: bool,
    /// Why these claims mean nothing on their own.
    pub warning: String,
    /// The decoded, unauthenticated claims.
    pub claims: ClaimsView,
}

impl Inspected {
    /// Builds an inspection report from unverified claims.
    pub fn new(claims: ClaimsView) -> Self {
        Self {
            verified: false,
            warning: "these claims are NOT cryptographically verified; \
                      anyone can mint a token carrying any claims. \
                      Use 'agent-uri attest verify' before trusting them."
                .to_string(),
            claims,
        }
    }
}

impl Report for Inspected {
    fn render_human(&self, w: &mut dyn Write) -> io::Result<()> {
        render_claims(w, &self.claims)
    }
}

/// A validated agent URI, broken into its parts.
#[derive(Debug, Clone, Serialize)]
pub struct UriValidated {
    /// Always `true`; an invalid URI is a refusal, not a report.
    pub valid: bool,
    /// The canonical form of the URI.
    pub uri: String,
    /// The authority the agent is rooted at.
    pub trust_root: String,
    /// The capability path.
    pub capability_path: String,
    /// The agent's `TypeID`.
    pub agent_id: String,
    /// The semantic prefix of the agent's `TypeID`.
    pub agent_prefix: String,
}

impl UriValidated {
    /// Breaks a parsed URI into its reportable parts.
    pub fn new(uri: &AgentUri) -> Self {
        Self {
            valid: true,
            uri: uri.canonical(),
            trust_root: uri.trust_root().as_str().to_string(),
            capability_path: uri.capability_path().as_str().to_string(),
            agent_id: uri.agent_id().to_string(),
            agent_prefix: uri.agent_id().prefix().as_str().to_string(),
        }
    }
}

impl Report for UriValidated {
    fn render_human(&self, w: &mut dyn Write) -> io::Result<()> {
        // The canonical form, bare, so it can be fed straight back into a pipeline.
        writeln!(w, "{}", self.uri)
    }
}

/// Renders a claim set as aligned fields.
fn render_claims(w: &mut dyn Write, claims: &ClaimsView) -> io::Result<()> {
    let expiry = format!(
        "{} ({})",
        claims.expires_at,
        timefmt::relative(claims.expires_in_seconds)
    );

    writeln!(w, "{:<14}{}", "agent uri", claims.agent_uri)?;
    writeln!(w, "{:<14}{}", "issuer", claims.issuer)?;

    match claims.capabilities.split_first() {
        Some((first, rest)) => {
            writeln!(w, "{:<14}{first}", "capabilities")?;
            for capability in rest {
                writeln!(w, "{:<14}{capability}", "")?;
            }
        }
        None => writeln!(w, "{:<14}(none)", "capabilities")?,
    }

    writeln!(w, "{:<14}{}", "issued at", claims.issued_at)?;
    writeln!(w, "{:<14}{expiry}", "expires at")?;

    if let Some(audience) = &claims.audience {
        writeln!(w, "{:<14}{audience}", "audience")?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use agent_uri_attestation::AttestationClaims;
    use chrono::TimeZone;

    use super::*;

    const URI: &str = "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q";

    fn claims() -> AttestationClaims {
        AttestationClaims::builder()
            .agent_uri(URI)
            .agent_key(&agent_uri_attestation::SigningKey::generate().verifying_key())
            .issuer("acme.com")
            .add_capability("workflow/approval/read")
            .ttl(Duration::from_hours(24))
            .build()
            .unwrap()
    }

    fn render(report: &impl Report) -> String {
        let mut buffer = Vec::new();
        report.render_human(&mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }

    #[test]
    fn claims_view_derives_expiry_from_the_supplied_now() {
        let claims = claims();
        let view = ClaimsView::new(&claims, claims.iat);

        assert!(!view.expired);
        assert!(!view.not_yet_valid);
        assert_eq!(view.expires_in_seconds, 86_400);
        assert_eq!(view.issuer, "acme.com");
        assert_eq!(view.agent_uri, URI);
    }

    #[test]
    fn claims_view_reports_an_expired_token_without_a_clock() {
        let claims = claims();
        let long_after = claims.exp + chrono::Duration::days(3);
        let view = ClaimsView::new(&claims, long_after);

        assert!(view.expired);
        assert_eq!(view.expires_in_seconds, -3 * 86_400);
        assert_eq!(timefmt::relative(view.expires_in_seconds), "3 days ago");
    }

    #[test]
    fn claims_view_reports_a_not_yet_valid_token() {
        let claims = claims();
        let before = claims.iat - chrono::Duration::hours(1);
        let view = ClaimsView::new(&claims, before);

        assert!(view.not_yet_valid);
    }

    #[test]
    fn claims_view_json_is_stable() {
        let mut claims = claims();
        claims.iat = Utc.timestamp_opt(0, 0).unwrap();
        claims.exp = Utc.timestamp_opt(86_400, 0).unwrap();
        claims.aud = Some("api.acme.com".to_string());

        let view = ClaimsView::new(&claims, claims.iat);
        let json = serde_json::to_value(&view).unwrap();

        assert_eq!(json["agent_uri"], URI);
        assert_eq!(json["issuer"], "acme.com");
        assert_eq!(json["capabilities"][0], "workflow/approval/read");
        assert_eq!(json["issued_at"], "1970-01-01T00:00:00Z");
        assert_eq!(json["expires_at"], "1970-01-02T00:00:00Z");
        assert_eq!(json["audience"], "api.acme.com");
        assert_eq!(json["expired"], false);
        assert_eq!(json["not_yet_valid"], false);
        assert_eq!(json["expires_in_seconds"], 86_400);
    }

    #[test]
    fn absent_audience_is_omitted_from_json() {
        let view = ClaimsView::new(&claims(), Utc::now());
        let json = serde_json::to_value(&view).unwrap();

        assert!(json.get("audience").is_none());
    }

    #[test]
    fn issued_token_renders_only_the_token() {
        let report = TokenIssued {
            token: "v4.public.abc".to_string(),
            claims: ClaimsView::new(&claims(), Utc::now()),
        };

        assert_eq!(render(&report), "v4.public.abc\n");
    }

    #[test]
    fn issued_token_json_wraps_token_and_claims() {
        let report = TokenIssued {
            token: "v4.public.abc".to_string(),
            claims: ClaimsView::new(&claims(), Utc::now()),
        };
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(json["token"], "v4.public.abc");
        assert_eq!(json["claims"]["issuer"], "acme.com");
    }

    #[test]
    fn public_key_renders_bare() {
        let report = PublicKey {
            public_key: "ab".repeat(32),
        };

        assert_eq!(render(&report), format!("{}\n", "ab".repeat(32)));
    }

    #[test]
    fn generated_key_never_renders_the_secret_unless_asked() {
        let report = KeyGenerated {
            public_key: "aa".repeat(32),
            path: Some("/keys/issuer.key".to_string()),
            secret_key: None,
        };
        let rendered = render(&report);

        assert!(rendered.contains(&"aa".repeat(32)));
        assert!(rendered.contains("/keys/issuer.key"));
    }

    #[test]
    fn generated_key_with_stdout_renders_only_the_secret() {
        let report = KeyGenerated {
            public_key: "aa".repeat(32),
            path: None,
            secret_key: Some("bb".repeat(32)),
        };

        // Exactly the secret, so it can be piped into a secret store verbatim.
        assert_eq!(render(&report), format!("{}\n", "bb".repeat(32)));
    }

    #[test]
    fn generated_key_json_omits_the_secret_by_default() {
        let report = KeyGenerated {
            public_key: "aa".repeat(32),
            path: Some("/keys/issuer.key".to_string()),
            secret_key: None,
        };
        let json = serde_json::to_value(&report).unwrap();

        assert!(json.get("secret_key").is_none());
        assert_eq!(json["public_key"], "aa".repeat(32));
    }

    #[test]
    fn inspection_carries_a_literal_verified_false() {
        let report = Inspected::new(ClaimsView::new(&claims(), Utc::now()));
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(json["verified"], false);
        assert!(json["warning"].as_str().unwrap().contains("NOT"));
    }

    #[test]
    fn verification_carries_a_literal_verified_true() {
        let report = Verification::new(
            ClaimsView::new(&claims(), Utc::now()),
            vec!["signature".to_string()],
        );
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(json["verified"], true);
        assert_eq!(json["checks"][0], "signature");
    }

    #[test]
    fn claims_render_aligned_with_every_capability() {
        let mut claims = claims();
        claims.capabilities = vec![
            "workflow/approval/read".into(),
            "workflow/approval/write".into(),
        ];
        let report = Inspected::new(ClaimsView::new(&claims, claims.iat));
        let rendered = render(&report);

        assert!(rendered.contains("agent uri     agent://acme.com/"));
        assert!(rendered.contains("issuer        acme.com"));
        assert!(rendered.contains("capabilities  workflow/approval/read"));
        assert!(rendered.contains("\n              workflow/approval/write"));
        assert!(rendered.contains("expires at    "));
        assert!(rendered.contains("(in 1 day)"));
    }

    #[test]
    fn claims_with_no_capabilities_say_so() {
        let mut claims = claims();
        claims.capabilities.clear();
        let report = Inspected::new(ClaimsView::new(&claims, claims.iat));

        assert!(render(&report).contains("capabilities  (none)"));
    }

    #[test]
    fn validated_uri_renders_its_canonical_form() {
        let uri = AgentUri::parse(URI).unwrap();
        let report = UriValidated::new(&uri);

        assert_eq!(render(&report), format!("{}\n", uri.canonical()));
    }

    #[test]
    fn validated_uri_json_breaks_out_the_parts() {
        let uri = AgentUri::parse(URI).unwrap();
        let json = serde_json::to_value(UriValidated::new(&uri)).unwrap();

        assert_eq!(json["valid"], true);
        assert_eq!(json["trust_root"], "acme.com");
        assert_eq!(json["capability_path"], "workflow/approval");
        assert_eq!(json["agent_prefix"], "rule");
        assert_eq!(json["agent_id"], "rule_01h455vb4pex5vsknk084sn02q");
    }
}
