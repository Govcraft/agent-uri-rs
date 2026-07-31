//! Token verifier for validating attestations.

use std::collections::HashMap;
use std::time::Duration;

use agent_uri::AgentUri;
use chrono::Utc;
use rusty_paseto::Error as PasetoUnifiedError;
use rusty_paseto::core::Paseto;
use rusty_paseto::prelude::*;

use agent_uri::CapabilityPath;

use crate::claims::AttestationClaims;
use crate::error::AttestationError;
use crate::keys::VerifyingKey;
use crate::verification;

/// Verifies attestation tokens for agent URIs.
///
/// The verifier maintains a set of trusted roots and their public keys,
/// validating that tokens were issued by authorized parties.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::{Issuer, Verifier, SigningKey};
/// use agent_uri::AgentUri;
/// use std::time::Duration;
///
/// // Create an issuer
/// let signing_key = SigningKey::generate();
/// let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
///
/// // Issue a token
/// let uri = AgentUri::parse(
///     "agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q"
/// ).unwrap();
/// let token = issuer.issue(&uri, &SigningKey::generate().verifying_key(), vec!["test".into()]).unwrap();
///
/// // Create a verifier with the issuer's public key
/// let mut verifier = Verifier::new();
/// verifier.add_trusted_root("acme.com", signing_key.verifying_key());
///
/// // Verify the token
/// let claims = verifier.verify(&token).unwrap();
/// assert_eq!(claims.iss, "acme.com");
/// ```
#[derive(Debug, Clone)]
pub struct Verifier {
    trusted_roots: HashMap<String, VerifyingKey>,
    leeway: Duration,
}

impl Default for Verifier {
    fn default() -> Self {
        Self {
            trusted_roots: HashMap::new(),
            leeway: Self::DEFAULT_LEEWAY,
        }
    }
}

impl Verifier {
    /// Clock-skew tolerance applied to a token's validity window by default.
    ///
    /// Attestations cross trust boundaries, which means the issuer's clock and
    /// the verifier's clock are different clocks. With exact comparisons, a
    /// verifier a few seconds ahead rejects tokens the issuer just minted, and
    /// one a few seconds behind rejects tokens that have not expired. Sixty
    /// seconds covers ordinary NTP-synchronized drift.
    ///
    /// The tolerance is symmetric: it also accepts a token for up to this long
    /// past its real expiry. Deployments that need exactness can set it to
    /// [`Duration::ZERO`] with [`Self::set_leeway`].
    pub const DEFAULT_LEEWAY: Duration = Duration::from_mins(1);

    /// Creates a new verifier with no trusted roots and [`Self::DEFAULT_LEEWAY`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new verifier with an explicit clock-skew tolerance.
    ///
    /// # Example
    ///
    /// ```
    /// use agent_uri_attestation::Verifier;
    /// use std::time::Duration;
    ///
    /// // Exact comparisons: no token outlives its `exp` by even a second.
    /// let strict = Verifier::with_leeway(Duration::ZERO);
    /// assert_eq!(strict.leeway(), Duration::ZERO);
    /// ```
    #[must_use]
    pub fn with_leeway(leeway: Duration) -> Self {
        Self {
            trusted_roots: HashMap::new(),
            leeway,
        }
    }

    /// Sets the clock-skew tolerance applied to `iat` and `exp`.
    ///
    /// See [`Self::DEFAULT_LEEWAY`] for what the tolerance buys and costs.
    pub fn set_leeway(&mut self, leeway: Duration) {
        self.leeway = leeway;
    }

    /// Returns the clock-skew tolerance applied to `iat` and `exp`.
    #[must_use]
    pub fn leeway(&self) -> Duration {
        self.leeway
    }

    /// The tolerance as a `chrono` duration, saturating on absurd values.
    fn leeway_chrono(&self) -> chrono::Duration {
        chrono::Duration::from_std(self.leeway).unwrap_or(chrono::Duration::MAX)
    }

    /// Adds a trusted root and its public key.
    ///
    /// # Arguments
    ///
    /// * `trust_root` - The trust root identifier (e.g., "acme.com")
    /// * `public_key` - The Ed25519 public key for this trust root
    pub fn add_trusted_root(&mut self, trust_root: impl Into<String>, public_key: VerifyingKey) {
        self.trusted_roots.insert(trust_root.into(), public_key);
    }

    /// Returns true if the given trust root is registered.
    #[must_use]
    pub fn has_trusted_root(&self, trust_root: &str) -> bool {
        self.trusted_roots.contains_key(trust_root)
    }

    /// Returns the number of registered trusted roots.
    #[must_use]
    pub fn trusted_root_count(&self) -> usize {
        self.trusted_roots.len()
    }

    /// Verifies an attestation token and returns its claims.
    ///
    /// This method:
    /// 0. Rejects tokens over [`crate::MAX_TOKEN_LENGTH`] bytes, before any
    ///    decoding or signature work
    /// 1. Parses the PASETO token
    /// 2. Verifies the signature using the issuer's public key
    /// 3. Checks the validity window: not before `iat`, not after `exp`, each
    ///    with [`Self::leeway`] of clock-skew tolerance
    /// 4. Validates the issuer is trusted
    /// 5. Binds the authenticated issuer to the attested URI's namespace
    ///
    /// # Issuer/namespace binding
    ///
    /// Step 5 is the security-critical check. Authenticating `iss` (steps 2-4)
    /// only proves *which trusted key* signed the token; it does not stop a key
    /// trusted for one authority from minting an attestation for a URI rooted at
    /// a *different* authority. This method therefore requires that `iss` equals
    /// the trust root (authority) parsed from the `agent_uri` claim, and fails
    /// closed (rejects) if that authority cannot be parsed. Because every
    /// higher-level verification path funnels through `verify`, this binding is
    /// enforced uniformly.
    ///
    /// # Errors
    ///
    /// Returns `AttestationError` if verification fails for any reason:
    /// - `TokenTooLong` - Token exceeds [`crate::MAX_TOKEN_LENGTH`] bytes
    ///   (checked before any decoding or signature work)
    /// - `InvalidSignature` - Signature doesn't match any trusted key
    /// - `TokenExpired` - Token has passed its expiration time
    /// - `TokenNotYetValid` - Token is dated further into the future than the
    ///   clock-skew tolerance allows
    /// - `UntrustedIssuer` - Issuer is not in the trusted roots set
    /// - `IssuerNamespaceMismatch` - Issuer does not own the URI's namespace
    /// - `InvalidTokenFormat` - Token is malformed
    /// - `InvalidClaims` - Claims cannot be parsed
    pub fn verify(&self, token: &str) -> Result<AttestationClaims, AttestationError> {
        self.verify_with_audience_context(token, None)
    }

    /// Verifies a token for a specific verifier audience.
    ///
    /// Audience-restricted tokens are accepted only when `verifier_audience`
    /// exactly matches their `aud` claim. Unrestricted tokens are accepted for
    /// any audience.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::verify`], plus
    /// [`AttestationError::AudienceMismatch`] for a non-matching audience.
    pub fn verify_for_audience(
        &self,
        token: &str,
        verifier_audience: &str,
    ) -> Result<AttestationClaims, AttestationError> {
        self.verify_with_audience_context(token, Some(verifier_audience))
    }

    fn verify_with_audience_context(
        &self,
        token: &str,
        verifier_audience: Option<&str>,
    ) -> Result<AttestationClaims, AttestationError> {
        // Length first: every later step is attacker-funded work (one Ed25519
        // verification per trusted root over the whole payload), so the cap has
        // to be enforced before anything is decoded.
        verification::check_token_length(token)?;

        if self.trusted_roots.is_empty() {
            return Err(AttestationError::UntrustedIssuer {
                issuer: "unknown".to_string(),
            });
        }

        // Try each trusted key until one works
        let (issuer, claims) = self.extract_and_verify(token)?;

        // Validate issuer is trusted (already verified by finding the key)
        if !self.trusted_roots.contains_key(&issuer) {
            return Err(AttestationError::UntrustedIssuer { issuer });
        }

        // Bind the authenticated issuer to the attested URI's namespace.
        // The issuer must equal the trust root (authority) of the `agent_uri`
        // claim. Fail closed when the authority cannot be parsed.
        if claims.trust_root() != Some(claims.iss.as_str()) {
            return Err(AttestationError::IssuerNamespaceMismatch {
                issuer: claims.iss.clone(),
                uri_trust_root: claims.trust_root().unwrap_or_default().to_string(),
            });
        }

        verification::validate_capability_scope(&claims.agent_uri, &claims.capabilities)?;
        // Callers act on the attested key, so it has to be a key. Checking it
        // here means every claim set this method hands back has one that
        // decodes, and no caller has to re-derive that.
        claims.agent_verifying_key()?;
        verification::validate_audience(claims.aud.as_deref(), verifier_audience)?;

        Ok(claims)
    }

    /// Verifies a token and checks it matches the expected agent URI.
    ///
    /// # Arguments
    ///
    /// * `token` - The PASETO token to verify
    /// * `expected_uri` - The agent URI that should be attested
    ///
    /// # Errors
    ///
    /// Returns `AttestationError` if:
    /// - Token verification fails (including `IssuerNamespaceMismatch` when the
    ///   issuer does not own the attested URI's namespace)
    /// - The token's `agent_uri` doesn't match `expected_uri`
    pub fn verify_for_uri(
        &self,
        token: &str,
        expected_uri: &AgentUri,
    ) -> Result<AttestationClaims, AttestationError> {
        // `verify` already binds `iss` to the `agent_uri` claim's trust root, so
        // an authenticated token's authority is guaranteed to equal its own
        // issuer here. Comparing the full `agent_uri` to `expected_uri` is the
        // only remaining, load-bearing check.
        let claims = self.verify(token)?;

        let expected_str = expected_uri.canonical();
        let token_uri = AgentUri::parse(&claims.agent_uri).map_err(|error| {
            AttestationError::InvalidClaims {
                reason: format!("invalid agent_uri claim: {error}"),
            }
        })?;
        if token_uri.canonical() != expected_str {
            return Err(AttestationError::UriMismatch {
                token_uri: claims.agent_uri.clone(),
                expected_uri: expected_str,
            });
        }

        Ok(claims)
    }

    /// Verifies a token, canonical subject URI, and verifier audience.
    ///
    /// # Errors
    ///
    /// Returns an error when signature, claims, audience, or subject validation
    /// fails.
    pub fn verify_for_uri_and_audience(
        &self,
        token: &str,
        expected_uri: &AgentUri,
        verifier_audience: &str,
    ) -> Result<AttestationClaims, AttestationError> {
        let claims = self.verify_for_audience(token, verifier_audience)?;
        let token_uri = AgentUri::parse(&claims.agent_uri).map_err(|error| {
            AttestationError::InvalidClaims {
                reason: format!("invalid agent_uri claim: {error}"),
            }
        })?;
        if token_uri.canonical() != expected_uri.canonical() {
            return Err(AttestationError::UriMismatch {
                token_uri: claims.agent_uri.clone(),
                expected_uri: expected_uri.canonical(),
            });
        }
        Ok(claims)
    }

    /// Verifies a token, checks URI match, AND validates capability coverage.
    ///
    /// This is the most comprehensive verification method, performing:
    /// 1. Signature verification using trusted keys
    /// 2. Expiration check
    /// 3. Issuer validation against trusted roots
    /// 4. Issuer/namespace binding (`iss` owns the attested URI's authority)
    /// 5. URI match verification
    /// 6. Capability coverage verification
    ///
    /// # Arguments
    ///
    /// * `token` - The PASETO token to verify
    /// * `uri` - The agent URI that should be attested
    /// * `required_capability` - The capability path required for the operation
    ///
    /// # Returns
    ///
    /// The verified `AttestationClaims` if all checks pass
    ///
    /// # Errors
    ///
    /// Returns `AttestationError` if any verification step fails:
    /// - `InvalidSignature` - Signature doesn't match any trusted key
    /// - `TokenExpired` - Token has passed its expiration time
    /// - `TokenNotYetValid` - Token is dated further into the future than the
    ///   clock-skew tolerance allows
    /// - `UntrustedIssuer` - Issuer is not in the trusted roots set
    /// - `IssuerNamespaceMismatch` - Issuer does not own the attested URI's namespace
    /// - `UriMismatch` - Token's `agent_uri` doesn't match expected URI
    /// - `InsufficientCapabilities` - Token capabilities don't cover required path
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentUri;
    /// use agent_uri::CapabilityPath;
    /// use agent_uri_attestation::{Issuer, Verifier, SigningKey};
    /// use std::time::Duration;
    ///
    /// let signing_key = SigningKey::generate();
    /// let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_secs(3600));
    ///
    /// let uri = AgentUri::parse(
    ///     "agent://acme.com/workflow/approval/agent_01h455vb4pex5vsknk084sn02q"
    /// ).unwrap();
    /// let token = issuer.issue(&uri, &SigningKey::generate().verifying_key(), vec!["workflow/approval".into()]).unwrap();
    ///
    /// let mut verifier = Verifier::new();
    /// verifier.add_trusted_root("acme.com", signing_key.verifying_key());
    ///
    /// // "workflow" capability covers "workflow/approval"
    /// let required = CapabilityPath::parse("workflow/approval").unwrap();
    /// let claims = verifier.verify_for_capability(&token, &uri, &required).unwrap();
    ///
    /// assert_eq!(claims.iss, "acme.com");
    /// ```
    pub fn verify_for_capability(
        &self,
        token: &str,
        uri: &AgentUri,
        required_capability: &CapabilityPath,
    ) -> Result<AttestationClaims, AttestationError> {
        if !required_capability.starts_with(uri.capability_path()) {
            return Err(AttestationError::CapabilityOutsideIdentity {
                identity_path: uri.capability_path().as_str().to_string(),
                capability: required_capability.as_str().to_string(),
            });
        }

        // First verify the token and URI match
        let claims = self.verify_for_uri(token, uri)?;

        // Then check capability coverage using pure function
        verification::check_capability_coverage(&claims.capabilities, required_capability)?;

        Ok(claims)
    }

    /// Verifies a token for a URI, required capability, and audience.
    ///
    /// # Errors
    ///
    /// Returns an error when any signature, claim, subject, capability, or
    /// audience check fails.
    pub fn verify_for_capability_and_audience(
        &self,
        token: &str,
        uri: &AgentUri,
        required_capability: &CapabilityPath,
        verifier_audience: &str,
    ) -> Result<AttestationClaims, AttestationError> {
        if !required_capability.starts_with(uri.capability_path()) {
            return Err(AttestationError::CapabilityOutsideIdentity {
                identity_path: uri.capability_path().as_str().to_string(),
                capability: required_capability.as_str().to_string(),
            });
        }
        let claims = self.verify_for_uri_and_audience(token, uri, verifier_audience)?;
        verification::check_capability_coverage(&claims.capabilities, required_capability)?;
        Ok(claims)
    }

    /// Internal method to extract issuer and verify signature.
    fn extract_and_verify(
        &self,
        token: &str,
    ) -> Result<(String, AttestationClaims), AttestationError> {
        // Try each trusted key until one works
        let mut last_error = None;

        for (trust_root, verifying_key) in &self.trusted_roots {
            match try_verify_with_key(token, verifying_key, self.leeway_chrono()) {
                Ok(claims) => {
                    // Verify the issuer matches the key we used
                    if claims.iss == *trust_root {
                        return Ok((trust_root.clone(), claims));
                    }
                    // Issuer mismatch - this key signed it but claims different issuer
                    last_error = Some(AttestationError::TrustRootMismatch {
                        token_root: claims.iss.clone(),
                        expected_root: trust_root.clone(),
                    });
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(AttestationError::UntrustedIssuer {
            issuer: "unknown".to_string(),
        }))
    }
}

/// Classifies a PASETO failure by its cause rather than by its message text.
///
/// The failure modes fall into two groups, and conflating them misleads callers:
///
/// - **Structural**: the string is not a well-formed v4.public token at all
///   (wrong header, bad base64, truncated). Nothing was verified because there
///   was nothing to verify.
/// - **Cryptographic**: the token is well-formed, but its signature does not
///   check out under this key. The token was tampered with, or this is simply
///   the wrong key for it.
///
/// Everything not explicitly structural is treated as a signature failure, so a
/// new cipher-side variant fails closed rather than being reported as a
/// malformed token.
///
/// The argument is taken as anything convertible into `rusty_paseto`'s unified
/// [`Error`](PasetoUnifiedError) rather than as the concrete per-layer error
/// [`Paseto::try_verify`] returns, because that per-layer type is deprecated and
/// due for removal. Classifying the unified error keeps this function pointed at
/// the type that survives, and that type is `#[non_exhaustive]`, so the closed
/// default below is required rather than merely prudent.
fn classify_paseto_error(error: impl Into<PasetoUnifiedError>) -> AttestationError {
    let error: PasetoUnifiedError = error.into();

    match error {
        PasetoUnifiedError::InvalidTokenStructure
        | PasetoUnifiedError::InvalidHeader
        | PasetoUnifiedError::FooterMismatch
        | PasetoUnifiedError::Base64Decode(_)
        | PasetoUnifiedError::Utf8(_)
        | PasetoUnifiedError::FromUtf8(_)
        // Size caps `rusty_paseto` enforces before it decodes anything. This
        // crate's own, far smaller cap runs first (see `check_token_length`),
        // so reaching these means the token was structurally rejected without
        // a signature ever being checked.
        | PasetoUnifiedError::TokenTooLarge
        | PasetoUnifiedError::FooterTooLarge => AttestationError::InvalidTokenFormat {
            reason: error.to_string(),
        },
        PasetoUnifiedError::InvalidKey => AttestationError::InvalidKeyFormat {
            reason: error.to_string(),
        },
        _ => AttestationError::InvalidSignature,
    }
}

/// Try to verify a token with a specific key.
///
/// Verification happens in two stages, in this order, and the order is what
/// makes the resulting error trustworthy:
///
/// 1. **Signature.** [`Paseto::try_verify`] authenticates the payload and hands
///    it back. Until this succeeds the payload is attacker-controlled, so no
///    claim in it may be believed, let alone reported.
/// 2. **Claims.** Only then are the (now authenticated) claims parsed and their
///    validity window checked, via the pure
///    [`verification::check_validity_window`].
///
/// That second stage is why `TokenExpired` can name the instant a token lapsed:
/// by then, `exp` has been authenticated, so reporting it is safe.
///
/// `leeway` is the verifier's clock-skew tolerance, applied to both ends of the
/// window.
fn try_verify_with_key(
    token: &str,
    verifying_key: &VerifyingKey,
    leeway: chrono::Duration,
) -> Result<AttestationClaims, AttestationError> {
    let key_bytes = verifying_key.to_bytes();
    let key_wrapper = Key::<32>::from(&key_bytes);
    let paseto_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&key_wrapper);

    // Stage 1: authenticate. Returns the verified payload, and validates no claims.
    let payload = Paseto::<V4, Public>::try_verify(token, &paseto_key, None, None)
        .map_err(classify_paseto_error)?;

    let json_value: serde_json::Value =
        serde_json::from_str(&payload).map_err(|e| AttestationError::InvalidClaims {
            reason: format!("token payload is not valid JSON: {e}"),
        })?;

    // Stage 2: the payload is authenticated, so its claims can now be believed,
    // and its validity window enforced with the real instants it carries.
    let claims = extract_claims(&json_value)?;
    verification::check_validity_window(claims.iat, claims.exp, Utc::now(), leeway)?;

    Ok(claims)
}

/// Names a JSON value's type, for claim-shape diagnostics.
fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// Reads a required string claim, distinguishing absent from wrong-typed.
///
/// The distinction matters for diagnosis: a claim nobody set and a claim set to
/// the wrong JSON type are different faults on the issuing side, and reporting
/// the second as "missing" sends the reader looking for the wrong bug. Both are
/// rejections either way — a claim this crate cannot read is never guessed at.
///
/// `null` counts as absent, so an explicitly-nulled claim reads the same as an
/// omitted one.
fn required_str_claim<'a>(
    json: &'a serde_json::Value,
    name: &str,
) -> Result<&'a str, AttestationError> {
    match json.get(name) {
        None | Some(serde_json::Value::Null) => Err(AttestationError::InvalidClaims {
            reason: format!("missing {name} claim"),
        }),
        Some(value) => value
            .as_str()
            .ok_or_else(|| AttestationError::InvalidClaims {
                reason: format!(
                    "{name} claim must be a string, but is {}",
                    json_type_name(value)
                ),
            }),
    }
}

/// Parses an RFC 3339 timestamp claim.
fn timestamp_claim(
    json: &serde_json::Value,
    name: &str,
) -> Result<chrono::DateTime<Utc>, AttestationError> {
    let raw = required_str_claim(json, name)?;
    Ok(chrono::DateTime::parse_from_rfc3339(raw)
        .map_err(|e| AttestationError::InvalidClaims {
            reason: format!("invalid {name} format: {e}"),
        })?
        .with_timezone(&Utc))
}

/// Extract `AttestationClaims` from parsed JSON value.
fn extract_claims(json: &serde_json::Value) -> Result<AttestationClaims, AttestationError> {
    let agent_uri = required_str_claim(json, "agent_uri")?.to_string();
    let agent_key = required_str_claim(json, "agent_key")?.to_string();
    let iss = required_str_claim(json, "iss")?.to_string();
    let iat = timestamp_claim(json, "iat")?;
    let exp = timestamp_claim(json, "exp")?;

    // A malformed `capabilities` claim must not decay into an empty list: that
    // would surface downstream as `MissingField`, which describes a token that
    // granted nothing rather than one whose grant could not be read.
    let capabilities: Vec<String> = match json.get("capabilities") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(value) => {
            serde_json::from_value(value.clone()).map_err(|e| AttestationError::InvalidClaims {
                reason: format!("capabilities claim must be an array of strings: {e}"),
            })?
        }
    };

    // An `aud` of the wrong type must not read as absent either: silently
    // dropping it would widen an audience-restricted token into an
    // unrestricted one.
    let aud = match json.get("aud") {
        None | Some(serde_json::Value::Null) => None,
        Some(_) => Some(required_str_claim(json, "aud")?.to_string()),
    };

    Ok(AttestationClaims {
        agent_uri,
        agent_key,
        capabilities,
        iss,
        iat,
        exp,
        aud,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::issuer::Issuer;
    use crate::keys::SigningKey;

    fn test_uri() -> AgentUri {
        AgentUri::parse("agent://acme.com/test/agent_01h455vb4pex5vsknk084sn02q").unwrap()
    }

    /// Signs an arbitrary JSON payload, bypassing the claim-shape checks the
    /// high-level builder applies.
    ///
    /// [`Issuer`] cannot mint a token whose `exp` is a number or whose `iss` is
    /// an array, so the only way to put one in front of the verifier is to sign
    /// the payload directly. The signature is genuine and the key is trusted:
    /// these tests are about what happens *after* authentication succeeds,
    /// which is precisely where a claim reader can be too trusting.
    fn sign_raw_payload(signing_key: &SigningKey, payload: &str) -> String {
        let key_bytes = signing_key.as_dalek().to_keypair_bytes();
        let key_wrapper = Key::<64>::from(&key_bytes);
        let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&key_wrapper);

        Paseto::<V4, Public>::builder()
            .set_payload(rusty_paseto::core::Payload::from(payload))
            .try_sign(&private_key)
            .expect("raw payload should sign")
    }

    /// A claim set that verifies cleanly, for tests to spoil one claim at a time.
    fn valid_claims_value() -> serde_json::Value {
        let now = Utc::now();
        serde_json::json!({
            "agent_uri": test_uri().canonical(),
            "agent_key": SigningKey::generate().verifying_key().to_base64(),
            "capabilities": ["test"],
            "iss": "acme.com",
            "iat": now.to_rfc3339(),
            "exp": (now + chrono::Duration::hours(1)).to_rfc3339(),
        })
    }

    /// Signs the valid claim set with `name` replaced by `value`.
    fn token_with_claim(signing_key: &SigningKey, name: &str, value: serde_json::Value) -> String {
        let mut claims = valid_claims_value();
        claims[name] = value;
        sign_raw_payload(signing_key, &claims.to_string())
    }

    /// Signs the valid claim set with `name` removed entirely.
    fn token_without_claim(signing_key: &SigningKey, name: &str) -> String {
        let mut claims = valid_claims_value();
        claims
            .as_object_mut()
            .expect("claims are an object")
            .remove(name);
        sign_raw_payload(signing_key, &claims.to_string())
    }

    fn verifier_trusting(signing_key: &SigningKey) -> Verifier {
        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());
        verifier
    }

    #[test]
    fn verifier_starts_empty() {
        let verifier = Verifier::new();
        assert_eq!(verifier.trusted_root_count(), 0);
        assert!(!verifier.has_trusted_root("acme.com"));
    }

    #[test]
    fn add_trusted_root() {
        let mut verifier = Verifier::new();
        let signing_key = SigningKey::generate();

        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        assert_eq!(verifier.trusted_root_count(), 1);
        assert!(verifier.has_trusted_root("acme.com"));
        assert!(!verifier.has_trusted_root("other.com"));
    }

    /// Corrupts a token's payload so that its decoded bytes definitely change.
    ///
    /// Flipping the *last* base64 character is not enough: the final character of
    /// a base64url payload can carry "don't care" bits that decode to the same
    /// bytes, leaving the signature intact and the test passing by accident. A
    /// character in the middle of the payload always lands on a full 6-bit group.
    fn tamper(token: &str) -> String {
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        let payload = &mut parts[2];

        let midpoint = payload.len() / 2;
        let original = payload.as_bytes()[midpoint] as char;
        let replacement = if original == 'a' { 'b' } else { 'a' };
        payload.replace_range(midpoint..=midpoint, &replacement.to_string());

        parts.join(".")
    }

    /// Signs claims verbatim, so tests can mint tokens outside the validity window.
    fn issue_raw(signing_key: &SigningKey, claims: &AttestationClaims) -> String {
        Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1))
            .issue_claims(claims)
            .unwrap()
    }

    /// Claims for `acme.com`, with a caller-chosen validity window.
    fn claims_valid_for(
        iat: chrono::DateTime<Utc>,
        exp: chrono::DateTime<Utc>,
    ) -> AttestationClaims {
        AttestationClaims {
            agent_uri: test_uri().to_string(),
            agent_key: SigningKey::generate().verifying_key().to_base64(),
            capabilities: vec!["test".into()],
            iss: "acme.com".into(),
            iat,
            exp,
            aud: None,
        }
    }

    #[test]
    fn a_tampered_token_is_reported_as_an_invalid_signature() {
        // Regression: the failure was classified by substring-matching the PASETO
        // error text for "signature". The cipher error says "A paseto cipher error
        // occurred", so this arm never fired and every tampered token surfaced as
        // InvalidTokenFormat, sending callers hunting for a copy-paste error.
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let token = issuer
            .issue(
                &test_uri(),
                &SigningKey::generate().verifying_key(),
                vec!["test".into()],
            )
            .unwrap();

        let tampered = tamper(&token);

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        assert_eq!(
            verifier.verify(&tampered),
            Err(AttestationError::InvalidSignature)
        );
    }

    #[test]
    fn a_token_signed_by_another_key_is_reported_as_an_invalid_signature() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key, Duration::from_hours(1));
        let token = issuer
            .issue(
                &test_uri(),
                &SigningKey::generate().verifying_key(),
                vec!["test".into()],
            )
            .unwrap();

        // The right authority, but the wrong key registered for it.
        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", SigningKey::generate().verifying_key());

        assert_eq!(
            verifier.verify(&token),
            Err(AttestationError::InvalidSignature)
        );
    }

    #[test]
    fn a_malformed_token_is_reported_as_an_invalid_format() {
        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", SigningKey::generate().verifying_key());

        // Structurally not a token: nothing was verified because there was nothing
        // to verify, and that is a different problem from a bad signature.
        assert!(matches!(
            verifier.verify("not-a-token"),
            Err(AttestationError::InvalidTokenFormat { .. })
        ));
    }

    #[test]
    fn an_expired_token_reports_the_instant_it_expired() {
        // Regression: `expired_at` was always the literal string "unknown", so a
        // caller could say only "expired", never "expired at T".
        let signing_key = SigningKey::generate();
        let now = Utc::now();
        let expired_at = now - chrono::Duration::days(3);
        let claims = claims_valid_for(now - chrono::Duration::days(4), expired_at);

        let token = issue_raw(&signing_key, &claims);

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        match verifier.verify(&token) {
            Err(AttestationError::TokenExpired {
                expired_at: reported,
            }) => {
                assert_ne!(reported, "unknown", "the real instant must be carried");

                // It is the token's own exp, to the second, and it round-trips.
                let parsed = chrono::DateTime::parse_from_rfc3339(&reported)
                    .expect("expired_at must be RFC 3339")
                    .with_timezone(&Utc);
                assert_eq!(parsed.timestamp(), expired_at.timestamp());
            }
            other => panic!("expected TokenExpired, got {other:?}"),
        }
    }

    #[test]
    fn a_tampered_expired_token_is_a_signature_failure_first() {
        // Precedence matters: claims are only believed after they are
        // authenticated. An attacker must not be able to steer the error message
        // by forging an expiry, so the signature check comes first.
        let signing_key = SigningKey::generate();
        let now = Utc::now();
        let claims = claims_valid_for(
            now - chrono::Duration::days(4),
            now - chrono::Duration::days(3),
        );

        let tampered = tamper(&issue_raw(&signing_key, &claims));

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        assert_eq!(
            verifier.verify(&tampered),
            Err(AttestationError::InvalidSignature),
            "an unauthenticated payload's exp must never be reported"
        );
    }

    #[test]
    fn a_token_inside_its_window_still_verifies() {
        let signing_key = SigningKey::generate();
        let now = Utc::now();
        let claims = claims_valid_for(
            now - chrono::Duration::hours(1),
            now + chrono::Duration::hours(1),
        );

        let token = issue_raw(&signing_key, &claims);

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        assert!(verifier.verify(&token).is_ok());
    }

    #[test]
    fn verify_valid_token() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let uri = test_uri();

        let token = issuer
            .issue(
                &uri,
                &SigningKey::generate().verifying_key(),
                vec!["test".into()],
            )
            .unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let claims = verifier.verify(&token).unwrap();

        assert_eq!(claims.agent_uri, uri.to_string());
        assert_eq!(claims.iss, "acme.com");
        assert_eq!(claims.capabilities, vec!["test"]);
    }

    #[test]
    fn verify_rejects_untrusted_issuer() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("evil.com", signing_key.clone(), Duration::from_hours(1));
        let uri =
            AgentUri::parse("agent://evil.com/test/agent_01h455vb4pex5vsknk084sn02q").unwrap();

        let token = issuer
            .issue(&uri, &SigningKey::generate().verifying_key(), vec![])
            .unwrap();

        let mut verifier = Verifier::new();
        // Register key under different trust root
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let result = verifier.verify(&token);

        // Token signed by key we know, but issuer claim doesn't match
        assert!(matches!(
            result,
            Err(AttestationError::TrustRootMismatch { .. })
        ));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signing_key1 = SigningKey::generate();
        let signing_key2 = SigningKey::generate();

        let issuer = Issuer::new("acme.com", signing_key1, Duration::from_hours(1));
        let uri = test_uri();

        let token = issuer
            .issue(&uri, &SigningKey::generate().verifying_key(), vec![])
            .unwrap();

        let mut verifier = Verifier::new();
        // Register different key
        verifier.add_trusted_root("acme.com", signing_key2.verifying_key());

        let result = verifier.verify(&token);

        // The token is structurally sound; only the signature fails to check
        // out. Since errors are classified by cause, that is exactly
        // InvalidSignature, and accepting InvalidTokenFormat here would let a
        // structural regression pass unnoticed.
        assert!(
            matches!(result, Err(AttestationError::InvalidSignature)),
            "Expected InvalidSignature, got {result:?}",
        );
    }

    #[test]
    fn verify_for_uri_matches() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let uri = test_uri();

        let token = issuer
            .issue(&uri, &SigningKey::generate().verifying_key(), vec![])
            .unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let claims = verifier.verify_for_uri(&token, &uri).unwrap();

        assert_eq!(claims.agent_uri, uri.to_string());
    }

    #[test]
    fn verify_for_uri_rejects_mismatch() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let uri1 = test_uri();
        let uri2 =
            AgentUri::parse("agent://acme.com/other/agent_01h455vb4pex5vsknk084sn02q").unwrap();

        let token = issuer
            .issue(&uri1, &SigningKey::generate().verifying_key(), vec![])
            .unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let result = verifier.verify_for_uri(&token, &uri2);

        assert!(matches!(result, Err(AttestationError::UriMismatch { .. })));
    }

    #[test]
    fn verify_empty_verifier_returns_untrusted() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key, Duration::from_hours(1));
        let uri = test_uri();

        let token = issuer
            .issue(&uri, &SigningKey::generate().verifying_key(), vec![])
            .unwrap();

        let verifier = Verifier::new();

        let result = verifier.verify(&token);

        assert!(matches!(
            result,
            Err(AttestationError::UntrustedIssuer { .. })
        ));
    }

    #[test]
    fn verify_rejects_cross_root_issuance() {
        // A key trusted as authority "acme.com" mints an attestation for a URI
        // rooted at a *different* authority "evil.com". The issuer claim is
        // authentic (matches the registered trust root), but it does not own the
        // attested URI's namespace, so every verification path must reject it.
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));

        let foreign_uri =
            AgentUri::parse("agent://evil.com/test/agent_01h455vb4pex5vsknk084sn02q").unwrap();
        let token = issuer
            .issue(
                &foreign_uri,
                &SigningKey::generate().verifying_key(),
                vec!["test".into()],
            )
            .unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        // verify
        assert!(
            matches!(
                verifier.verify(&token),
                Err(AttestationError::IssuerNamespaceMismatch { .. })
            ),
            "verify should reject cross-root issuance"
        );

        // verify_for_uri (even when the caller's expected URI matches the token)
        assert!(
            matches!(
                verifier.verify_for_uri(&token, &foreign_uri),
                Err(AttestationError::IssuerNamespaceMismatch { .. })
            ),
            "verify_for_uri should reject cross-root issuance"
        );

        // verify_for_capability
        let required = CapabilityPath::parse("test").unwrap();
        assert!(
            matches!(
                verifier.verify_for_capability(&token, &foreign_uri, &required),
                Err(AttestationError::IssuerNamespaceMismatch { .. })
            ),
            "verify_for_capability should reject cross-root issuance"
        );
    }

    #[test]
    fn verify_for_capability_same_root_still_accepts() {
        // Regression: legitimate same-root attestations still verify end to end.
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let uri =
            AgentUri::parse("agent://acme.com/workflow/approval/agent_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        let token = issuer
            .issue(
                &uri,
                &SigningKey::generate().verifying_key(),
                vec!["workflow/approval".into()],
            )
            .unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let required = CapabilityPath::parse("workflow/approval").unwrap();

        assert!(verifier.verify(&token).is_ok());
        assert!(verifier.verify_for_uri(&token, &uri).is_ok());
        let claims = verifier
            .verify_for_capability(&token, &uri, &required)
            .unwrap();
        assert_eq!(claims.iss, "acme.com");
    }

    #[test]
    fn verify_rejects_unparseable_agent_uri() {
        // Fail closed: when the `agent_uri` claim has no parseable authority,
        // `trust_root()` is `None` and verification must reject rather than skip
        // the issuer/namespace binding.
        let result = AttestationClaims::builder()
            .agent_uri("not-an-agent-uri")
            .agent_key(&SigningKey::generate().verifying_key())
            .issuer("acme.com")
            .ttl(Duration::from_hours(1))
            .build();
        assert!(matches!(
            result,
            Err(AttestationError::InvalidClaims { .. })
        ));
    }

    #[test]
    fn audience_restricted_token_requires_matching_verifier() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let uri = test_uri();
        let claims = AttestationClaims::builder()
            .agent_uri(uri.canonical())
            .agent_key(&SigningKey::generate().verifying_key())
            .issuer("acme.com")
            .add_capability("test")
            .audience("api.globex.com")
            .build()
            .unwrap();
        let token = issuer.issue_claims(&claims).unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        assert!(matches!(
            verifier.verify(&token),
            Err(AttestationError::AudienceMismatch { .. })
        ));
        assert!(matches!(
            verifier.verify_for_audience(&token, "api.evil.com"),
            Err(AttestationError::AudienceMismatch { .. })
        ));
        assert!(
            verifier
                .verify_for_uri_and_audience(&token, &uri, "api.globex.com")
                .is_ok()
        );
    }

    #[test]
    fn broader_or_unrelated_capabilities_are_rejected() {
        let uri =
            AgentUri::parse("agent://acme.com/workflow/approval/agent_01h455vb4pex5vsknk084sn02q")
                .unwrap();

        for capability in ["workflow", "financial/payment", "workflow/review"] {
            let result = AttestationClaims::builder()
                .agent_uri(uri.canonical())
                .agent_key(&SigningKey::generate().verifying_key())
                .issuer("acme.com")
                .add_capability(capability)
                .build();
            assert!(matches!(
                result,
                Err(AttestationError::CapabilityOutsideIdentity { .. })
            ));
        }

        assert!(
            AttestationClaims::builder()
                .agent_uri(uri.canonical())
                .agent_key(&SigningKey::generate().verifying_key())
                .issuer("acme.com")
                .add_capability("workflow/approval/invoice")
                .build()
                .is_ok()
        );
    }

    #[test]
    fn verify_multiple_capabilities() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let uri = test_uri();

        let capabilities = vec![
            "test/read".to_string(),
            "test/write".to_string(),
            "test/admin".to_string(),
        ];
        let token = issuer
            .issue(
                &uri,
                &SigningKey::generate().verifying_key(),
                capabilities.clone(),
            )
            .unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let claims = verifier.verify(&token).unwrap();

        assert_eq!(claims.capabilities, capabilities);
    }

    /// Builds a syntactically plausible but oversized token.
    fn oversized_token() -> String {
        format!("v4.public.{}", "A".repeat(crate::MAX_TOKEN_LENGTH))
    }

    #[test]
    fn verify_rejects_oversized_token() {
        let signing_key = SigningKey::generate();
        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let token = oversized_token();
        match verifier.verify(&token) {
            Err(AttestationError::TokenTooLong { max, actual }) => {
                assert_eq!(max, crate::MAX_TOKEN_LENGTH);
                assert_eq!(actual, token.len());
            }
            other => panic!("Expected TokenTooLong, got {other:?}"),
        }
    }

    #[test]
    fn oversized_token_is_rejected_before_any_key_is_tried() {
        // Many trusted roots, none of which should be consulted: the length
        // check must short-circuit ahead of the O(trusted keys) signature loop.
        let mut verifier = Verifier::new();
        for index in 0..32 {
            verifier.add_trusted_root(
                format!("root{index}.com"),
                SigningKey::generate().verifying_key(),
            );
        }

        // A signature failure would report InvalidSignature; TokenTooLong proves
        // the loop never ran.
        assert!(matches!(
            verifier.verify(&oversized_token()),
            Err(AttestationError::TokenTooLong { .. })
        ));
    }

    #[test]
    fn oversized_token_is_rejected_even_with_no_trusted_roots() {
        let verifier = Verifier::new();

        assert!(matches!(
            verifier.verify(&oversized_token()),
            Err(AttestationError::TokenTooLong { .. })
        ));
    }

    #[test]
    fn a_valid_token_padded_past_the_cap_is_rejected() {
        let signing_key = SigningKey::generate();
        let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));
        let uri = test_uri();
        let token = issuer
            .issue(
                &uri,
                &SigningKey::generate().verifying_key(),
                vec!["test".into()],
            )
            .unwrap();

        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());
        assert!(verifier.verify(&token).is_ok());

        let padded = format!("{token}{}", "A".repeat(crate::MAX_TOKEN_LENGTH));
        assert!(matches!(
            verifier.verify(&padded),
            Err(AttestationError::TokenTooLong { .. })
        ));
    }

    #[test]
    fn every_verify_entry_point_enforces_the_cap() {
        let signing_key = SigningKey::generate();
        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let token = oversized_token();
        let uri = test_uri();
        let capability = CapabilityPath::parse("test/read").unwrap();

        let results = [
            verifier.verify(&token),
            verifier.verify_for_audience(&token, "verifier.example"),
            verifier.verify_for_uri(&token, &uri),
            verifier.verify_for_uri_and_audience(&token, &uri, "verifier.example"),
            verifier.verify_for_capability(&token, &uri, &capability),
            verifier.verify_for_capability_and_audience(
                &token,
                &uri,
                &capability,
                "verifier.example",
            ),
        ];

        for result in results {
            assert!(
                matches!(result, Err(AttestationError::TokenTooLong { .. })),
                "Expected TokenTooLong, got {result:?}",
            );
        }
    }

    #[test]
    fn token_at_the_cap_is_not_rejected_for_length() {
        let signing_key = SigningKey::generate();
        let mut verifier = Verifier::new();
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        let token = format!("v4.public.{}", "A".repeat(crate::MAX_TOKEN_LENGTH - 10));
        assert_eq!(token.len(), crate::MAX_TOKEN_LENGTH);

        // It is still garbage, so it must fail; just not on length grounds.
        assert!(!matches!(
            verifier.verify(&token),
            Err(AttestationError::TokenTooLong { .. })
        ));
    }

    #[test]
    fn raw_signed_token_with_valid_claims_verifies() {
        // Guards every test below: if the raw-signing helper produced something
        // the verifier rejects for its own reasons, the negative tests would
        // pass without exercising what they claim to.
        let signing_key = SigningKey::generate();
        let token = sign_raw_payload(&signing_key, &valid_claims_value().to_string());

        let claims = verifier_trusting(&signing_key).verify(&token).unwrap();

        assert_eq!(claims.iss, "acme.com");
        assert_eq!(claims.capabilities, vec!["test".to_string()]);
    }

    #[test]
    fn other_paseto_versions_and_purposes_are_rejected_as_malformed() {
        // Header confusion: a token for a different version or purpose must be
        // refused on shape, never routed into v4.public verification.
        let signing_key = SigningKey::generate();
        let verifier = verifier_trusting(&signing_key);
        let token = sign_raw_payload(&signing_key, &valid_claims_value().to_string());
        let body = token
            .strip_prefix("v4.public.")
            .expect("issued token carries the v4.public header");

        for header in [
            "v4.local",
            "v3.public",
            "v2.public",
            "v1.local",
            "v4.publik",
        ] {
            let confused = format!("{header}.{body}");
            let result = verifier.verify(&confused);
            assert!(
                matches!(result, Err(AttestationError::InvalidTokenFormat { .. })),
                "Expected InvalidTokenFormat for header '{header}', got {result:?}",
            );
        }
    }

    #[test]
    fn a_bare_payload_with_no_header_is_rejected_as_malformed() {
        let signing_key = SigningKey::generate();
        let token = sign_raw_payload(&signing_key, &valid_claims_value().to_string());
        let body = token.strip_prefix("v4.public.").unwrap().to_string();

        assert!(matches!(
            verifier_trusting(&signing_key).verify(&body),
            Err(AttestationError::InvalidTokenFormat { .. })
        ));
    }

    #[test]
    fn wrong_typed_claims_are_rejected_and_named_as_wrong_typed() {
        let signing_key = SigningKey::generate();
        let verifier = verifier_trusting(&signing_key);

        let cases = [
            ("exp", serde_json::json!(1_924_991_999_i64), "a number"),
            ("iss", serde_json::json!(["acme.com"]), "an array"),
            ("iat", serde_json::json!(true), "a boolean"),
            (
                "agent_uri",
                serde_json::json!({"uri": "agent://a/b/c"}),
                "an object",
            ),
        ];

        for (name, value, type_name) in cases {
            let token = token_with_claim(&signing_key, name, value);
            match verifier.verify(&token) {
                Err(AttestationError::InvalidClaims { reason }) => {
                    assert!(
                        reason.contains(name) && reason.contains(type_name),
                        "Expected '{name}' and '{type_name}' in reason, got: {reason}",
                    );
                    assert!(
                        !reason.contains("missing"),
                        "A wrong-typed '{name}' must not be reported as missing: {reason}",
                    );
                }
                other => panic!("Expected InvalidClaims for '{name}', got {other:?}"),
            }
        }
    }

    #[test]
    fn absent_claims_are_reported_as_missing() {
        let signing_key = SigningKey::generate();
        let verifier = verifier_trusting(&signing_key);

        for name in ["exp", "iss", "iat", "agent_uri", "agent_key"] {
            let token = token_without_claim(&signing_key, name);
            match verifier.verify(&token) {
                Err(AttestationError::InvalidClaims { reason }) => assert!(
                    reason.contains("missing") && reason.contains(name),
                    "Expected a missing-'{name}' reason, got: {reason}",
                ),
                other => panic!("Expected InvalidClaims for absent '{name}', got {other:?}"),
            }
        }
    }

    #[test]
    fn null_claims_read_as_absent() {
        let signing_key = SigningKey::generate();
        let token = token_with_claim(&signing_key, "iss", serde_json::Value::Null);

        match verifier_trusting(&signing_key).verify(&token) {
            Err(AttestationError::InvalidClaims { reason }) => {
                assert!(reason.contains("missing iss"), "got: {reason}");
            }
            other => panic!("Expected InvalidClaims, got {other:?}"),
        }
    }

    #[test]
    fn malformed_capabilities_is_distinct_from_absent_capabilities() {
        let signing_key = SigningKey::generate();
        let verifier = verifier_trusting(&signing_key);

        // Present but unreadable: the grant could not be parsed, which is not
        // the same as a token that granted nothing.
        for value in [
            serde_json::json!("test"),
            serde_json::json!(["test", 5]),
            serde_json::json!(42),
            serde_json::json!({"cap": "test"}),
        ] {
            let token = token_with_claim(&signing_key, "capabilities", value.clone());
            let result = verifier.verify(&token);
            assert!(
                matches!(result, Err(AttestationError::InvalidClaims { .. })),
                "Expected InvalidClaims for capabilities {value}, got {result:?}",
            );
        }

        // Absent: MissingField is the accurate report here, and it stays.
        let token = token_without_claim(&signing_key, "capabilities");
        assert!(matches!(
            verifier.verify(&token),
            Err(AttestationError::MissingField {
                field: "capabilities"
            })
        ));
    }

    #[test]
    fn a_wrong_typed_audience_does_not_widen_the_token() {
        // `aud` used to be read with `as_str()`, so a non-string silently read
        // as None — turning an audience-restricted token into one any verifier
        // would accept. It must fail closed instead.
        let signing_key = SigningKey::generate();
        let verifier = verifier_trusting(&signing_key);

        for value in [
            serde_json::json!(42),
            serde_json::json!(["api.acme.com"]),
            serde_json::json!(true),
        ] {
            let token = token_with_claim(&signing_key, "aud", value.clone());
            let result = verifier.verify(&token);
            assert!(
                matches!(result, Err(AttestationError::InvalidClaims { .. })),
                "Expected InvalidClaims for aud {value}, got {result:?}",
            );
        }
    }

    #[test]
    fn a_null_audience_leaves_the_token_unrestricted() {
        let signing_key = SigningKey::generate();
        let token = token_with_claim(&signing_key, "aud", serde_json::Value::Null);

        let claims = verifier_trusting(&signing_key).verify(&token).unwrap();

        assert_eq!(claims.aud, None);
    }

    #[test]
    fn an_unparseable_timestamp_is_named_as_a_format_fault() {
        let signing_key = SigningKey::generate();
        let token = token_with_claim(&signing_key, "exp", serde_json::json!("not-a-timestamp"));

        match verifier_trusting(&signing_key).verify(&token) {
            Err(AttestationError::InvalidClaims { reason }) => {
                assert!(reason.contains("invalid exp format"), "got: {reason}");
            }
            other => panic!("Expected InvalidClaims, got {other:?}"),
        }
    }

    /// Signs a token whose window is shifted by `offset` from now.
    fn token_dated(signing_key: &SigningKey, offset: chrono::Duration) -> String {
        let iat = Utc::now() + offset;
        let mut claims = valid_claims_value();
        claims["iat"] = serde_json::json!(iat.to_rfc3339());
        claims["exp"] = serde_json::json!((iat + chrono::Duration::hours(1)).to_rfc3339());
        sign_raw_payload(signing_key, &claims.to_string())
    }

    #[test]
    fn a_future_dated_token_is_rejected() {
        // Without a not-before check, a token dated into the future verifies
        // today and keeps verifying until its `exp` — an arbitrarily post-dated
        // credential.
        let signing_key = SigningKey::generate();
        let token = token_dated(&signing_key, chrono::Duration::hours(1));

        match verifier_trusting(&signing_key).verify(&token) {
            Err(AttestationError::TokenNotYetValid { valid_from }) => {
                assert!(!valid_from.is_empty());
            }
            other => panic!("Expected TokenNotYetValid, got {other:?}"),
        }
    }

    #[test]
    fn a_slightly_future_dated_token_is_tolerated_by_default() {
        // An issuer clock a few seconds ahead is the ordinary case, and must
        // not look like an attack.
        let signing_key = SigningKey::generate();
        let token = token_dated(&signing_key, chrono::Duration::seconds(10));

        assert!(verifier_trusting(&signing_key).verify(&token).is_ok());
    }

    #[test]
    fn zero_leeway_rejects_even_a_slightly_future_dated_token() {
        let signing_key = SigningKey::generate();
        let token = token_dated(&signing_key, chrono::Duration::seconds(10));

        let mut verifier = Verifier::with_leeway(Duration::ZERO);
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        assert!(matches!(
            verifier.verify(&token),
            Err(AttestationError::TokenNotYetValid { .. })
        ));
    }

    #[test]
    fn the_leeway_also_covers_a_just_expired_token() {
        let signing_key = SigningKey::generate();
        let mut claims = valid_claims_value();
        let expired_at = Utc::now() - chrono::Duration::seconds(10);
        claims["iat"] = serde_json::json!((expired_at - chrono::Duration::hours(1)).to_rfc3339());
        claims["exp"] = serde_json::json!(expired_at.to_rfc3339());
        let token = sign_raw_payload(&signing_key, &claims.to_string());

        // Default tolerance accepts it; exact comparison does not.
        assert!(verifier_trusting(&signing_key).verify(&token).is_ok());

        let mut strict = Verifier::with_leeway(Duration::ZERO);
        strict.add_trusted_root("acme.com", signing_key.verifying_key());
        assert!(matches!(
            strict.verify(&token),
            Err(AttestationError::TokenExpired { .. })
        ));
    }

    #[test]
    fn leeway_defaults_and_round_trips() {
        assert_eq!(Verifier::new().leeway(), Verifier::DEFAULT_LEEWAY);
        assert!(Verifier::DEFAULT_LEEWAY > Duration::ZERO);
        assert_eq!(
            Verifier::with_leeway(Duration::from_secs(5)).leeway(),
            Duration::from_secs(5)
        );

        let mut verifier = Verifier::new();
        verifier.set_leeway(Duration::ZERO);
        assert_eq!(verifier.leeway(), Duration::ZERO);
    }

    #[test]
    fn an_absurd_leeway_does_not_panic() {
        // `chrono::Duration` cannot represent every `std::time::Duration`, so
        // the conversion has to saturate rather than unwrap.
        let signing_key = SigningKey::generate();
        let token = token_dated(&signing_key, chrono::Duration::hours(1));

        let mut verifier = Verifier::with_leeway(Duration::MAX);
        verifier.add_trusted_root("acme.com", signing_key.verifying_key());

        assert!(verifier.verify(&token).is_ok());
    }

    #[test]
    fn every_verify_entry_point_enforces_the_validity_window() {
        let signing_key = SigningKey::generate();
        let verifier = verifier_trusting(&signing_key);
        let token = token_dated(&signing_key, chrono::Duration::hours(1));
        let uri = test_uri();
        let capability = CapabilityPath::parse("test").unwrap();

        let results = [
            verifier.verify(&token),
            verifier.verify_for_audience(&token, "verifier.example"),
            verifier.verify_for_uri(&token, &uri),
            verifier.verify_for_uri_and_audience(&token, &uri, "verifier.example"),
            verifier.verify_for_capability(&token, &uri, &capability),
            verifier.verify_for_capability_and_audience(
                &token,
                &uri,
                &capability,
                "verifier.example",
            ),
        ];

        for result in results {
            assert!(
                matches!(result, Err(AttestationError::TokenNotYetValid { .. })),
                "Expected TokenNotYetValid, got {result:?}",
            );
        }
    }
}
