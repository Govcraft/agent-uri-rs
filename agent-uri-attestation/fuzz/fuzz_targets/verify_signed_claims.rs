//! Fuzzes what the verifier does *after* the signature checks out.
//!
//! `verify_token` cannot reach this code. An arbitrary string never gets past
//! Ed25519, so the claim parsing, the URI parsing, the capability scoping, the
//! key decoding, and the audience comparison are all downstream of a gate the
//! fuzzer cannot open. This target opens it by signing the payload with a key
//! the verifier trusts, and then asks the same question of everything behind
//! it: does it return, and when it accepts, was it entitled to.
//!
//! That is not a weaker threat model than it sounds. A trust root signs what it
//! is asked to sign, its signer may be a different program from this one, and a
//! compromised or merely buggy issuer produces exactly this: authentic
//! signatures over claims nobody sane would mint.
//!
//! Payloads are built and signed directly rather than through [`Issuer`], which
//! validates capability scope and the agent key before it will mint anything.
//! Going through it would mean fuzzing the verifier only with claims the issuer
//! already approved, which is the half that was never in question.
//!
//! [`Issuer`]: agent_uri_attestation::Issuer

#![no_main]

use agent_uri_attestation::{AttestationError, SigningKey, validate_capability_scope};
use agent_uri_attestation_fuzz as harness;
use arbitrary::Arbitrary;
use chrono::{DateTime, Duration, Utc};
use libfuzzer_sys::fuzz_target;
use rusty_paseto::core::{Key, Paseto, PasetoAsymmetricPrivateKey, Payload, Public, V4};
use serde_json::{Map, Value, json};

/// Which claim each bit of `omit` drops.
///
/// Dropping claims is the interesting half: a verifier that reads a claim it
/// was never given, or that treats an absent claim as an empty one, fails open.
const OMITTABLE: [&str; 8] = [
    "jti",
    "agent_uri",
    "agent_key",
    "capabilities",
    "iss",
    "iat",
    "exp",
    "aud",
];

/// A URI rooted at [`harness::TRUSTED_ROOT`], for the `plausible` flags below.
const PLAUSIBLE_URI: &str = "agent://acme.com/test/llm_01h455vb4pex5vsknk084sn02q";

/// The capability path of [`PLAUSIBLE_URI`], which is what its token may attest.
const PLAUSIBLE_CAPABILITY: &str = "test";

#[derive(Debug, Arbitrary)]
struct FuzzClaims<'a> {
    jti: &'a str,
    agent_uri: &'a str,
    agent_key: &'a str,
    capabilities: Vec<&'a str>,
    iss: &'a str,
    iat_millis: i64,
    exp_millis: i64,
    aud: Option<&'a str>,
    /// One bit per entry of [`OMITTABLE`]: set means leave that claim out.
    omit: u8,
    /// Sign with a key the verifier does not hold.
    forge: bool,
    /// The audience the verifier is asked to accept for, if any.
    verifier_audience: Option<&'a str>,
    /// Which claims to replace with values that would actually pass.
    ///
    /// Without these the target measures almost nothing past `extract_claims`:
    /// random bytes will not spell a parseable agent URI whose authority equals
    /// a trusted root, let alone one with base64 that decodes to an Ed25519 key
    /// and a validity window containing now. Every check after the first one
    /// that fails is then unreachable, and the deep half of the verifier — the
    /// half worth fuzzing — never runs.
    ///
    /// Each flag hands one of those back, so the fuzzer can walk inwards a
    /// check at a time and, with all of them set, produce a token that must be
    /// accepted.
    plausible: Plausible,
}

/// Which parts of a token to make well-formed rather than arbitrary.
#[derive(Debug, Arbitrary)]
struct Plausible {
    iss: bool,
    agent_uri: bool,
    agent_key: bool,
    capabilities: bool,
    window: bool,
}

impl Plausible {
    /// True when nothing is left arbitrary, so the token should verify.
    fn all(&self) -> bool {
        self.iss && self.agent_uri && self.agent_key && self.capabilities && self.window
    }
}

fuzz_target!(|input: FuzzClaims<'_>| {
    let payload = build_payload(&input);
    let signer = if input.forge {
        harness::untrusted_signer()
    } else {
        // The outgoing key of the pair, so the verifier has to find it rather
        // than match the first key it holds.
        harness::trusted_signers()[0].clone()
    };
    let token = sign(&signer, &payload);

    let verifier = harness::verifier();
    let verified = match input.verifier_audience {
        Some(audience) => verifier.verify_for_audience(&token, audience),
        None => verifier.verify(&token),
    };

    // The other direction, and the one a panic-only target cannot see: when
    // nothing is left arbitrary the token is exactly what an honest issuer
    // would mint, and refusing it is as much a defect as accepting a forgery.
    let should_verify = !input.forge
        && input.omit == 0
        && input.plausible.all()
        && input.aud.is_none() == input.verifier_audience.is_none()
        && input
            .aud
            .zip(input.verifier_audience)
            .is_none_or(|(a, b)| a == b);

    let claims = match verified {
        Ok(claims) => claims,
        Err(error) => {
            assert!(
                !should_verify,
                "refused a token an honest issuer would mint: {error}"
            );
            // Beyond that, only that it returned: which refusal is the
            // verifier's business, and pinning one here would turn every
            // reordering of the checks into a spurious crash.
            let _ = error.to_string();
            return;
        }
    };

    assert!(
        !input.forge,
        "a token signed by an untrusted key was accepted"
    );

    // Everything below is a property the verifier's own documentation claims
    // holds of anything it returns. A fuzzer that only asked "did it panic"
    // would miss an accept that should have been a refusal, which is the more
    // dangerous of the two failures.
    assert_eq!(
        claims.trust_root(),
        Some(claims.iss.as_str()),
        "accepted a token whose issuer does not own the URI's namespace"
    );
    assert!(
        claims.iss == harness::TRUSTED_ROOT || claims.iss == harness::OTHER_ROOT,
        "accepted a token from an issuer that is not trusted: {}",
        claims.iss
    );
    assert!(
        claims.agent_verifying_key().is_ok(),
        "accepted a token whose agent_key does not decode, restoring bearer semantics"
    );
    assert!(
        validate_capability_scope(&claims.agent_uri, &claims.capabilities).is_ok(),
        "accepted capabilities outside the subject URI's identity scope"
    );
    if let Some(audience) = claims.aud.as_deref() {
        assert_eq!(
            Some(audience),
            input.verifier_audience,
            "accepted an audience-restricted token for the wrong audience"
        );
    }

    // The claims round-trip through the crate's own error type without
    // panicking on anything the payload smuggled in.
    let _ = AttestationError::InvalidClaims {
        reason: claims.agent_uri.clone(),
    }
    .to_string();
});

/// Renders the fuzzer's claims as the JSON a PASETO payload carries.
fn build_payload(input: &FuzzClaims<'_>) -> String {
    let now = Utc::now();
    let mut claims = Map::new();

    claims.insert("jti".into(), json!(input.jti));
    claims.insert(
        "agent_uri".into(),
        if input.plausible.agent_uri {
            json!(PLAUSIBLE_URI)
        } else {
            json!(input.agent_uri)
        },
    );
    claims.insert(
        "agent_key".into(),
        if input.plausible.agent_key {
            json!(harness::signer(7).verifying_key().to_base64())
        } else {
            json!(input.agent_key)
        },
    );
    claims.insert(
        "capabilities".into(),
        if input.plausible.capabilities {
            json!([PLAUSIBLE_CAPABILITY])
        } else {
            json!(input.capabilities)
        },
    );
    claims.insert(
        "iss".into(),
        if input.plausible.iss {
            json!(harness::TRUSTED_ROOT)
        } else {
            json!(input.iss)
        },
    );

    let (iat, exp) = if input.plausible.window {
        (
            rfc3339(now - Duration::minutes(1)),
            rfc3339(now + Duration::hours(1)),
        )
    } else {
        (timestamp(input.iat_millis), timestamp(input.exp_millis))
    };
    claims.insert("iat".into(), json!(iat));
    claims.insert("exp".into(), json!(exp));

    if let Some(aud) = input.aud {
        claims.insert("aud".into(), json!(aud));
    }

    for (bit, name) in OMITTABLE.iter().enumerate() {
        if input.omit & (1 << bit) != 0 {
            claims.remove(*name);
        }
    }

    Value::Object(claims).to_string()
}

/// An RFC 3339 instant, or a string that is not one.
///
/// Out-of-range millisecond counts are the fuzzer asking what happens to a
/// timestamp claim that does not parse, which is a question worth answering
/// rather than skipping.
fn timestamp(millis: i64) -> String {
    DateTime::from_timestamp_millis(millis)
        .map_or_else(|| format!("not-a-timestamp-{millis}"), rfc3339)
}

/// The timestamp format the issuer writes, so the verifier reads what it writes.
fn rfc3339(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Signs a payload verbatim, with no validation of what it says.
fn sign(signing_key: &SigningKey, payload: &str) -> String {
    let mut key_bytes = [0u8; 64];
    key_bytes[..32].copy_from_slice(&signing_key.to_bytes());
    key_bytes[32..].copy_from_slice(&signing_key.verifying_key().to_bytes());

    let key_wrapper = Key::<64>::from(&key_bytes);
    let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::from(&key_wrapper);

    Paseto::<V4, Public>::builder()
        .set_payload(Payload::from(payload))
        .try_sign(&private_key)
        .expect("a well-formed payload signs")
}
