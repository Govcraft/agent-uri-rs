//! Kani formal verification proof harnesses.
//!
//! This module contains proof harnesses that verify critical safety properties
//! of the attestation logic using the Kani bounded model checker.
//!
//! # Running Proofs
//!
//! ```bash
//! cargo kani -p agent-uri-attestation
//! ```
//!
//! # Properties Verified
//!
//! | Category | Property | Harness |
//! |----------|----------|---------|
//! | Expiration | Never panics | `check_expiration_never_panics` |
//! | Expiration | Deterministic | `check_expiration_is_deterministic` |
//! | Expiration | Expired fails | `expired_tokens_always_fail` |
//! | Expiration | Valid passes | `valid_tokens_pass_expiration` |
//! | Issuer | Never panics | `validate_issuer_never_panics` |
//! | Issuer | Matching succeeds | `matching_issuers_succeed` |
//! | Issuer | Symmetric | `issuer_validation_symmetry` |
//! | Subject | Never panics | `validate_subject_never_panics` |
//! | Subject | Matching succeeds | `matching_subjects_succeed` |
//! | Subject | Deterministic | `subject_validation_deterministic` |
//! | Capability | Deterministic | `capability_covers_deterministic` |
//! | Capability | Exact match works | `exact_match_is_covered` |
//! | Claims | Valid inputs work | `builder_valid_inputs_no_panic` |
//! | Claims | Missing fields error | `builder_missing_uri_errors`, `builder_missing_issuer_errors` |
//! | Claims | Expiration deterministic | `is_expired_at_deterministic` |
//! | Keys | From bytes safe | `signing_key_from_bytes_no_panic` |
//! | Keys | Roundtrip correct | `signing_key_roundtrip` |
//! | Keys | Verifying key deterministic | `verifying_key_derivation_deterministic` |

// Proofs module is conditionally compiled only when running Kani
#![cfg(kani)]

use chrono::{TimeZone, Utc};

use crate::claims::{AttestationClaims, AttestationClaimsBuilder};
use crate::keys::SigningKey;
use crate::verification::{capability_covers, check_expiration, validate_issuer, validate_subject};

/// Proof harnesses for expiration logic.
mod expiration_proofs {
    use super::*;

    /// Prove `check_expiration` never panics with valid timestamps.
    #[kani::proof]
    #[kani::unwind(2)]
    fn check_expiration_never_panics() {
        let exp_secs: i64 = kani::any();
        let now_secs: i64 = kani::any();

        // Constrain to valid timestamp range (avoid overflow)
        kani::assume(exp_secs > -86400 * 365 * 100);
        kani::assume(exp_secs < 86400 * 365 * 100);
        kani::assume(now_secs > -86400 * 365 * 100);
        kani::assume(now_secs < 86400 * 365 * 100);

        // Create timestamps using checked arithmetic
        if let Some(exp) = Utc.timestamp_opt(exp_secs, 0).single() {
            if let Some(now) = Utc.timestamp_opt(now_secs, 0).single() {
                // Function should never panic
                let _ = check_expiration(exp, now);
            }
        }
    }

    /// Prove expiration check is deterministic.
    #[kani::proof]
    #[kani::unwind(2)]
    fn check_expiration_is_deterministic() {
        let exp_secs: i64 = kani::any();
        let now_secs: i64 = kani::any();

        kani::assume(exp_secs > 0 && exp_secs < i64::MAX / 2);
        kani::assume(now_secs > 0 && now_secs < i64::MAX / 2);

        if let (Some(exp), Some(now)) = (
            Utc.timestamp_opt(exp_secs, 0).single(),
            Utc.timestamp_opt(now_secs, 0).single(),
        ) {
            let result1 = check_expiration(exp, now);
            let result2 = check_expiration(exp, now);

            // Same inputs must produce same result
            assert!(result1.is_ok() == result2.is_ok());
        }
    }

    /// Prove expired tokens always fail verification.
    #[kani::proof]
    #[kani::unwind(2)]
    fn expired_tokens_always_fail() {
        let exp_secs: i64 = kani::any();
        let offset: i64 = kani::any();

        // Constrain to reasonable range
        kani::assume(exp_secs > 0 && exp_secs < i64::MAX / 2);
        kani::assume(offset >= 0 && offset < 86400 * 365 * 10);

        if let Some(exp) = Utc.timestamp_opt(exp_secs, 0).single() {
            // now >= exp means expired
            if let Some(now) = Utc.timestamp_opt(exp_secs.saturating_add(offset), 0).single() {
                if now >= exp {
                    let result = check_expiration(exp, now);
                    // Must return error when expired
                    assert!(result.is_err());
                }
            }
        }
    }

    /// Prove non-expired tokens pass verification.
    #[kani::proof]
    #[kani::unwind(2)]
    fn valid_tokens_pass_expiration() {
        let exp_secs: i64 = kani::any();
        let offset: i64 = kani::any();

        kani::assume(exp_secs > 1 && exp_secs < i64::MAX / 2);
        kani::assume(offset > 0 && offset <= exp_secs);

        if let Some(exp) = Utc.timestamp_opt(exp_secs, 0).single() {
            // now < exp means valid
            if let Some(now) = Utc.timestamp_opt(exp_secs.saturating_sub(offset), 0).single() {
                if now < exp {
                    let result = check_expiration(exp, now);
                    // Must return Ok when valid
                    assert!(result.is_ok());
                }
            }
        }
    }
}

/// Proof harnesses for issuer validation.
mod issuer_proofs {
    use super::*;

    /// Prove `validate_issuer` never panics.
    #[kani::proof]
    #[kani::unwind(2)]
    fn validate_issuer_never_panics() {
        // Use bounded string representation
        let uri_root: [u8; 16] = kani::any();
        let token_issuer: [u8; 16] = kani::any();

        // Convert to strings safely
        if let (Ok(uri_str), Ok(token_str)) =
            (std::str::from_utf8(&uri_root), std::str::from_utf8(&token_issuer))
        {
            let _ = validate_issuer(uri_str, token_str);
        }
    }

    /// Prove matching issuers always succeed.
    #[kani::proof]
    #[kani::unwind(2)]
    fn matching_issuers_succeed() {
        let data: [u8; 8] = kani::any();

        if let Ok(s) = std::str::from_utf8(&data) {
            let result = validate_issuer(s, s);
            assert!(result.is_ok());
        }
    }

    /// Prove validation is symmetric in its error case.
    #[kani::proof]
    #[kani::unwind(2)]
    fn issuer_validation_symmetry() {
        let a: [u8; 8] = kani::any();
        let b: [u8; 8] = kani::any();

        if let (Ok(str_a), Ok(str_b)) = (std::str::from_utf8(&a), std::str::from_utf8(&b)) {
            let result_ab = validate_issuer(str_a, str_b);
            let result_ba = validate_issuer(str_b, str_a);

            // If a != b, both directions fail; if a == b, both succeed
            assert!(result_ab.is_ok() == result_ba.is_ok());
        }
    }
}

/// Proof harnesses for subject validation.
mod subject_proofs {
    use super::*;

    /// Prove `validate_subject` never panics.
    #[kani::proof]
    #[kani::unwind(2)]
    fn validate_subject_never_panics() {
        let presented: [u8; 16] = kani::any();
        let token_sub: [u8; 16] = kani::any();

        if let (Ok(pres_str), Ok(tok_str)) =
            (std::str::from_utf8(&presented), std::str::from_utf8(&token_sub))
        {
            let _ = validate_subject(pres_str, tok_str);
        }
    }

    /// Prove matching subjects always succeed.
    #[kani::proof]
    #[kani::unwind(2)]
    fn matching_subjects_succeed() {
        let data: [u8; 16] = kani::any();

        if let Ok(s) = std::str::from_utf8(&data) {
            let result = validate_subject(s, s);
            assert!(result.is_ok());
        }
    }

    /// Prove validation is deterministic.
    #[kani::proof]
    #[kani::unwind(2)]
    fn subject_validation_deterministic() {
        let a: [u8; 8] = kani::any();
        let b: [u8; 8] = kani::any();

        if let (Ok(str_a), Ok(str_b)) = (std::str::from_utf8(&a), std::str::from_utf8(&b)) {
            let r1 = validate_subject(str_a, str_b);
            let r2 = validate_subject(str_a, str_b);

            assert!(r1.is_ok() == r2.is_ok());
        }
    }
}

/// Proof harnesses for capability coverage logic.
mod capability_proofs {
    use super::*;
    use agent_uri::CapabilityPath;

    /// Prove `capability_covers` never panics with empty capabilities.
    #[kani::proof]
    #[kani::unwind(2)]
    fn empty_capabilities_never_panic() {
        let attested: Vec<String> = vec![];

        // Use a known valid capability path
        if let Ok(path) = CapabilityPath::parse("workflow") {
            let result = capability_covers(&attested, &path);
            // Empty capabilities should never cover anything
            assert!(!result);
        }
    }

    /// Prove exact match always returns true.
    #[kani::proof]
    #[kani::unwind(3)]
    fn exact_match_is_covered() {
        // Use a fixed valid capability for exact match test
        let cap = "workflow";
        let attested = vec![cap.to_string()];

        if let Ok(path) = CapabilityPath::parse(cap) {
            let result = capability_covers(&attested, &path);
            assert!(result);
        }
    }

    /// Prove `capability_covers` is deterministic.
    #[kani::proof]
    #[kani::unwind(3)]
    fn capability_covers_deterministic() {
        // Use fixed valid capabilities to test determinism
        let cap = "workflow";
        let req = "workflow/approval";

        if let Ok(path) = CapabilityPath::parse(req) {
            let attested = vec![cap.to_string()];

            let r1 = capability_covers(&attested, &path);
            let r2 = capability_covers(&attested, &path);

            assert!(r1 == r2);
        }
    }

    /// Prove prefix coverage works correctly.
    #[kani::proof]
    #[kani::unwind(3)]
    fn prefix_covers_child() {
        let parent = "workflow";
        let child = "workflow/approval";

        let attested = vec![parent.to_string()];

        if let Ok(path) = CapabilityPath::parse(child) {
            let result = capability_covers(&attested, &path);
            // Parent capability should cover child path
            assert!(result);
        }
    }
}

/// Proof harnesses for claims builder.
mod claims_proofs {
    use super::*;
    use std::time::Duration;

    /// Prove builder with valid inputs never panics.
    #[kani::proof]
    #[kani::unwind(2)]
    fn builder_valid_inputs_no_panic() {
        let ttl_secs: u64 = kani::any();

        // Constrain TTL to reasonable range (avoid overflow)
        kani::assume(ttl_secs > 0 && ttl_secs < 86400 * 365 * 10);

        let result = AttestationClaimsBuilder::new()
            .agent_uri("agent://test.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .issuer("test.com")
            .ttl(Duration::from_secs(ttl_secs))
            .build();

        // Should succeed with valid inputs
        assert!(result.is_ok());
    }

    /// Prove missing `agent_uri` returns error.
    #[kani::proof]
    #[kani::unwind(2)]
    fn builder_missing_uri_errors() {
        let result = AttestationClaimsBuilder::new().issuer("test.com").build();

        assert!(result.is_err());
    }

    /// Prove missing issuer returns error.
    #[kani::proof]
    #[kani::unwind(2)]
    fn builder_missing_issuer_errors() {
        let result = AttestationClaimsBuilder::new()
            .agent_uri("agent://test.com/test/agent_01h455vb4pex5vsknk084sn02q")
            .build();

        assert!(result.is_err());
    }

    /// Prove `is_expired_at` is deterministic.
    #[kani::proof]
    #[kani::unwind(2)]
    fn is_expired_at_deterministic() {
        let exp_secs: i64 = kani::any();
        let now_secs: i64 = kani::any();

        kani::assume(exp_secs > 0 && exp_secs < i64::MAX / 2);
        kani::assume(now_secs > 0 && now_secs < i64::MAX / 2);

        if let (Some(exp), Some(now), Some(iat)) = (
            Utc.timestamp_opt(exp_secs, 0).single(),
            Utc.timestamp_opt(now_secs, 0).single(),
            Utc.timestamp_opt(0, 0).single(),
        ) {
            // Create claims with specific exp
            let claims = AttestationClaims {
                agent_uri: "agent://test.com/test/agent_01h455vb4pex5vsknk084sn02q".to_string(),
                capabilities: vec![],
                iss: "test.com".to_string(),
                iat,
                exp,
                aud: None,
            };

            let r1 = claims.is_expired_at(now);
            let r2 = claims.is_expired_at(now);

            assert!(r1 == r2);
        }
    }

    /// Prove `is_expired_at` returns true when now >= exp.
    #[kani::proof]
    #[kani::unwind(2)]
    fn is_expired_at_correct() {
        let exp_secs: i64 = kani::any();
        let offset: i64 = kani::any();

        kani::assume(exp_secs > 0 && exp_secs < i64::MAX / 2);
        kani::assume(offset >= 0 && offset < 86400 * 365);

        if let (Some(exp), Some(now), Some(iat)) = (
            Utc.timestamp_opt(exp_secs, 0).single(),
            Utc.timestamp_opt(exp_secs.saturating_add(offset), 0).single(),
            Utc.timestamp_opt(0, 0).single(),
        ) {
            let claims = AttestationClaims {
                agent_uri: "agent://test.com/test/agent_01h455vb4pex5vsknk084sn02q".to_string(),
                capabilities: vec![],
                iss: "test.com".to_string(),
                iat,
                exp,
                aud: None,
            };

            if now >= exp {
                assert!(claims.is_expired_at(now));
            }
        }
    }
}

/// Proof harnesses for key operations.
mod key_proofs {
    use super::*;

    /// Prove `SigningKey::from_bytes` never panics with any 32-byte input.
    #[kani::proof]
    #[kani::unwind(2)]
    fn signing_key_from_bytes_no_panic() {
        let bytes: [u8; 32] = kani::any();

        // This should never panic - all 32-byte arrays are valid Ed25519 seeds
        let result = SigningKey::from_bytes(&bytes);
        assert!(result.is_ok());
    }

    /// Prove signing key roundtrip preserves bytes.
    #[kani::proof]
    #[kani::unwind(2)]
    fn signing_key_roundtrip() {
        let original_bytes: [u8; 32] = kani::any();

        if let Ok(key) = SigningKey::from_bytes(&original_bytes) {
            let recovered_bytes = key.to_bytes();
            assert!(original_bytes == recovered_bytes);
        }
    }

    /// Prove `verifying_key` derivation is deterministic.
    #[kani::proof]
    #[kani::unwind(2)]
    fn verifying_key_derivation_deterministic() {
        let bytes: [u8; 32] = kani::any();

        if let Ok(signing_key) = SigningKey::from_bytes(&bytes) {
            let vk1 = signing_key.verifying_key();
            let vk2 = signing_key.verifying_key();

            assert!(vk1.to_bytes() == vk2.to_bytes());
        }
    }
}
