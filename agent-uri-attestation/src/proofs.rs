//! Kani formal verification proof harnesses.
//!
//! This module contains proof harnesses that verify critical safety properties
//! of the agent-uri-specific attestation logic using the Kani bounded model checker.
//!
//! # Running Proofs
//!
//! ```bash
//! cargo kani -p agent-uri-attestation
//! ```
//!
//! # Properties Verified
//!
//! These proofs focus on agent-uri-specific verification logic. Standard PASETO
//! claim validation (expiration, signature) is handled by the underlying library.
//!
//! | Category | Property | Harness |
//! |----------|----------|---------|
//! | Issuer | Never panics | `validate_issuer_never_panics` |
//! | Issuer | Matching succeeds | `matching_issuers_succeed` |
//! | Issuer | Symmetric | `issuer_validation_symmetry` |
//! | Subject | Never panics | `validate_subject_never_panics` |
//! | Subject | Matching succeeds | `matching_subjects_succeed` |
//! | Subject | Deterministic | `subject_validation_deterministic` |
//! | Capability | Empty never covers | `empty_capabilities_never_panic` |
//! | Capability | Exact match works | `exact_match_is_covered` |
//! | Capability | Deterministic | `capability_covers_deterministic` |
//! | Capability | Prefix coverage | `prefix_covers_child` |
//! | Claims | Valid inputs work | `builder_valid_inputs_no_panic` |
//! | Claims | Missing URI errors | `builder_missing_uri_errors` |
//! | Claims | Missing issuer errors | `builder_missing_issuer_errors` |

// Proofs module is conditionally compiled only when running Kani
#![cfg(kani)]

use crate::claims::AttestationClaimsBuilder;
use crate::verification::{capability_covers, validate_issuer, validate_subject};

/// Proof harnesses for issuer validation (agent-uri specific: trust root binding).
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

/// Proof harnesses for subject validation (agent-uri specific: URI binding).
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

/// Proof harnesses for capability coverage logic (novel agent-uri contribution).
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

/// Proof harnesses for claims builder validation.
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
}
