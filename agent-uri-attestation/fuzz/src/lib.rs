//! The verifier both fuzz targets run against, and the keys it trusts.
//!
//! Every key here is derived from a fixed seed rather than generated. A fuzz
//! run has to be reproducible from its corpus alone: with `SigningKey::generate`
//! a crashing input would depend on keys that no longer exist by the time
//! anyone tries to reproduce it.
//!
//! This is a library rather than a module included into each target, so that
//! what one target uses and the other does not is still compiled once and is
//! not dead code in either.

use agent_uri_attestation::{AcceptAll, SigningKey, TrustedKey, Verifier};

/// The trust root whose keys the verifier holds.
pub const TRUSTED_ROOT: &str = "acme.com";

/// A second trusted root, so a token can name the wrong one of two.
pub const OTHER_ROOT: &str = "other.com";

/// The key `TRUSTED_ROOT` is rotating away from, and the one it is rotating to.
///
/// Two keys under one root means the verifier's trial-verification loop is
/// exercised rather than short-circuited on the first key it holds.
#[must_use]
pub fn trusted_signers() -> [SigningKey; 2] {
    [signer(1), signer(2)]
}

/// A key no verifier here trusts. Anything it signs must be refused.
#[must_use]
pub fn untrusted_signer() -> SigningKey {
    signer(9)
}

/// A key derived from a fixed seed byte.
#[must_use]
pub fn signer(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32]).expect("a fixed 32-byte seed is a valid Ed25519 key")
}

/// A verifier holding two keys for one root and one for another.
///
/// `AcceptAll` because revocation is not what these targets are probing, and a
/// verifier without a revocation source refuses everything before it decodes a
/// byte — which would make the run measure nothing.
#[must_use]
pub fn verifier() -> Verifier {
    let mut verifier = Verifier::new().with_revocation(AcceptAll);
    let [outgoing, incoming] = trusted_signers();

    verifier.add_trusted_key(
        TRUSTED_ROOT,
        TrustedKey::new(outgoing.verifying_key()).with_id("outgoing"),
    );
    verifier.add_trusted_key(
        TRUSTED_ROOT,
        TrustedKey::new(incoming.verifying_key()).with_id("incoming"),
    );
    verifier.add_trusted_root(OTHER_ROOT, signer(3).verifying_key());

    verifier
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use agent_uri::AgentUri;
    use agent_uri_attestation::Issuer;

    /// A harness that accepts nothing would let a fuzz run report success
    /// having exercised only the refusal path. This is the check that the
    /// targets are aimed at something.
    #[test]
    fn the_harness_verifier_accepts_a_genuinely_issued_token() {
        for signing_key in trusted_signers() {
            let issuer = Issuer::new(TRUSTED_ROOT, signing_key, Duration::from_secs(3600));
            let uri = AgentUri::parse(&format!(
                "agent://{TRUSTED_ROOT}/test/llm_01h455vb4pex5vsknk084sn02q"
            ))
            .expect("the fixed URI is valid");
            let token = issuer
                .issue(&uri, &signer(7).verifying_key(), vec!["test".into()])
                .expect("the fixed claims mint");

            verifier()
                .verify(&token)
                .expect("a token from a trusted key must verify");
        }
    }

    #[test]
    fn the_untrusted_signer_is_not_one_of_the_trusted_ones() {
        let untrusted = untrusted_signer().verifying_key();

        for trusted in trusted_signers() {
            assert_ne!(trusted.verifying_key(), untrusted);
        }
        assert_ne!(signer(3).verifying_key(), untrusted);
    }
}
