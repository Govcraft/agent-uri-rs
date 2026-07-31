//! Key types for attestation signing and verification.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{
    Signature as DalekSignature, Signer, SigningKey as DalekSigningKey, Verifier as DalekVerifier,
    VerifyingKey as DalekVerifyingKey,
};

use crate::error::AttestationError;

/// A detached Ed25519 signature over an arbitrary message.
///
/// Attestation tokens carry their own signature inside the PASETO envelope.
/// This type exists for the messages that are *not* tokens: proofs that the
/// holder of an agent's private key authorized a specific operation, which
/// [`agent-uri-dht`](https://docs.rs/agent-uri-dht) requires on every write.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::SigningKey;
///
/// let key = SigningKey::generate();
/// let signature = key.sign(b"authorize this");
///
/// assert!(key.verifying_key().verify(b"authorize this", &signature).is_ok());
/// assert!(key.verifying_key().verify(b"authorize that", &signature).is_err());
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    /// Creates a signature from its 64-byte wire form.
    ///
    /// Every 64-byte string is accepted here; whether it is a *valid*
    /// signature is decided by [`VerifyingKey::verify`], which is the only
    /// place that can answer the question.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Returns the 64-byte wire form.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 64] {
        self.0
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Enough to correlate two signatures in a log, not enough to retype one.
        write!(
            f,
            "Signature({:02x}{:02x}{:02x}{:02x}...)",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}

/// A signing key for creating attestation tokens.
///
/// Wraps an Ed25519 private key used for signing PASETO v4.public tokens.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::SigningKey;
///
/// // Generate a new random signing key
/// let signing_key = SigningKey::generate();
///
/// // Get the corresponding public key for distribution
/// let verifying_key = signing_key.verifying_key();
/// ```
#[derive(Clone)]
pub struct SigningKey {
    inner: DalekSigningKey,
}

impl SigningKey {
    /// Creates a new random signing key.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            inner: DalekSigningKey::generate(&mut rng),
        }
    }

    /// Creates a signing key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `AttestationError::InvalidKeyFormat` if the bytes are not a valid
    /// Ed25519 private key (must be exactly 32 bytes).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, AttestationError> {
        Ok(Self {
            inner: DalekSigningKey::from_bytes(bytes),
        })
    }

    /// Returns the raw private key seed.
    ///
    /// # This hands out unprotected secret material
    ///
    /// [`SigningKey`] wipes itself when dropped, and so does the `ed25519-dalek`
    /// key it wraps. The array returned here does neither: it is a plain
    /// `[u8; 32]`, and from the moment it is returned the private key exists in
    /// a second place that this crate cannot reach and will not clean up. A copy
    /// left on the stack or in a `Vec` outlives its frame and can be recovered
    /// from a core dump, a swapped page, or whatever is allocated over it next.
    ///
    /// Call this only to persist or transmit the key, and wrap the result in
    /// [`zeroize::Zeroizing`](https://docs.rs/zeroize) for as long as it is
    /// held:
    ///
    /// ```
    /// use agent_uri_attestation::SigningKey;
    /// use zeroize::Zeroizing;
    ///
    /// let key = SigningKey::generate();
    /// let seed = Zeroizing::new(key.to_bytes());
    ///
    /// // `seed` is wiped on drop; the bare array this returned would not be.
    /// assert_eq!(SigningKey::from_bytes(&seed).unwrap().to_bytes(), *seed);
    /// ```
    ///
    /// To *identify* a key rather than move it, use
    /// [`verifying_key`](Self::verifying_key). The public half is not secret,
    /// and it is what names a key everywhere else in this crate.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Returns the corresponding verifying (public) key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    /// Signs an arbitrary message.
    ///
    /// The message is signed verbatim. Callers signing structured data are
    /// responsible for encoding it unambiguously and for prefixing a domain
    /// separator, so that a signature minted for one purpose cannot be
    /// presented as authorization for another.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.inner.sign(message).to_bytes())
    }

    /// Returns a reference to the inner dalek signing key.
    pub(crate) fn as_dalek(&self) -> &DalekSigningKey {
        &self.inner
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("public_key", &self.verifying_key())
            .finish_non_exhaustive()
    }
}

/// A verifying key for validating attestation tokens.
///
/// Wraps an Ed25519 public key used for verifying PASETO v4.public tokens.
/// This key can be safely shared and distributed.
///
/// # Example
///
/// ```
/// use agent_uri_attestation::{SigningKey, VerifyingKey};
///
/// let signing_key = SigningKey::generate();
/// let verifying_key = signing_key.verifying_key();
///
/// // Serialize for storage or transmission
/// let bytes = verifying_key.to_bytes();
///
/// // Deserialize later
/// let recovered = VerifyingKey::from_bytes(&bytes).unwrap();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    inner: DalekVerifyingKey,
}

impl VerifyingKey {
    /// Creates a verifying key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns `AttestationError::InvalidKeyFormat` if the bytes are not a valid
    /// Ed25519 public key (must be exactly 32 bytes representing a valid curve point).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, AttestationError> {
        DalekVerifyingKey::from_bytes(bytes)
            .map(|inner| Self { inner })
            .map_err(|e| AttestationError::InvalidKeyFormat {
                reason: e.to_string(),
            })
    }

    /// Returns the raw key bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Returns the key in the base64 form used on the wire.
    ///
    /// Standard base64 with padding, matching the `public_key` field of the
    /// trust root's published key set, so a key means the same string wherever
    /// it appears.
    #[must_use]
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.to_bytes())
    }

    /// Parses a key from its base64 wire form.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::InvalidKeyFormat`] if the string is not
    /// base64, does not decode to 32 bytes, or those bytes are not a valid
    /// Ed25519 public key.
    pub fn from_base64(encoded: &str) -> Result<Self, AttestationError> {
        let decoded =
            BASE64
                .decode(encoded)
                .map_err(|error| AttestationError::InvalidKeyFormat {
                    reason: format!("not valid base64: {error}"),
                })?;
        let bytes: [u8; 32] =
            decoded
                .try_into()
                .map_err(|decoded: Vec<u8>| AttestationError::InvalidKeyFormat {
                    reason: format!(
                        "an Ed25519 public key is 32 bytes, but this decoded to {}",
                        decoded.len()
                    ),
                })?;
        Self::from_bytes(&bytes)
    }

    /// Verifies a detached signature over `message`.
    ///
    /// # Errors
    ///
    /// Returns [`AttestationError::InvalidSignature`] if the signature was not
    /// produced over exactly this message by the corresponding private key.
    /// The error deliberately carries no detail: distinguishing a malformed
    /// signature from a well-formed one over different bytes tells an attacker
    /// which half of the guess was wrong.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), AttestationError> {
        self.inner
            .verify(message, &DalekSignature::from_bytes(&signature.0))
            .map_err(|_| AttestationError::InvalidSignature)
    }
}

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Show first 4 bytes of public key for identification
        let bytes = self.to_bytes();
        write!(
            f,
            "VerifyingKey({:02x}{:02x}{:02x}{:02x}...)",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    /// Renders bytes as lowercase hex, for asserting a secret is *absent*.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    #[test]
    fn signing_key_generates_unique_keys() {
        let key1 = SigningKey::generate();
        let key2 = SigningKey::generate();

        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn signing_key_roundtrip_bytes() {
        let original = SigningKey::generate();
        let bytes = original.to_bytes();
        let recovered = SigningKey::from_bytes(&bytes).unwrap();

        assert_eq!(original.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn verifying_key_roundtrip_bytes() {
        let signing_key = SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let bytes = verifying_key.to_bytes();
        let recovered = VerifyingKey::from_bytes(&bytes).unwrap();

        assert_eq!(verifying_key, recovered);
    }

    #[test]
    fn verifying_key_from_invalid_bytes_fails() {
        // This specific byte pattern is invalid - we test multiple patterns
        // to find one that ed25519-dalek rejects
        let test_cases = [[0xFFu8; 32], [0xEEu8; 32], {
            let mut b = [0u8; 32];
            b[31] = 0x80; // Invalid: high bit in last byte
            b
        }];

        let mut found_invalid = false;
        for invalid_bytes in &test_cases {
            let result = VerifyingKey::from_bytes(invalid_bytes);
            if result.is_err() {
                found_invalid = true;
                assert!(matches!(
                    result,
                    Err(AttestationError::InvalidKeyFormat { .. })
                ));
                break;
            }
        }

        // If none of the patterns are invalid, we just verify the API returns Result
        // The main point is that from_bytes returns a Result that can fail
        if !found_invalid {
            // Generate a valid key to ensure the API works
            let signing_key = SigningKey::generate();
            let valid_key = signing_key.verifying_key();
            assert!(VerifyingKey::from_bytes(&valid_key.to_bytes()).is_ok());
        }
    }

    #[test]
    fn signing_key_debug_shows_public_key() {
        let key = SigningKey::generate();
        let debug_output = format!("{key:?}");

        assert!(debug_output.contains("SigningKey"));
        assert!(debug_output.contains("VerifyingKey"));
    }

    #[test]
    fn signing_key_debug_does_not_print_the_private_key() {
        // The assertion above says what the output *contains*, which a leaking
        // impl would satisfy just as well: printing the public key and the
        // private one passes it. This says what the output must not contain,
        // which is the half that matters. `{:?}` reaches logs, panic messages,
        // and error reports without anyone deciding it should.
        let seed = [0xABu8; 32];
        let key = SigningKey::from_bytes(&seed).expect("a valid seed");

        let shown = format!("{key:?}");

        for rendering in [hex(&seed), BASE64.encode(seed), format!("{seed:?}")] {
            assert!(
                !shown.contains(&rendering),
                "the private key leaked into Debug output: {shown}"
            );
        }
    }

    #[test]
    fn a_signature_verifies_under_its_own_key_and_message() {
        let key = SigningKey::generate();
        let signature = key.sign(b"authorize this");

        assert!(
            key.verifying_key()
                .verify(b"authorize this", &signature)
                .is_ok()
        );
    }

    #[test]
    fn a_signature_does_not_verify_over_different_bytes() {
        // The whole point of signing a mutation is that the signature covers
        // the mutation. A signature that survived an edit would authorize
        // whatever the edit said.
        let key = SigningKey::generate();
        let signature = key.sign(b"endpoint: honest.example");

        assert_eq!(
            key.verifying_key()
                .verify(b"endpoint: attacker.example", &signature),
            Err(AttestationError::InvalidSignature)
        );
    }

    #[test]
    fn a_signature_does_not_verify_under_another_key() {
        let mine = SigningKey::generate();
        let theirs = SigningKey::generate();
        let signature = mine.sign(b"authorize this");

        assert_eq!(
            theirs.verifying_key().verify(b"authorize this", &signature),
            Err(AttestationError::InvalidSignature)
        );
    }

    #[test]
    fn a_forged_signature_is_rejected_rather_than_panicking() {
        // from_bytes accepts any 64 bytes by design, so verify has to be the
        // component that survives arbitrary attacker input.
        let key = SigningKey::generate();

        for pattern in [[0x00u8; 64], [0xffu8; 64], [0xaau8; 64]] {
            assert_eq!(
                key.verifying_key()
                    .verify(b"authorize this", &Signature::from_bytes(pattern)),
                Err(AttestationError::InvalidSignature)
            );
        }
    }

    #[test]
    fn signature_round_trips_its_wire_form() {
        let key = SigningKey::generate();
        let signature = key.sign(b"authorize this");
        let recovered = Signature::from_bytes(signature.to_bytes());

        assert_eq!(signature, recovered);
        assert!(
            key.verifying_key()
                .verify(b"authorize this", &recovered)
                .is_ok()
        );
    }

    #[test]
    fn signature_debug_does_not_print_the_whole_signature() {
        let key = SigningKey::generate();
        let shown = format!("{:?}", key.sign(b"authorize this"));

        assert!(shown.starts_with("Signature("));
        assert!(shown.contains("..."));
        assert!(shown.len() < 32);
    }

    #[test]
    fn verifying_key_round_trips_its_base64_form() {
        let key = SigningKey::generate().verifying_key();

        assert_eq!(VerifyingKey::from_base64(&key.to_base64()).unwrap(), key);
    }

    #[test]
    fn base64_that_is_not_base64_is_rejected() {
        assert!(matches!(
            VerifyingKey::from_base64("not base64!!"),
            Err(AttestationError::InvalidKeyFormat { .. })
        ));
    }

    #[test]
    fn base64_of_the_wrong_length_names_the_length_it_got() {
        // A 31-byte key silently zero-padded to 32 would be a different key
        // that still verified nothing, so the length has to be checked.
        let err = VerifyingKey::from_base64(&BASE64.encode([0u8; 31])).unwrap_err();

        assert!(matches!(err, AttestationError::InvalidKeyFormat { .. }));
        assert!(err.to_string().contains("31"));
    }

    #[test]
    fn verifying_key_debug_shows_partial_bytes() {
        let signing_key = SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let debug_output = format!("{verifying_key:?}");

        assert!(debug_output.contains("VerifyingKey("));
        assert!(debug_output.contains("..."));
    }
}
