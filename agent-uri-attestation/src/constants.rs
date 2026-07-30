//! Constants for attestation token validation.

/// Maximum total attestation token length, in bytes.
///
/// This is the practical PASETO v4.public ceiling documented in `grammar.abnf`
/// and enforced by [`crate::check_token_length`] before a token is decoded or
/// signature-checked. A well-formed token is base64url plus ASCII separators,
/// so its byte length and character length coincide; measuring bytes also
/// bounds the work done on non-ASCII garbage.
pub const MAX_TOKEN_LENGTH: usize = 8192;
