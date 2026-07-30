//! Trust roots supplied on the command line as `<root>=<public-key-hex>`.
//!
//! A trust root pairs an authority (`acme.com`) with the Ed25519 public key that
//! is allowed to attest URIs beneath it. This is the operator's registry, passed
//! in by hand: `--trust-root acme.com=3b6a...`.

use std::fmt;
use std::str::FromStr;

use agent_uri_attestation::VerifyingKey;

/// Number of hex characters in an encoded 32-byte public key.
const HEX_LEN: usize = 64;

/// An authority paired with the public key trusted to speak for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedRoot {
    /// The authority, e.g. `acme.com`.
    pub root: String,
    /// The public key trusted to attest URIs under that authority.
    pub key: VerifyingKey,
}

/// Why a `<root>=<hex>` pair could not be understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustedRootError {
    /// The argument had no `=`.
    MissingSeparator,
    /// The authority side was empty.
    EmptyRoot,
    /// The key was not 64 hex characters.
    BadLength(usize),
    /// The key was not valid hex.
    NotHex(String),
    /// The bytes are not a valid Ed25519 public key.
    NotAKey(String),
}

impl fmt::Display for TrustedRootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSeparator => write!(
                f,
                "expected '<root>=<public-key-hex>', e.g. 'acme.com=3b6a...'; the '=' is missing"
            ),
            Self::EmptyRoot => write!(
                f,
                "the authority is empty; write '<root>=<public-key-hex>', e.g. 'acme.com=3b6a...'"
            ),
            Self::BadLength(len) => write!(
                f,
                "public key has {len} characters; an Ed25519 public key is {HEX_LEN} hex characters \
                 (get it with 'agent-uri key public')"
            ),
            Self::NotHex(reason) => write!(f, "public key is not valid hex: {reason}"),
            Self::NotAKey(reason) => write!(f, "not a valid Ed25519 public key: {reason}"),
        }
    }
}

impl std::error::Error for TrustedRootError {}

impl FromStr for TrustedRoot {
    type Err = TrustedRootError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (root, hex_key) = input
            .split_once('=')
            .ok_or(TrustedRootError::MissingSeparator)?;

        let root = root.trim();
        if root.is_empty() {
            return Err(TrustedRootError::EmptyRoot);
        }

        let key = decode_public(hex_key.trim())?;

        Ok(Self {
            root: root.to_string(),
            key,
        })
    }
}

/// Decodes a public key from 64 hex characters.
///
/// The same encoding `--trust-root` uses, so a key that was printed by
/// `agent-uri key generate` can be pasted wherever a key is asked for.
///
/// # Errors
///
/// Returns [`TrustedRootError`] if the input is not 64 hex characters
/// decoding to a valid Ed25519 public key.
pub fn decode_public(hex_key: &str) -> Result<VerifyingKey, TrustedRootError> {
    if hex_key.len() != HEX_LEN {
        return Err(TrustedRootError::BadLength(hex_key.len()));
    }

    let bytes =
        hex::decode(hex_key).map_err(|source| TrustedRootError::NotHex(source.to_string()))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TrustedRootError::BadLength(hex_key.len()))?;

    VerifyingKey::from_bytes(&bytes).map_err(|source| TrustedRootError::NotAKey(source.to_string()))
}

/// Encodes a public key as 64 lowercase hex characters.
pub fn encode_public(key: &VerifyingKey) -> String {
    hex::encode(key.to_bytes())
}

#[cfg(test)]
mod tests {
    use agent_uri_attestation::SigningKey;

    use super::*;

    fn public_hex() -> String {
        encode_public(&SigningKey::generate().verifying_key())
    }

    #[test]
    fn parses_a_root_and_key() {
        let hex_key = public_hex();
        let parsed: TrustedRoot = format!("acme.com={hex_key}").parse().unwrap();

        assert_eq!(parsed.root, "acme.com");
        assert_eq!(encode_public(&parsed.key), hex_key);
    }

    #[test]
    fn parses_an_authority_with_a_port() {
        let parsed: TrustedRoot = format!("localhost:8472={}", public_hex()).parse().unwrap();
        assert_eq!(parsed.root, "localhost:8472");
    }

    #[test]
    fn rejects_a_missing_separator() {
        assert_eq!(
            "acme.com".parse::<TrustedRoot>(),
            Err(TrustedRootError::MissingSeparator)
        );
    }

    #[test]
    fn rejects_an_empty_root() {
        let input = format!("={}", public_hex());
        assert_eq!(
            input.parse::<TrustedRoot>(),
            Err(TrustedRootError::EmptyRoot)
        );
    }

    #[test]
    fn rejects_a_short_key() {
        assert_eq!(
            "acme.com=abcd".parse::<TrustedRoot>(),
            Err(TrustedRootError::BadLength(4))
        );
    }

    #[test]
    fn rejects_non_hex() {
        let input = format!("acme.com={}", "z".repeat(HEX_LEN));
        assert!(matches!(
            input.parse::<TrustedRoot>(),
            Err(TrustedRootError::NotHex(_))
        ));
    }

    #[test]
    fn rejects_bytes_that_are_not_a_curve_point() {
        // 0x02 followed by zeros is not a valid compressed Edwards y-coordinate,
        // so it fails to decompress. Length and hex are both fine here: this is
        // specifically the curve check rejecting it.
        let not_a_point = format!("02{}", "00".repeat(31));
        let input = format!("acme.com={not_a_point}");

        assert!(matches!(
            input.parse::<TrustedRoot>(),
            Err(TrustedRootError::NotAKey(_))
        ));
    }

    #[test]
    fn error_messages_name_the_fix() {
        let message = TrustedRootError::MissingSeparator.to_string();
        assert!(message.contains("<root>=<public-key-hex>"));

        let message = TrustedRootError::BadLength(4).to_string();
        assert!(message.contains("agent-uri key public"));
    }
}
