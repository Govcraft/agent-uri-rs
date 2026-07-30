//! DHT key derivation and distance metrics.

use std::fmt;

use agent_uri::{CapabilityPath, TrustRoot};
use sha2::{Digest, Sha256};

/// DHT key derived from trust root and capability path.
///
/// A 256-bit hash used as the key in a Kademlia-style DHT.
/// Keys are derived deterministically from trust root and capability path,
/// enabling capability-based discovery.
///
/// # Key Derivation
///
/// ```text
/// key = SHA256(trust_root || "/" || capability_path)
/// ```
///
/// # Examples
///
/// ```
/// use agent_uri::{TrustRoot, CapabilityPath};
/// use agent_uri_dht::DhtKey;
///
/// let trust_root = TrustRoot::parse("anthropic.com").unwrap();
/// let path = CapabilityPath::parse("assistant/chat").unwrap();
/// let key = DhtKey::derive(&trust_root, &path);
///
/// // Keys are deterministic
/// let key2 = DhtKey::derive(&trust_root, &path);
/// assert_eq!(key, key2);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DhtKey([u8; 32]);

impl DhtKey {
    /// Creates a `DhtKey` from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32-byte array representing the key
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the key as a byte slice.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives a DHT key from trust root and capability path.
    ///
    /// The key is computed as: `SHA256(trust_root || "/" || capability_path)`
    ///
    /// # Arguments
    ///
    /// * `trust_root` - The trust root (authority)
    /// * `capability_path` - The capability path
    ///
    /// # Returns
    ///
    /// A deterministic 256-bit key for DHT lookup.
    #[must_use]
    pub fn derive(trust_root: &TrustRoot, capability_path: &CapabilityPath) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(trust_root.as_str().as_bytes());
        hasher.update(b"/");
        hasher.update(capability_path.as_str().as_bytes());

        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Derives a DHT key for a specific path depth (prefix query support).
    ///
    /// This enables hierarchical discovery by deriving keys for path prefixes.
    ///
    /// # Arguments
    ///
    /// * `trust_root` - The trust root (authority)
    /// * `capability_path` - The full capability path
    /// * `depth` - The number of path segments to include (1-indexed)
    ///
    /// # Returns
    ///
    /// A key for the path truncated to the specified depth.
    /// Returns `None` if depth is 0 or exceeds the path depth.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::{TrustRoot, CapabilityPath};
    /// use agent_uri_dht::DhtKey;
    ///
    /// let trust_root = TrustRoot::parse("anthropic.com").unwrap();
    /// let path = CapabilityPath::parse("assistant/chat/streaming").unwrap();
    ///
    /// // Key for "assistant" only
    /// let key1 = DhtKey::derive_at_depth(&trust_root, &path, 1).unwrap();
    ///
    /// // Key for "assistant/chat"
    /// let key2 = DhtKey::derive_at_depth(&trust_root, &path, 2).unwrap();
    ///
    /// // Full path key
    /// let key3 = DhtKey::derive_at_depth(&trust_root, &path, 3).unwrap();
    /// assert_eq!(key3, DhtKey::derive(&trust_root, &path));
    /// ```
    #[must_use]
    pub fn derive_at_depth(
        trust_root: &TrustRoot,
        capability_path: &CapabilityPath,
        depth: usize,
    ) -> Option<Self> {
        if depth == 0 || depth > capability_path.depth() {
            return None;
        }

        let mut hasher = Sha256::new();
        hasher.update(trust_root.as_str().as_bytes());
        hasher.update(b"/");

        // Build truncated path
        let segments = capability_path.segments();
        let prefix_path: String = segments[..depth]
            .iter()
            .map(agent_uri::PathSegment::as_str)
            .collect::<Vec<_>>()
            .join("/");

        hasher.update(prefix_path.as_bytes());

        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        Some(Self(bytes))
    }

    /// Computes the XOR distance to another key.
    ///
    /// This is the fundamental distance metric for Kademlia routing.
    /// Closer keys (lower XOR distance) are more likely to be stored
    /// on the same or nearby nodes.
    ///
    /// # Arguments
    ///
    /// * `other` - The key to compute distance to
    ///
    /// # Returns
    ///
    /// A `DhtKey` representing the XOR distance (interpretable as a 256-bit unsigned integer).
    #[must_use]
    pub fn distance(&self, other: &Self) -> Self {
        let mut result = [0u8; 32];
        for (i, (a, b)) in self.0.iter().zip(other.0.iter()).enumerate() {
            result[i] = a ^ b;
        }
        Self(result)
    }

    /// Returns the leading zero bits in the key.
    ///
    /// Useful for Kademlia bucket calculations.
    #[must_use]
    pub fn leading_zeros(&self) -> u32 {
        let mut count = 0u32;
        for byte in &self.0 {
            if *byte == 0 {
                count += 8;
            } else {
                count += byte.leading_zeros();
                break;
            }
        }
        count
    }
}

impl fmt::Debug for DhtKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DhtKey({self})")
    }
}

impl fmt::Display for DhtKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Display as hex, truncated for readability
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "...")
    }
}

impl AsRef<[u8]> for DhtKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for DhtKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Serialize as hex string
        use core::fmt::Write as _;

        let mut hex = String::with_capacity(self.0.len() * 2);
        for byte in &self.0 {
            let _ = write!(&mut hex, "{byte:02x}");
        }
        serializer.serialize_str(&hex)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DhtKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        if hex.len() != 64 {
            return Err(serde::de::Error::custom(
                "DhtKey hex string must be 64 characters",
            ));
        }
        let mut bytes = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).map_err(serde::de::Error::custom)?;
            bytes[i] = u8::from_str_radix(s, 16).map_err(serde::de::Error::custom)?;
        }
        Ok(Self(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(key: &DhtKey) -> String {
        use std::fmt::Write as _;
        key.as_bytes().iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    #[test]
    fn derivation_matches_the_specs_test_vectors() {
        // SPECIFICATION.md Appendix B.4. A key derivation is an interoperability
        // surface: two implementations that disagree on one byte cannot see each
        // other's registrations at all. Pinning the published digests here is
        // what stops a refactor from moving them quietly.
        let anthropic = TrustRoot::parse("anthropic.com").unwrap();
        let chat = CapabilityPath::parse("assistant/chat").unwrap();
        assert_eq!(
            hex(&DhtKey::derive(&anthropic, &chat)),
            "ee7f343128163eec1164fb5afc0a019df215fc73decb14bc58fef1a4966e8262"
        );

        let openai = TrustRoot::parse("openai.com").unwrap();
        assert_eq!(
            hex(&DhtKey::derive(&openai, &chat)),
            "c5a97797f98cc507b8604ebd16a27071e87056b047c8f2625182287d14b31f53"
        );

        let acme = TrustRoot::parse("acme.com").unwrap();
        let invoice = CapabilityPath::parse("workflow/approval/invoice").unwrap();
        let expected = [
            "16889f14c0da9c42cae8063d495e33b4fa1b12cabfdd019c1491b217a56c857a",
            "b15b22d3c95b3091743a071ed616d9715038a7afd559a7dc28f3d7a1f9eec03e",
            "d9786664a610a9aaa2799a65c6bd3f9baa44a067f7511cb179c63041021f25f2",
        ];
        for (depth, want) in (1..=3).zip(expected) {
            let key = DhtKey::derive_at_depth(&acme, &invoice, depth).unwrap();
            assert_eq!(hex(&key), want, "depth {depth}");
        }
    }

    #[test]
    fn derive_is_deterministic() {
        let trust_root = TrustRoot::parse("anthropic.com").unwrap();
        let path = CapabilityPath::parse("assistant/chat").unwrap();

        let key1 = DhtKey::derive(&trust_root, &path);
        let key2 = DhtKey::derive(&trust_root, &path);

        assert_eq!(key1, key2);
    }

    #[test]
    fn different_inputs_produce_different_keys() {
        let trust_root1 = TrustRoot::parse("anthropic.com").unwrap();
        let trust_root2 = TrustRoot::parse("openai.com").unwrap();
        let path = CapabilityPath::parse("assistant/chat").unwrap();

        let key1 = DhtKey::derive(&trust_root1, &path);
        let key2 = DhtKey::derive(&trust_root2, &path);

        assert_ne!(key1, key2);
    }

    #[test]
    fn different_paths_produce_different_keys() {
        let trust_root = TrustRoot::parse("anthropic.com").unwrap();
        let path1 = CapabilityPath::parse("assistant/chat").unwrap();
        let path2 = CapabilityPath::parse("assistant/code").unwrap();

        let key1 = DhtKey::derive(&trust_root, &path1);
        let key2 = DhtKey::derive(&trust_root, &path2);

        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_at_depth_zero_returns_none() {
        let trust_root = TrustRoot::parse("anthropic.com").unwrap();
        let path = CapabilityPath::parse("assistant/chat").unwrap();

        assert!(DhtKey::derive_at_depth(&trust_root, &path, 0).is_none());
    }

    #[test]
    fn derive_at_depth_exceeding_path_returns_none() {
        let trust_root = TrustRoot::parse("anthropic.com").unwrap();
        let path = CapabilityPath::parse("assistant/chat").unwrap();

        assert!(DhtKey::derive_at_depth(&trust_root, &path, 3).is_none());
    }

    #[test]
    fn derive_at_full_depth_equals_derive() {
        let trust_root = TrustRoot::parse("anthropic.com").unwrap();
        let path = CapabilityPath::parse("assistant/chat").unwrap();

        let key1 = DhtKey::derive(&trust_root, &path);
        let key2 = DhtKey::derive_at_depth(&trust_root, &path, 2).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn derive_at_partial_depth_produces_different_key() {
        let trust_root = TrustRoot::parse("anthropic.com").unwrap();
        let path = CapabilityPath::parse("assistant/chat/streaming").unwrap();

        let key1 = DhtKey::derive_at_depth(&trust_root, &path, 1).unwrap();
        let key2 = DhtKey::derive_at_depth(&trust_root, &path, 2).unwrap();
        let key3 = DhtKey::derive_at_depth(&trust_root, &path, 3).unwrap();

        assert_ne!(key1, key2);
        assert_ne!(key2, key3);
        assert_ne!(key1, key3);
    }

    #[test]
    fn distance_to_self_is_zero() {
        let trust_root = TrustRoot::parse("anthropic.com").unwrap();
        let path = CapabilityPath::parse("assistant/chat").unwrap();
        let key = DhtKey::derive(&trust_root, &path);

        let distance = key.distance(&key);

        assert_eq!(distance, DhtKey::from_bytes([0u8; 32]));
    }

    #[test]
    fn distance_is_symmetric() {
        let trust_root = TrustRoot::parse("anthropic.com").unwrap();
        let path1 = CapabilityPath::parse("assistant/chat").unwrap();
        let path2 = CapabilityPath::parse("assistant/code").unwrap();

        let key1 = DhtKey::derive(&trust_root, &path1);
        let key2 = DhtKey::derive(&trust_root, &path2);

        assert_eq!(key1.distance(&key2), key2.distance(&key1));
    }

    #[test]
    fn leading_zeros_for_zero_key() {
        let key = DhtKey::from_bytes([0u8; 32]);
        assert_eq!(key.leading_zeros(), 256);
    }

    #[test]
    fn leading_zeros_for_first_byte_set() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x80; // 10000000 in binary
        let key = DhtKey::from_bytes(bytes);
        assert_eq!(key.leading_zeros(), 0);
    }

    #[test]
    fn leading_zeros_for_partial_byte() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x08; // 00001000 in binary
        let key = DhtKey::from_bytes(bytes);
        assert_eq!(key.leading_zeros(), 4);
    }

    #[test]
    fn display_shows_truncated_hex() {
        let key = DhtKey::from_bytes([0xab; 32]);
        let display = format!("{key}");
        assert!(display.starts_with("abababab"));
        assert!(display.ends_with("..."));
    }

    #[test]
    fn debug_includes_display() {
        let key = DhtKey::from_bytes([0xab; 32]);
        let debug = format!("{key:?}");
        assert!(debug.starts_with("DhtKey("));
        assert!(debug.contains("abababab"));
    }
}
