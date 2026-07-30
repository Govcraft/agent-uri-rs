//! Node identity and peer addressing.

use std::fmt;

/// The identity of a node participating in the DHT.
///
/// Opaque and backend-defined: a Kademlia backend derives it from the node's
/// public key, while the in-process simulator synthesizes one. Length varies
/// by backend, so this holds bytes rather than a fixed-size array.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(Vec<u8>);

impl NodeId {
    /// Creates a node identity from raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Returns the raw bytes of this identity.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns true if this identity carries no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Truncated hex, matching DhtKey's display convention.
        for byte in self.0.iter().take(8) {
            write!(f, "{byte:02x}")?;
        }
        if self.0.len() > 8 {
            write!(f, "...")?;
        }
        Ok(())
    }
}

impl AsRef<[u8]> for NodeId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// The address of a peer used to join the overlay.
///
/// Held as an opaque string because the encoding is the backend's business: a
/// libp2p backend parses a multiaddr, the simulator ignores it entirely.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerAddr(String);

impl PeerAddr {
    /// Creates a peer address from its backend-specific string form.
    #[must_use]
    pub fn new(addr: impl Into<String>) -> Self {
        Self(addr.into())
    }

    /// Returns the address string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The outcome of a write that had to reach a quorum of replicas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteReceipt {
    acknowledged: usize,
    required: usize,
}

impl WriteReceipt {
    /// Records a write acknowledged by `acknowledged` replicas against a
    /// quorum of `required`.
    #[must_use]
    pub const fn new(acknowledged: usize, required: usize) -> Self {
        Self {
            acknowledged,
            required,
        }
    }

    /// Returns how many replicas acknowledged the write.
    #[must_use]
    pub const fn acknowledged(&self) -> usize {
        self.acknowledged
    }

    /// Returns how many acknowledgements the requested quorum needed.
    #[must_use]
    pub const fn required(&self) -> usize {
        self.required
    }

    /// Returns true if the write reached more replicas than the quorum needed.
    ///
    /// Useful for callers that want to know a write is durable beyond the
    /// minimum they asked for.
    #[must_use]
    pub const fn exceeded_quorum(&self) -> bool {
        self.acknowledged > self.required
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_round_trips_bytes() {
        let id = NodeId::from_bytes(vec![1, 2, 3]);
        assert_eq!(id.as_bytes(), &[1, 2, 3]);
        assert!(!id.is_empty());
    }

    #[test]
    fn node_id_display_is_truncated_hex() {
        let id = NodeId::from_bytes(vec![0xab; 16]);
        let shown = id.to_string();
        assert_eq!(shown, "abababababababab...");
    }

    #[test]
    fn short_node_id_display_has_no_ellipsis() {
        let id = NodeId::from_bytes(vec![0xab; 4]);
        assert_eq!(id.to_string(), "abababab");
    }

    #[test]
    fn peer_addr_keeps_its_string_form() {
        let addr = PeerAddr::new("/ip4/127.0.0.1/tcp/4001");
        assert_eq!(addr.as_str(), "/ip4/127.0.0.1/tcp/4001");
        assert_eq!(addr.to_string(), "/ip4/127.0.0.1/tcp/4001");
    }

    #[test]
    fn receipt_reports_acknowledgements() {
        let r = WriteReceipt::new(11, 11);
        assert_eq!(r.acknowledged(), 11);
        assert_eq!(r.required(), 11);
        assert!(!r.exceeded_quorum());
    }

    #[test]
    fn receipt_detects_writes_beyond_quorum() {
        assert!(WriteReceipt::new(20, 11).exceeded_quorum());
    }
}
