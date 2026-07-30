//! Per-operation options for distributed DHT operations.

use std::num::NonZeroUsize;
use std::time::Duration;

/// How many replicas must respond for an operation to be considered successful.
///
/// A DHT operation is answered by several nodes, and a caller trades latency
/// against confidence by choosing how many of them to wait for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quorum {
    /// One replica suffices. Lowest latency, weakest guarantee.
    One,
    /// A majority of the replication factor.
    Majority,
    /// Every replica in the replication factor.
    All,
    /// An explicit number of replicas.
    N(NonZeroUsize),
}

impl Quorum {
    /// Resolves this quorum to a concrete replica count for a replication factor.
    ///
    /// The result is clamped to `replication_factor`, so `N` larger than the
    /// replication factor is treated as `All` rather than being unsatisfiable.
    #[must_use]
    pub fn resolve(self, replication_factor: NonZeroUsize) -> usize {
        let k = replication_factor.get();
        match self {
            Self::One => 1,
            Self::Majority => k / 2 + 1,
            Self::All => k,
            Self::N(n) => n.get().min(k),
        }
    }
}

/// Options for operations that write to the DHT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteOptions {
    /// Maximum time to wait before abandoning the operation.
    pub timeout: Duration,
    /// How many replicas must acknowledge the write.
    pub quorum: Quorum,
}

impl WriteOptions {
    /// Default write timeout.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

    /// Creates write options with the default timeout and quorum.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            timeout: Self::DEFAULT_TIMEOUT,
            quorum: Quorum::Majority,
        }
    }

    /// Sets the timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the quorum.
    #[must_use]
    pub const fn with_quorum(mut self, quorum: Quorum) -> Self {
        self.quorum = quorum;
        self
    }
}

impl Default for WriteOptions {
    /// Majority quorum, because a write that lands on one replica is lost to
    /// the next churn event.
    fn default() -> Self {
        Self::new()
    }
}

/// Options for operations that read from the DHT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOptions {
    /// Maximum time to wait before abandoning the operation.
    pub timeout: Duration,
    /// How many replicas must answer before the result is returned.
    pub quorum: Quorum,
    /// Maximum number of DHT keys read to satisfy one lookup call.
    ///
    /// A broad capability path may be spread across several keys, so a lookup
    /// can fan out. This bounds both the latency and the attacker-funded work
    /// of a single call; a truncated result reports a cursor.
    pub max_keys: usize,
    /// Where to resume a previous lookup, if any.
    pub cursor: Option<crate::Cursor>,
}

impl ReadOptions {
    /// Default read timeout.
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

    /// Default maximum keys read per lookup.
    pub const DEFAULT_MAX_KEYS: usize = 16;

    /// Creates read options with the defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            timeout: Self::DEFAULT_TIMEOUT,
            quorum: Quorum::One,
            max_keys: Self::DEFAULT_MAX_KEYS,
            cursor: None,
        }
    }

    /// Sets the timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the quorum.
    #[must_use]
    pub const fn with_quorum(mut self, quorum: Quorum) -> Self {
        self.quorum = quorum;
        self
    }

    /// Sets the maximum number of DHT keys read per lookup.
    #[must_use]
    pub const fn with_max_keys(mut self, max_keys: usize) -> Self {
        self.max_keys = max_keys;
        self
    }

    /// Resumes a lookup from a cursor returned by a previous page.
    #[must_use]
    pub fn with_cursor(mut self, cursor: crate::Cursor) -> Self {
        self.cursor = Some(cursor);
        self
    }
}

impl Default for ReadOptions {
    /// `Quorum::One`, matching the usual DHT read: the first replica to answer
    /// wins. Raise it when a stale or withheld record is a concern, since
    /// records are signed but a replica can still answer with an older one.
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    #[test]
    fn one_resolves_to_one() {
        assert_eq!(Quorum::One.resolve(k(20)), 1);
    }

    #[test]
    fn majority_is_strictly_more_than_half() {
        assert_eq!(Quorum::Majority.resolve(k(20)), 11);
        assert_eq!(Quorum::Majority.resolve(k(3)), 2);
        assert_eq!(Quorum::Majority.resolve(k(1)), 1);
    }

    #[test]
    fn all_resolves_to_the_replication_factor() {
        assert_eq!(Quorum::All.resolve(k(20)), 20);
    }

    #[test]
    fn explicit_n_is_honored_below_the_replication_factor() {
        assert_eq!(Quorum::N(k(5)).resolve(k(20)), 5);
    }

    #[test]
    fn explicit_n_clamps_to_the_replication_factor() {
        // An unsatisfiable quorum would fail every write; clamping degrades to
        // All instead, which is the strictest achievable request.
        assert_eq!(Quorum::N(k(100)).resolve(k(20)), 20);
    }

    #[test]
    fn write_defaults_to_majority() {
        assert_eq!(WriteOptions::default().quorum, Quorum::Majority);
        assert_eq!(WriteOptions::default().timeout, Duration::from_secs(30));
    }

    #[test]
    fn read_defaults_to_one() {
        let opts = ReadOptions::default();
        assert_eq!(opts.quorum, Quorum::One);
        assert_eq!(opts.max_keys, 16);
        assert!(opts.cursor.is_none());
    }

    #[test]
    fn builders_override_defaults() {
        let w = WriteOptions::new()
            .with_timeout(Duration::from_secs(5))
            .with_quorum(Quorum::All);
        assert_eq!(w.timeout, Duration::from_secs(5));
        assert_eq!(w.quorum, Quorum::All);

        let r = ReadOptions::new()
            .with_timeout(Duration::from_secs(1))
            .with_quorum(Quorum::Majority)
            .with_max_keys(4);
        assert_eq!(r.timeout, Duration::from_secs(1));
        assert_eq!(r.quorum, Quorum::Majority);
        assert_eq!(r.max_keys, 4);
    }
}
