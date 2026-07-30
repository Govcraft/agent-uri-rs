//! Reconciling two copies of the same record.
//!
//! Kademlia gives no ordering and no consensus. The same key is held by several
//! nodes, each of which may have seen a different subset of the writes, and
//! replication copies values between them in whichever direction happens to
//! fire first. A backend that treated the newest arrival as authoritative would
//! let a stale replica undo a fresh write every time it replicated.
//!
//! So every value this backend stores reconciles by a rule that does not depend
//! on arrival order:
//!
//! - **Identity records** take the greater `(registered_at, sequence)`. Records
//!   are immutable and signed, so the comparison is over two candidates, never
//!   a merge of their contents.
//! - **Pointer pages** take the union, keeping the later expiry per URI.
//! - **Shard descriptors** take the greater level.
//!
//! All three are commutative, associative, and idempotent, which is what makes
//! them safe under arbitrary replication. Applying the same write twice, or in
//! the other order, or from two peers at once, lands in the same place.
//!
//! The same rule runs on both sides of a read: a node applies it when a record
//! arrives, and a reader applies it across the copies several nodes returned.
//! A reader is therefore no worse off than the freshest replica that answered.

use std::collections::HashMap;
use std::time::SystemTime;

use crate::record::{IdentityRecord, Pointer, PointerPage, ShardDescriptor};

/// Returns whichever identity record is later in the record's history.
///
/// Ties go to `held`: two records at one version are the same write, and
/// preferring the copy already stored avoids rewriting a record for nothing.
#[must_use]
pub fn newer_identity(held: IdentityRecord, incoming: IdentityRecord) -> IdentityRecord {
    if incoming.version() > held.version() {
        incoming
    } else {
        held
    }
}

/// Returns true if `incoming` is a later write than `held`.
#[must_use]
pub fn supersedes(held: &IdentityRecord, incoming: &IdentityRecord) -> bool {
    incoming.version() > held.version()
}

/// Picks the record to serve from every copy the overlay returned.
///
/// Replicas answer independently and some will be behind. Taking the greatest
/// version means a lookup is as fresh as the best-informed node that replied,
/// rather than as fresh as the fastest one.
#[must_use]
pub fn best_of(records: impl IntoIterator<Item = IdentityRecord>) -> Option<IdentityRecord> {
    records.into_iter().reduce(newer_identity)
}

/// Unions two pointer pages, dropping pointers that have expired.
///
/// Pointers are only hints, so losing one costs a discovery rather than
/// correctness, but keeping the later expiry per URI means a page that has seen
/// a republication does not regress to the pre-republication lifetime when it
/// merges with a copy that has not.
#[must_use]
pub fn merge_pages(pages: impl IntoIterator<Item = PointerPage>, now: SystemTime) -> PointerPage {
    let mut latest: HashMap<String, u64> = HashMap::new();
    for page in pages {
        for pointer in page.pointers {
            if pointer.is_expired(now) {
                continue;
            }
            latest
                .entry(pointer.agent_uri)
                .and_modify(|expiry| *expiry = (*expiry).max(pointer.expires_at_millis))
                .or_insert(pointer.expires_at_millis);
        }
    }

    let mut pointers: Vec<Pointer> = latest
        .into_iter()
        .map(|(agent_uri, expires_at_millis)| Pointer {
            agent_uri,
            expires_at_millis,
        })
        .collect();
    // Iteration order of a HashMap is not stable, and a page whose bytes differ
    // run to run would make two nodes holding the same set disagree about
    // whether they hold the same record.
    pointers.sort_by(|a, b| a.agent_uri.cmp(&b.agent_uri));
    PointerPage::new(pointers)
}

/// Returns the wider of two shard levels.
///
/// A level only ever grows. A reader at the higher level reads every page the
/// lower level's publishers write to, so taking the maximum can lose coverage
/// only in the direction of reading more keys than necessary.
#[must_use]
pub fn widest_descriptor(held: ShardDescriptor, incoming: ShardDescriptor) -> ShardDescriptor {
    ShardDescriptor::at_level(held.level.max(incoming.level))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::WireKind;
    use agent_uri::AgentUri;
    use agent_uri_attestation::SigningKey;
    use agent_uri_dht::{Endpoint, Registration};
    use std::time::Duration;

    fn record(registered_at: SystemTime, sequence: u64) -> IdentityRecord {
        let uri =
            AgentUri::parse("agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q")
                .unwrap();
        let state = Registration::new(
            uri,
            SigningKey::generate().verifying_key(),
            vec![Endpoint::https("agent.anthropic.com:443")],
        )
        .with_registered_at(registered_at)
        .with_sequence(sequence);
        IdentityRecord {
            state,
            kind: WireKind::Register,
            refresh_ttl_millis: None,
            signature: crate::record::WireSignature::new([0u8; 64]),
        }
    }

    fn epoch(offset_secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(offset_secs)
    }

    #[test]
    fn a_higher_sequence_wins_within_an_instance() {
        let old = record(epoch(1000), 3);
        let new = record(epoch(1000), 4);
        assert!(supersedes(&old, &new));
        assert_eq!(newer_identity(old, new.clone()).version(), new.version());
    }

    #[test]
    fn a_stale_replica_cannot_undo_a_fresh_write() {
        // The case that motivates the whole module: replication fires in the
        // wrong direction and hands a node a copy older than the one it holds.
        let held = record(epoch(1000), 9);
        let stale = record(epoch(1000), 2);
        assert!(!supersedes(&held, &stale));
        assert_eq!(
            newer_identity(held.clone(), stale).version(),
            held.version()
        );
    }

    #[test]
    fn a_later_instance_outranks_a_higher_sequence_in_an_earlier_one() {
        // An agent that deregisters and returns restarts its sequence at zero.
        // Ordering on the sequence alone would leave the old record on top and
        // the returning agent permanently unreachable.
        let old = record(epoch(1000), 500);
        let reborn = record(epoch(2000), 0);
        assert!(supersedes(&old, &reborn));
    }

    #[test]
    fn an_identical_version_does_not_displace_the_held_copy() {
        let held = record(epoch(1000), 4);
        let duplicate = record(epoch(1000), 4);
        assert!(!supersedes(&held, &duplicate));
    }

    #[test]
    fn merging_is_order_independent() {
        let a = record(epoch(1000), 1);
        let b = record(epoch(1000), 7);
        let c = record(epoch(2000), 0);

        let forward = best_of(vec![a.clone(), b.clone(), c.clone()]).unwrap();
        let backward = best_of(vec![c.clone(), b, a]).unwrap();
        assert_eq!(forward.version(), backward.version());
        assert_eq!(forward.version(), c.version());
    }

    #[test]
    fn best_of_nothing_is_nothing() {
        assert!(best_of(Vec::new()).is_none());
    }

    #[test]
    fn pages_union_rather_than_replace() {
        let now = epoch(1000);
        let future = now + Duration::from_mins(1);
        let a = PointerPage::new(vec![Pointer::new("agent://a.com/x/c_1", future)]);
        let b = PointerPage::new(vec![Pointer::new("agent://a.com/x/c_2", future)]);

        let merged = merge_pages(vec![a, b], now);
        assert_eq!(merged.pointers.len(), 2);
    }

    #[test]
    fn a_republished_pointer_keeps_the_later_expiry() {
        let now = epoch(1000);
        let soon = now + Duration::from_secs(10);
        let later = now + Duration::from_mins(10);
        let a = PointerPage::new(vec![Pointer::new("agent://a.com/x/c_1", soon)]);
        let b = PointerPage::new(vec![Pointer::new("agent://a.com/x/c_1", later)]);

        for pages in [vec![a.clone(), b.clone()], vec![b, a]] {
            let merged = merge_pages(pages, now);
            assert_eq!(merged.pointers.len(), 1);
            assert_eq!(
                merged.pointers[0].expires_at_millis,
                crate::record::millis(later)
            );
        }
    }

    #[test]
    fn expired_pointers_are_dropped_on_merge() {
        // Pages are grow-only, so expiry is the only thing that reclaims them.
        let now = epoch(1000);
        let page = PointerPage::new(vec![
            Pointer::new("agent://a.com/x/c_1", now - Duration::from_secs(1)),
            Pointer::new("agent://a.com/x/c_2", now + Duration::from_secs(1)),
        ]);
        let merged = merge_pages(vec![page], now);
        assert_eq!(merged.pointers.len(), 1);
        assert_eq!(merged.pointers[0].agent_uri, "agent://a.com/x/c_2");
    }

    #[test]
    fn merging_a_page_with_itself_changes_nothing() {
        let now = epoch(1000);
        let page = PointerPage::new(vec![Pointer::new(
            "agent://a.com/x/c_1",
            now + Duration::from_mins(1),
        )]);
        let once = merge_pages(vec![page.clone()], now);
        let twice = merge_pages(vec![page.clone(), page], now);
        assert_eq!(once, twice);
    }

    #[test]
    fn merged_pages_encode_identically_regardless_of_input_order() {
        // Two nodes holding the same pointer set must produce the same bytes,
        // or replication will shuttle a record back and forth forever.
        let now = epoch(1000);
        let future = now + Duration::from_mins(1);
        let pointers: Vec<Pointer> = (0..16)
            .map(|n| Pointer::new(format!("agent://a.com/x/c_{n}"), future))
            .collect();
        let forward = merge_pages(
            pointers.iter().cloned().map(|p| PointerPage::new(vec![p])),
            now,
        );
        let backward = merge_pages(
            pointers
                .iter()
                .rev()
                .cloned()
                .map(|p| PointerPage::new(vec![p])),
            now,
        );
        assert_eq!(forward.encode().unwrap(), backward.encode().unwrap());
    }

    #[test]
    fn a_descriptor_only_grows() {
        assert_eq!(
            widest_descriptor(ShardDescriptor::at_level(3), ShardDescriptor::at_level(1)).level,
            3
        );
        assert_eq!(
            widest_descriptor(ShardDescriptor::at_level(1), ShardDescriptor::at_level(3)).level,
            3
        );
    }
}
