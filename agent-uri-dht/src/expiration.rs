//! When the simulator's registrations lapse, in the order they will.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::time::SystemTime;

/// The expiry schedule behind [`SimulatedDht`](crate::SimulatedDht).
///
/// Eviction has to cost about what a write costs, because the simulator evicts
/// on write. Scanning the store for lapsed records costs the size of the store
/// instead: it charges every write for records it has nothing to do with, and
/// it gets more expensive the longer the simulation runs, which is the wrong
/// direction for the one structure that exists to keep the store small (issue
/// #55). Deadlines kept in order cost only what is actually due, and a store
/// where nothing has lapsed costs one comparison.
///
/// A superseded deadline is left in the queue rather than hunted down and
/// removed: a binary heap has no way to remove from the middle, and a record
/// whose expiry moves has not become due, it has become wrong about when it
/// will. [`Expirations::current`] is the authority. A popped deadline that
/// disagrees with it describes a record that no longer holds that deadline, so
/// it is discarded rather than acted on. The queue therefore holds one entry
/// per expiry ever assigned and drains back to one per live record as those
/// instants pass.
#[derive(Debug, Default)]
pub(crate) struct Expirations {
    /// Every deadline recorded, soonest first, including superseded ones.
    due: BinaryHeap<Reverse<(SystemTime, String)>>,

    /// The deadline each live registration actually holds.
    current: HashMap<String, SystemTime>,

    /// How many queued deadlines have been looked at, ever.
    ///
    /// The whole point of this type is that a drain costs what is due rather
    /// than what is stored, and that is a claim about work done, which no
    /// amount of inspecting the result afterwards can settle. Counted only in
    /// test builds, so the measurement stays off the path it measures.
    #[cfg(test)]
    examined: usize,
}

impl Expirations {
    /// Records the deadline `uri` now holds, superseding any it held before.
    ///
    /// Called for the expiry a write results in rather than for the change to
    /// it, so an expiry moved earlier is scheduled at the earlier instant
    /// instead of waiting out the one it replaced.
    pub(crate) fn set(&mut self, uri: &str, expires_at: SystemTime) {
        self.due.push(Reverse((expires_at, uri.to_string())));
        self.current.insert(uri.to_string(), expires_at);
    }

    /// Forgets `uri`, whose record is gone.
    ///
    /// Its queued deadlines stay until they surface, where they will find
    /// nothing to match and be discarded. That is also what makes a URI safe to
    /// re-register: the new record's deadline is the current one, and the old
    /// entries can no longer speak for it.
    pub(crate) fn forget(&mut self, uri: &str) {
        self.current.remove(uri);
    }

    /// Forgets every registration.
    pub(crate) fn clear(&mut self) {
        self.due.clear();
        self.current.clear();
    }

    /// Removes and returns every registration due at or before `now`.
    ///
    /// The boundary matches [`Registration::is_expired`](crate::Registration::is_expired):
    /// a record whose deadline is exactly `now` has lapsed. Anything later is
    /// left where it is, so the work done is proportional to what is due and
    /// not to what is stored.
    pub(crate) fn take_due(&mut self, now: SystemTime) -> Vec<String> {
        let mut lapsed = Vec::new();

        while let Some(Reverse((deadline, uri))) = self.due.pop() {
            #[cfg(test)]
            {
                self.examined += 1;
            }
            if deadline > now {
                // The queue is ordered, so nothing behind this is due either.
                self.due.push(Reverse((deadline, uri)));
                break;
            }
            if self.current.get(&uri) == Some(&deadline) {
                self.current.remove(&uri);
                lapsed.push(uri);
            }
        }

        lapsed
    }

    /// How many deadlines are queued, including superseded ones.
    pub(crate) fn queued(&self) -> usize {
        self.due.len()
    }
}

#[cfg(test)]
impl Expirations {
    /// How many registrations have a deadline.
    pub(crate) fn tracked(&self) -> usize {
        self.current.len()
    }

    /// How many queued deadlines every drain so far has looked at.
    pub(crate) fn examined(&self) -> usize {
        self.examined
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(offset_secs: i64) -> SystemTime {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let offset = Duration::from_secs(offset_secs.unsigned_abs());
        if offset_secs < 0 {
            base - offset
        } else {
            base + offset
        }
    }

    /// `now` for these tests: deadlines before this have lapsed.
    fn now() -> SystemTime {
        at(0)
    }

    #[test]
    fn nothing_is_due_before_its_deadline() {
        let mut expirations = Expirations::default();
        expirations.set("agent://example.com/a/one", at(60));

        assert!(expirations.take_due(now()).is_empty());
        assert_eq!(expirations.tracked(), 1);
    }

    #[test]
    fn a_deadline_that_has_arrived_is_due() {
        // Exactly `now`, which `Registration::is_expired` counts as expired. A
        // schedule that waited for the next instant would hold a record the
        // rest of the simulator already treats as gone.
        let mut expirations = Expirations::default();
        expirations.set("agent://example.com/a/one", now());

        assert_eq!(
            expirations.take_due(now()),
            vec!["agent://example.com/a/one"]
        );
        assert_eq!(expirations.tracked(), 0);
    }

    #[test]
    fn the_soonest_deadline_comes_first() {
        let mut expirations = Expirations::default();
        expirations.set("agent://example.com/a/late", at(-1));
        expirations.set("agent://example.com/a/early", at(-60));

        assert_eq!(
            expirations.take_due(now()),
            vec!["agent://example.com/a/early", "agent://example.com/a/late"]
        );
    }

    #[test]
    fn only_what_is_due_is_examined() {
        // The reason this type exists: one lapsed record among a hundred live
        // ones costs the lapsed one and the first live one it reaches, not a
        // walk of everything stored (issue #55). Asserting on the result would
        // not show this, since a drain that read every entry and put the live
        // ones back returns the same answer and leaves the same queue.
        let mut expirations = Expirations::default();
        for index in 0..100 {
            expirations.set(&format!("agent://example.com/a/live{index}"), at(60));
        }
        expirations.set("agent://example.com/a/lapsed", at(-1));

        assert_eq!(
            expirations.take_due(now()),
            vec!["agent://example.com/a/lapsed"]
        );
        assert_eq!(
            expirations.examined(),
            2,
            "a drain must stop at the first deadline that has not arrived"
        );
        assert_eq!(expirations.queued(), 100, "a live deadline was consumed");
    }

    #[test]
    fn a_deadline_moved_later_survives_the_one_it_replaced() {
        // The superseded entry is still queued and surfaces first. Acting on
        // it would evict a record that was renewed before it ever lapsed.
        let mut expirations = Expirations::default();
        expirations.set("agent://example.com/a/one", at(-1));
        expirations.set("agent://example.com/a/one", at(60));

        assert!(expirations.take_due(now()).is_empty());
        assert_eq!(expirations.tracked(), 1);
    }

    #[test]
    fn a_deadline_moved_earlier_is_due_at_the_new_one() {
        // The record it replaced is not due until later, so a schedule that
        // only ever waited for the entry it already held would keep this one
        // past the instant it lapsed.
        let mut expirations = Expirations::default();
        expirations.set("agent://example.com/a/one", at(3600));
        expirations.set("agent://example.com/a/one", at(-1));

        assert_eq!(
            expirations.take_due(now()),
            vec!["agent://example.com/a/one"]
        );
    }

    #[test]
    fn a_forgotten_registration_is_not_due() {
        let mut expirations = Expirations::default();
        expirations.set("agent://example.com/a/one", at(-1));
        expirations.forget("agent://example.com/a/one");

        assert!(expirations.take_due(now()).is_empty());
    }

    #[test]
    fn re_registering_does_not_inherit_the_old_deadline() {
        // A URI given up and taken again is a different record at the same
        // name. The deadline the first one was carrying says nothing about the
        // second, and evicting on it would take the new record out.
        let mut expirations = Expirations::default();
        expirations.set("agent://example.com/a/one", at(-1));
        expirations.forget("agent://example.com/a/one");
        expirations.set("agent://example.com/a/one", at(3600));

        assert!(expirations.take_due(now()).is_empty());
        assert_eq!(expirations.tracked(), 1);
    }

    #[test]
    fn a_due_registration_is_reported_once() {
        let mut expirations = Expirations::default();
        expirations.set("agent://example.com/a/one", at(-60));
        expirations.set("agent://example.com/a/one", at(-1));

        assert_eq!(
            expirations.take_due(now()),
            vec!["agent://example.com/a/one"]
        );
        assert!(
            expirations.take_due(now()).is_empty(),
            "the record is gone; its remaining entries speak for nothing"
        );
    }

    #[test]
    fn clearing_forgets_everything() {
        let mut expirations = Expirations::default();
        expirations.set("agent://example.com/a/one", at(-1));
        expirations.clear();

        assert!(expirations.take_due(now()).is_empty());
        assert_eq!(expirations.queued(), 0);
        assert_eq!(expirations.tracked(), 0);
    }
}
