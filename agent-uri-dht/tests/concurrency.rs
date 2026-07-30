//! What `SimulatedDht` promises when more than one thread is using it.
//!
//! The crate's other tests drive one operation at a time, which is the wrong
//! shape for the two defects this file exists because of: a lock-order
//! inversion that deadlocked registration against migration (#47) and an
//! `update_endpoint` split across three lock scopes, where a reader between
//! phases saw half of a write and an interleaved `deregister` had its own
//! removal undone (#48). Both were found by reading the lock sites. Neither
//! was executed by anything, which is why each survived several refactors.
//!
//! Every test here is written against the public API, so none of them depend
//! on the state being one lock, three locks, or a lock-free structure. That is
//! the point: they describe the guarantees a caller is owed, and stay true
//! across whatever holds them up.
//!
//! Three habits worth keeping when adding to this file:
//!
//! - **Race at a barrier, not at thread spawn.** Threads started in a loop
//!   tend to run in a loop. Signing the write first and releasing everyone at
//!   once is what makes the contended window the one under test.
//! - **Bound the wait.** A lock-ordering regression reports as a run that
//!   never returns rather than a failure, so [`join_within`] fails on a
//!   deadline with a name on it instead of hanging the suite.
//! - **Watch the new test fail before trusting it.** A concurrency test that
//!   has only ever passed has not been shown to test anything: it may be
//!   asserting something the type system already guarantees, or racing a
//!   window that never opens. Every test below was run against a deliberately
//!   broken simulator and seen to fail:
//!
//!   | test | broken by |
//!   |---|---|
//!   | racing registrations | splitting the taken-check from the insert |
//!   | writes at one sequence | splitting the sequence check from the write |
//!   | ancestor propagation | writing the exact key and skipping ancestors |
//!   | orphaned entries | keeping an ancestor key after its last record left |
//!   | every operation | the three-lock revision from before #47 |
//!
//! `loom` was considered and is not used. #49 raised it for the lock-order
//! interleavings, conditioned on the state staying behind several locks; #47
//! consolidated it to one, and an exhaustive interleaving search over a single
//! lock has nothing to enumerate. It would also mean building the crate
//! against loom's primitives under `cfg(loom)`, which is a real cost to carry
//! for that.
//!
//! The register-versus-migrate deadlock that #47 closed has its own regression
//! test next to the code it guards, in `simulation.rs`.

use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use agent_uri::AgentUri;
use agent_uri_attestation::SigningKey;
use agent_uri_dht::{
    Dht, DhtError, Endpoint, Mutation, MutationProof, Query, ReadOptions, Registration,
    SimulatedDht, SimulationConfig, WriteOptions, WriteReceipt,
};
use futures::executor::block_on;

/// Long enough that a healthy run never approaches it, short enough that a
/// deadlocked one fails while someone is still watching. Every test here
/// finishes in well under a second.
const DEADLINE: Duration = Duration::from_mins(1);

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// Joins every worker, or fails on a deadline rather than hanging.
///
/// A deadlocked thread cannot be joined, so joining happens on a thread of its
/// own and the test waits on a channel instead. A worker that panicked is
/// carried back rather than swallowed: its join result is returned and
/// unwrapped by the caller, so a panic reports as a panic and only a genuine
/// hang reports as the deadline.
fn join_within<T: Send + 'static>(handles: Vec<JoinHandle<T>>) -> Vec<T> {
    let (done, finished) = mpsc::channel();
    thread::spawn(move || {
        let outcomes: Vec<_> = handles.into_iter().map(JoinHandle::join).collect();
        let _ = done.send(outcomes);
    });

    finished
        .recv_timeout(DEADLINE)
        .expect("the workers never finished: deadlocked, starved, or waiting on something that a correct implementation would have made happen")
        .into_iter()
        .map(|outcome| outcome.expect("a worker panicked"))
        .collect()
}

/// Runs `work` on `threads` threads, releasing them all at once.
///
/// The barrier is what makes these tests about concurrency rather than about
/// thread startup: without it the first worker routinely finishes before the
/// last one is spawned, and a race that is never run cannot fail.
fn race<T, F>(threads: usize, work: F) -> Vec<T>
where
    T: Send + 'static,
    F: Fn(usize) -> T + Send + Sync + 'static,
{
    let barrier = Arc::new(Barrier::new(threads));
    let work = Arc::new(work);

    join_within(
        (0..threads)
            .map(|index| {
                let barrier = Arc::clone(&barrier);
                let work = Arc::clone(&work);
                thread::spawn(move || {
                    barrier.wait();
                    work(index)
                })
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Attestation verification is off throughout. These tests are about what
/// happens when operations overlap, and a rejected token would stop them
/// before they overlapped. Registration's own authorization proof is still
/// required and still checked, because that is part of what is being raced.
fn dht() -> Arc<SimulatedDht> {
    Arc::new(SimulatedDht::new(
        SimulationConfig::default().with_verify_attestations(false),
    ))
}

/// Crockford base32, which is the alphabet an agent ID is drawn from.
const ALPHABET: &[u8] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// A distinct agent per index, all under `assistant/chat`, so they share both
/// ancestor keys and therefore contend on the same index entries.
fn agent(index: usize) -> AgentUri {
    let id = format!(
        "llm_01h455vb4pex5vsknk084sn0{}{}",
        ALPHABET[index / ALPHABET.len()] as char,
        ALPHABET[index % ALPHABET.len()] as char,
    );
    AgentUri::parse(&format!("agent://anthropic.com/assistant/chat/{id}")).unwrap()
}

fn home() -> Endpoint {
    Endpoint::https("us-east-1.agent.anthropic.com")
}

fn record(uri: &AgentUri, key: &SigningKey, endpoints: Vec<Endpoint>) -> Registration {
    Registration::new(uri.clone(), key.verifying_key(), endpoints)
}

fn register(
    dht: &SimulatedDht,
    uri: &AgentUri,
    key: &SigningKey,
    endpoints: Vec<Endpoint>,
) -> Result<WriteReceipt, DhtError> {
    let registration = record(uri, key, endpoints);
    let proof = MutationProof::sign_registration(key, &registration);
    block_on(dht.register(registration, &proof, WriteOptions::default()))
}

/// The record as the DHT currently holds it, which is what a caller preparing
/// a write would have looked up. `None` once it is deregistered.
fn current(dht: &SimulatedDht, uri: &AgentUri) -> Option<Registration> {
    lookup_exact(dht, uri.capability_path().as_str())
        .into_iter()
        .find(|r| r.agent_uri() == uri)
}

/// Signs against the record as it stands and submits, the way an agent would.
/// Returns `NotFound` if the record went away between the read and the write,
/// which is a legitimate outcome when something else is deregistering it.
fn update(
    dht: &SimulatedDht,
    uri: &AgentUri,
    key: &SigningKey,
    endpoints: Vec<Endpoint>,
) -> Result<WriteReceipt, DhtError> {
    let found = current(dht, uri).ok_or_else(|| DhtError::not_found(uri.canonical()))?;
    let mutation = Mutation::UpdateEndpoint {
        endpoints: &endpoints,
        expires_at: found.expires_at(),
    };
    let proof = MutationProof::sign_next(key, &found, &mutation);
    block_on(dht.update_endpoint(uri, endpoints, &proof, WriteOptions::default()))
}

fn refresh(
    dht: &SimulatedDht,
    uri: &AgentUri,
    key: &SigningKey,
    ttl: Duration,
) -> Result<WriteReceipt, DhtError> {
    let found = current(dht, uri).ok_or_else(|| DhtError::not_found(uri.canonical()))?;
    let expires_at = SystemTime::now() + ttl;
    let proof = MutationProof::sign_next(key, &found, &Mutation::Refresh { ttl, expires_at });
    block_on(dht.refresh(uri, ttl, expires_at, &proof, WriteOptions::default()))
}

fn deregister(dht: &SimulatedDht, uri: &AgentUri, key: &SigningKey) -> Result<(), DhtError> {
    let found = current(dht, uri).ok_or_else(|| DhtError::not_found(uri.canonical()))?;
    let proof = MutationProof::sign_next(key, &found, &Mutation::Deregister);
    block_on(dht.deregister(uri, &proof, WriteOptions::default()))
}

fn lookup(dht: &SimulatedDht, query: &Query) -> Vec<Registration> {
    block_on(dht.lookup(query, &ReadOptions::default()))
        .expect("the simulator never fails a lookup")
        .into_items()
}

fn lookup_prefix(dht: &SimulatedDht, path: &str) -> Vec<Registration> {
    lookup(dht, &Query::prefix(root(), parse_path(path)))
}

fn lookup_exact(dht: &SimulatedDht, path: &str) -> Vec<Registration> {
    lookup(dht, &Query::exact(root(), parse_path(path)))
}

fn root() -> agent_uri::TrustRoot {
    agent_uri::TrustRoot::parse("anthropic.com").unwrap()
}

fn parse_path(path: &str) -> agent_uri::CapabilityPath {
    agent_uri::CapabilityPath::parse(path).unwrap()
}

/// Every agent registered here sits at `assistant/chat`, so once the last one
/// leaves both ancestor keys should be gone rather than left holding an empty
/// list. An orphaned key is the shape #48's interleaving produced.
fn assert_empty(dht: &SimulatedDht) {
    let stats = dht.stats();
    assert_eq!(
        stats.total_registrations, 0,
        "the URI index still has entries"
    );
    assert_eq!(
        stats.unique_keys, 0,
        "an ancestor key outlived its last record"
    );
    assert!(lookup_prefix(dht, "assistant").is_empty());
}

/// Checks that both ancestor keys agree about who is present. A record written
/// to one and not the other is discoverable by an exact query and invisible to
/// a broader one, which is the failure a caller would report as a flaky DHT.
fn assert_indices_agree(dht: &SimulatedDht, expected: &HashSet<String>) {
    let uris = |records: Vec<Registration>| {
        records
            .into_iter()
            .map(|r| r.agent_uri().canonical())
            .collect::<HashSet<_>>()
    };

    assert_eq!(&uris(lookup_prefix(dht, "assistant")), expected);
    assert_eq!(&uris(lookup_exact(dht, "assistant/chat")), expected);
    assert_eq!(dht.stats().total_registrations, expected.len());
    assert_eq!(
        dht.stats().unique_keys,
        usize::from(!expected.is_empty()) * 2,
        "one key per ancestor depth while anyone is registered, none once nobody is",
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Registration checks whether a URI is taken and then takes it. Those are one
/// step or they are a race, and if they are a race then two agents both find
/// the URI free and the second silently overwrites the first's record,
/// including the key that says who may change it later.
#[test]
fn only_one_of_many_racing_registrations_is_accepted() {
    const CLAIMANTS: usize = 8;

    let dht = dht();
    let uri = agent(0);
    let key = SigningKey::generate();

    let outcomes = {
        let (dht, uri, key) = (Arc::clone(&dht), uri.clone(), key.clone());
        race(CLAIMANTS, move |index| {
            // A distinct endpoint per claimant, so the winner is identifiable
            // rather than merely counted.
            let endpoint = Endpoint::https(format!("claimant-{index}.anthropic.com"));
            register(&dht, &uri, &key, vec![endpoint]).map(|_| index)
        })
    };

    let winners: Vec<usize> = outcomes
        .iter()
        .filter_map(|o| o.as_ref().ok())
        .copied()
        .collect();
    assert_eq!(winners.len(), 1, "exactly one claimant takes the URI");

    for outcome in &outcomes {
        assert!(
            matches!(outcome, Ok(_) | Err(DhtError::AlreadyRegistered { .. })),
            "a loser is told the URI is taken, not something else: {outcome:?}",
        );
    }

    // The record is the winner's, whole. A second registration that landed on
    // top would show up here as somebody else's endpoint.
    let stored = current(&dht, &uri).expect("the winner's record is there");
    assert_eq!(
        stored.endpoints(),
        [Endpoint::https(format!(
            "claimant-{}.anthropic.com",
            winners[0]
        ))],
    );
    assert_indices_agree(&dht, &HashSet::from([uri.canonical()]));
}

/// Every writer signs against the record it read, so two writers that read the
/// same record produce two proofs at the same position. Applying both would
/// lose the first write while telling its author it succeeded. The sequence
/// check and the write have to be one step for the second to be refused.
#[test]
fn only_one_of_many_writes_at_the_same_sequence_is_accepted() {
    const WRITERS: usize = 8;

    let dht = dht();
    let uri = agent(0);
    let key = SigningKey::generate();
    register(&dht, &uri, &key, vec![home()]).unwrap();

    // Every writer signs against the same observed record, off the critical
    // path, so the barrier releases eight ready-to-apply writes at once.
    let found = current(&dht, &uri).unwrap();
    assert_eq!(found.sequence(), 0);

    let outcomes = {
        let (dht, uri, key) = (Arc::clone(&dht), uri.clone(), key.clone());
        race(WRITERS, move |index| {
            let endpoints = vec![Endpoint::https(format!("writer-{index}.anthropic.com"))];
            let mutation = Mutation::UpdateEndpoint {
                endpoints: &endpoints,
                expires_at: found.expires_at(),
            };
            let proof = MutationProof::sign_next(&key, &found, &mutation);
            block_on(dht.update_endpoint(&uri, endpoints, &proof, WriteOptions::default()))
                .map(|_| index)
        })
    };

    let winners: Vec<usize> = outcomes
        .iter()
        .filter_map(|o| o.as_ref().ok())
        .copied()
        .collect();
    assert_eq!(
        winners.len(),
        1,
        "exactly one write at a given position lands"
    );

    for outcome in &outcomes {
        assert!(
            matches!(outcome, Ok(_) | Err(DhtError::StaleSequence { .. })),
            "a loser is told its position was taken: {outcome:?}",
        );
    }

    let stored = current(&dht, &uri).expect("the record survives the contest");
    assert_eq!(
        stored.endpoints(),
        [Endpoint::https(format!(
            "writer-{}.anthropic.com",
            winners[0]
        ))],
    );
    assert_eq!(stored.sequence(), 1, "the record advanced exactly once");
}

/// A write reaches every ancestor key, or it reaches some of them and the
/// record answers differently depending on which query found it.
///
/// The reader here queries the broad ancestor key while the writer flips the
/// record between two endpoint sets, and it insists on eventually observing
/// both. That is the assertion with teeth. Checking only that each observed
/// value is *one of* the two would pass against an implementation that updated
/// the exact key and left the ancestor copy at its original value forever,
/// because a stale value is still a published one.
///
/// It is deliberately not asserting that a reader never catches a set with one
/// endpoint from each write. Endpoints are replaced as a whole under the lock,
/// so no reader can observe half of one, and a test that cannot fail is worse
/// than no test: it reads as coverage.
#[test]
fn an_update_reaches_the_ancestor_keys_a_reader_queries() {
    const READERS: usize = 4;

    let dht = dht();
    let uri = agent(0);
    let key = SigningKey::generate();

    let one = vec![Endpoint::https("one.anthropic.com")];
    let two = vec![
        Endpoint::https("two-a.anthropic.com"),
        Endpoint::https("two-b.anthropic.com"),
    ];
    register(&dht, &uri, &key, one.clone()).unwrap();

    // The writer keeps flipping until every reader has seen both values, so
    // the test never depends on a reader being scheduled inside a fixed number
    // of writes. If a value never propagates, no reader ever finishes and the
    // deadline reports it.
    let satisfied = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(READERS + 1));
    let mut handles = Vec::new();

    handles.push({
        let (dht, uri, key) = (Arc::clone(&dht), uri.clone(), key.clone());
        let (one, two) = (one.clone(), two.clone());
        let (barrier, satisfied) = (Arc::clone(&barrier), Arc::clone(&satisfied));
        thread::spawn(move || {
            barrier.wait();
            let mut flip = 0_usize;
            while satisfied.load(Ordering::Acquire) < READERS {
                let next = if flip.is_multiple_of(2) {
                    two.clone()
                } else {
                    one.clone()
                };
                update(&dht, &uri, &key, next).expect("the writer owns this record");
                flip += 1;
            }
        })
    });

    for _ in 0..READERS {
        let (dht, uri) = (Arc::clone(&dht), uri.clone());
        let (one, two) = (one.clone(), two.clone());
        let (barrier, satisfied) = (Arc::clone(&barrier), Arc::clone(&satisfied));
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut seen: HashSet<Vec<Endpoint>> = HashSet::new();
            while seen.len() < 2 {
                for found in lookup_prefix(&dht, "assistant") {
                    assert_eq!(found.agent_uri(), &uri);
                    assert!(
                        found.endpoints() == one || found.endpoints() == two,
                        "a reader saw a record that was never published: {:?}",
                        found.endpoints(),
                    );
                    seen.insert(found.endpoints().to_vec());
                }
            }
            satisfied.fetch_add(1, Ordering::Release);
        }));
    }

    join_within(handles);
}

/// The indices are only consistent with each other between operations, so the
/// question a churn test answers is whether every operation puts them back.
/// Registering writes to two ancestor keys and one URI entry; deregistering
/// takes all three away, and takes the ancestor key itself away once its last
/// record leaves. An interleaving that skips a step leaves an agent findable
/// by one query and not another, or leaves a key behind holding nothing.
#[test]
fn concurrent_churn_leaves_no_orphaned_index_entries() {
    const AGENTS: usize = 8;
    const ROUNDS: usize = 50;

    let dht = dht();
    let keys: Vec<SigningKey> = (0..AGENTS).map(|_| SigningKey::generate()).collect();

    {
        let (dht, keys) = (Arc::clone(&dht), keys.clone());
        race(AGENTS, move |index| {
            let (uri, key) = (agent(index), &keys[index]);
            for _ in 0..ROUNDS {
                register(&dht, &uri, key, vec![home()]).expect("a free URI can be claimed");
                deregister(&dht, &uri, key).expect("its own key gives it up");
            }
        });
    }

    // Everyone left, so nothing may remain: not a URI entry, and not an
    // ancestor key holding an empty list.
    assert_empty(&dht);

    // And again, with half the agents staying, because "removes everything"
    // and "removes exactly the right thing" are different properties and only
    // the second one is interesting.
    let stayers: HashSet<String> = {
        let (dht, keys) = (Arc::clone(&dht), keys.clone());
        race(AGENTS, move |index| {
            let (uri, key) = (agent(index), &keys[index]);
            for _ in 0..ROUNDS {
                register(&dht, &uri, key, vec![home()]).expect("a free URI can be claimed");
                deregister(&dht, &uri, key).expect("its own key gives it up");
            }
            register(&dht, &uri, key, vec![home()]).expect("a free URI can be claimed");
            if index.is_multiple_of(2) {
                Some(uri.canonical())
            } else {
                deregister(&dht, &uri, key).expect("its own key gives it up");
                None
            }
        })
        .into_iter()
        .flatten()
        .collect()
    };

    assert_eq!(stayers.len(), AGENTS.div_ceil(2));
    assert_indices_agree(&dht, &stayers);
}

/// Every operation the trait offers, run against every other one at once.
///
/// The specific pairing that deadlocked was registration against migration,
/// but nothing made that pair special: it was the only pair anyone had looked
/// at. This runs all of them, including `expire_stale`, which takes the write
/// lock without going through the trait and so is the path least likely to be
/// remembered when the locking changes.
#[test]
fn every_operation_runs_against_every_other_without_deadlock() {
    const AGENTS: usize = 6;
    const ROUNDS: usize = 40;
    const SWEEPS: usize = 200;

    let dht = dht();
    let keys: Vec<SigningKey> = (0..AGENTS).map(|_| SigningKey::generate()).collect();
    for (index, key) in keys.iter().enumerate() {
        register(&dht, &agent(index), key, vec![home()]).unwrap();
    }

    let running = Arc::new(AtomicUsize::new(AGENTS));
    let barrier = Arc::new(Barrier::new(AGENTS + 2));
    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    // One worker per agent, each cycling through every mutating operation.
    // Agents are disjoint so that a lost race cannot be mistaken for a hang.
    for (index, key) in keys.iter().enumerate() {
        let (dht, uri, key) = (Arc::clone(&dht), agent(index), key.clone());
        let (barrier, running) = (Arc::clone(&barrier), Arc::clone(&running));
        handles.push(thread::spawn(move || {
            barrier.wait();
            for round in 0..ROUNDS {
                let moved = Endpoint::https(format!("eu-west-{round}.agent.anthropic.com"));
                dht.simulate_migration(&uri, moved, &key)
                    .expect("a registered agent migrates");
                update(&dht, &uri, &key, vec![home()]).expect("its own key repoints it");
                refresh(&dht, &uri, &key, Duration::from_hours(2)).expect("its own key renews it");
                deregister(&dht, &uri, &key).expect("its own key gives it up");
                register(&dht, &uri, &key, vec![home()]).expect("and takes it back");
            }
            running.fetch_sub(1, Ordering::Release);
        }));
    }

    // A reader, because a lookup takes the read side and a writer starved by
    // readers is its own kind of hang.
    handles.push({
        let (dht, barrier, running) =
            (Arc::clone(&dht), Arc::clone(&barrier), Arc::clone(&running));
        thread::spawn(move || {
            barrier.wait();
            while running.load(Ordering::Acquire) > 0 {
                for found in lookup_prefix(&dht, "assistant") {
                    assert_eq!(found.endpoints().len(), 1, "a record is never half-written");
                }
            }
        })
    });

    // A sweeper, for the write path that does not go through the trait. TTLs
    // here are hours, so it should never actually remove anything: if it does,
    // expiry has started disagreeing with what refresh just wrote.
    handles.push({
        let (dht, barrier) = (Arc::clone(&dht), Arc::clone(&barrier));
        thread::spawn(move || {
            barrier.wait();
            for _ in 0..SWEEPS {
                assert_eq!(dht.expire_stale(), 0, "nothing registered here has expired");
            }
        })
    });

    join_within(handles);

    // Each worker's last act was to register, so everyone is present and both
    // ancestor keys say so.
    let expected: HashSet<String> = (0..AGENTS).map(|index| agent(index).canonical()).collect();
    assert_indices_agree(&dht, &expected);
}
