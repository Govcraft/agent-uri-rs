//! Criterion benchmarks for DHT operations.
//!
//! These benchmarks support Evaluation 5 (Scalability Microbenchmarks)
//! from the agent-uri paper.
//!
//! ## Success Criteria
//!
//! | Operation | Threshold | Rationale |
//! |-----------|-----------|-----------|
//! | DHT key derivation | <5us | One SHA256, should be fast |
//! | PathTrie insert | O(d) | Linear with path depth |
//! | PathTrie get_exact | O(d) | Fast lookup |
//! | PathTrie get_prefix | O(d+n) | Scales with descendants |
//! | SimulatedDht register | Fast | Single agent registration |
//! | SimulatedDht lookup_exact | Fast | From populated DHT |
//! | SimulatedDht lookup_prefix | Scales | With result count |

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

use agent_uri::{AgentUri, CapabilityPath, TrustRoot};
use agent_uri_dht::{Dht, DhtKey, Endpoint, PathTrie, Registration, SimulatedDht};

// ============================================================================
// DhtKey Benchmarks
// ============================================================================

/// Benchmarks `DhtKey::derive()` with varying path depths (1-5 segments).
///
/// Expected: <5us per derivation (one SHA256 hash).
fn bench_dht_key_derive(c: &mut Criterion) {
    let trust_root = TrustRoot::parse("anthropic.com").expect("valid trust root");
    let paths = [
        CapabilityPath::parse("assistant").expect("valid path"),
        CapabilityPath::parse("assistant/chat").expect("valid path"),
        CapabilityPath::parse("assistant/chat/streaming").expect("valid path"),
        CapabilityPath::parse("assistant/chat/streaming/v2").expect("valid path"),
        CapabilityPath::parse("assistant/chat/streaming/v2/beta").expect("valid path"),
    ];

    let mut group = c.benchmark_group("dht_key/derive");

    for (depth, path) in paths.iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("depth", depth + 1), path, |b, path| {
            b.iter(|| DhtKey::derive(&trust_root, path));
        });
    }

    group.finish();
}

/// Benchmarks `DhtKey::derive_at_depth()` with varying depths.
///
/// Tests prefix key derivation for hierarchical queries.
fn bench_dht_key_derive_at_depth(c: &mut Criterion) {
    let trust_root = TrustRoot::parse("anthropic.com").expect("valid trust root");
    let full_path =
        CapabilityPath::parse("assistant/chat/streaming/v2/beta").expect("valid path");

    let mut group = c.benchmark_group("dht_key/derive_at_depth");

    for depth in 1..=5 {
        group.bench_with_input(BenchmarkId::new("depth", depth), &depth, |b, &depth| {
            b.iter(|| DhtKey::derive_at_depth(&trust_root, &full_path, depth));
        });
    }

    group.finish();
}

/// Benchmarks `DhtKey::distance()` computation.
///
/// Expected: Very fast (XOR of 32 bytes, ~100ns).
fn bench_dht_key_distance(c: &mut Criterion) {
    let trust_root = TrustRoot::parse("anthropic.com").expect("valid trust root");
    let path1 = CapabilityPath::parse("assistant/chat").expect("valid path");
    let path2 = CapabilityPath::parse("assistant/code").expect("valid path");

    let key1 = DhtKey::derive(&trust_root, &path1);
    let key2 = DhtKey::derive(&trust_root, &path2);

    c.bench_function("dht_key/distance", |b| {
        b.iter(|| key1.distance(&key2));
    });
}

// ============================================================================
// PathTrie Benchmarks
// ============================================================================

/// Benchmarks `PathTrie::insert()` into tries of varying sizes.
///
/// Expected: O(d) where d is path depth, independent of tree size.
fn bench_path_trie_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_trie/insert");

    for size in [100, 1000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("existing_size", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    || {
                        // Setup: create trie with existing entries
                        let mut trie = PathTrie::<String>::new();
                        for i in 0..size {
                            let path = CapabilityPath::parse(&format!(
                                "cat{}/sub{}",
                                i / 100,
                                i % 100
                            ))
                            .expect("valid path");
                            trie.insert(&path, format!("value{i}"));
                        }
                        trie
                    },
                    |mut trie| {
                        // Benchmark: insert one more entry
                        let path = CapabilityPath::parse("new/path").expect("valid path");
                        trie.insert(&path, "new_value".to_string());
                        trie
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmarks `PathTrie::get_exact()` lookup.
///
/// Expected: O(d) where d is path depth.
fn bench_path_trie_get_exact(c: &mut Criterion) {
    // Pre-populate trie with 1000 entries
    let mut trie = PathTrie::<String>::new();
    let paths: Vec<CapabilityPath> = (0..1000)
        .map(|i| {
            CapabilityPath::parse(&format!("cat{}/sub{}", i / 100, i % 100)).expect("valid path")
        })
        .collect();

    for (i, path) in paths.iter().enumerate() {
        trie.insert(path, format!("value{i}"));
    }

    let mut group = c.benchmark_group("path_trie/get_exact");

    // Benchmark lookups at different positions
    let lookup_paths = [
        ("first", CapabilityPath::parse("cat0/sub0").expect("valid path")),
        ("middle", CapabilityPath::parse("cat5/sub50").expect("valid path")),
        ("last", CapabilityPath::parse("cat9/sub99").expect("valid path")),
    ];

    for (name, path) in &lookup_paths {
        group.bench_with_input(BenchmarkId::new("position", *name), path, |b, path| {
            b.iter(|| trie.get_exact(path));
        });
    }

    group.finish();
}

/// Benchmarks `PathTrie::get_prefix()` with varying result sizes.
///
/// Expected: O(d + n) where d is path depth and n is descendant count.
fn bench_path_trie_get_prefix(c: &mut Criterion) {
    // Create trie with hierarchical structure:
    // 10 categories x 10 subcategories x 10 items = 1000 total
    let mut trie = PathTrie::<String>::new();

    for cat in 0..10 {
        for sub in 0..10 {
            for item in 0..10 {
                let path = CapabilityPath::parse(&format!("cat{cat}/sub{sub}/item{item}"))
                    .expect("valid path");
                trie.insert(&path, format!("value_{cat}_{sub}_{item}"));
            }
        }
    }

    let mut group = c.benchmark_group("path_trie/get_prefix");

    // 10 results (one subcategory)
    let prefix_10 = CapabilityPath::parse("cat0/sub0").expect("valid path");
    group.bench_function("10_results", |b| {
        b.iter(|| trie.get_prefix(&prefix_10));
    });

    // 100 results (one category)
    let prefix_100 = CapabilityPath::parse("cat0").expect("valid path");
    group.bench_function("100_results", |b| {
        b.iter(|| trie.get_prefix(&prefix_100));
    });

    group.finish();
}

// ============================================================================
// SimulatedDht Benchmarks
// ============================================================================

/// Generates a unique agent URI for benchmarking.
///
/// The TypeID suffix must be exactly 26 characters using base32 charset.
/// We use a fixed prefix and encode the index in the last few characters.
fn make_agent_uri(index: usize) -> AgentUri {
    // TypeID suffix: 26 chars using Crockford base32 (0-9, a-h, j-k, m-n, p-t, v-z)
    // Format: "01h455vb4pex5vsknk08" (20 chars) + 4 hex digits + "qq" = 26 chars
    // Using lowercase hex which is subset of base32 charset
    AgentUri::parse(&format!(
        "agent://anthropic.com/cat{}/sub{}/llm_01h455vb4pex5vsknk08{:04x}qq",
        index / 1000,
        (index / 10) % 100,
        index % 0xFFFF
    ))
    .expect("valid URI")
}

/// Benchmarks `SimulatedDht::register()` for a single agent.
///
/// Expected: Fast single registration.
fn bench_simulated_dht_register(c: &mut Criterion) {
    c.bench_function("simulated_dht/register", |b| {
        b.iter_batched(
            || {
                let dht = SimulatedDht::with_defaults();
                let uri = AgentUri::parse(
                    "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q",
                )
                .expect("valid URI");
                let endpoint = Endpoint::https("agent.anthropic.com:443");
                let registration = Registration::new(uri, vec![endpoint]);
                (dht, registration)
            },
            |(dht, registration)| {
                dht.register(registration).expect("registration succeeds");
                dht
            },
            BatchSize::SmallInput,
        );
    });
}

/// Benchmarks `SimulatedDht::lookup_exact()` from DHTs of varying sizes.
///
/// Expected: Fast lookup, some index overhead.
fn bench_simulated_dht_lookup_exact(c: &mut Criterion) {
    let mut group = c.benchmark_group("simulated_dht/lookup_exact");

    for size in [100, 1000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("dht_size", size),
            &size,
            |b, &size| {
                b.iter_batched(
                    || {
                        // Setup: populate DHT
                        let dht = SimulatedDht::with_defaults();
                        for i in 0..size {
                            let uri = make_agent_uri(i);
                            let registration = Registration::new(
                                uri,
                                vec![Endpoint::https(format!("agent{i}.anthropic.com"))],
                            );
                            // Ignore errors for duplicates at same path
                            let _ = dht.register(registration);
                        }
                        dht
                    },
                    |dht| {
                        // Benchmark: lookup
                        let trust_root = TrustRoot::parse("anthropic.com").expect("valid");
                        let path = CapabilityPath::parse("cat0/sub0").expect("valid");
                        dht.lookup_exact(&trust_root, &path).expect("lookup succeeds")
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

/// Benchmarks `SimulatedDht::lookup_prefix()` with varying result sizes.
///
/// Expected: Scales with number of results.
fn bench_simulated_dht_lookup_prefix(c: &mut Criterion) {
    // Create DHT with hierarchical structure:
    // 10 categories x 10 subcategories x 10 agents = 1000 total
    let dht = SimulatedDht::with_defaults();

    for cat in 0..10 {
        for sub in 0..10 {
            for item in 0..10 {
                // TypeID suffix: 26 chars, encode cat/sub/item in last 4 hex digits
                let index = cat * 100 + sub * 10 + item;
                let uri = AgentUri::parse(&format!(
                    "agent://anthropic.com/cat{cat}/sub{sub}/llm_01h455vb4pex5vsknk08{index:04x}qq",
                ))
                .expect("valid URI");
                let registration = Registration::new(
                    uri,
                    vec![Endpoint::https(format!(
                        "agent{cat}{sub}{item}.anthropic.com"
                    ))],
                );
                // Ignore duplicate errors
                let _ = dht.register(registration);
            }
        }
    }

    let trust_root = TrustRoot::parse("anthropic.com").expect("valid");

    let mut group = c.benchmark_group("simulated_dht/lookup_prefix");

    // ~10 results (agents in one subcategory)
    let path_10 = CapabilityPath::parse("cat0/sub0").expect("valid path");
    group.bench_function("10_results", |b| {
        b.iter(|| dht.lookup_prefix(&trust_root, &path_10));
    });

    // ~100 results (agents in one category)
    let path_100 = CapabilityPath::parse("cat0").expect("valid path");
    group.bench_function("100_results", |b| {
        b.iter(|| dht.lookup_prefix(&trust_root, &path_100));
    });

    group.finish();
}

// ============================================================================
// Memory Benchmarks
// ============================================================================

/// Benchmarks Registration creation to estimate per-registration memory.
///
/// Expected: <1KB per registration to support 100K agents in <100MB.
fn bench_memory_per_registration(c: &mut Criterion) {
    c.bench_function("memory/registration_creation", |b| {
        b.iter_batched(
            || {
                let uri = AgentUri::parse(
                    "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q",
                )
                .expect("valid URI");
                let endpoint = Endpoint::https("agent.anthropic.com:443");
                (uri, endpoint)
            },
            |(uri, endpoint)| Registration::new(uri, vec![endpoint]),
            BatchSize::SmallInput,
        );
    });
}

/// Benchmarks DHT memory scaling with registration count.
///
/// Tests memory efficiency with 1K, 10K, and 100K registrations.
fn bench_dht_memory_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory/dht_scaling");

    // Only test smaller sizes for benchmarking speed
    // 100K would take too long for repeated benchmark iterations
    for count in [1000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("registrations", count),
            &count,
            |b, &count| {
                b.iter_batched(
                    || {
                        let dht = SimulatedDht::with_defaults();
                        let registrations: Vec<Registration> = (0..count)
                            .map(|i| {
                                let uri = make_agent_uri(i);
                                Registration::new(
                                    uri,
                                    vec![Endpoint::https(format!("agent{i}.anthropic.com"))],
                                )
                            })
                            .collect();
                        (dht, registrations)
                    },
                    |(dht, registrations)| {
                        dht.register_batch(registrations).expect("batch succeeds");
                        let stats = dht.stats();
                        stats.memory_bytes()
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================

criterion_group!(
    benches,
    bench_dht_key_derive,
    bench_dht_key_derive_at_depth,
    bench_dht_key_distance,
    bench_path_trie_insert,
    bench_path_trie_get_exact,
    bench_path_trie_get_prefix,
    bench_simulated_dht_register,
    bench_simulated_dht_lookup_exact,
    bench_simulated_dht_lookup_prefix,
    bench_memory_per_registration,
    bench_dht_memory_scaling,
);

criterion_main!(benches);
