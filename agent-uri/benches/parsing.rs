//! Criterion benchmarks for agent-uri scalability evaluation.
//!
//! These benchmarks support Evaluation 5 (Scalability) in the academic paper.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use agent_uri::{AgentId, AgentUri, AgentUriBuilder, CapabilityPath, TrustRoot};

/// Benchmark: AgentUri::parse with varying URI lengths
fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse");

    // Test cases with varying complexity
    let test_cases = [
        ("minimal", "agent://a.co/x/llm_01h455vb4pex5vsknk084sn02q"),
        (
            "typical",
            "agent://anthropic.com/assistant/chat/llm_chat_01h455vb4pex5vsknk084sn02q",
        ),
        (
            "deep_path",
            "agent://example.com/level1/level2/level3/level4/level5/llm_01h455vb4pex5vsknk084sn02q",
        ),
        (
            "with_query",
            "agent://example.com/tool/code/llm_01h455vb4pex5vsknk084sn02q?version=2.0&ttl=300",
        ),
        (
            "with_fragment",
            "agent://example.com/tool/code/llm_01h455vb4pex5vsknk084sn02q#summarization",
        ),
        (
            "full",
            "agent://example.com/tool/code/llm_01h455vb4pex5vsknk084sn02q?version=2.0#summarization",
        ),
    ];

    for (name, uri) in test_cases {
        group.throughput(Throughput::Bytes(uri.len() as u64));
        group.bench_with_input(BenchmarkId::new("uri", name), &uri, |b, uri| {
            b.iter(|| AgentUri::parse(black_box(uri)));
        });
    }

    group.finish();
}

/// Benchmark: AgentUri canonical form generation
fn bench_canonical(c: &mut Criterion) {
    let mut group = c.benchmark_group("canonical");

    let test_cases = [
        (
            "no_extras",
            "agent://anthropic.com/assistant/chat/llm_01h455vb4pex5vsknk084sn02q",
        ),
        (
            "with_query",
            "agent://example.com/tool/code/llm_01h455vb4pex5vsknk084sn02q?version=2.0",
        ),
        (
            "with_fragment",
            "agent://example.com/tool/code/llm_01h455vb4pex5vsknk084sn02q#test",
        ),
        (
            "full",
            "agent://example.com/tool/code/llm_01h455vb4pex5vsknk084sn02q?version=2.0#test",
        ),
    ];

    for (name, uri_str) in test_cases {
        let uri = AgentUri::parse(uri_str).expect("valid test URI");
        group.bench_with_input(BenchmarkId::new("canonical", name), &uri, |b, uri| {
            b.iter(|| black_box(uri).canonical());
        });
    }

    group.finish();
}

/// Benchmark: CapabilityPath::starts_with at varying depths
fn bench_starts_with(c: &mut Criterion) {
    let mut group = c.benchmark_group("starts_with");

    // Create paths of varying depths
    let depths = [1, 2, 4, 8, 16];

    for depth in depths {
        let segments: Vec<&str> = (0..depth)
            .map(|i| match i % 4 {
                0 => "alpha",
                1 => "beta",
                2 => "gamma",
                _ => "delta",
            })
            .collect();

        let path_str = segments.join("/");
        let path = CapabilityPath::parse(&path_str).expect("valid test path");

        // Test starts_with against half-depth prefix
        let prefix_depth = (depth / 2).max(1);
        let prefix_str = segments[..prefix_depth].join("/");
        let prefix = CapabilityPath::parse(&prefix_str).expect("valid test prefix");

        group.bench_with_input(
            BenchmarkId::new("depth", depth),
            &(path, prefix),
            |b, (path, prefix)| {
                b.iter(|| black_box(path).starts_with(black_box(prefix)));
            },
        );
    }

    group.finish();
}

/// Benchmark: Builder pattern construction
fn bench_builder(c: &mut Criterion) {
    let mut group = c.benchmark_group("builder");

    // Pre-parse components for fair comparison
    let trust_root = TrustRoot::parse("anthropic.com").expect("valid trust root");
    let cap_path = CapabilityPath::parse("assistant/chat").expect("valid capability path");
    let agent_id = AgentId::new("llm_chat");

    group.bench_function("with_components", |b| {
        b.iter(|| {
            AgentUriBuilder::new()
                .trust_root(black_box(trust_root.clone()))
                .capability_path(black_box(cap_path.clone()))
                .agent_id(black_box(agent_id.clone()))
                .build()
        });
    });

    group.bench_function("with_try_methods", |b| {
        b.iter(|| {
            AgentUriBuilder::new()
                .try_trust_root(black_box("anthropic.com"))
                .expect("valid trust root")
                .try_capability_path(black_box("assistant/chat"))
                .expect("valid capability path")
                .try_agent_id(black_box("llm_chat_01h455vb4pex5vsknk084sn02q"))
                .expect("valid agent id")
                .build()
        });
    });

    group.finish();
}

/// Benchmark: CapabilityPath construction methods
fn bench_capability_path_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("capability_path_construction");

    // Benchmark parse
    group.bench_function("parse", |b| {
        b.iter(|| CapabilityPath::parse(black_box("assistant/chat/streaming")));
    });

    // Benchmark try_from_strs
    group.bench_function("try_from_strs", |b| {
        b.iter(|| CapabilityPath::try_from_strs(black_box(&["assistant", "chat", "streaming"])));
    });

    // Benchmark from_segments (pre-parsed)
    use agent_uri::PathSegment;
    let segments = vec![
        PathSegment::parse("assistant").expect("valid"),
        PathSegment::parse("chat").expect("valid"),
        PathSegment::parse("streaming").expect("valid"),
    ];

    group.bench_function("from_segments", |b| {
        b.iter(|| CapabilityPath::from_segments(black_box(segments.clone())));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_parse,
    bench_canonical,
    bench_starts_with,
    bench_builder,
    bench_capability_path_construction,
);
criterion_main!(benches);
