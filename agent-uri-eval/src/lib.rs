//! Evaluation infrastructure for the Agent Identity URI Scheme paper.
//!
//! This crate provides two evaluations:
//!
//! 1. **Capability Expressiveness** (Eval 1): Tests whether the capability path
//!    grammar can represent real-world tool definitions with high coverage and
//!    low collision rate.
//!
//! 2. **Discovery Precision** (Eval 2): Tests whether capability-based DHT
//!    routing returns agents that can handle a task with acceptable
//!    precision/recall.
//!
//! # Quick Start
//!
//! ## Eval 1: Capability Expressiveness
//!
//! ```rust
//! use agent_uri_eval::{
//!     ToolDef, ToolSource, MappingConfig,
//!     evaluate_expressiveness, evaluate_flat_namespace,
//! };
//!
//! // Create a corpus of tool definitions
//! let tools = vec![
//!     ToolDef::with_category("searchWeb", "internet", ToolSource::LangChain),
//!     ToolDef::with_category("readFile", "filesystem", ToolSource::OpenAi),
//!     ToolDef::with_category("sendEmail", "communication", ToolSource::Mcp),
//! ];
//!
//! // Run evaluation
//! let results = evaluate_expressiveness(&tools, &MappingConfig::default());
//!
//! // Check criteria
//! println!("Coverage: {:.1}%", results.coverage.coverage_rate * 100.0);
//! println!("Collision rate: {:.2}%", results.collisions.collision_rate * 100.0);
//! println!("All criteria passed: {}", results.criteria.all_passed());
//!
//! // Run ablation with flat namespace
//! let flat_results = evaluate_flat_namespace(&tools);
//! println!("Flat collision rate: {:.2}%", flat_results.collisions.collision_rate * 100.0);
//! ```
//!
//! ## Eval 2: Discovery Precision
//!
//! ```rust
//! use agent_uri::CapabilityPath;
//! use agent_uri_eval::{
//!     DiscoveryConfig, DiscoveryEvaluator, MatchMode,
//!     PathGenerator, TreeConfig, AgentIdGenerator,
//!     aggregate_results,
//! };
//!
//! // Create evaluator
//! let config = DiscoveryConfig {
//!     num_agents: 100,
//!     num_queries: 50,
//!     ..Default::default()
//! };
//! let mut evaluator = DiscoveryEvaluator::new(&config).unwrap();
//!
//! // Generate and register agents
//! let mut path_gen = PathGenerator::with_seed(42);
//! let mut id_gen = AgentIdGenerator::new("eval");
//! let paths = path_gen.generate_hierarchical(config.num_agents);
//!
//! for path in &paths {
//!     evaluator.register_agent(path, &id_gen.generate_next()).unwrap();
//! }
//!
//! // Run queries and compute metrics
//! let mut results = Vec::new();
//! for path in paths.iter().take(config.num_queries) {
//!     if let Ok(result) = evaluator.evaluate_query(path, MatchMode::Prefix) {
//!         results.push(result);
//!     }
//! }
//!
//! let summary = aggregate_results(&results, evaluator.agent_count(), false);
//! println!("Mean precision: {:.2}", summary.mean_precision);
//! println!("Mean recall: {:.2}", summary.mean_recall);
//! println!("Mean F1: {:.2}", summary.mean_f1);
//! ```
//!
//! # Success Criteria
//!
//! From the paper specification:
//!
//! | Metric | Threshold |
//! |--------|-----------|
//! | Coverage rate | >= 90% |
//! | Collision rate | < 1% |
//! | Mean path depth | 2-4 |
//! | Max path depth | <= 10 |
//! | Discovery precision | >= 0.80 |
//! | Discovery recall | >= 0.70 |
//! | Discovery F1 | >= 0.75 |
//!
//! # What Eval 2 Measures
//!
//! Discovery precision and recall are measured against [`SimulatedDht`], a
//! single in-process index holding one authoritative copy. Nothing in the
//! harness partitions, replicates, drops a peer, or times out, and every
//! registration is visible to every query that follows it. Two limits follow,
//! and both bear on how the figures may be reported (issue #57).
//!
//! **They are a conformance check, not a retrieval-quality result.**
//! [`DiscoveryEvaluator::ground_truth`] decides relevance by path containment,
//! and the store answers a prefix query by path containment, so the two sets
//! agree by construction. Precision and recall come out at 1.00 with zero
//! variance, and will for any corpus the simulator accepts. What that
//! demonstrates is real but narrow: prefix semantics hold at scale, across every
//! materialized ancestor key and across paging, and a departure from 1.00 is a
//! defect in one of those. It is not evidence that capability paths retrieve the
//! agents a task needs, because there is no gap between what the query asks and
//! what ground truth counts for a metric to measure. The number that carries
//! information about the corpus is mean result size, which is why the exact-mode
//! ablation is worth running: it reports how much of a subtree a prefix query
//! pulls in, not a better or worse score.
//!
//! **They say nothing about distributed deployment.** A real overlay answers a
//! lookup from whichever replicas it reached, and a Kademlia record cannot hold
//! a whole subtree, so an ancestor key holds sharded pointers a lookup has to
//! dereference. Those mechanisms have their own failure modes, and none of them
//! run here. Recall against a deployment is bounded above by what is measured
//! here, not estimated by it.
//!
//! [`SimulatedDht`]: agent_uri_dht::SimulatedDht
//! [`DiscoveryEvaluator::ground_truth`]: crate::DiscoveryEvaluator::ground_truth

#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod collision;
pub mod corpus;
pub mod discovery;
pub mod error;
pub mod expressiveness;
pub mod generator;
pub mod mapping;
pub mod metrics;
pub mod report;
pub mod tool_def;

// Re-exports
pub use collision::{Collision, CollisionEntry, CollisionReport};
pub use corpus::{
    CorpusFile, CorpusMetadata, LoadedCorpus, RawToolDef, RawToolParameter, load_corpus_directory,
    load_corpus_file, parse_tool_source,
};
pub use discovery::{
    DiscoveryConfig, DiscoveryEvaluator, DiscoveryResults, MatchMode, QueryResult,
    aggregate_results,
};
pub use error::{CorpusError, DiscoveryError, EvalError, MappingError};
pub use expressiveness::{
    CriteriaResults, CriterionStatus, DepthDistribution, ExpressivenessResults,
    evaluate_expressiveness, evaluate_flat_namespace,
};
pub use generator::{AgentIdGenerator, PathGenerator, TreeConfig};
pub use mapping::{MappingConfig, MappingResult, map_tool_to_path, map_tools_batch};
pub use metrics::{CoverageMetrics, Histogram, PrecisionRecallMetrics, mean, stddev};
pub use report::{EvaluationReport, EvaluationSummary, ReportMetadata};
pub use tool_def::{ToolDef, ToolSource};
