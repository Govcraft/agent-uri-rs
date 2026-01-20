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

#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod collision;
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
pub use discovery::{
    aggregate_results, DiscoveryConfig, DiscoveryEvaluator, DiscoveryResults, MatchMode,
    QueryResult,
};
pub use error::{CorpusError, DiscoveryError, EvalError, MappingError};
pub use expressiveness::{
    evaluate_expressiveness, evaluate_flat_namespace, CriteriaResults, CriterionStatus,
    DepthDistribution, ExpressivenessResults,
};
pub use generator::{AgentIdGenerator, PathGenerator, TreeConfig};
pub use mapping::{map_tool_to_path, map_tools_batch, MappingConfig, MappingResult};
pub use metrics::{mean, stddev, CoverageMetrics, Histogram, PrecisionRecallMetrics};
pub use report::{EvaluationReport, EvaluationSummary, ReportMetadata};
pub use tool_def::{ToolDef, ToolSource};
