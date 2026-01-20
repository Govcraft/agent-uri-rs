//! Run Eval 2: Discovery Precision Evaluation
//!
//! This example generates synthetic agents with capability paths and evaluates
//! how well the DHT-based discovery returns relevant results.
//!
//! # Configuration
//!
//! Environment variables (with defaults):
//! - `EVAL_NUM_AGENTS`: Number of agents to register (default: 100)
//! - `EVAL_NUM_QUERIES`: Number of queries to run (default: 100)
//! - `EVAL_SEED`: Random seed for reproducibility (default: 42)
//!
//! # Output
//!
//! - JSON results written to `results/eval2_discovery.json`
//! - Summary statistics printed to stdout
//!
//! # Usage
//!
//! ```bash
//! cargo run --package agent-uri-eval --example run_discovery
//!
//! # With custom configuration
//! EVAL_NUM_AGENTS=500 EVAL_NUM_QUERIES=500 cargo run --package agent-uri-eval --example run_discovery
//! ```

use std::env;
use std::fs;
use std::path::Path;

use agent_uri_eval::{
    aggregate_results, DiscoveryConfig, DiscoveryEvaluator, EvaluationReport, MatchMode,
    PathGenerator,
};

/// Directory to write results to.
const RESULTS_DIR: &str = "results";

/// Output file name.
const OUTPUT_FILE: &str = "eval2_discovery.json";

/// Default number of agents.
///
/// Note: The simulated DHT has a default capacity of 20 registrations per key.
/// With hierarchical paths, multiple agents may share prefixes. Using a smaller
/// number of agents (100-200) avoids hitting capacity limits. For larger
/// evaluations, the DHT capacity would need to be increased in the library.
const DEFAULT_NUM_AGENTS: usize = 100;

/// Default number of queries.
const DEFAULT_NUM_QUERIES: usize = 100;

/// Default random seed.
const DEFAULT_SEED: u64 = 42;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Eval 2: Discovery Precision ===\n");

    // Parse configuration from environment
    let config = parse_config();
    println!("Configuration:");
    println!("  Agents:  {}", config.num_agents);
    println!("  Queries: {}", config.num_queries);
    println!("  Seed:    {}", config.seed);
    println!();

    // Create evaluator
    let mut evaluator = DiscoveryEvaluator::new(&config)?;

    // Generate capability paths
    println!("Generating hierarchical capability paths...");
    let mut path_gen = PathGenerator::with_seed(config.seed);
    let paths = path_gen.generate_hierarchical(config.num_agents);
    println!("  Generated {} unique paths", paths.len());

    // Register agents with valid TypeID prefixes
    // AgentId requires prefixes to be lowercase letters only (no digits)
    // We use type classes like "llm", "rule", "hybrid", etc.
    println!("Registering agents...");
    let type_prefixes = ["llm", "rule", "hybrid", "sensor", "actuator", "composite"];
    for (i, path) in paths.iter().enumerate() {
        // Cycle through type prefixes and add a letter suffix for uniqueness
        let prefix_base = type_prefixes[i % type_prefixes.len()];
        // Use letter suffixes (a-z repeated) to ensure valid prefix
        let suffix_letters = generate_letter_suffix(i);
        let agent_prefix = format!("{prefix_base}_{suffix_letters}");
        evaluator.register_agent(path, &agent_prefix)?;
    }
    println!("  Registered {} agents", evaluator.agent_count());
    println!();

    // Run prefix-mode queries
    println!("Running prefix-mode queries...");
    let prefix_results = run_queries(&evaluator, &paths, MatchMode::Prefix, config.num_queries)?;
    let prefix_summary = aggregate_results(&prefix_results, evaluator.agent_count(), false);

    // Run exact-mode queries (ablation)
    println!("Running exact-mode queries (ablation)...");
    let exact_results = run_queries(&evaluator, &paths, MatchMode::Exact, config.num_queries)?;
    let exact_summary = aggregate_results(&exact_results, evaluator.agent_count(), false);
    println!();

    // Print summary
    print_summary(&prefix_summary, &exact_summary);

    // Build report
    let report = EvaluationReport::new()
        .with_discovery_prefix(prefix_summary)
        .with_discovery_exact(exact_summary)
        .compute_summary();

    // Ensure results directory exists
    let results_dir = Path::new(RESULTS_DIR);
    if !results_dir.exists() {
        fs::create_dir_all(results_dir)?;
    }

    // Write JSON output
    let output_path = results_dir.join(OUTPUT_FILE);
    let json = report.to_json()?;
    fs::write(&output_path, json)?;
    println!("\nResults written to: {}", output_path.display());

    // Report success/failure
    if report.summary.discovery_passed {
        println!("\n[PASS] All discovery criteria met");
    } else {
        println!("\n[FAIL] Some criteria not met:");
        for criterion in &report.summary.failed_criteria {
            println!("  - {criterion}");
        }
    }

    Ok(())
}

/// Parses configuration from environment variables.
fn parse_config() -> DiscoveryConfig {
    let num_agents = env::var("EVAL_NUM_AGENTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_NUM_AGENTS);

    let num_queries = env::var("EVAL_NUM_QUERIES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_NUM_QUERIES);

    let seed = env::var("EVAL_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SEED);

    DiscoveryConfig {
        num_agents,
        num_queries,
        seed,
        ..Default::default()
    }
}

/// Runs queries and collects results.
fn run_queries(
    evaluator: &DiscoveryEvaluator,
    paths: &[agent_uri::CapabilityPath],
    mode: MatchMode,
    num_queries: usize,
) -> Result<Vec<agent_uri_eval::QueryResult>, Box<dyn std::error::Error>> {
    let mut results = Vec::with_capacity(num_queries);

    // Use a subset of registered paths as queries
    // This ensures queries will have at least some matches
    for path in paths.iter().take(num_queries) {
        match evaluator.evaluate_query(path, mode) {
            Ok(result) => results.push(result),
            Err(e) => {
                // Log error but continue with other queries
                eprintln!("  Warning: query failed for {}: {e}", path.as_str());
            }
        }
    }

    println!("  Completed {} queries", results.len());
    Ok(results)
}

/// Prints a summary of the evaluation results.
fn print_summary(
    prefix: &agent_uri_eval::DiscoveryResults,
    exact: &agent_uri_eval::DiscoveryResults,
) {
    println!("=== Prefix Mode Results ===");
    println!("  Queries:         {}", prefix.num_queries);
    println!("  Mean precision:  {:.3}", prefix.mean_precision);
    println!("  Mean recall:     {:.3}", prefix.mean_recall);
    println!("  Mean F1:         {:.3}", prefix.mean_f1);
    println!("  Stddev prec:     {:.3}", prefix.stddev_precision);
    println!("  Stddev recall:   {:.3}", prefix.stddev_recall);
    println!("  Mean result size: {:.1}", prefix.mean_result_size);
    println!();

    println!("=== Exact Mode Results (Ablation) ===");
    println!("  Queries:         {}", exact.num_queries);
    println!("  Mean precision:  {:.3}", exact.mean_precision);
    println!("  Mean recall:     {:.3}", exact.mean_recall);
    println!("  Mean F1:         {:.3}", exact.mean_f1);
    println!("  Stddev prec:     {:.3}", exact.stddev_precision);
    println!("  Stddev recall:   {:.3}", exact.stddev_recall);
    println!("  Mean result size: {:.1}", exact.mean_result_size);
    println!();

    println!("=== Criteria Check (Prefix Mode) ===");
    println!(
        "  Precision >= 0.80:  {} ({:.3})",
        status_str(prefix.mean_precision >= 0.80),
        prefix.mean_precision
    );
    println!(
        "  Recall >= 0.70:     {} ({:.3})",
        status_str(prefix.mean_recall >= 0.70),
        prefix.mean_recall
    );
    println!(
        "  F1 >= 0.75:         {} ({:.3})",
        status_str(prefix.mean_f1 >= 0.75),
        prefix.mean_f1
    );
}

/// Converts a boolean to a status string.
fn status_str(passed: bool) -> &'static str {
    if passed {
        "PASS"
    } else {
        "FAIL"
    }
}

/// Generates a letter-only suffix for the given index.
///
/// Converts index to base-26 representation using letters a-z.
/// Examples: 0 -> "a", 25 -> "z", 26 -> "ba", 702 -> "baa"
fn generate_letter_suffix(index: usize) -> String {
    let mut result = String::new();
    let mut n = index;

    loop {
        let remainder = n % 26;
        let c = (b'a' + remainder as u8) as char;
        result.insert(0, c);
        n /= 26;
        if n == 0 {
            break;
        }
        // Adjust for 1-indexed conversion (like Excel columns)
        n -= 1;
    }

    result
}
