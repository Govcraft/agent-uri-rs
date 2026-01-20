//! Run Eval 1: Capability Expressiveness with Real Corpus
//!
//! This example loads real tool definitions from JSON corpus files and evaluates
//! how well the capability path grammar can represent them.
//!
//! # Output
//!
//! - JSON results written to `results/eval1_real_corpus.json`
//! - Summary statistics printed to stdout
//!
//! # Usage
//!
//! ```bash
//! cargo run --package agent-uri-eval --example run_real_corpus -- \
//!     --corpus-dir /path/to/corpus/data/raw
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use agent_uri_eval::{
    evaluate_expressiveness, evaluate_flat_namespace, load_corpus_directory, EvaluationReport,
    ExpressivenessResults, MappingConfig,
};

/// Default corpus directory (relative to crate root).
const DEFAULT_CORPUS_DIR: &str = "corpus";

/// Output directory for results.
const RESULTS_DIR: &str = "results";

/// Output file name.
const OUTPUT_FILE: &str = "eval1_real_corpus.json";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse arguments
    let args: Vec<String> = std::env::args().collect();
    let corpus_dir = parse_corpus_dir(&args)?;

    println!("=== Eval 1: Capability Expressiveness (Real Corpus) ===\n");

    // Load corpus
    println!("Loading corpus from: {}", corpus_dir.display());
    let corpus = load_corpus_directory(&corpus_dir)?;

    println!(
        "Loaded {} tools from {} files",
        corpus.tools.len(),
        corpus.files_loaded
    );
    println!("\nSource breakdown:");
    for (source, count) in &corpus.source_counts {
        println!("  {source}: {count}");
    }

    if corpus.has_warnings() {
        println!("\nWarnings:");
        for warning in &corpus.warnings {
            println!("  - {warning}");
        }
    }
    println!();

    // Run hierarchical evaluation
    println!("Running hierarchical namespace evaluation...");
    let hierarchical = evaluate_expressiveness(&corpus.tools, &MappingConfig::default());

    // Run flat namespace evaluation (ablation)
    println!("Running flat namespace evaluation (ablation)...\n");
    let flat = evaluate_flat_namespace(&corpus.tools);

    // Print summary
    print_summary(&hierarchical, &flat);

    // Build report
    let report = EvaluationReport::new()
        .with_expressiveness(hierarchical)
        .with_expressiveness_flat(flat)
        .compute_summary();

    // Write results
    let results_dir = Path::new(RESULTS_DIR);
    if !results_dir.exists() {
        fs::create_dir_all(results_dir)?;
    }

    let output_path = results_dir.join(OUTPUT_FILE);
    let json = report.to_json()?;
    fs::write(&output_path, json)?;
    println!("\nResults written to: {}", output_path.display());

    // Report pass/fail
    if report.summary.expressiveness_passed {
        println!("\n[PASS] All expressiveness criteria met");
    } else {
        println!("\n[FAIL] Some criteria not met:");
        for criterion in &report.summary.failed_criteria {
            println!("  - {criterion}");
        }
    }

    Ok(())
}

fn parse_corpus_dir(args: &[String]) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut corpus_dir = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--corpus-dir" => {
                if i + 1 >= args.len() {
                    return Err("--corpus-dir requires a path argument".into());
                }
                corpus_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            _ => {
                return Err(format!("Unknown argument: {}", args[i]).into());
            }
        }
    }

    Ok(corpus_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_CORPUS_DIR)))
}

fn print_usage() {
    println!("Usage: run_real_corpus [OPTIONS]");
    println!();
    println!("Options:");
    println!("  --corpus-dir PATH  Directory containing corpus JSON files");
    println!("  -h, --help         Print this help message");
}

fn print_summary(hierarchical: &ExpressivenessResults, flat: &ExpressivenessResults) {
    println!("=== Hierarchical Namespace Results ===");
    println!("  Total tools:     {}", hierarchical.coverage.total_tools);
    println!("  Mapped tools:    {}", hierarchical.coverage.mapped_tools);
    println!(
        "  Coverage:        {:.1}%",
        hierarchical.coverage.coverage_rate * 100.0
    );
    println!(
        "  Unique paths:    {}",
        hierarchical.collisions.unique_paths
    );
    println!(
        "  Collisions:      {}",
        hierarchical.collisions.collision_count
    );
    println!(
        "  Collision rate:  {:.2}%",
        hierarchical.collisions.collision_rate * 100.0
    );
    println!(
        "  Mean depth:      {:.2}",
        hierarchical.depth_distribution.mean
    );
    println!("  Max depth:       {}", hierarchical.depth_distribution.max);
    println!();

    println!("=== Flat Namespace Results (Ablation) ===");
    println!("  Total tools:     {}", flat.coverage.total_tools);
    println!("  Mapped tools:    {}", flat.coverage.mapped_tools);
    println!(
        "  Coverage:        {:.1}%",
        flat.coverage.coverage_rate * 100.0
    );
    println!("  Unique paths:    {}", flat.collisions.unique_paths);
    println!("  Collisions:      {}", flat.collisions.collision_count);
    println!(
        "  Collision rate:  {:.2}%",
        flat.collisions.collision_rate * 100.0
    );
    println!();

    println!("=== Criteria Check ===");
    let status_str = |met: bool| if met { "PASS" } else { "FAIL" };
    println!(
        "  Coverage >= 90%:       {} ({:.1}%)",
        status_str(hierarchical.criteria.coverage_met.is_met()),
        hierarchical.coverage.coverage_rate * 100.0
    );
    println!(
        "  Collision rate < 1%:   {} ({:.2}%)",
        status_str(hierarchical.criteria.collision_rate_met.is_met()),
        hierarchical.collisions.collision_rate * 100.0
    );
    println!(
        "  Mean depth in [2,4]:   {} ({:.2})",
        status_str(hierarchical.criteria.depth_range_met.is_met()),
        hierarchical.depth_distribution.mean
    );
    println!(
        "  Max depth <= 10:       {} ({})",
        status_str(hierarchical.criteria.max_depth_met.is_met()),
        hierarchical.depth_distribution.max
    );
}
