//! Run Eval 1: Capability Expressiveness Evaluation
//!
//! This example generates a synthetic corpus of tool definitions and evaluates
//! how well the capability path grammar can represent them.
//!
//! # Output
//!
//! - JSON results written to `results/eval1_expressiveness.json`
//! - Summary statistics printed to stdout
//!
//! # Usage
//!
//! ```bash
//! cargo run --package agent-uri-eval --example run_expressiveness
//! ```

use std::fs;
use std::path::Path;

use agent_uri_eval::{
    evaluate_expressiveness, evaluate_flat_namespace, EvaluationReport, MappingConfig, ToolDef,
    ToolSource,
};

/// Number of synthetic tools to generate per source.
const TOOLS_PER_SOURCE: usize = 100;

/// Directory to write results to.
const RESULTS_DIR: &str = "results";

/// Output file name.
const OUTPUT_FILE: &str = "eval1_expressiveness.json";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Eval 1: Capability Expressiveness ===\n");

    // Generate synthetic corpus
    let corpus = generate_synthetic_corpus();
    println!("Generated {} tool definitions\n", corpus.len());

    // Run hierarchical evaluation (default config)
    println!("Running hierarchical namespace evaluation...");
    let hierarchical = evaluate_expressiveness(&corpus, &MappingConfig::default());

    // Run flat namespace evaluation (ablation)
    println!("Running flat namespace evaluation (ablation)...\n");
    let flat = evaluate_flat_namespace(&corpus);

    // Print summary
    print_summary(&hierarchical, &flat);

    // Build report
    let report = EvaluationReport::new()
        .with_expressiveness(hierarchical)
        .with_expressiveness_flat(flat)
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

/// Generates a synthetic corpus of tool definitions.
///
/// Creates tools with various naming patterns across multiple sources
/// to simulate real-world tool ecosystems.
fn generate_synthetic_corpus() -> Vec<ToolDef> {
    let mut corpus = Vec::with_capacity(TOOLS_PER_SOURCE * 5);

    // LangChain-style tools (snake_case with categories)
    let langchain_tools = [
        ("search_web", "internet"),
        ("search_images", "internet"),
        ("read_file", "filesystem"),
        ("write_file", "filesystem"),
        ("list_directory", "filesystem"),
        ("execute_command", "system"),
        ("get_env_variable", "system"),
        ("send_http_request", "network"),
        ("parse_json", "data"),
        ("query_database", "database"),
        ("insert_record", "database"),
        ("delete_record", "database"),
        ("create_vector_store", "ml"),
        ("embed_text", "ml"),
        ("similarity_search", "ml"),
        ("generate_text", "llm"),
        ("summarize_text", "llm"),
        ("translate_text", "llm"),
        ("extract_entities", "nlp"),
        ("sentiment_analysis", "nlp"),
    ];
    for (name, category) in langchain_tools {
        corpus.push(ToolDef::with_category(name, category, ToolSource::LangChain));
    }

    // MCP-style tools (camelCase with namespaces)
    let mcp_tools = [
        ("searchWeb", "browser"),
        ("clickElement", "browser"),
        ("typeText", "browser"),
        ("takeScreenshot", "browser"),
        ("readFile", "fs"),
        ("writeFile", "fs"),
        ("deleteFile", "fs"),
        ("createDirectory", "fs"),
        ("runCommand", "shell"),
        ("getProcesses", "shell"),
        ("sendEmail", "email"),
        ("readInbox", "email"),
        ("createCalendarEvent", "calendar"),
        ("getWeather", "api"),
        ("getNews", "api"),
        ("getStockPrice", "api"),
        ("translateText", "language"),
        ("detectLanguage", "language"),
        ("compressImage", "media"),
        ("convertVideo", "media"),
    ];
    for (name, category) in mcp_tools {
        corpus.push(ToolDef::with_category(name, category, ToolSource::Mcp));
    }

    // OpenAI-style tools (function names)
    let openai_tools = [
        ("get_current_weather", "weather"),
        ("search_products", "ecommerce"),
        ("add_to_cart", "ecommerce"),
        ("checkout", "ecommerce"),
        ("get_user_profile", "user"),
        ("update_preferences", "user"),
        ("send_notification", "notification"),
        ("schedule_reminder", "notification"),
        ("create_task", "productivity"),
        ("list_tasks", "productivity"),
        ("complete_task", "productivity"),
        ("search_knowledge_base", "knowledge"),
        ("add_document", "knowledge"),
        ("ask_question", "qa"),
        ("get_answer", "qa"),
        ("analyze_data", "analytics"),
        ("generate_report", "analytics"),
        ("create_chart", "visualization"),
        ("export_pdf", "export"),
        ("share_document", "collaboration"),
    ];
    for (name, category) in openai_tools {
        corpus.push(ToolDef::with_category(name, category, ToolSource::OpenAi));
    }

    // HuggingFace-style tools (model-centric)
    let huggingface_tools = [
        ("text_classification", "classification"),
        ("token_classification", "ner"),
        ("question_answering", "qa"),
        ("text_generation", "generation"),
        ("text2text_generation", "generation"),
        ("summarization", "summarization"),
        ("translation", "translation"),
        ("fill_mask", "mlm"),
        ("feature_extraction", "embeddings"),
        ("image_classification", "vision"),
        ("object_detection", "vision"),
        ("image_segmentation", "vision"),
        ("image_to_text", "multimodal"),
        ("text_to_image", "multimodal"),
        ("audio_classification", "audio"),
        ("automatic_speech_recognition", "audio"),
        ("text_to_speech", "audio"),
        ("zero_shot_classification", "zeroshot"),
        ("sentence_similarity", "similarity"),
        ("table_question_answering", "structured"),
    ];
    for (name, category) in huggingface_tools {
        corpus.push(ToolDef::with_category(name, category, ToolSource::HuggingFace));
    }

    // Synthetic tools (edge cases and stress tests)
    let synthetic_tools = [
        // Very long names
        ("performComplexDataTransformationAndValidation", "etl"),
        // Acronyms
        ("getAPIResponse", "api"),
        ("parseHTMLContent", "parser"),
        ("validateJSONSchema", "validation"),
        ("encryptAESData", "crypto"),
        // Mixed patterns
        ("OAuth2_authenticate", "auth"),
        ("CRUD_operations", "database"),
        // Single word
        ("search", "general"),
        ("read", "general"),
        ("write", "general"),
        ("delete", "general"),
        ("update", "general"),
        // Deep categories
        ("process", "data/transform/batch"),
        ("stream", "data/ingest/realtime"),
        // Special characters (should be normalized)
        ("send-email", "communication"),
        ("get.weather", "external"),
        // Numbers
        ("query2sql", "database"),
        ("text2vec", "embeddings"),
        ("img2text", "multimodal"),
        ("gpt4_completion", "llm"),
    ];
    for (name, category) in synthetic_tools {
        corpus.push(ToolDef::with_category(name, category, ToolSource::Synthetic));
    }

    corpus
}

/// Prints a summary of the evaluation results.
fn print_summary(
    hierarchical: &agent_uri_eval::ExpressivenessResults,
    flat: &agent_uri_eval::ExpressivenessResults,
) {
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
    println!("  Coverage:        {:.1}%", flat.coverage.coverage_rate * 100.0);
    println!("  Unique paths:    {}", flat.collisions.unique_paths);
    println!("  Collisions:      {}", flat.collisions.collision_count);
    println!(
        "  Collision rate:  {:.2}%",
        flat.collisions.collision_rate * 100.0
    );
    println!("  Mean depth:      {:.2}", flat.depth_distribution.mean);
    println!("  Max depth:       {}", flat.depth_distribution.max);
    println!();

    println!("=== Criteria Check ===");
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

/// Converts a boolean to a status string.
fn status_str(passed: bool) -> &'static str {
    if passed {
        "PASS"
    } else {
        "FAIL"
    }
}
