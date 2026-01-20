//! Evaluation 1: Capability expressiveness metrics.

use serde::{Deserialize, Serialize};

use crate::collision::{detect_collisions, CollisionReport};
use crate::mapping::{map_tools_batch, MappingConfig, MappingResult};
use crate::metrics::{count_as_f64, mean, stddev, CoverageMetrics, Histogram};
use crate::tool_def::ToolDef;

/// Complete results for capability expressiveness evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpressivenessResults {
    /// Coverage metrics.
    pub coverage: CoverageMetrics,
    /// Collision report.
    pub collisions: CollisionReport,
    /// Path depth distribution.
    pub depth_distribution: DepthDistribution,
    /// Success criteria check results.
    pub criteria: CriteriaResults,
}

/// Path depth distribution statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepthDistribution {
    /// Mean path depth.
    pub mean: f64,
    /// Standard deviation.
    pub stddev: f64,
    /// Minimum depth.
    pub min: usize,
    /// Maximum depth.
    pub max: usize,
    /// Histogram of depths.
    pub histogram: Histogram,
}

/// Status of a single evaluation criterion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CriterionStatus {
    /// Criterion was met.
    Met,
    /// Criterion was not met.
    NotMet,
}

impl CriterionStatus {
    /// Returns true if the criterion was met.
    #[must_use]
    pub fn is_met(self) -> bool {
        matches!(self, Self::Met)
    }
}

impl From<bool> for CriterionStatus {
    fn from(met: bool) -> Self {
        if met {
            Self::Met
        } else {
            Self::NotMet
        }
    }
}

/// Success criteria evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriteriaResults {
    /// Coverage >= 90%.
    pub coverage_met: CriterionStatus,
    /// Collision rate < 1%.
    pub collision_rate_met: CriterionStatus,
    /// Mean depth in 2-4 range.
    pub depth_range_met: CriterionStatus,
    /// Max depth <= 10.
    pub max_depth_met: CriterionStatus,
}

impl CriteriaResults {
    /// Returns true if all criteria are met.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.coverage_met.is_met()
            && self.collision_rate_met.is_met()
            && self.depth_range_met.is_met()
            && self.max_depth_met.is_met()
    }
}

/// Runs the capability expressiveness evaluation.
///
/// # Arguments
///
/// * `tools` - Corpus of tool definitions
/// * `config` - Mapping configuration
///
/// # Returns
///
/// Complete evaluation results with metrics and criteria checks.
#[must_use]
pub fn evaluate_expressiveness(tools: &[ToolDef], config: &MappingConfig) -> ExpressivenessResults {
    // Map all tools
    let results = map_tools_batch(tools, config);

    // Compute coverage
    let coverage = CoverageMetrics::compute(&results);

    // Detect collisions
    let collisions = detect_collisions(&results);

    // Compute depth distribution
    let depth_distribution = compute_depth_distribution(&results);

    // Check criteria
    let criteria = check_criteria(&coverage, &collisions, &depth_distribution);

    ExpressivenessResults {
        coverage,
        collisions,
        depth_distribution,
        criteria,
    }
}

/// Computes path depth distribution from mapping results.
fn compute_depth_distribution(results: &[MappingResult]) -> DepthDistribution {
    let depths_usize: Vec<usize> = results
        .iter()
        .filter_map(|r| r.path.as_ref().ok())
        .map(agent_uri::CapabilityPath::depth)
        .collect();

    if depths_usize.is_empty() {
        return DepthDistribution {
            mean: 0.0,
            stddev: 0.0,
            min: 0,
            max: 0,
            histogram: Histogram::from_values(&[], 10),
        };
    }

    let depths: Vec<f64> = depths_usize.iter().map(|&d| count_as_f64(d)).collect();
    let m = mean(&depths);
    let s = stddev(&depths);
    let min = *depths_usize.iter().min().unwrap_or(&0);
    let max = *depths_usize.iter().max().unwrap_or(&0);
    let histogram = Histogram::from_values(&depths, 10);

    DepthDistribution {
        mean: m,
        stddev: s,
        min,
        max,
        histogram,
    }
}

/// Checks success criteria.
fn check_criteria(
    coverage: &CoverageMetrics,
    collisions: &CollisionReport,
    depth: &DepthDistribution,
) -> CriteriaResults {
    CriteriaResults {
        coverage_met: CriterionStatus::from(coverage.coverage_rate >= 0.90),
        collision_rate_met: CriterionStatus::from(collisions.collision_rate < 0.01),
        depth_range_met: CriterionStatus::from(depth.mean >= 2.0 && depth.mean <= 4.0),
        max_depth_met: CriterionStatus::from(depth.max <= 10),
    }
}

/// Runs ablation: flat namespace (single-segment paths).
///
/// This disables category usage and limits path depth to 1 segment,
/// demonstrating the necessity of hierarchical paths.
#[must_use]
pub fn evaluate_flat_namespace(tools: &[ToolDef]) -> ExpressivenessResults {
    let config = MappingConfig {
        use_category: false,
        max_depth: 1,
        collapse_hyphens: true,
        split_name: false,
    };
    evaluate_expressiveness(tools, &config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool_def::ToolSource;

    fn sample_corpus() -> Vec<ToolDef> {
        vec![
            ToolDef::with_category("searchWeb", "internet", ToolSource::LangChain),
            ToolDef::with_category("readFile", "filesystem", ToolSource::LangChain),
            ToolDef::with_category("writeFile", "filesystem", ToolSource::LangChain),
            ToolDef::with_category("sendEmail", "communication", ToolSource::OpenAi),
            ToolDef::with_category("createCalendarEvent", "calendar", ToolSource::Mcp),
        ]
    }

    #[test]
    fn evaluate_sample_corpus() {
        let tools = sample_corpus();
        let results = evaluate_expressiveness(&tools, &MappingConfig::default());

        assert_eq!(results.coverage.total_tools, 5);
        assert_eq!(results.coverage.mapped_tools, 5);
        assert!((results.coverage.coverage_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn depth_distribution_computed() {
        let tools = sample_corpus();
        let results = evaluate_expressiveness(&tools, &MappingConfig::default());

        // All tools should have category + name segments = depth 2+
        assert!(results.depth_distribution.min >= 2);
        assert!(results.depth_distribution.max <= 10);
    }

    #[test]
    fn criteria_checked() {
        let tools = sample_corpus();
        let results = evaluate_expressiveness(&tools, &MappingConfig::default());

        // Sample corpus should pass most criteria
        assert!(results.criteria.coverage_met.is_met());
        assert!(results.criteria.collision_rate_met.is_met());
        assert!(results.criteria.max_depth_met.is_met());
    }

    #[test]
    fn flat_namespace_produces_different_results() {
        let tools = sample_corpus();

        let hierarchical = evaluate_expressiveness(&tools, &MappingConfig::default());
        let flat = evaluate_flat_namespace(&tools);

        // Flat should have max depth of 1
        assert_eq!(flat.depth_distribution.max, 1);

        // Hierarchical should have deeper paths
        assert!(hierarchical.depth_distribution.max > flat.depth_distribution.max);
    }

    #[test]
    fn flat_namespace_increases_collisions() {
        // Create tools that would collide with flat namespace
        let tools = vec![
            ToolDef::with_category("search", "web", ToolSource::LangChain),
            ToolDef::with_category("search", "files", ToolSource::LangChain),
        ];

        let hierarchical = evaluate_expressiveness(&tools, &MappingConfig::default());
        let flat = evaluate_flat_namespace(&tools);

        // Hierarchical should have no collisions (web/search vs files/search)
        assert_eq!(hierarchical.collisions.collision_count, 0);

        // Flat should have collision (both become just "search")
        assert_eq!(flat.collisions.collision_count, 1);
    }

    #[test]
    fn empty_corpus() {
        let tools: Vec<ToolDef> = vec![];
        let results = evaluate_expressiveness(&tools, &MappingConfig::default());

        assert_eq!(results.coverage.total_tools, 0);
        assert!((results.coverage.coverage_rate - 0.0).abs() < f64::EPSILON);
    }
}
