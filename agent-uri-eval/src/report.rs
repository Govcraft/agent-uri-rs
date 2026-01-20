//! JSON report generation for evaluation results.

use serde::{Deserialize, Serialize};

use crate::discovery::DiscoveryResults;
use crate::error::EvalError;
use crate::expressiveness::ExpressivenessResults;

/// Complete evaluation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationReport {
    /// Report metadata.
    pub metadata: ReportMetadata,
    /// Eval 1: Capability expressiveness results.
    pub expressiveness: Option<ExpressivenessResults>,
    /// Eval 2: Discovery precision results (prefix mode).
    pub discovery_prefix: Option<DiscoveryResults>,
    /// Eval 2: Discovery precision results (exact mode - ablation).
    pub discovery_exact: Option<DiscoveryResults>,
    /// Ablation: Flat namespace expressiveness.
    pub expressiveness_flat: Option<ExpressivenessResults>,
    /// Summary of criteria met.
    pub summary: EvaluationSummary,
}

/// Report metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    /// Report generation timestamp.
    pub generated_at: String,
    /// Version of agent-uri-eval.
    pub eval_version: String,
    /// Git commit hash (if available).
    pub git_commit: Option<String>,
    /// Machine info.
    pub machine: Option<String>,
}

impl Default for ReportMetadata {
    fn default() -> Self {
        Self {
            generated_at: chrono::Utc::now().to_rfc3339(),
            eval_version: env!("CARGO_PKG_VERSION").to_string(),
            git_commit: None,
            machine: None,
        }
    }
}

/// Summary of evaluation results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationSummary {
    /// Eval 1 passed all criteria.
    pub expressiveness_passed: bool,
    /// Eval 2 passed all criteria.
    pub discovery_passed: bool,
    /// All evaluations passed.
    pub all_passed: bool,
    /// List of failed criteria.
    pub failed_criteria: Vec<String>,
}

impl EvaluationReport {
    /// Creates a new empty report.
    #[must_use]
    pub fn new() -> Self {
        Self {
            metadata: ReportMetadata::default(),
            expressiveness: None,
            discovery_prefix: None,
            discovery_exact: None,
            expressiveness_flat: None,
            summary: EvaluationSummary {
                expressiveness_passed: false,
                discovery_passed: false,
                all_passed: false,
                failed_criteria: Vec::new(),
            },
        }
    }

    /// Sets expressiveness results.
    #[must_use]
    pub fn with_expressiveness(mut self, results: ExpressivenessResults) -> Self {
        self.expressiveness = Some(results);
        self
    }

    /// Sets discovery prefix results.
    #[must_use]
    pub fn with_discovery_prefix(mut self, results: DiscoveryResults) -> Self {
        self.discovery_prefix = Some(results);
        self
    }

    /// Sets discovery exact results (ablation).
    #[must_use]
    pub fn with_discovery_exact(mut self, results: DiscoveryResults) -> Self {
        self.discovery_exact = Some(results);
        self
    }

    /// Sets flat namespace results (ablation).
    #[must_use]
    pub fn with_expressiveness_flat(mut self, results: ExpressivenessResults) -> Self {
        self.expressiveness_flat = Some(results);
        self
    }

    /// Sets git commit info.
    #[must_use]
    pub fn with_git_commit(mut self, commit: impl Into<String>) -> Self {
        self.metadata.git_commit = Some(commit.into());
        self
    }

    /// Sets machine info.
    #[must_use]
    pub fn with_machine(mut self, machine: impl Into<String>) -> Self {
        self.metadata.machine = Some(machine.into());
        self
    }

    /// Computes summary from results.
    #[must_use]
    pub fn compute_summary(mut self) -> Self {
        let mut failed = Vec::new();

        // Check expressiveness criteria
        let expr_passed = if let Some(ref e) = self.expressiveness {
            if !e.criteria.coverage_met.is_met() {
                failed.push(format!(
                    "Coverage {:.1}% < 90%",
                    e.coverage.coverage_rate * 100.0
                ));
            }
            if !e.criteria.collision_rate_met.is_met() {
                failed.push(format!(
                    "Collision rate {:.2}% >= 1%",
                    e.collisions.collision_rate * 100.0
                ));
            }
            if !e.criteria.depth_range_met.is_met() {
                failed.push(format!(
                    "Mean depth {:.1} not in [2,4]",
                    e.depth_distribution.mean
                ));
            }
            if !e.criteria.max_depth_met.is_met() {
                failed.push(format!("Max depth {} > 10", e.depth_distribution.max));
            }
            e.criteria.all_passed()
        } else {
            false
        };

        // Check discovery criteria
        let disc_passed = if let Some(ref d) = self.discovery_prefix {
            if d.mean_precision < 0.80 {
                failed.push(format!("Precision {:.2} < 0.80", d.mean_precision));
            }
            if d.mean_recall < 0.70 {
                failed.push(format!("Recall {:.2} < 0.70", d.mean_recall));
            }
            if d.mean_f1 < 0.75 {
                failed.push(format!("F1 {:.2} < 0.75", d.mean_f1));
            }
            d.mean_precision >= 0.80 && d.mean_recall >= 0.70 && d.mean_f1 >= 0.75
        } else {
            false
        };

        self.summary = EvaluationSummary {
            expressiveness_passed: expr_passed,
            discovery_passed: disc_passed,
            all_passed: expr_passed && disc_passed,
            failed_criteria: failed,
        };

        self
    }

    /// Serializes to JSON.
    ///
    /// # Errors
    ///
    /// Returns `EvalError::Json` if serialization fails.
    pub fn to_json(&self) -> Result<String, EvalError> {
        serde_json::to_string_pretty(self).map_err(|e| EvalError::Json {
            context: "report serialization".to_string(),
            message: e.to_string(),
        })
    }

    /// Serializes to compact JSON.
    ///
    /// # Errors
    ///
    /// Returns `EvalError::Json` if serialization fails.
    pub fn to_json_compact(&self) -> Result<String, EvalError> {
        serde_json::to_string(self).map_err(|e| EvalError::Json {
            context: "report serialization".to_string(),
            message: e.to_string(),
        })
    }
}

impl Default for EvaluationReport {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collision::CollisionReport;
    use crate::expressiveness::{CriteriaResults, CriterionStatus, DepthDistribution};
    use crate::metrics::{CoverageMetrics, Histogram};
    use std::collections::HashMap;

    fn mock_expressiveness_passing() -> ExpressivenessResults {
        ExpressivenessResults {
            coverage: CoverageMetrics {
                total_tools: 100,
                mapped_tools: 95,
                coverage_rate: 0.95,
                unmapped_tools: 5,
                failure_reasons: HashMap::new(),
            },
            collisions: CollisionReport {
                total_tools: 100,
                mapped_tools: 95,
                unique_paths: 94,
                collision_count: 0,
                collision_rate: 0.0,
                collisions: vec![],
            },
            depth_distribution: DepthDistribution {
                mean: 3.0,
                stddev: 1.0,
                min: 2,
                max: 5,
                histogram: Histogram::from_values(&[3.0], 10),
            },
            criteria: CriteriaResults {
                coverage_met: CriterionStatus::Met,
                collision_rate_met: CriterionStatus::Met,
                depth_range_met: CriterionStatus::Met,
                max_depth_met: CriterionStatus::Met,
            },
        }
    }

    fn mock_discovery_passing() -> DiscoveryResults {
        DiscoveryResults {
            num_agents: 1000,
            num_queries: 100,
            match_mode: crate::discovery::MatchMode::Prefix,
            mean_precision: 0.85,
            mean_recall: 0.80,
            mean_f1: 0.82,
            stddev_precision: 0.1,
            stddev_recall: 0.1,
            mean_result_size: 10.0,
            query_results: None,
        }
    }

    #[test]
    fn report_creation() {
        let report = EvaluationReport::new();
        assert!(report.expressiveness.is_none());
        assert!(report.discovery_prefix.is_none());
    }

    #[test]
    fn report_with_results() {
        let report = EvaluationReport::new()
            .with_expressiveness(mock_expressiveness_passing())
            .with_discovery_prefix(mock_discovery_passing())
            .compute_summary();

        assert!(report.summary.expressiveness_passed);
        assert!(report.summary.discovery_passed);
        assert!(report.summary.all_passed);
        assert!(report.summary.failed_criteria.is_empty());
    }

    #[test]
    fn report_to_json() {
        let report = EvaluationReport::new()
            .with_expressiveness(mock_expressiveness_passing())
            .compute_summary();

        let json = report.to_json().unwrap();
        assert!(json.contains("expressiveness"));
        assert!(json.contains("coverage"));
    }

    #[test]
    fn report_metadata() {
        let report = EvaluationReport::new()
            .with_git_commit("abc123")
            .with_machine("test-machine");

        assert_eq!(report.metadata.git_commit, Some("abc123".to_string()));
        assert_eq!(report.metadata.machine, Some("test-machine".to_string()));
    }

    #[test]
    fn summary_records_failures() {
        let mut expr = mock_expressiveness_passing();
        expr.criteria.coverage_met = CriterionStatus::NotMet;
        expr.coverage.coverage_rate = 0.85;

        let report = EvaluationReport::new()
            .with_expressiveness(expr)
            .compute_summary();

        assert!(!report.summary.expressiveness_passed);
        assert!(!report.summary.all_passed);
        assert!(report
            .summary
            .failed_criteria
            .iter()
            .any(|c| c.contains("Coverage")));
    }
}
