//! Common metric types for evaluation.

use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use serde::{Deserialize, Serialize};

/// Converts a count to f64 for statistical calculations.
///
/// Evaluation counts must fit in u32 (< 4 billion), which converts
/// to f64 without precision loss.
///
/// # Panics
///
/// Panics if count exceeds `u32::MAX`.
#[inline]
pub(crate) fn count_as_f64(count: usize) -> f64 {
    f64::from(u32::try_from(count).expect("evaluation count exceeds u32::MAX"))
}

/// Converts an index to f64 for histogram calculations.
///
/// # Panics
///
/// Panics if index exceeds `u32::MAX`.
#[inline]
pub(crate) fn index_as_f64(index: usize) -> f64 {
    f64::from(u32::try_from(index).expect("index exceeds u32::MAX"))
}

/// Converts a non-negative f64 to usize for bin indexing.
///
/// Returns `fallback` if the value is negative, infinite, NaN, or too large.
///
/// This function intentionally truncates the f64 to get a bin index.
/// The value is first validated to be in a safe range.
#[inline]
fn f64_to_bin_index(value: f64, max_bin: usize) -> usize {
    // Handle special cases
    if !value.is_finite() || value < 0.0 {
        return 0;
    }

    // Convert max_bin to f64 for comparison (safe since max_bin is typically small)
    let max_f64 = count_as_f64(max_bin);

    // Clamp to valid range and convert
    let clamped = value.min(max_f64);

    // Safe integer conversion: we know clamped is in [0, max_bin] which fits in usize
    // Using to_bits and back would be overkill; instead we rely on the bounds check
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let result = clamped as usize;
    result.min(max_bin)
}

use crate::error::MappingError;
use crate::mapping::MappingResult;

/// Precision/Recall/F1 metrics for discovery evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PrecisionRecallMetrics {
    /// Precision: relevant / returned.
    pub precision: f64,
    /// Recall: `returned_relevant` / `all_relevant`.
    pub recall: f64,
    /// F1 score: harmonic mean of precision and recall.
    pub f1: f64,
    /// Number of relevant agents returned.
    pub true_positives: usize,
    /// Number of irrelevant agents returned.
    pub false_positives: usize,
    /// Number of relevant agents not returned.
    pub false_negatives: usize,
}

impl PrecisionRecallMetrics {
    /// Computes metrics from sets of returned and relevant items.
    ///
    /// # Arguments
    ///
    /// * `returned` - Items returned by the query
    /// * `relevant` - Ground truth relevant items
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri_eval::PrecisionRecallMetrics;
    /// use std::collections::HashSet;
    ///
    /// let returned: HashSet<_> = [1, 2, 3, 4].into_iter().collect();
    /// let relevant: HashSet<_> = [2, 3, 5, 6].into_iter().collect();
    ///
    /// let metrics = PrecisionRecallMetrics::compute(&returned, &relevant);
    /// // TP=2 (2,3), FP=2 (1,4), FN=2 (5,6)
    /// // Precision = 2/4 = 0.5
    /// // Recall = 2/4 = 0.5
    /// assert!((metrics.precision - 0.5).abs() < f64::EPSILON);
    /// ```
    #[must_use]
    pub fn compute<T: Eq + Hash>(returned: &HashSet<T>, relevant: &HashSet<T>) -> Self {
        let true_positives = returned.intersection(relevant).count();
        let false_positives = returned.difference(relevant).count();
        let false_negatives = relevant.difference(returned).count();

        let precision = if returned.is_empty() {
            0.0
        } else {
            count_as_f64(true_positives) / count_as_f64(returned.len())
        };

        let recall = if relevant.is_empty() {
            0.0
        } else {
            count_as_f64(true_positives) / count_as_f64(relevant.len())
        };

        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };

        Self {
            precision,
            recall,
            f1,
            true_positives,
            false_positives,
            false_negatives,
        }
    }

    /// Creates metrics from raw counts.
    #[must_use]
    pub fn from_counts(
        true_positives: usize,
        false_positives: usize,
        false_negatives: usize,
    ) -> Self {
        let total_returned = true_positives + false_positives;
        let total_relevant = true_positives + false_negatives;

        let precision = if total_returned > 0 {
            count_as_f64(true_positives) / count_as_f64(total_returned)
        } else {
            0.0
        };

        let recall = if total_relevant > 0 {
            count_as_f64(true_positives) / count_as_f64(total_relevant)
        } else {
            0.0
        };

        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };

        Self {
            precision,
            recall,
            f1,
            true_positives,
            false_positives,
            false_negatives,
        }
    }
}

/// Histogram for distribution analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Histogram {
    /// Bin edges (N+1 values for N bins).
    pub bins: Vec<f64>,
    /// Counts per bin.
    pub counts: Vec<usize>,
    /// Total count.
    pub total: usize,
}

impl Histogram {
    /// Creates a histogram from values with specified number of bins.
    #[must_use]
    pub fn from_values(values: &[f64], num_bins: usize) -> Self {
        if values.is_empty() || num_bins == 0 {
            return Self {
                bins: vec![],
                counts: vec![],
                total: 0,
            };
        }

        let min = values.iter().copied().fold(f64::INFINITY, f64::min);
        let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);

        let bin_width = if (max - min).abs() < f64::EPSILON {
            1.0
        } else {
            (max - min) / count_as_f64(num_bins)
        };

        let mut bins = Vec::with_capacity(num_bins + 1);
        for i in 0..=num_bins {
            bins.push(min + index_as_f64(i) * bin_width);
        }

        let mut counts = vec![0; num_bins];
        for &v in values {
            // Compute bin index: guaranteed non-negative and < num_bins
            let bin_f64 = ((v - min) / bin_width).floor();
            let bin = f64_to_bin_index(bin_f64, num_bins - 1);
            counts[bin] += 1;
        }

        Self {
            bins,
            counts,
            total: values.len(),
        }
    }

    /// Creates a histogram from integer values.
    #[must_use]
    pub fn from_usize_values(values: &[usize], num_bins: usize) -> Self {
        let float_values: Vec<f64> = values.iter().map(|&v| count_as_f64(v)).collect();
        Self::from_values(&float_values, num_bins)
    }
}

/// Computes mean of values.
#[must_use]
pub fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / count_as_f64(values.len())
}

/// Computes standard deviation.
#[must_use]
pub fn stddev(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let m = mean(values);
    let variance = values.iter().map(|v| (v - m).powi(2)).sum::<f64>() / count_as_f64(values.len() - 1);
    variance.sqrt()
}

/// Coverage metrics for expressiveness evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageMetrics {
    /// Total tools in corpus.
    pub total_tools: usize,
    /// Tools that mapped successfully.
    pub mapped_tools: usize,
    /// Coverage rate (mapped / total).
    pub coverage_rate: f64,
    /// Tools that failed to map.
    pub unmapped_tools: usize,
    /// Reasons for mapping failures (error -> count).
    pub failure_reasons: HashMap<String, usize>,
}

impl CoverageMetrics {
    /// Computes coverage metrics from mapping results.
    #[must_use]
    pub fn compute(results: &[MappingResult]) -> Self {
        let total_tools = results.len();
        let mapped_tools = results.iter().filter(|r| r.path.is_ok()).count();
        let unmapped_tools = total_tools - mapped_tools;
        let coverage_rate = if total_tools > 0 {
            count_as_f64(mapped_tools) / count_as_f64(total_tools)
        } else {
            0.0
        };

        let mut failure_reasons = HashMap::new();
        for result in results {
            if let Err(e) = &result.path {
                let reason = match e {
                    MappingError::EmptyName => "empty_name".to_string(),
                    MappingError::NoSegments { .. } => "no_segments".to_string(),
                    MappingError::InvalidSegment { .. } => "invalid_segment".to_string(),
                    MappingError::PathTooLong { .. } => "path_too_long".to_string(),
                };
                *failure_reasons.entry(reason).or_insert(0) += 1;
            }
        }

        Self {
            total_tools,
            mapped_tools,
            coverage_rate,
            unmapped_tools,
            failure_reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precision_recall_perfect() {
        let returned: HashSet<_> = [1, 2, 3].into_iter().collect();
        let relevant: HashSet<_> = [1, 2, 3].into_iter().collect();
        let m = PrecisionRecallMetrics::compute(&returned, &relevant);

        assert!((m.precision - 1.0).abs() < f64::EPSILON);
        assert!((m.recall - 1.0).abs() < f64::EPSILON);
        assert!((m.f1 - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn precision_recall_partial() {
        let returned: HashSet<_> = [1, 2, 3, 4].into_iter().collect();
        let relevant: HashSet<_> = [2, 3, 5, 6].into_iter().collect();
        let m = PrecisionRecallMetrics::compute(&returned, &relevant);

        assert!((m.precision - 0.5).abs() < f64::EPSILON);
        assert!((m.recall - 0.5).abs() < f64::EPSILON);
        assert!((m.f1 - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn precision_recall_empty_returned() {
        let returned: HashSet<i32> = HashSet::new();
        let relevant: HashSet<_> = [1, 2, 3].into_iter().collect();
        let m = PrecisionRecallMetrics::compute(&returned, &relevant);

        assert!((m.precision - 0.0).abs() < f64::EPSILON);
        assert!((m.recall - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn precision_recall_empty_relevant() {
        let returned: HashSet<_> = [1, 2, 3].into_iter().collect();
        let relevant: HashSet<i32> = HashSet::new();
        let m = PrecisionRecallMetrics::compute(&returned, &relevant);

        assert!((m.precision - 0.0).abs() < f64::EPSILON);
        assert!((m.recall - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn from_counts_correct() {
        let m = PrecisionRecallMetrics::from_counts(2, 2, 2);
        // Precision = 2/4 = 0.5
        // Recall = 2/4 = 0.5
        assert!((m.precision - 0.5).abs() < f64::EPSILON);
        assert!((m.recall - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn histogram_basic() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let hist = Histogram::from_values(&values, 5);

        assert_eq!(hist.total, 5);
        assert_eq!(hist.bins.len(), 6); // N+1 edges
        assert_eq!(hist.counts.len(), 5);
    }

    #[test]
    fn histogram_empty() {
        let values: Vec<f64> = vec![];
        let hist = Histogram::from_values(&values, 5);

        assert_eq!(hist.total, 0);
        assert!(hist.bins.is_empty());
    }

    #[test]
    fn mean_and_stddev() {
        let values = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let m = mean(&values);
        let s = stddev(&values);

        assert!((m - 5.0).abs() < f64::EPSILON);
        // Sample stddev is sqrt(32/7) ≈ 2.138
        assert!((s - 2.138).abs() < 0.01);
    }
}
