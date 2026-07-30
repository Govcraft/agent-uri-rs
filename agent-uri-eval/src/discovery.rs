//! Evaluation 2: Discovery precision simulation.

use std::collections::{HashMap, HashSet};

use agent_uri::{AgentId, AgentUriBuilder, CapabilityPath, TrustRoot};
use agent_uri_dht::{
    Dht, Endpoint, Query, ReadOptions, Registration, SimulatedDht, SimulationConfig, WriteOptions,
};
use futures::executor::block_on;
use serde::{Deserialize, Serialize};

use crate::error::DiscoveryError;
use crate::metrics::{PrecisionRecallMetrics, count_as_f64};

/// Configuration for discovery evaluation.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Number of agents to generate.
    pub num_agents: usize,
    /// Number of queries to run.
    pub num_queries: usize,
    /// Trust root for all agents.
    pub trust_root: String,
    /// Capability tree depth range (min, max).
    pub depth_range: (usize, usize),
    /// Branching factor (children per node).
    pub branching_factor: usize,
    /// Seed for reproducibility.
    pub seed: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            num_agents: 1000,
            num_queries: 1000,
            trust_root: "eval.example.com".to_string(),
            depth_range: (1, 5),
            branching_factor: 5,
            seed: 42,
        }
    }
}

/// Match mode for discovery queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatchMode {
    /// Exact path match only.
    Exact,
    /// Prefix match (includes children).
    Prefix,
}

/// Result of a single discovery query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    /// The query path.
    pub query_path: String,
    /// Match mode used.
    pub match_mode: MatchMode,
    /// Number of agents returned.
    pub returned_count: usize,
    /// Number of relevant agents (ground truth).
    pub relevant_count: usize,
    /// Precision/recall metrics.
    pub metrics: PrecisionRecallMetrics,
}

/// Aggregated discovery evaluation results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResults {
    /// Number of agents registered.
    pub num_agents: usize,
    /// Number of queries run.
    pub num_queries: usize,
    /// Match mode tested.
    pub match_mode: MatchMode,
    /// Mean precision across queries.
    pub mean_precision: f64,
    /// Mean recall across queries.
    pub mean_recall: f64,
    /// Mean F1 across queries.
    pub mean_f1: f64,
    /// Standard deviation of precision.
    pub stddev_precision: f64,
    /// Standard deviation of recall.
    pub stddev_recall: f64,
    /// Mean result set size.
    pub mean_result_size: f64,
    /// Individual query results (optional, for detailed analysis).
    pub query_results: Option<Vec<QueryResult>>,
}

/// Discovery evaluation harness.
pub struct DiscoveryEvaluator {
    dht: SimulatedDht,
    trust_root: TrustRoot,
    /// Map from path string to registered agent URIs.
    registrations: HashMap<String, Vec<String>>,
}

impl DiscoveryEvaluator {
    /// Creates a new evaluator with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns `DiscoveryError` if trust root parsing fails.
    pub fn new(config: &DiscoveryConfig) -> Result<Self, DiscoveryError> {
        let trust_root =
            TrustRoot::parse(&config.trust_root).map_err(|e| DiscoveryError::InvalidQuery {
                reason: format!("invalid trust root: {e}"),
            })?;

        Ok(Self {
            // This evaluation isolates indexing semantics. Registration-time
            // cryptographic verification is covered by DHT integration tests.
            dht: SimulatedDht::new(SimulationConfig::default().with_verify_attestations(false)),
            trust_root,
            registrations: HashMap::new(),
        })
    }

    /// Returns the trust root.
    #[must_use]
    pub fn trust_root(&self) -> &TrustRoot {
        &self.trust_root
    }

    /// Registers an agent at the given capability path.
    ///
    /// `agent_prefix` is a *prefix*, not a whole agent id: the id is completed
    /// with a fresh `UUIDv7` suffix. A prefix admits only lowercase letters and
    /// underscores (`llm`, `rule_chat`); use [`AgentIdGenerator`] to mint a
    /// series of distinct ones.
    ///
    /// [`AgentIdGenerator`]: crate::AgentIdGenerator
    ///
    /// # Errors
    ///
    /// Returns `DiscoveryError` if the prefix is not a valid agent prefix, or if
    /// registration fails.
    pub fn register_agent(
        &mut self,
        path: &CapabilityPath,
        agent_prefix: &str,
    ) -> Result<String, DiscoveryError> {
        // Fallibly, not `AgentId::new`, which panics: this function returns a
        // Result precisely so a caller with a bad prefix gets an error to handle
        // rather than a process that dies mid-evaluation.
        let agent_id = AgentId::try_new(agent_prefix).map_err(|e| DiscoveryError::Dht {
            operation: "build_agent_id".to_string(),
            message: format!("'{agent_prefix}' is not a valid agent prefix: {e}"),
        })?;

        let uri = AgentUriBuilder::new()
            .trust_root(self.trust_root.clone())
            .capability_path(path.clone())
            .agent_id(agent_id)
            .build()
            .map_err(|e| DiscoveryError::Dht {
                operation: "build_uri".to_string(),
                message: e.to_string(),
            })?;

        let uri_str = uri.as_str().to_string();
        let endpoint = Endpoint::https("agent.eval.example.com:443");
        let registration = Registration::new(uri.clone(), vec![endpoint]);

        block_on(self.dht.register(registration, WriteOptions::default())).map_err(|e| {
            DiscoveryError::Dht {
                operation: "register".to_string(),
                message: e.to_string(),
            }
        })?;

        // Track registration for ground truth
        self.registrations
            .entry(path.as_str().to_string())
            .or_default()
            .push(uri_str.clone());

        Ok(uri_str)
    }

    /// Queries for agents matching the given path.
    ///
    /// # Arguments
    ///
    /// * `path` - Capability path to query
    /// * `mode` - Exact or prefix matching
    ///
    /// # Returns
    ///
    /// Set of agent URI strings that matched.
    ///
    /// # Errors
    ///
    /// Returns `DiscoveryError` if lookup fails.
    pub fn query(
        &self,
        path: &CapabilityPath,
        mode: MatchMode,
    ) -> Result<HashSet<String>, DiscoveryError> {
        let query = match mode {
            MatchMode::Exact => Query::exact(self.trust_root.clone(), path.clone()),
            MatchMode::Prefix => Query::prefix(self.trust_root.clone(), path.clone()),
        };

        // Every page, not just the first. A recall measurement that stops at
        // one page reports the page size as the ceiling and calls it a result.
        let mut found = HashSet::new();
        let mut options = ReadOptions::default();
        loop {
            let page =
                block_on(self.dht.lookup(&query, &options)).map_err(|e| DiscoveryError::Dht {
                    operation: "lookup".to_string(),
                    message: e.to_string(),
                })?;
            let next = page.next_cursor();
            found.extend(
                page.into_items()
                    .into_iter()
                    .map(|r| r.agent_uri().as_str().to_string()),
            );
            match next {
                Some(cursor) => options = options.with_cursor(cursor),
                None => break,
            }
        }

        Ok(found)
    }

    /// Computes ground truth for a query (which agents should match).
    ///
    /// For exact mode: agents registered at exactly this path.
    /// For prefix mode: agents registered at this path or any child path.
    #[must_use]
    pub fn ground_truth(&self, path: &CapabilityPath, mode: MatchMode) -> HashSet<String> {
        let mut relevant = HashSet::new();
        let query_path = path.as_str();

        for (reg_path, uris) in &self.registrations {
            let is_match = match mode {
                MatchMode::Exact => reg_path == query_path,
                MatchMode::Prefix => {
                    reg_path == query_path || reg_path.starts_with(&format!("{query_path}/"))
                }
            };
            if is_match {
                relevant.extend(uris.iter().cloned());
            }
        }

        relevant
    }

    /// Evaluates a single query.
    ///
    /// # Errors
    ///
    /// Returns `DiscoveryError` if query fails.
    pub fn evaluate_query(
        &self,
        path: &CapabilityPath,
        mode: MatchMode,
    ) -> Result<QueryResult, DiscoveryError> {
        let returned = self.query(path, mode)?;
        let relevant = self.ground_truth(path, mode);
        let metrics = PrecisionRecallMetrics::compute(&returned, &relevant);

        Ok(QueryResult {
            query_path: path.as_str().to_string(),
            match_mode: mode,
            returned_count: returned.len(),
            relevant_count: relevant.len(),
            metrics,
        })
    }

    /// Returns registered paths for generating queries.
    #[must_use]
    pub fn registered_paths(&self) -> Vec<String> {
        self.registrations.keys().cloned().collect()
    }

    /// Returns count of registered agents.
    #[must_use]
    pub fn agent_count(&self) -> usize {
        self.registrations.values().map(Vec::len).sum()
    }

    /// Clears all registrations.
    pub fn clear(&mut self) {
        self.dht.clear();
        self.registrations.clear();
    }
}

/// Aggregates multiple query results into summary statistics.
#[must_use]
pub fn aggregate_results(
    results: &[QueryResult],
    num_agents: usize,
    include_details: bool,
) -> DiscoveryResults {
    if results.is_empty() {
        return DiscoveryResults {
            num_agents,
            num_queries: 0,
            match_mode: MatchMode::Prefix,
            mean_precision: 0.0,
            mean_recall: 0.0,
            mean_f1: 0.0,
            stddev_precision: 0.0,
            stddev_recall: 0.0,
            mean_result_size: 0.0,
            query_results: None,
        };
    }

    let precisions: Vec<f64> = results.iter().map(|r| r.metrics.precision).collect();
    let recalls: Vec<f64> = results.iter().map(|r| r.metrics.recall).collect();
    let f1s: Vec<f64> = results.iter().map(|r| r.metrics.f1).collect();
    let sizes: Vec<f64> = results
        .iter()
        .map(|r| count_as_f64(r.returned_count))
        .collect();

    let mean_precision = precisions.iter().sum::<f64>() / count_as_f64(precisions.len());
    let mean_recall = recalls.iter().sum::<f64>() / count_as_f64(recalls.len());
    let mean_f1 = f1s.iter().sum::<f64>() / count_as_f64(f1s.len());
    let mean_result_size = sizes.iter().sum::<f64>() / count_as_f64(sizes.len());

    let stddev_precision = if precisions.len() > 1 {
        let variance = precisions
            .iter()
            .map(|p| (p - mean_precision).powi(2))
            .sum::<f64>()
            / count_as_f64(precisions.len() - 1);
        variance.sqrt()
    } else {
        0.0
    };

    let stddev_recall = if recalls.len() > 1 {
        let variance = recalls
            .iter()
            .map(|r| (r - mean_recall).powi(2))
            .sum::<f64>()
            / count_as_f64(recalls.len() - 1);
        variance.sqrt()
    } else {
        0.0
    };

    DiscoveryResults {
        num_agents,
        num_queries: results.len(),
        match_mode: results[0].match_mode,
        mean_precision,
        mean_recall,
        mean_f1,
        stddev_precision,
        stddev_recall,
        mean_result_size,
        query_results: if include_details {
            Some(results.to_vec())
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentIdGenerator;

    /// An evaluator over a throwaway trust root.
    fn evaluator() -> DiscoveryEvaluator {
        let config = DiscoveryConfig {
            num_agents: 10,
            trust_root: "test.example.com".to_string(),
            ..Default::default()
        };
        DiscoveryEvaluator::new(&config).unwrap()
    }

    #[test]
    fn an_invalid_prefix_is_an_error_not_a_panic() {
        // This function returns a Result, and used to call `AgentId::new`, which
        // panics. A caller handing it a bad prefix took the whole process down
        // mid-evaluation instead of getting an error it could report.
        let mut eval = evaluator();
        let path = CapabilityPath::parse("assistant/chat").unwrap();

        // Digits are not admissible in an agent prefix.
        let result = eval.register_agent(&path, "agent1");

        assert!(result.is_err(), "a prefix with a digit must be refused");
        assert!(
            format!("{}", result.unwrap_err()).contains("not a valid agent prefix"),
            "the error must say what was wrong with it"
        );
    }

    #[test]
    fn generated_prefixes_register_successfully() {
        // The regression the failing doctest was reporting: the generator's output
        // must actually be registrable, which is the only reason it exists.
        let mut eval = evaluator();
        let path = CapabilityPath::parse("assistant/chat").unwrap();
        let mut id_gen = AgentIdGenerator::new("eval");

        for _ in 0..30 {
            let prefix = id_gen.generate_next();
            assert!(
                eval.register_agent(&path, &prefix).is_ok(),
                "generator produced '{prefix}', which the evaluator would not register"
            );
        }

        assert_eq!(eval.agent_count(), 30);
    }

    #[test]
    fn evaluator_registers_and_queries() {
        let config = DiscoveryConfig {
            num_agents: 10,
            trust_root: "test.example.com".to_string(),
            ..Default::default()
        };
        let mut eval = DiscoveryEvaluator::new(&config).unwrap();

        let path = CapabilityPath::parse("assistant/chat").unwrap();
        eval.register_agent(&path, "test").unwrap();

        let results = eval.query(&path, MatchMode::Exact).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn prefix_query_finds_children() {
        let config = DiscoveryConfig::default();
        let mut eval = DiscoveryEvaluator::new(&config).unwrap();

        let parent = CapabilityPath::parse("assistant").unwrap();
        let child1 = CapabilityPath::parse("assistant/chat").unwrap();
        let child2 = CapabilityPath::parse("assistant/code").unwrap();

        eval.register_agent(&child1, "chat").unwrap();
        eval.register_agent(&child2, "code").unwrap();

        let results = eval.query(&parent, MatchMode::Prefix).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn exact_query_excludes_children() {
        let config = DiscoveryConfig::default();
        let mut eval = DiscoveryEvaluator::new(&config).unwrap();

        let parent = CapabilityPath::parse("assistant").unwrap();
        let child = CapabilityPath::parse("assistant/chat").unwrap();

        eval.register_agent(&parent, "parent").unwrap();
        eval.register_agent(&child, "child").unwrap();

        let results = eval.query(&parent, MatchMode::Exact).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn ground_truth_exact() {
        let config = DiscoveryConfig::default();
        let mut eval = DiscoveryEvaluator::new(&config).unwrap();

        let path1 = CapabilityPath::parse("assistant/chat").unwrap();
        let path2 = CapabilityPath::parse("assistant/code").unwrap();

        eval.register_agent(&path1, "agenta").unwrap();
        eval.register_agent(&path2, "agentb").unwrap();

        let gt = eval.ground_truth(&path1, MatchMode::Exact);
        assert_eq!(gt.len(), 1);
    }

    #[test]
    fn ground_truth_prefix() {
        let config = DiscoveryConfig::default();
        let mut eval = DiscoveryEvaluator::new(&config).unwrap();

        let parent = CapabilityPath::parse("assistant").unwrap();
        let child1 = CapabilityPath::parse("assistant/chat").unwrap();
        let child2 = CapabilityPath::parse("assistant/code").unwrap();

        eval.register_agent(&child1, "agenta").unwrap();
        eval.register_agent(&child2, "agentb").unwrap();

        let gt = eval.ground_truth(&parent, MatchMode::Prefix);
        assert_eq!(gt.len(), 2);
    }

    #[test]
    fn evaluate_query_computes_metrics() {
        let config = DiscoveryConfig::default();
        let mut eval = DiscoveryEvaluator::new(&config).unwrap();

        let path = CapabilityPath::parse("assistant/chat").unwrap();
        eval.register_agent(&path, "agenta").unwrap();

        let result = eval.evaluate_query(&path, MatchMode::Exact).unwrap();

        // Should have perfect precision/recall for exact match
        assert!((result.metrics.precision - 1.0).abs() < f64::EPSILON);
        assert!((result.metrics.recall - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_results_computes_means() {
        let results = vec![
            QueryResult {
                query_path: "a".to_string(),
                match_mode: MatchMode::Prefix,
                returned_count: 5,
                relevant_count: 5,
                metrics: PrecisionRecallMetrics::from_counts(4, 1, 1),
            },
            QueryResult {
                query_path: "b".to_string(),
                match_mode: MatchMode::Prefix,
                returned_count: 10,
                relevant_count: 8,
                metrics: PrecisionRecallMetrics::from_counts(6, 4, 2),
            },
        ];

        let summary = aggregate_results(&results, 100, false);

        assert_eq!(summary.num_queries, 2);
        assert!(summary.mean_precision > 0.0);
        assert!(summary.mean_recall > 0.0);
    }

    #[test]
    fn clear_removes_registrations() {
        let config = DiscoveryConfig::default();
        let mut eval = DiscoveryEvaluator::new(&config).unwrap();

        let path = CapabilityPath::parse("test").unwrap();
        eval.register_agent(&path, "agent").unwrap();
        assert_eq!(eval.agent_count(), 1);

        eval.clear();
        assert_eq!(eval.agent_count(), 0);
    }
}
