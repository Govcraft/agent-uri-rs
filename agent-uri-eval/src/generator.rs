//! Synthetic data generation for evaluation.

use agent_uri::CapabilityPath;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

/// Configuration for synthetic capability tree generation.
#[derive(Debug, Clone)]
pub struct TreeConfig {
    /// Maximum depth of the tree.
    pub max_depth: usize,
    /// Branching factor (children per node).
    pub branching_factor: usize,
    /// Probability of terminating at each level.
    pub termination_prob: f64,
    /// Vocabulary for path segments.
    pub vocabulary: Vec<String>,
}

impl Default for TreeConfig {
    fn default() -> Self {
        Self {
            max_depth: 5,
            branching_factor: 5,
            termination_prob: 0.3,
            vocabulary: default_vocabulary(),
        }
    }
}

/// Returns default vocabulary for path segments.
fn default_vocabulary() -> Vec<String> {
    vec![
        // Categories
        "assistant",
        "workflow",
        "data",
        "system",
        "api",
        "file",
        "network",
        "security",
        "storage",
        "compute",
        "analytics",
        "ml",
        "vision",
        "nlp",
        // Actions
        "search",
        "read",
        "write",
        "delete",
        "update",
        "list",
        "create",
        "process",
        "analyze",
        "transform",
        "validate",
        "export",
        "import",
        // Domains
        "web",
        "email",
        "calendar",
        "database",
        "cache",
        "queue",
        "stream",
        "document",
        "image",
        "audio",
        "video",
        "code",
        "config",
        "log",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Generates synthetic capability paths.
///
/// Uses a seeded RNG for deterministic, reproducible output.
pub struct PathGenerator {
    rng: ChaCha8Rng,
    config: TreeConfig,
}

impl PathGenerator {
    /// Creates a new generator with the given seed.
    #[must_use]
    pub fn new(seed: u64, config: TreeConfig) -> Self {
        Self {
            rng: ChaCha8Rng::seed_from_u64(seed),
            config,
        }
    }

    /// Creates a generator with default config.
    #[must_use]
    pub fn with_seed(seed: u64) -> Self {
        Self::new(seed, TreeConfig::default())
    }

    /// Generates N random capability paths.
    pub fn generate(&mut self, count: usize) -> Vec<CapabilityPath> {
        (0..count).filter_map(|_| self.generate_one()).collect()
    }

    /// Generates a single random capability path.
    fn generate_one(&mut self) -> Option<CapabilityPath> {
        let depth = self.random_depth();
        let segments: Vec<String> = (0..depth).map(|_| self.random_segment()).collect();

        let segment_strs: Vec<&str> = segments.iter().map(String::as_str).collect();
        CapabilityPath::try_from_strs(&segment_strs).ok()
    }

    /// Generates a random depth for a path.
    fn random_depth(&mut self) -> usize {
        let mut depth = 1;
        while depth < self.config.max_depth {
            if self.rng.gen_range(0.0..1.0) < self.config.termination_prob {
                break;
            }
            depth += 1;
        }
        depth
    }

    /// Selects a random segment from the vocabulary.
    fn random_segment(&mut self) -> String {
        let idx = self.rng.gen_range(0..self.config.vocabulary.len());
        self.config.vocabulary[idx].clone()
    }

    /// Generates paths at various depths for a hierarchical tree.
    ///
    /// Returns paths organized by prefix to enable realistic discovery queries.
    pub fn generate_hierarchical(&mut self, count: usize) -> Vec<CapabilityPath> {
        let mut paths = Vec::with_capacity(count);

        // Generate some top-level categories
        let num_categories = (count / 100).clamp(5, 50);
        let categories: Vec<String> = (0..num_categories)
            .map(|_| self.random_segment())
            .collect();

        for _ in 0..count {
            // Pick a random category as prefix
            let cat_idx = self.rng.gen_range(0..categories.len());
            let category = &categories[cat_idx];

            // Generate additional depth
            let extra_depth = self.random_depth().saturating_sub(1);
            let mut segments = vec![category.clone()];
            for _ in 0..extra_depth {
                segments.push(self.random_segment());
            }

            let segment_strs: Vec<&str> = segments.iter().map(String::as_str).collect();
            if let Ok(path) = CapabilityPath::try_from_strs(&segment_strs) {
                paths.push(path);
            }
        }

        paths
    }
}

/// Generates agent IDs with a prefix.
pub struct AgentIdGenerator {
    prefix: String,
    counter: u64,
}

impl AgentIdGenerator {
    /// Creates a new generator with the given prefix.
    #[must_use]
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            counter: 0,
        }
    }

    /// Generates the next agent ID.
    pub fn generate_next(&mut self) -> String {
        self.counter += 1;
        format!("{}_{:08x}", self.prefix, self.counter)
    }

    /// Resets the counter.
    pub fn reset(&mut self) {
        self.counter = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_produces_valid_paths() {
        let mut generator = PathGenerator::new(42, TreeConfig::default());
        let paths = generator.generate(100);

        assert!(!paths.is_empty());
        for path in &paths {
            assert!(path.depth() >= 1);
            assert!(path.depth() <= 5);
        }
    }

    #[test]
    fn generator_is_deterministic() {
        let mut generator1 = PathGenerator::new(42, TreeConfig::default());
        let mut generator2 = PathGenerator::new(42, TreeConfig::default());

        let paths1 = generator1.generate(10);
        let paths2 = generator2.generate(10);

        assert_eq!(paths1, paths2);
    }

    #[test]
    fn generator_different_seeds_different_output() {
        let mut generator1 = PathGenerator::new(42, TreeConfig::default());
        let mut generator2 = PathGenerator::new(123, TreeConfig::default());

        let paths1 = generator1.generate(10);
        let paths2 = generator2.generate(10);

        // Very unlikely to be equal with different seeds
        assert_ne!(paths1, paths2);
    }

    #[test]
    fn hierarchical_generation() {
        let mut generator = PathGenerator::with_seed(42);
        let paths = generator.generate_hierarchical(100);

        assert!(!paths.is_empty());

        // Should have some shared prefixes
        let first_segments: Vec<_> = paths.iter().map(|p| p.segments()[0].as_str()).collect();
        let unique_first: std::collections::HashSet<_> = first_segments.iter().collect();

        // Should have fewer unique first segments than total paths
        assert!(unique_first.len() < paths.len());
    }

    #[test]
    fn agent_id_generator_increments() {
        let mut id_gen = AgentIdGenerator::new("test");

        assert_eq!(id_gen.generate_next(), "test_00000001");
        assert_eq!(id_gen.generate_next(), "test_00000002");
        assert_eq!(id_gen.generate_next(), "test_00000003");
    }

    #[test]
    fn agent_id_generator_reset() {
        let mut id_gen = AgentIdGenerator::new("agent");
        id_gen.generate_next();
        id_gen.generate_next();
        id_gen.reset();

        assert_eq!(id_gen.generate_next(), "agent_00000001");
    }
}
