//! Collision detection for capability path mappings.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::mapping::MappingResult;
use crate::metrics::count_as_f64;

/// A collision between multiple tools mapping to the same path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collision {
    /// The capability path where collision occurred.
    pub path: String,
    /// Tools that collided at this path.
    pub tools: Vec<CollisionEntry>,
}

/// Entry in a collision report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollisionEntry {
    /// Tool name.
    pub name: String,
    /// Tool source.
    pub source: String,
    /// Tool category (if any).
    pub category: Option<String>,
}

/// Report of all collisions in a corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollisionReport {
    /// Total number of tools in corpus.
    pub total_tools: usize,
    /// Number of tools that mapped successfully.
    pub mapped_tools: usize,
    /// Number of unique paths.
    pub unique_paths: usize,
    /// Number of paths with collisions.
    pub collision_count: usize,
    /// Collision rate (collisions / `mapped_tools`).
    pub collision_rate: f64,
    /// Detailed collision information.
    pub collisions: Vec<Collision>,
}

/// Detects collisions in mapping results.
///
/// A collision occurs when two or more distinct tools map to the same
/// capability path.
///
/// # Arguments
///
/// * `results` - Mapping results from `map_tools_batch`
///
/// # Returns
///
/// A `CollisionReport` with statistics and detailed collision information.
#[must_use]
pub fn detect_collisions(results: &[MappingResult]) -> CollisionReport {
    let mut by_path: HashMap<String, Vec<&MappingResult>> = HashMap::new();

    // Group successful mappings by path
    for result in results {
        if let Ok(path) = &result.path {
            by_path
                .entry(path.as_str().to_string())
                .or_default()
                .push(result);
        }
    }

    let total_tools = results.len();
    let mapped_tools = results.iter().filter(|r| r.path.is_ok()).count();
    let unique_paths = by_path.len();

    // Find collisions (paths with more than one tool)
    let collisions: Vec<Collision> = by_path
        .into_iter()
        .filter(|(_, tools)| tools.len() > 1)
        .map(|(path, tools)| Collision {
            path,
            tools: tools
                .into_iter()
                .map(|r| CollisionEntry {
                    name: r.tool.name().to_string(),
                    source: r.tool.source().to_string(),
                    category: r.tool.category().map(String::from),
                })
                .collect(),
        })
        .collect();

    let collision_count = collisions.len();
    let collision_rate = if mapped_tools > 0 {
        count_as_f64(collision_count) / count_as_f64(mapped_tools)
    } else {
        0.0
    };

    CollisionReport {
        total_tools,
        mapped_tools,
        unique_paths,
        collision_count,
        collision_rate,
        collisions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mapping::{map_tools_batch, MappingConfig};
    use crate::tool_def::{ToolDef, ToolSource};

    #[test]
    fn no_collisions_in_distinct_tools() {
        let tools = vec![
            ToolDef::new("search_web", ToolSource::LangChain),
            ToolDef::new("read_file", ToolSource::LangChain),
            ToolDef::new("write_file", ToolSource::LangChain),
        ];
        let results = map_tools_batch(&tools, &MappingConfig::default());
        let report = detect_collisions(&results);

        assert_eq!(report.collision_count, 0);
        assert!((report.collision_rate - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn detects_collision_same_name() {
        let tools = vec![
            ToolDef::new("search_web", ToolSource::LangChain),
            ToolDef::new("search_web", ToolSource::OpenAi), // Same name, different source
        ];
        let results = map_tools_batch(&tools, &MappingConfig::default());
        let report = detect_collisions(&results);

        assert_eq!(report.collision_count, 1);
        assert_eq!(report.collisions[0].tools.len(), 2);
    }

    #[test]
    fn collision_rate_calculated_correctly() {
        let tools = vec![
            ToolDef::new("tool_a", ToolSource::Synthetic),
            ToolDef::new("tool_a", ToolSource::Synthetic), // Collision
            ToolDef::new("tool_b", ToolSource::Synthetic),
            ToolDef::new("tool_c", ToolSource::Synthetic),
        ];
        let results = map_tools_batch(&tools, &MappingConfig::default());
        let report = detect_collisions(&results);

        // 4 tools, 3 unique paths, 1 collision
        assert_eq!(report.total_tools, 4);
        assert_eq!(report.mapped_tools, 4);
        assert_eq!(report.unique_paths, 3);
        assert_eq!(report.collision_count, 1);
        // Collision rate = 1/4 = 0.25
        assert!((report.collision_rate - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn empty_corpus() {
        let results: Vec<MappingResult> = vec![];
        let report = detect_collisions(&results);

        assert_eq!(report.total_tools, 0);
        assert_eq!(report.collision_count, 0);
        assert!((report.collision_rate - 0.0).abs() < f64::EPSILON);
    }
}
