//! Deterministic mapping rules to convert tool definitions to capability paths.

use agent_uri::{CapabilityPath, MAX_PATH_SEGMENTS};

use crate::error::MappingError;
use crate::tool_def::ToolDef;

/// Result of mapping a tool to a capability path.
#[derive(Debug, Clone)]
pub struct MappingResult {
    /// The original tool definition.
    pub tool: ToolDef,
    /// The mapped capability path (if successful).
    pub path: Result<CapabilityPath, MappingError>,
}

/// Configuration for the mapping algorithm.
#[derive(Debug, Clone)]
pub struct MappingConfig {
    /// Whether to use category as first path segment.
    pub use_category: bool,
    /// Maximum path depth.
    pub max_depth: usize,
    /// Whether to collapse consecutive hyphens.
    pub collapse_hyphens: bool,
    /// Whether to split tool name on camelCase/underscores.
    pub split_name: bool,
}

impl Default for MappingConfig {
    fn default() -> Self {
        Self {
            use_category: true,
            max_depth: MAX_PATH_SEGMENTS,
            collapse_hyphens: true,
            split_name: true,
        }
    }
}

/// Maps a tool definition to a capability path.
///
/// # Mapping Rules (Deterministic)
///
/// 1. If category is present and `use_category` is true, prepend as first segment
/// 2. Split tool name on underscores and camelCase boundaries
/// 3. Normalize each segment: lowercase, replace invalid chars with hyphens
/// 4. Remove empty segments
/// 5. Collapse consecutive hyphens if configured
/// 6. Build `CapabilityPath` from segments
///
/// # Errors
///
/// Returns `MappingError` if:
/// - Tool name is empty
/// - No valid segments can be extracted
/// - Resulting path exceeds constraints
///
/// # Examples
///
/// ```
/// use agent_uri_eval::{ToolDef, ToolSource, map_tool_to_path, MappingConfig};
///
/// let tool = ToolDef::with_category("searchWeb", "internet", ToolSource::LangChain);
/// let path = map_tool_to_path(&tool, &MappingConfig::default()).unwrap();
/// assert_eq!(path.as_str(), "internet/search-web");
/// ```
pub fn map_tool_to_path(
    tool: &ToolDef,
    config: &MappingConfig,
) -> Result<CapabilityPath, MappingError> {
    if tool.name().is_empty() {
        return Err(MappingError::EmptyName);
    }

    let mut segments = Vec::new();

    // Add category as first segment if present and configured
    if config.use_category
        && let Some(cat) = tool.category()
    {
        let normalized = normalize_segment(cat, config.collapse_hyphens);
        if !normalized.is_empty() {
            segments.push(normalized);
        }
    }

    // Process tool name into segments
    if config.split_name {
        let name_parts = split_tool_name(tool.name());

        // If we have a category, join name parts into single segment
        // Otherwise, treat each part as a separate segment
        if segments.is_empty() {
            // No category - each part becomes a segment
            for part in name_parts {
                let normalized = normalize_segment(&part, config.collapse_hyphens);
                if !normalized.is_empty() {
                    segments.push(normalized);
                }
            }
        } else {
            // Has category - join name parts with hyphens
            let joined = name_parts.join("-");
            let normalized = normalize_segment(&joined, config.collapse_hyphens);
            if !normalized.is_empty() {
                segments.push(normalized);
            }
        }
    } else {
        // Use tool name as single segment without splitting
        let normalized = normalize_segment(tool.name(), config.collapse_hyphens);
        if !normalized.is_empty() {
            segments.push(normalized);
        }
    }

    if segments.is_empty() {
        return Err(MappingError::NoSegments {
            tool_name: tool.name().to_string(),
        });
    }

    if segments.len() > config.max_depth {
        return Err(MappingError::PathTooLong {
            tool_name: tool.name().to_string(),
            segments: segments.len(),
            max_segments: config.max_depth,
        });
    }

    // Convert to PathSegment vec
    let segment_strs: Vec<&str> = segments.iter().map(String::as_str).collect();
    CapabilityPath::try_from_strs(&segment_strs).map_err(|e| MappingError::InvalidSegment {
        tool_name: tool.name().to_string(),
        segment: segments.join("/"),
        reason: e.to_string(),
    })
}

/// Splits a tool name on underscores and camelCase boundaries.
///
/// # Examples
///
/// - `"searchWeb"` -> `["search", "web"]`
/// - `"search_web_results"` -> `["search", "web", "results"]`
/// - `"SearchWebResults"` -> `["search", "web", "results"]`
/// - `"HTTPClient"` -> `["http", "client"]`
fn split_tool_name(name: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();

    let chars: Vec<char> = name.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c == '_' || c == '-' {
            // Delimiter - push current segment
            if !current.is_empty() {
                segments.push(current);
                current = String::new();
            }
        } else if c.is_ascii_uppercase() {
            // Check for camelCase boundary
            let is_boundary = i > 0 && {
                let prev = chars[i - 1];
                prev.is_ascii_lowercase()
                    || (i + 1 < chars.len() && chars[i + 1].is_ascii_lowercase())
            };
            if is_boundary && !current.is_empty() {
                segments.push(current);
                current = String::new();
            }
            current.push(c.to_ascii_lowercase());
        } else {
            current.push(c.to_ascii_lowercase());
        }
    }

    if !current.is_empty() {
        segments.push(current);
    }

    segments
}

/// Normalizes a segment for use in a capability path.
///
/// - Converts to lowercase
/// - Replaces non-alphanumeric chars with hyphens
/// - Optionally collapses consecutive hyphens
/// - Trims leading/trailing hyphens
fn normalize_segment(s: &str, collapse_hyphens: bool) -> String {
    let mut result = String::with_capacity(s.len());

    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            result.push(c.to_ascii_lowercase());
        } else {
            result.push('-');
        }
    }

    if collapse_hyphens {
        // Collapse consecutive hyphens
        let mut collapsed = String::with_capacity(result.len());
        let mut prev_hyphen = false;
        for c in result.chars() {
            if c == '-' {
                if !prev_hyphen {
                    collapsed.push(c);
                }
                prev_hyphen = true;
            } else {
                collapsed.push(c);
                prev_hyphen = false;
            }
        }
        result = collapsed;
    }

    // Trim leading/trailing hyphens
    result.trim_matches('-').to_string()
}

/// Maps a batch of tools to capability paths.
#[must_use]
pub fn map_tools_batch(tools: &[ToolDef], config: &MappingConfig) -> Vec<MappingResult> {
    tools
        .iter()
        .map(|tool| MappingResult {
            tool: tool.clone(),
            path: map_tool_to_path(tool, config),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool_def::ToolSource;

    #[test]
    fn split_snake_case() {
        assert_eq!(
            split_tool_name("search_web_results"),
            vec!["search", "web", "results"]
        );
    }

    #[test]
    fn split_camel_case() {
        assert_eq!(split_tool_name("searchWeb"), vec!["search", "web"]);
    }

    #[test]
    fn split_pascal_case() {
        assert_eq!(
            split_tool_name("SearchWebResults"),
            vec!["search", "web", "results"]
        );
    }

    #[test]
    fn split_acronym() {
        assert_eq!(split_tool_name("HTTPClient"), vec!["http", "client"]);
    }

    #[test]
    fn split_mixed() {
        assert_eq!(
            split_tool_name("getHTTPResponse_fast"),
            vec!["get", "http", "response", "fast"]
        );
    }

    #[test]
    fn normalize_removes_special_chars() {
        assert_eq!(normalize_segment("search@web!", true), "search-web");
    }

    #[test]
    fn normalize_collapses_hyphens() {
        assert_eq!(normalize_segment("search--web", true), "search-web");
    }

    #[test]
    fn normalize_trims_hyphens() {
        assert_eq!(normalize_segment("-search-web-", true), "search-web");
    }

    #[test]
    fn map_with_category() {
        let tool = ToolDef::with_category("searchWeb", "internet", ToolSource::LangChain);
        let path = map_tool_to_path(&tool, &MappingConfig::default()).unwrap();
        assert_eq!(path.as_str(), "internet/search-web");
    }

    #[test]
    fn map_without_category() {
        let tool = ToolDef::new("search_web_results", ToolSource::OpenAi);
        let path = map_tool_to_path(&tool, &MappingConfig::default()).unwrap();
        assert_eq!(path.as_str(), "search/web/results");
    }

    #[test]
    fn map_empty_name_fails() {
        let tool = ToolDef::new("", ToolSource::Synthetic);
        let result = map_tool_to_path(&tool, &MappingConfig::default());
        assert!(matches!(result, Err(MappingError::EmptyName)));
    }

    #[test]
    fn map_only_special_chars_fails() {
        let tool = ToolDef::new("@#$%", ToolSource::Synthetic);
        let result = map_tool_to_path(&tool, &MappingConfig::default());
        assert!(matches!(result, Err(MappingError::NoSegments { .. })));
    }

    #[test]
    fn batch_mapping() {
        let tools = vec![
            ToolDef::new("search_web", ToolSource::LangChain),
            ToolDef::new("read_file", ToolSource::LangChain),
        ];
        let results = map_tools_batch(&tools, &MappingConfig::default());
        assert_eq!(results.len(), 2);
        assert!(results[0].path.is_ok());
        assert!(results[1].path.is_ok());
    }
}
