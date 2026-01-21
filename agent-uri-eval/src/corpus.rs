//! Corpus loading functionality for real tool definitions.
//!
//! This module provides functions to load tool definitions from JSON corpus files
//! extracted from various sources (`LangChain`, MCP, smolagents).
//!
//! # File Format
//!
//! Corpus files use the following JSON structure:
//!
//! ```json
//! {
//!   "metadata": {
//!     "source": "langchain_community.tools",
//!     "extraction_date": "2026-01-20T00:00:00Z",
//!     "tool_count": 163,
//!     "extractor_version": "1.0.0"
//!   },
//!   "tools": [
//!     {
//!       "name": "SearchWeb",
//!       "description": "Search the web",
//!       "source": "langchain_community.tools",
//!       "category": "internet",
//!       "parameters": [],
//!       "return_type": "str",
//!       "tags": ["search"]
//!     }
//!   ]
//! }
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use std::path::Path;
//! use agent_uri_eval::corpus::load_corpus_directory;
//!
//! let corpus = load_corpus_directory(Path::new("corpus/")).unwrap();
//! println!("Loaded {} tools from {} files", corpus.tools.len(), corpus.files_loaded);
//! ```

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::CorpusError;
use crate::tool_def::{ToolDef, ToolSource};

/// Valid source strings for mapping to `ToolSource`.
const VALID_SOURCES: &[&str] = &[
    "langchain_community.tools",
    "langchain",
    "mcp",
    "smolagents",
    "openai",
    "huggingface",
    "crewai",
    "crewai_tools",
    "autogen",
    "synthetic",
];

/// Metadata about a corpus extraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusMetadata {
    /// Source identifier (e.g., `langchain_community.tools`).
    pub source: String,
    /// ISO 8601 timestamp of extraction.
    pub extraction_date: String,
    /// Number of tools in this corpus file.
    pub tool_count: usize,
    /// Version of the extractor used.
    pub extractor_version: String,
    /// Optional notes about the extraction.
    #[serde(default)]
    pub notes: Option<String>,
    /// Optional GitHub repo (for MCP).
    #[serde(default)]
    pub github_repo: Option<String>,
}

/// A parameter definition from corpus JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawToolParameter {
    /// Parameter name.
    pub name: String,
    /// Parameter type (string, number, array, etc.).
    #[serde(rename = "type")]
    pub param_type: String,
    /// Whether the parameter is required.
    #[serde(default)]
    pub required: bool,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
}

/// Raw tool definition as it appears in corpus JSON files.
///
/// This is an internal deserialization type. Use `into_tool_def()` to
/// convert to the public `ToolDef` type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawToolDef {
    /// Tool name.
    pub name: String,
    /// Tool description.
    #[serde(default)]
    pub description: Option<String>,
    /// Source identifier string.
    pub source: String,
    /// Module path within the source.
    #[serde(default)]
    pub module_path: Option<String>,
    /// Category for hierarchical organization.
    #[serde(default)]
    pub category: Option<String>,
    /// Parameter definitions.
    #[serde(default)]
    pub parameters: Vec<RawToolParameter>,
    /// Return type.
    #[serde(default)]
    pub return_type: Option<String>,
    /// Tags for the tool.
    #[serde(default)]
    pub tags: Vec<String>,
}

impl RawToolDef {
    /// Converts a raw JSON tool definition into a `ToolDef`.
    ///
    /// # Returns
    ///
    /// A `ToolDef` with the source string mapped to `ToolSource` enum.
    ///
    /// # Errors
    ///
    /// Returns `CorpusError::UnknownSource` if the source string is not recognized.
    pub fn into_tool_def(self) -> Result<ToolDef, CorpusError> {
        let source = parse_tool_source(&self.source)?;

        let mut tool = if let Some(category) = self.category {
            ToolDef::with_category(&self.name, category, source)
        } else {
            ToolDef::new(&self.name, source)
        };

        if let Some(desc) = self.description {
            tool = tool.description(desc);
        }

        if let Some(module) = self.module_path {
            tool = tool.source_id(module);
        }

        Ok(tool)
    }
}

/// A corpus file containing tool definitions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusFile {
    /// Metadata about the extraction.
    pub metadata: CorpusMetadata,
    /// Raw tool definitions.
    pub tools: Vec<RawToolDef>,
}

/// A loaded corpus with tools converted to `ToolDef`.
#[derive(Debug, Clone, Default)]
pub struct LoadedCorpus {
    /// All loaded tool definitions.
    pub tools: Vec<ToolDef>,
    /// Source breakdown (source -> count).
    pub source_counts: HashMap<ToolSource, usize>,
    /// Total files loaded.
    pub files_loaded: usize,
    /// Any warnings during loading (e.g., unknown source strings).
    pub warnings: Vec<String>,
}

impl LoadedCorpus {
    /// Creates an empty `LoadedCorpus`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds tools from a file, updating source counts.
    pub fn add_tools(&mut self, tools: Vec<ToolDef>) {
        for tool in &tools {
            *self.source_counts.entry(tool.source()).or_insert(0) += 1;
        }
        self.tools.extend(tools);
    }

    /// Adds a warning message.
    pub fn add_warning(&mut self, warning: impl Into<String>) {
        self.warnings.push(warning.into());
    }

    /// Returns true if there were any warnings during loading.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }
}

/// Parses a source string from JSON into a `ToolSource` enum.
///
/// # Arguments
///
/// * `source` - The source string from JSON (e.g., `langchain_community.tools`)
///
/// # Returns
///
/// The corresponding `ToolSource` variant.
///
/// # Errors
///
/// Returns `CorpusError::UnknownSource` if the source string is not recognized.
///
/// # Mapping Rules
///
/// - `langchain_community.tools` | `langchain` -> `ToolSource::LangChain`
/// - `mcp` -> `ToolSource::Mcp`
/// - `smolagents` -> `ToolSource::Smolagents`
/// - `openai` -> `ToolSource::OpenAi`
/// - `huggingface` -> `ToolSource::HuggingFace`
/// - `synthetic` -> `ToolSource::Synthetic`
pub fn parse_tool_source(source: &str) -> Result<ToolSource, CorpusError> {
    match source {
        "langchain_community.tools" | "langchain" => Ok(ToolSource::LangChain),
        "mcp" | "mcp_community" => Ok(ToolSource::Mcp),
        "smolagents" => Ok(ToolSource::Smolagents),
        "openai" => Ok(ToolSource::OpenAi),
        "huggingface" => Ok(ToolSource::HuggingFace),
        "crewai" | "crewai_tools" => Ok(ToolSource::CrewAi),
        "autogen" => Ok(ToolSource::AutoGen),
        "synthetic" => Ok(ToolSource::Synthetic),
        _ => Err(CorpusError::UnknownSource {
            source: source.to_string(),
            valid_sources: VALID_SOURCES.iter().map(|s| (*s).to_string()).collect(),
        }),
    }
}

/// Loads a single corpus JSON file.
///
/// # Arguments
///
/// * `path` - Path to the JSON file
///
/// # Returns
///
/// Vector of `ToolDef` loaded from the file.
///
/// # Errors
///
/// - `CorpusError::FileNotFound` if the path doesn't exist
/// - `CorpusError::ReadFailed` if the file can't be read
/// - `CorpusError::JsonDeserialize` if JSON parsing fails
/// - `CorpusError::UnknownSource` if a tool has an unrecognized source
///
/// # Examples
///
/// ```rust,no_run
/// use std::path::Path;
/// use agent_uri_eval::corpus::load_corpus_file;
///
/// let tools = load_corpus_file(Path::new("corpus/langchain_tools.json")).unwrap();
/// println!("Loaded {} tools", tools.len());
/// ```
pub fn load_corpus_file(path: &Path) -> Result<Vec<ToolDef>, CorpusError> {
    let path_str = path.display().to_string();

    // Check if file exists
    if !path.exists() {
        return Err(CorpusError::FileNotFound { path: path_str });
    }

    // Read file contents
    let contents = std::fs::read_to_string(path).map_err(|e| CorpusError::ReadFailed {
        path: path_str.clone(),
        message: e.to_string(),
    })?;

    // Parse JSON
    let corpus_file: CorpusFile =
        serde_json::from_str(&contents).map_err(|e| CorpusError::JsonDeserialize {
            path: path_str,
            message: e.to_string(),
        })?;

    // Convert raw tools to ToolDef
    let mut tools = Vec::with_capacity(corpus_file.tools.len());
    for raw_tool in corpus_file.tools {
        tools.push(raw_tool.into_tool_def()?);
    }

    Ok(tools)
}

/// Loads all JSON corpus files from a directory.
///
/// Finds all `*.json` files in the directory and loads them as corpus files.
/// Files that fail to load are skipped with warnings in the result.
///
/// # Arguments
///
/// * `dir` - Path to the directory containing JSON files
///
/// # Returns
///
/// A `LoadedCorpus` containing all successfully loaded tools and metadata.
///
/// # Errors
///
/// - `CorpusError::InvalidDirectory` if the path is not a directory
/// - `CorpusError::NoFilesFound` if no JSON files are found
///
/// # Examples
///
/// ```rust,no_run
/// use std::path::Path;
/// use agent_uri_eval::corpus::load_corpus_directory;
///
/// let corpus = load_corpus_directory(Path::new("corpus/")).unwrap();
/// println!("Loaded {} tools from {} files", corpus.tools.len(), corpus.files_loaded);
/// for (source, count) in &corpus.source_counts {
///     println!("  {}: {}", source, count);
/// }
/// ```
pub fn load_corpus_directory(dir: &Path) -> Result<LoadedCorpus, CorpusError> {
    let dir_str = dir.display().to_string();

    // Check if directory exists and is a directory
    if !dir.exists() || !dir.is_dir() {
        return Err(CorpusError::InvalidDirectory { path: dir_str });
    }

    // Find all JSON files
    let json_files: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| CorpusError::ReadFailed {
            path: dir_str.clone(),
            message: e.to_string(),
        })?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        })
        .collect();

    if json_files.is_empty() {
        return Err(CorpusError::NoFilesFound { directory: dir_str });
    }

    let mut corpus = LoadedCorpus::new();

    for entry in json_files {
        let path = entry.path();
        match load_corpus_file(&path) {
            Ok(tools) => {
                corpus.add_tools(tools);
                corpus.files_loaded += 1;
            }
            Err(e) => {
                corpus.add_warning(format!("Failed to load '{}': {}", path.display(), e));
            }
        }
    }

    Ok(corpus)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    const SAMPLE_CORPUS_JSON: &str = r#"{
        "metadata": {
            "source": "test",
            "extraction_date": "2026-01-20T00:00:00Z",
            "tool_count": 2,
            "extractor_version": "1.0.0"
        },
        "tools": [
            {
                "name": "test_tool",
                "description": "A test tool",
                "source": "langchain_community.tools",
                "module_path": "langchain_community.tools.test",
                "category": "testing",
                "parameters": [],
                "return_type": "str",
                "tags": ["test"]
            },
            {
                "name": "another_tool",
                "source": "mcp",
                "category": "filesystem"
            }
        ]
    }"#;

    fn create_test_file(dir: &Path, name: &str, content: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn parse_tool_source_langchain_community() {
        let result = parse_tool_source("langchain_community.tools");
        assert_eq!(result, Ok(ToolSource::LangChain));
    }

    #[test]
    fn parse_tool_source_langchain_short() {
        let result = parse_tool_source("langchain");
        assert_eq!(result, Ok(ToolSource::LangChain));
    }

    #[test]
    fn parse_tool_source_mcp() {
        let result = parse_tool_source("mcp");
        assert_eq!(result, Ok(ToolSource::Mcp));
    }

    #[test]
    fn parse_tool_source_smolagents() {
        let result = parse_tool_source("smolagents");
        assert_eq!(result, Ok(ToolSource::Smolagents));
    }

    #[test]
    fn parse_tool_source_openai() {
        let result = parse_tool_source("openai");
        assert_eq!(result, Ok(ToolSource::OpenAi));
    }

    #[test]
    fn parse_tool_source_huggingface() {
        let result = parse_tool_source("huggingface");
        assert_eq!(result, Ok(ToolSource::HuggingFace));
    }

    #[test]
    fn parse_tool_source_synthetic() {
        let result = parse_tool_source("synthetic");
        assert_eq!(result, Ok(ToolSource::Synthetic));
    }

    #[test]
    fn parse_tool_source_unknown() {
        let result = parse_tool_source("unknown");
        assert!(matches!(result, Err(CorpusError::UnknownSource { .. })));

        if let Err(CorpusError::UnknownSource {
            source,
            valid_sources,
        }) = result
        {
            assert_eq!(source, "unknown");
            assert!(!valid_sources.is_empty());
        }
    }

    #[test]
    fn parse_tool_source_empty() {
        let result = parse_tool_source("");
        assert!(matches!(result, Err(CorpusError::UnknownSource { .. })));
    }

    #[test]
    fn raw_tool_def_into_tool_def_with_category() {
        let raw = RawToolDef {
            name: "test_tool".to_string(),
            description: Some("A test tool".to_string()),
            source: "mcp".to_string(),
            module_path: Some("@mcp/test".to_string()),
            category: Some("testing".to_string()),
            parameters: vec![],
            return_type: None,
            tags: vec![],
        };

        let tool = raw.into_tool_def().unwrap();

        assert_eq!(tool.name(), "test_tool");
        assert_eq!(tool.description_text(), Some("A test tool"));
        assert_eq!(tool.source(), ToolSource::Mcp);
        assert_eq!(tool.category(), Some("testing"));
        assert_eq!(tool.source_id_str(), Some("@mcp/test"));
    }

    #[test]
    fn raw_tool_def_into_tool_def_without_category() {
        let raw = RawToolDef {
            name: "simple_tool".to_string(),
            description: None,
            source: "smolagents".to_string(),
            module_path: None,
            category: None,
            parameters: vec![],
            return_type: None,
            tags: vec![],
        };

        let tool = raw.into_tool_def().unwrap();

        assert_eq!(tool.name(), "simple_tool");
        assert_eq!(tool.description_text(), None);
        assert_eq!(tool.source(), ToolSource::Smolagents);
        assert_eq!(tool.category(), None);
    }

    #[test]
    fn raw_tool_def_into_tool_def_unknown_source() {
        let raw = RawToolDef {
            name: "tool".to_string(),
            description: None,
            source: "invalid_source".to_string(),
            module_path: None,
            category: None,
            parameters: vec![],
            return_type: None,
            tags: vec![],
        };

        let result = raw.into_tool_def();
        assert!(matches!(result, Err(CorpusError::UnknownSource { .. })));
    }

    #[test]
    fn load_corpus_file_success() {
        let dir = tempdir().unwrap();
        let path = create_test_file(dir.path(), "test.json", SAMPLE_CORPUS_JSON);

        let tools = load_corpus_file(&path).unwrap();

        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name(), "test_tool");
        assert_eq!(tools[0].source(), ToolSource::LangChain);
        assert_eq!(tools[0].category(), Some("testing"));
        assert_eq!(tools[0].description_text(), Some("A test tool"));

        assert_eq!(tools[1].name(), "another_tool");
        assert_eq!(tools[1].source(), ToolSource::Mcp);
        assert_eq!(tools[1].category(), Some("filesystem"));
    }

    #[test]
    fn load_corpus_file_not_found() {
        let result = load_corpus_file(Path::new("/nonexistent/path.json"));
        assert!(matches!(result, Err(CorpusError::FileNotFound { .. })));
    }

    #[test]
    fn load_corpus_file_invalid_json() {
        let dir = tempdir().unwrap();
        let path = create_test_file(dir.path(), "invalid.json", "{ invalid json }");

        let result = load_corpus_file(&path);
        assert!(matches!(result, Err(CorpusError::JsonDeserialize { .. })));
    }

    #[test]
    fn load_corpus_file_empty_tools() {
        let dir = tempdir().unwrap();
        let content = r#"{
            "metadata": {
                "source": "test",
                "extraction_date": "2026-01-20",
                "tool_count": 0,
                "extractor_version": "1.0.0"
            },
            "tools": []
        }"#;
        let path = create_test_file(dir.path(), "empty.json", content);

        let tools = load_corpus_file(&path).unwrap();
        assert!(tools.is_empty());
    }

    #[test]
    fn load_corpus_directory_success() {
        let dir = tempdir().unwrap();
        create_test_file(dir.path(), "corpus1.json", SAMPLE_CORPUS_JSON);
        create_test_file(dir.path(), "corpus2.json", SAMPLE_CORPUS_JSON);

        let corpus = load_corpus_directory(dir.path()).unwrap();

        assert_eq!(corpus.files_loaded, 2);
        assert_eq!(corpus.tools.len(), 4);
        assert!(!corpus.has_warnings());
    }

    #[test]
    fn load_corpus_directory_updates_source_counts() {
        let dir = tempdir().unwrap();
        create_test_file(dir.path(), "corpus.json", SAMPLE_CORPUS_JSON);

        let corpus = load_corpus_directory(dir.path()).unwrap();

        assert_eq!(corpus.source_counts.get(&ToolSource::LangChain), Some(&1));
        assert_eq!(corpus.source_counts.get(&ToolSource::Mcp), Some(&1));
    }

    #[test]
    fn load_corpus_directory_no_json_files() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("readme.txt"), "not a json file").unwrap();

        let result = load_corpus_directory(dir.path());
        assert!(matches!(result, Err(CorpusError::NoFilesFound { .. })));
    }

    #[test]
    fn load_corpus_directory_invalid_directory() {
        let result = load_corpus_directory(Path::new("/nonexistent/directory"));
        assert!(matches!(result, Err(CorpusError::InvalidDirectory { .. })));
    }

    #[test]
    fn load_corpus_directory_with_invalid_file() {
        let dir = tempdir().unwrap();
        create_test_file(dir.path(), "valid.json", SAMPLE_CORPUS_JSON);
        create_test_file(dir.path(), "invalid.json", "{ broken }");

        let corpus = load_corpus_directory(dir.path()).unwrap();

        assert_eq!(corpus.files_loaded, 1);
        assert_eq!(corpus.tools.len(), 2);
        assert!(corpus.has_warnings());
        assert_eq!(corpus.warnings.len(), 1);
    }

    #[test]
    fn load_corpus_directory_ignores_non_json() {
        let dir = tempdir().unwrap();
        create_test_file(dir.path(), "corpus.json", SAMPLE_CORPUS_JSON);
        create_test_file(dir.path(), "readme.md", "# Readme");
        create_test_file(dir.path(), "data.txt", "some text");

        let corpus = load_corpus_directory(dir.path()).unwrap();

        assert_eq!(corpus.files_loaded, 1);
        assert_eq!(corpus.tools.len(), 2);
    }

    #[test]
    fn loaded_corpus_new_is_empty() {
        let corpus = LoadedCorpus::new();

        assert!(corpus.tools.is_empty());
        assert!(corpus.source_counts.is_empty());
        assert_eq!(corpus.files_loaded, 0);
        assert!(!corpus.has_warnings());
    }

    #[test]
    fn loaded_corpus_add_warning() {
        let mut corpus = LoadedCorpus::new();
        assert!(!corpus.has_warnings());

        corpus.add_warning("Test warning");
        assert!(corpus.has_warnings());
        assert_eq!(corpus.warnings.len(), 1);
    }

    #[test]
    fn corpus_metadata_deserialize() {
        let json = r#"{
            "source": "test",
            "extraction_date": "2026-01-20",
            "tool_count": 5,
            "extractor_version": "1.0.0",
            "notes": "Test notes",
            "github_repo": "https://github.com/test/repo"
        }"#;

        let metadata: CorpusMetadata = serde_json::from_str(json).unwrap();

        assert_eq!(metadata.source, "test");
        assert_eq!(metadata.tool_count, 5);
        assert_eq!(metadata.notes, Some("Test notes".to_string()));
        assert_eq!(
            metadata.github_repo,
            Some("https://github.com/test/repo".to_string())
        );
    }

    #[test]
    fn corpus_metadata_deserialize_minimal() {
        let json = r#"{
            "source": "test",
            "extraction_date": "2026-01-20",
            "tool_count": 0,
            "extractor_version": "1.0.0"
        }"#;

        let metadata: CorpusMetadata = serde_json::from_str(json).unwrap();

        assert_eq!(metadata.notes, None);
        assert_eq!(metadata.github_repo, None);
    }
}
