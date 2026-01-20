//! Tool definition types for corpus extraction.

use serde::{Deserialize, Serialize};

/// Source of the tool definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolSource {
    /// `LangChain` community tools.
    LangChain,
    /// MCP server registry.
    Mcp,
    /// `OpenAI` function calling specs.
    OpenAi,
    /// `HuggingFace` Transformers Agents.
    HuggingFace,
    /// Smolagents (`HuggingFace` successor to `transformers.agents`).
    Smolagents,
    /// Synthetic/test data.
    Synthetic,
}

impl std::fmt::Display for ToolSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LangChain => write!(f, "langchain"),
            Self::Mcp => write!(f, "mcp"),
            Self::OpenAi => write!(f, "openai"),
            Self::HuggingFace => write!(f, "huggingface"),
            Self::Smolagents => write!(f, "smolagents"),
            Self::Synthetic => write!(f, "synthetic"),
        }
    }
}

/// A tool definition extracted from a corpus.
///
/// Represents a single tool/function that can be mapped to a capability path.
///
/// # Examples
///
/// ```
/// use agent_uri_eval::{ToolDef, ToolSource};
///
/// // Create a simple tool
/// let tool = ToolDef::new("search_web", ToolSource::LangChain);
///
/// // Create a tool with category
/// let tool = ToolDef::with_category("searchWeb", "internet", ToolSource::LangChain);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolDef {
    /// Tool name as defined in the source.
    name: String,
    /// Optional description of the tool.
    description: Option<String>,
    /// Optional category for hierarchical organization.
    category: Option<String>,
    /// Source of this tool definition.
    source: ToolSource,
    /// Original identifier in the source system.
    source_id: Option<String>,
}

impl ToolDef {
    /// Creates a new tool definition.
    #[must_use]
    pub fn new(name: impl Into<String>, source: ToolSource) -> Self {
        Self {
            name: name.into(),
            description: None,
            category: None,
            source,
            source_id: None,
        }
    }

    /// Creates a tool with category.
    #[must_use]
    pub fn with_category(
        name: impl Into<String>,
        category: impl Into<String>,
        source: ToolSource,
    ) -> Self {
        Self {
            name: name.into(),
            description: None,
            category: Some(category.into()),
            source,
            source_id: None,
        }
    }

    /// Sets the description.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Sets the source ID.
    #[must_use]
    pub fn source_id(mut self, id: impl Into<String>) -> Self {
        self.source_id = Some(id.into());
        self
    }

    /// Returns the tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the tool description.
    #[must_use]
    pub fn description_text(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the category.
    #[must_use]
    pub fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }

    /// Returns the source.
    #[must_use]
    pub fn source(&self) -> ToolSource {
        self.source
    }

    /// Returns the source ID.
    #[must_use]
    pub fn source_id_str(&self) -> Option<&str> {
        self.source_id.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_def_basic() {
        let tool = ToolDef::new("search_web", ToolSource::LangChain);
        assert_eq!(tool.name(), "search_web");
        assert_eq!(tool.source(), ToolSource::LangChain);
        assert!(tool.category().is_none());
    }

    #[test]
    fn tool_def_with_category() {
        let tool = ToolDef::with_category("searchWeb", "internet", ToolSource::OpenAi);
        assert_eq!(tool.name(), "searchWeb");
        assert_eq!(tool.category(), Some("internet"));
        assert_eq!(tool.source(), ToolSource::OpenAi);
    }

    #[test]
    fn tool_def_builder_chain() {
        let tool = ToolDef::new("test", ToolSource::Synthetic)
            .description("A test tool")
            .source_id("test-001");

        assert_eq!(tool.description_text(), Some("A test tool"));
        assert_eq!(tool.source_id_str(), Some("test-001"));
    }

    #[test]
    fn tool_source_display() {
        assert_eq!(ToolSource::LangChain.to_string(), "langchain");
        assert_eq!(ToolSource::Mcp.to_string(), "mcp");
        assert_eq!(ToolSource::OpenAi.to_string(), "openai");
        assert_eq!(ToolSource::HuggingFace.to_string(), "huggingface");
        assert_eq!(ToolSource::Smolagents.to_string(), "smolagents");
        assert_eq!(ToolSource::Synthetic.to_string(), "synthetic");
    }
}
