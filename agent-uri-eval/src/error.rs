//! Custom error types for the eval crate.

use std::fmt;

/// Top-level error type for the eval crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalError {
    /// Error mapping a tool to a capability path.
    Mapping(MappingError),
    /// Error in corpus extraction or analysis.
    Corpus(CorpusError),
    /// Error in discovery simulation.
    Discovery(DiscoveryError),
    /// I/O error (for file operations).
    Io {
        /// The operation that failed.
        operation: String,
        /// Error message.
        message: String,
    },
    /// JSON serialization/deserialization error.
    Json {
        /// Context where error occurred.
        context: String,
        /// Error message.
        message: String,
    },
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapping(e) => write!(f, "mapping error: {e}"),
            Self::Corpus(e) => write!(f, "corpus error: {e}"),
            Self::Discovery(e) => write!(f, "discovery error: {e}"),
            Self::Io { operation, message } => {
                write!(f, "I/O error during {operation}: {message}")
            }
            Self::Json { context, message } => {
                write!(f, "JSON error in {context}: {message}")
            }
        }
    }
}

impl std::error::Error for EvalError {}

/// Error during tool-to-capability mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingError {
    /// Tool name is empty.
    EmptyName,
    /// Tool name has no mappable segments.
    NoSegments {
        /// The tool name that had no segments.
        tool_name: String,
    },
    /// Invalid segment after normalization.
    InvalidSegment {
        /// The tool name.
        tool_name: String,
        /// The invalid segment.
        segment: String,
        /// Reason for invalidity.
        reason: String,
    },
    /// Resulting path exceeds constraints.
    PathTooLong {
        /// The tool name.
        tool_name: String,
        /// Number of segments produced.
        segments: usize,
        /// Maximum allowed segments.
        max_segments: usize,
    },
}

impl fmt::Display for MappingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => write!(f, "tool name is empty"),
            Self::NoSegments { tool_name } => {
                write!(f, "tool '{tool_name}' has no mappable segments")
            }
            Self::InvalidSegment {
                tool_name,
                segment,
                reason,
            } => {
                write!(
                    f,
                    "tool '{tool_name}' has invalid segment '{segment}': {reason}"
                )
            }
            Self::PathTooLong {
                tool_name,
                segments,
                max_segments,
            } => {
                write!(
                    f,
                    "tool '{tool_name}' produces {segments} segments, max is {max_segments}"
                )
            }
        }
    }
}

impl std::error::Error for MappingError {}

/// Error in corpus operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorpusError {
    /// Empty corpus provided.
    EmptyCorpus,
    /// Duplicate tool detected.
    DuplicateTool {
        /// Tool name.
        name: String,
        /// Source of the tool.
        source: String,
    },
    /// Parse error in corpus file.
    ParseError {
        /// File name.
        file: String,
        /// Line number.
        line: usize,
        /// Error message.
        message: String,
    },
    /// File not found.
    FileNotFound {
        /// Path that was not found.
        path: String,
    },
    /// Failed to read file.
    ReadFailed {
        /// Path to the file.
        path: String,
        /// Error message.
        message: String,
    },
    /// JSON deserialization failed.
    JsonDeserialize {
        /// Path to the file.
        path: String,
        /// Error message from `serde_json`.
        message: String,
    },
    /// Unknown source string in corpus file.
    UnknownSource {
        /// The unknown source string.
        source: String,
        /// Valid source strings.
        valid_sources: Vec<String>,
    },
    /// Directory not found or not a directory.
    InvalidDirectory {
        /// Path that was invalid.
        path: String,
    },
    /// No JSON files found in directory.
    NoFilesFound {
        /// Directory that was searched.
        directory: String,
    },
}

impl fmt::Display for CorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCorpus => write!(f, "corpus is empty"),
            Self::DuplicateTool { name, source } => {
                write!(f, "duplicate tool '{name}' from source '{source}'")
            }
            Self::ParseError {
                file,
                line,
                message,
            } => {
                write!(f, "parse error in {file} line {line}: {message}")
            }
            Self::FileNotFound { path } => {
                write!(f, "corpus file not found: '{path}'")
            }
            Self::ReadFailed { path, message } => {
                write!(f, "failed to read corpus file '{path}': {message}")
            }
            Self::JsonDeserialize { path, message } => {
                write!(f, "failed to parse JSON in '{path}': {message}")
            }
            Self::UnknownSource {
                source,
                valid_sources,
            } => {
                write!(
                    f,
                    "unknown tool source '{source}'; valid sources are: {}",
                    valid_sources.join(", ")
                )
            }
            Self::InvalidDirectory { path } => {
                write!(f, "invalid directory: '{path}' is not a directory or does not exist")
            }
            Self::NoFilesFound { directory } => {
                write!(f, "no JSON files found in directory '{directory}'")
            }
        }
    }
}

impl std::error::Error for CorpusError {}

/// Error in discovery simulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// No agents registered for query.
    NoAgentsRegistered,
    /// Invalid query parameters.
    InvalidQuery {
        /// Reason for invalidity.
        reason: String,
    },
    /// DHT error during operation.
    Dht {
        /// The operation that failed.
        operation: String,
        /// Error message.
        message: String,
    },
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAgentsRegistered => write!(f, "no agents registered in DHT"),
            Self::InvalidQuery { reason } => write!(f, "invalid query: {reason}"),
            Self::Dht { operation, message } => {
                write!(f, "DHT error during {operation}: {message}")
            }
        }
    }
}

impl std::error::Error for DiscoveryError {}

impl From<MappingError> for EvalError {
    fn from(e: MappingError) -> Self {
        Self::Mapping(e)
    }
}

impl From<CorpusError> for EvalError {
    fn from(e: CorpusError) -> Self {
        Self::Corpus(e)
    }
}

impl From<DiscoveryError> for EvalError {
    fn from(e: DiscoveryError) -> Self {
        Self::Discovery(e)
    }
}
