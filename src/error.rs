//! Error types for agent URI parsing.

use std::fmt;

/// Errors that can occur when parsing an agent URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// The input that failed to parse
    pub input: String,
    /// The specific error that occurred
    pub kind: ParseErrorKind,
}

/// Specific parsing error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// URI is empty
    Empty,
    /// URI exceeds maximum length
    TooLong {
        /// Maximum allowed length
        max: usize,
        /// Actual length
        actual: usize,
    },
    /// Missing or invalid scheme (expected "agent://")
    InvalidScheme {
        /// The scheme that was found, if any
        found: Option<String>,
    },
    /// Trust root parsing failed
    InvalidTrustRoot(TrustRootError),
    /// Capability path parsing failed
    InvalidCapabilityPath(CapabilityPathError),
    /// Agent ID parsing failed
    InvalidAgentId(AgentIdError),
    /// Query string parsing failed
    InvalidQuery(QueryError),
    /// Fragment parsing failed
    InvalidFragment(FragmentError),
    /// Missing required component
    MissingComponent {
        /// Name of the missing component
        component: &'static str,
    },
    /// Unexpected character at position
    UnexpectedChar {
        /// The unexpected character
        char: char,
        /// Position in the input
        position: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to parse agent URI '{}': ", self.input)?;
        match &self.kind {
            ParseErrorKind::Empty => write!(f, "input is empty"),
            ParseErrorKind::TooLong { max, actual } => {
                write!(
                    f,
                    "URI length {actual} exceeds maximum {max}; consider shorter capability path or trust root"
                )
            }
            ParseErrorKind::InvalidScheme { found } => match found {
                Some(s) => write!(f, "expected scheme 'agent://', found '{s}'"),
                None => write!(f, "missing scheme; URI must start with 'agent://'"),
            },
            ParseErrorKind::InvalidTrustRoot(e) => write!(f, "invalid trust root: {e}"),
            ParseErrorKind::InvalidCapabilityPath(e) => write!(f, "invalid capability path: {e}"),
            ParseErrorKind::InvalidAgentId(e) => write!(f, "invalid agent ID: {e}"),
            ParseErrorKind::InvalidQuery(e) => write!(f, "invalid query string: {e}"),
            ParseErrorKind::InvalidFragment(e) => write!(f, "invalid fragment: {e}"),
            ParseErrorKind::MissingComponent { component } => {
                write!(f, "missing required component: {component}")
            }
            ParseErrorKind::UnexpectedChar { char, position } => {
                write!(f, "unexpected character '{char}' at position {position}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Errors for trust root parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustRootError {
    /// Trust root is empty
    Empty,
    /// Trust root exceeds maximum length
    TooLong {
        /// Maximum allowed length
        max: usize,
        /// Actual length
        actual: usize,
    },
    /// Invalid domain name
    InvalidDomain {
        /// The invalid domain
        domain: String,
        /// Reason for invalidity
        reason: &'static str,
    },
    /// Invalid IP address
    InvalidIpAddress {
        /// The invalid value
        value: String,
        /// Reason for invalidity
        reason: &'static str,
    },
    /// Invalid port number
    InvalidPort {
        /// The invalid value
        value: String,
        /// Reason for invalidity
        reason: &'static str,
    },
    /// DNS label too long
    LabelTooLong {
        /// The too-long label
        label: String,
        /// Maximum allowed length
        max: usize,
        /// Actual length
        actual: usize,
    },
    /// Invalid character in domain
    InvalidChar {
        /// The invalid character
        char: char,
        /// Position in the input
        position: usize,
    },
}

impl fmt::Display for TrustRootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "trust root cannot be empty"),
            Self::TooLong { max, actual } => {
                write!(f, "trust root length {actual} exceeds maximum {max}")
            }
            Self::InvalidDomain { domain, reason } => {
                write!(f, "invalid domain '{domain}': {reason}")
            }
            Self::InvalidIpAddress { value, reason } => {
                write!(f, "invalid IP address '{value}': {reason}")
            }
            Self::InvalidPort { value, reason } => {
                write!(f, "invalid port '{value}': {reason}")
            }
            Self::LabelTooLong { label, max, actual } => {
                write!(f, "DNS label '{label}' is {actual} chars, max is {max}")
            }
            Self::InvalidChar { char, position } => {
                write!(f, "invalid character '{char}' at position {position}")
            }
        }
    }
}

impl std::error::Error for TrustRootError {}

/// Errors for capability path parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityPathError {
    /// Path is empty
    Empty,
    /// Path exceeds maximum length
    TooLong {
        /// Maximum allowed length
        max: usize,
        /// Actual length
        actual: usize,
    },
    /// Too many segments
    TooManySegments {
        /// Maximum allowed segments
        max: usize,
        /// Actual segment count
        actual: usize,
    },
    /// Invalid segment
    InvalidSegment {
        /// The invalid segment
        segment: String,
        /// Index of the segment
        index: usize,
        /// Reason for invalidity
        reason: PathSegmentError,
    },
}

impl fmt::Display for CapabilityPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(
                f,
                "capability path cannot be empty; at least one segment required"
            ),
            Self::TooLong { max, actual } => {
                write!(f, "capability path length {actual} exceeds maximum {max}")
            }
            Self::TooManySegments { max, actual } => {
                write!(f, "path has {actual} segments, maximum is {max}")
            }
            Self::InvalidSegment {
                segment,
                index,
                reason,
            } => {
                write!(f, "invalid segment '{segment}' at index {index}: {reason}")
            }
        }
    }
}

impl std::error::Error for CapabilityPathError {}

/// Errors for path segment parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegmentError {
    /// Segment is empty
    Empty,
    /// Segment exceeds maximum length
    TooLong {
        /// Maximum allowed length
        max: usize,
        /// Actual length
        actual: usize,
    },
    /// Invalid character (not lowercase alphanumeric or hyphen)
    InvalidChar {
        /// The invalid character
        char: char,
        /// Position in the input
        position: usize,
    },
}

impl fmt::Display for PathSegmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "segment cannot be empty"),
            Self::TooLong { max, actual } => {
                write!(f, "segment length {actual} exceeds maximum {max}")
            }
            Self::InvalidChar { char, position } => {
                write!(
                    f,
                    "invalid character '{char}' at position {position}; only lowercase letters, digits, and hyphens allowed"
                )
            }
        }
    }
}

impl std::error::Error for PathSegmentError {}

/// Errors for agent ID parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentIdError {
    /// Agent ID is empty
    Empty,
    /// Agent ID exceeds maximum length
    TooLong {
        /// Maximum allowed length
        max: usize,
        /// Actual length
        actual: usize,
    },
    /// Invalid prefix
    InvalidPrefix(AgentPrefixError),
    /// Invalid `TypeID` suffix
    InvalidSuffix {
        /// The invalid value
        value: String,
        /// Reason for invalidity
        reason: &'static str,
    },
    /// Missing underscore separator
    MissingSeparator,
    /// `TypeID` parsing failed
    TypeIdError(String),
}

impl fmt::Display for AgentIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "agent ID cannot be empty"),
            Self::TooLong { max, actual } => {
                write!(f, "agent ID length {actual} exceeds maximum {max}")
            }
            Self::InvalidPrefix(e) => write!(f, "invalid prefix: {e}"),
            Self::InvalidSuffix { value, reason } => {
                write!(f, "invalid suffix '{value}': {reason}")
            }
            Self::MissingSeparator => {
                write!(f, "missing underscore separator between prefix and suffix")
            }
            Self::TypeIdError(msg) => write!(f, "`TypeID` error: {msg}"),
        }
    }
}

impl std::error::Error for AgentIdError {}

/// Errors for agent prefix parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentPrefixError {
    /// Prefix is empty
    Empty,
    /// Prefix exceeds maximum length
    TooLong {
        /// Maximum allowed length
        max: usize,
        /// Actual length
        actual: usize,
    },
    /// Invalid character (not lowercase letter or underscore)
    InvalidChar {
        /// The invalid character
        char: char,
        /// Position in the input
        position: usize,
    },
    /// Prefix must start with a letter
    MustStartWithLetter {
        /// The character found
        found: char,
    },
    /// Prefix must end with a letter
    MustEndWithLetter {
        /// The character found
        found: char,
    },
    /// Contains digits (not allowed per `TypeID` spec)
    ContainsDigit {
        /// Position of the digit
        position: usize,
    },
}

impl fmt::Display for AgentPrefixError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "prefix cannot be empty"),
            Self::TooLong { max, actual } => {
                write!(f, "prefix length {actual} exceeds maximum {max}")
            }
            Self::InvalidChar { char, position } => {
                write!(
                    f,
                    "invalid character '{char}' at position {position}; only lowercase letters and underscores allowed"
                )
            }
            Self::MustStartWithLetter { found } => {
                write!(f, "prefix must start with a letter, found '{found}'")
            }
            Self::MustEndWithLetter { found } => {
                write!(f, "prefix must end with a letter, found '{found}'")
            }
            Self::ContainsDigit { position } => {
                write!(f, "prefix cannot contain digits (found at position {position})")
            }
        }
    }
}

impl std::error::Error for AgentPrefixError {}

/// Errors for query string parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// Invalid parameter name
    InvalidParamName {
        /// The invalid name
        name: String,
        /// Reason for invalidity
        reason: &'static str,
    },
    /// Invalid parameter value
    InvalidParamValue {
        /// Parameter name
        name: String,
        /// The invalid value
        value: String,
        /// Reason for invalidity
        reason: &'static str,
    },
    /// Duplicate parameter
    DuplicateParam {
        /// The duplicated name
        name: String,
    },
    /// Invalid percent encoding
    InvalidPercentEncoding {
        /// The invalid value
        value: String,
    },
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParamName { name, reason } => {
                write!(f, "invalid parameter name '{name}': {reason}")
            }
            Self::InvalidParamValue { name, value, reason } => {
                write!(f, "invalid value '{value}' for parameter '{name}': {reason}")
            }
            Self::DuplicateParam { name } => {
                write!(f, "duplicate parameter '{name}'")
            }
            Self::InvalidPercentEncoding { value } => {
                write!(f, "invalid percent encoding in '{value}'")
            }
        }
    }
}

impl std::error::Error for QueryError {}

/// Errors for fragment parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentError {
    /// Invalid character in fragment
    InvalidChar {
        /// The invalid character
        char: char,
        /// Position in the input
        position: usize,
    },
}

impl fmt::Display for FragmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChar { char, position } => {
                write!(
                    f,
                    "invalid character '{char}' at position {position}; allowed: alphanumeric, hyphen, underscore, dot, slash"
                )
            }
        }
    }
}

impl std::error::Error for FragmentError {}
