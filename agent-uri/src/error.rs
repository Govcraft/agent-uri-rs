//! Error types for agent URI parsing.

use std::fmt;

use crate::constants::MAX_URI_LENGTH;

/// How much of a rejected input an error keeps.
///
/// Set to the longest URI that could ever have parsed, so an input the parser
/// might plausibly have accepted is kept whole and only what could not be a
/// URI at all is cut.
const MAX_ERROR_INPUT_LENGTH: usize = MAX_URI_LENGTH;

/// Errors that can occur when parsing an agent URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// The input that failed to parse, cut to the first 512 characters and
    /// marked with `…` if there was more.
    ///
    /// A parser reads what it is given, and what it is given may be a
    /// megabyte. Keeping all of it hands a caller who logs or collects errors
    /// a full copy of an input that was rejected precisely for being
    /// unusable — the rejection itself becomes the cost. Anything within the
    /// length a URI may have is kept verbatim, so this is only ever a cut of
    /// something that could not have parsed at any length; when the length was
    /// the complaint, [`ParseErrorKind::TooLong`] carries what it actually was.
    pub input: String,
    /// The specific error that occurred
    pub kind: ParseErrorKind,
}

impl ParseError {
    /// Builds an error, keeping only as much of the input as is worth keeping.
    pub(crate) fn new(input: &str, kind: ParseErrorKind) -> Self {
        Self {
            input: truncate_input(input),
            kind,
        }
    }
}

/// Appended to a cut input so a reader can tell a cut string from a short one.
const TRUNCATION_MARKER: char = '…';

/// Keeps the first [`MAX_ERROR_INPUT_LENGTH`] characters of `input`.
///
/// Characters, not bytes. Cutting at a byte offset panics in the middle of a
/// character, which is the mistake this crate keeps having to unmake (issues
/// #33 and #89), and it is not a mistake worth making inside the type whose
/// whole job is reporting that something was wrong.
fn truncate_input(input: &str) -> String {
    let mut chars = input.chars();
    let mut kept: String = chars.by_ref().take(MAX_ERROR_INPUT_LENGTH).collect();

    if chars.next().is_some() {
        kept.push(TRUNCATION_MARKER);
    }

    kept
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
    /// The leading type class is not a valid core or extension class
    InvalidTypeClass {
        /// The rejected type-class text
        class: String,
        /// Reason for invalidity
        reason: &'static str,
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
            Self::InvalidTypeClass { class, reason } => {
                write!(f, "invalid type class '{class}': {reason}")
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
                write!(
                    f,
                    "prefix cannot contain digits (found at position {position})"
                )
            }
        }
    }
}

impl std::error::Error for AgentPrefixError {}

/// Errors for query string parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryError {
    /// Input exceeds maximum length
    TooLong {
        /// Maximum allowed length
        max: usize,
        /// Actual length
        actual: usize,
    },
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
    /// Percent-decoded octets did not form valid UTF-8
    InvalidUtf8 {
        /// The offending value, as written in the URI
        value: String,
    },
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { max, actual } => {
                write!(f, "query string length {actual} exceeds maximum {max}")
            }
            Self::InvalidParamName { name, reason } => {
                write!(f, "invalid parameter name '{name}': {reason}")
            }
            Self::InvalidParamValue {
                name,
                value,
                reason,
            } => {
                write!(
                    f,
                    "invalid value '{value}' for parameter '{name}': {reason}"
                )
            }
            Self::DuplicateParam { name } => {
                write!(f, "duplicate parameter '{name}'")
            }
            Self::InvalidPercentEncoding { value } => {
                write!(f, "invalid percent encoding in '{value}'")
            }
            Self::InvalidUtf8 { value } => {
                write!(f, "percent-encoded value '{value}' is not valid UTF-8")
            }
        }
    }
}

impl std::error::Error for QueryError {}

/// Errors for fragment parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentError {
    /// Input exceeds maximum length
    TooLong {
        /// Maximum allowed length
        max: usize,
        /// Actual length
        actual: usize,
    },
    /// Invalid character in fragment
    InvalidChar {
        /// The invalid character
        char: char,
        /// Position in the input
        position: usize,
    },
    /// The fragment is empty; a bare '#' carries no fragment.
    Empty,
}

impl fmt::Display for FragmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { max, actual } => {
                write!(f, "fragment length {actual} exceeds maximum {max}")
            }
            Self::InvalidChar { char, position } => {
                write!(
                    f,
                    "invalid character '{char}' at position {position}; allowed: alphanumeric, hyphen, underscore, dot, slash"
                )
            }
            Self::Empty => write!(f, "fragment must not be empty; omit the '#' instead"),
        }
    }
}

impl std::error::Error for FragmentError {}

/// Errors that can occur when building an agent URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderError {
    /// The resulting URI would exceed the maximum length.
    UriTooLong {
        /// Maximum allowed length
        max: usize,
        /// Actual length
        actual: usize,
    },
    /// The components could not be assembled into a valid URI
    InvalidUri(ParseError),
}

impl fmt::Display for BuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UriTooLong { max, actual } => {
                write!(
                    f,
                    "resulting URI length {actual} exceeds maximum {max}; \
                     consider shorter component values"
                )
            }
            Self::InvalidUri(e) => write!(f, "cannot build agent URI: {e}"),
        }
    }
}

impl std::error::Error for BuilderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUri(e) => Some(e),
            Self::UriTooLong { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_input_a_uri_could_have_been_is_kept_whole() {
        // Truncation must never reach an input the parser might plausibly
        // have accepted, or the error stops describing what was rejected.
        let input = format!("agent://{}", "a".repeat(MAX_ERROR_INPUT_LENGTH - 8));
        assert_eq!(input.chars().count(), MAX_ERROR_INPUT_LENGTH);

        let error = ParseError::new(&input, ParseErrorKind::Empty);

        assert_eq!(error.input, input);
        assert!(!error.input.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn a_hostile_input_is_not_copied_into_the_error() {
        // The whole point: rejecting a megabyte must not cost a megabyte.
        let input = "a".repeat(4 * 1024 * 1024);

        let error = ParseError::new(
            &input,
            ParseErrorKind::TooLong {
                max: MAX_URI_LENGTH,
                actual: input.len(),
            },
        );

        assert_eq!(error.input.chars().count(), MAX_ERROR_INPUT_LENGTH + 1);
        assert!(error.input.ends_with(TRUNCATION_MARKER));

        // What was cut is not lost, because the length was the complaint and
        // the complaint carries it.
        let ParseErrorKind::TooLong { actual, .. } = error.kind else {
            panic!("wrong kind");
        };
        assert_eq!(actual, 4 * 1024 * 1024);
    }

    #[test]
    fn truncation_counts_characters_and_not_bytes() {
        // Cutting at a byte offset lands inside a character and panics. Each
        // of these is four bytes, so a byte-counting cut would slice one in
        // half well before the character limit.
        let input = "\u{1f300}".repeat(MAX_ERROR_INPUT_LENGTH * 2);
        assert!(input.len() > MAX_ERROR_INPUT_LENGTH * 4);

        let error = ParseError::new(&input, ParseErrorKind::Empty);

        assert_eq!(error.input.chars().count(), MAX_ERROR_INPUT_LENGTH + 1);
        assert!(
            error
                .input
                .chars()
                .take(MAX_ERROR_INPUT_LENGTH)
                .all(|c| c == '\u{1f300}'),
            "a character was cut in half"
        );
    }

    #[test]
    fn an_input_one_character_over_the_limit_is_marked() {
        let input = "a".repeat(MAX_ERROR_INPUT_LENGTH + 1);

        let error = ParseError::new(&input, ParseErrorKind::Empty);

        assert!(error.input.ends_with(TRUNCATION_MARKER));
        assert_eq!(
            error.input.chars().filter(|c| *c == 'a').count(),
            MAX_ERROR_INPUT_LENGTH
        );
    }

    #[test]
    fn a_truncated_input_still_renders() {
        // `Display` interpolates the input, so a cut that produced invalid
        // UTF-8 would surface here rather than in the field.
        let error = ParseError::new(
            &"\u{1f300}".repeat(MAX_ERROR_INPUT_LENGTH + 4),
            ParseErrorKind::Empty,
        );

        assert!(error.to_string().contains(TRUNCATION_MARKER));
    }
}
