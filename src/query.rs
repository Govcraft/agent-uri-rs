//! Query parameters type for agent URIs.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use crate::error::QueryError;

/// Query parameters from an agent URI.
///
/// Stores key-value pairs from the query string, sorted lexicographically
/// by key for consistent normalization.
///
/// # Reserved Parameters
///
/// - `version`: Capability version constraint (semver)
/// - `attestation`: Inline PASETO attestation token
/// - `resolver`: Hint for resolution endpoint
/// - `ttl`: Cache TTL hint in seconds
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueryParams {
    params: BTreeMap<String, String>,
}

impl QueryParams {
    /// Creates an empty query params instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses query parameters from a query string (without leading '?').
    ///
    /// # Errors
    ///
    /// Returns `QueryError` if any parameter is invalid.
    pub fn parse(input: &str) -> Result<Self, QueryError> {
        if input.is_empty() {
            return Ok(Self::new());
        }

        let mut params = BTreeMap::new();

        for pair in input.split('&') {
            if pair.is_empty() {
                continue;
            }

            let (name, value) = if let Some(eq_idx) = pair.find('=') {
                let name = &pair[..eq_idx];
                let value = &pair[eq_idx + 1..];
                (name, value)
            } else {
                (pair, "")
            };

            // Validate name
            Self::validate_param_name(name)?;

            // Validate and decode value
            let decoded_value = Self::decode_value(name, value)?;

            // Check for duplicates
            if params.contains_key(name) {
                return Err(QueryError::DuplicateParam {
                    name: name.to_string(),
                });
            }

            params.insert(name.to_string(), decoded_value);
        }

        Ok(Self { params })
    }

    /// Returns the value for a parameter, if present.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.params.get(name).map(String::as_str)
    }

    /// Returns true if the query is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    /// Returns the number of parameters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.params.len()
    }

    /// Returns an iterator over the parameters.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.params.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Returns the version parameter, if present.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.get("version")
    }

    /// Returns the TTL parameter, if present.
    #[must_use]
    pub fn ttl(&self) -> Option<u64> {
        self.get("ttl").and_then(|s| s.parse().ok())
    }

    fn validate_param_name(name: &str) -> Result<(), QueryError> {
        if name.is_empty() {
            return Err(QueryError::InvalidParamName {
                name: name.to_string(),
                reason: "parameter name cannot be empty",
            });
        }

        for c in name.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
                return Err(QueryError::InvalidParamName {
                    name: name.to_string(),
                    reason: "name must be alphanumeric, hyphen, or underscore",
                });
            }
        }

        Ok(())
    }

    fn decode_value(name: &str, value: &str) -> Result<String, QueryError> {
        let mut decoded = String::with_capacity(value.len());
        let mut chars = value.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '%' {
                let hex: String = chars.by_ref().take(2).collect();
                if hex.len() != 2 {
                    return Err(QueryError::InvalidPercentEncoding {
                        value: value.to_string(),
                    });
                }
                let byte =
                    u8::from_str_radix(&hex, 16).map_err(|_| QueryError::InvalidPercentEncoding {
                        value: value.to_string(),
                    })?;
                decoded.push(byte as char);
            } else if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                decoded.push(c);
            } else {
                return Err(QueryError::InvalidParamValue {
                    name: name.to_string(),
                    value: value.to_string(),
                    reason: "contains invalid unencoded character",
                });
            }
        }

        Ok(decoded)
    }
}

impl fmt::Display for QueryParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pairs: Vec<String> = self
            .params
            .iter()
            .map(|(k, v)| {
                if v.is_empty() {
                    k.clone()
                } else {
                    format!("{k}={v}")
                }
            })
            .collect();
        write!(f, "{}", pairs.join("&"))
    }
}

impl FromStr for QueryParams {
    type Err = QueryError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty() {
        let params = QueryParams::parse("").unwrap();
        assert!(params.is_empty());
    }

    #[test]
    fn parse_single_param() {
        let params = QueryParams::parse("version=2.0").unwrap();
        assert_eq!(params.get("version"), Some("2.0"));
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn parse_multiple_params() {
        let params = QueryParams::parse("version=2.0&ttl=300").unwrap();
        assert_eq!(params.get("version"), Some("2.0"));
        assert_eq!(params.get("ttl"), Some("300"));
        assert_eq!(params.len(), 2);
    }

    #[test]
    fn parse_param_without_value() {
        let params = QueryParams::parse("flag").unwrap();
        assert_eq!(params.get("flag"), Some(""));
    }

    #[test]
    fn parse_percent_encoded() {
        let params = QueryParams::parse("name=%41%42%43").unwrap();
        assert_eq!(params.get("name"), Some("ABC"));
    }

    #[test]
    fn version_helper() {
        let params = QueryParams::parse("version=2.0").unwrap();
        assert_eq!(params.version(), Some("2.0"));
    }

    #[test]
    fn ttl_helper() {
        let params = QueryParams::parse("ttl=300").unwrap();
        assert_eq!(params.ttl(), Some(300));
    }

    #[test]
    fn ttl_invalid_returns_none() {
        let params = QueryParams::parse("ttl=invalid").unwrap();
        assert_eq!(params.ttl(), None);
    }

    #[test]
    fn parse_duplicate_fails() {
        let result = QueryParams::parse("version=1.0&version=2.0");
        assert!(matches!(result, Err(QueryError::DuplicateParam { .. })));
    }

    #[test]
    fn parse_invalid_name_fails() {
        let result = QueryParams::parse("invalid@name=value");
        assert!(matches!(result, Err(QueryError::InvalidParamName { .. })));
    }

    #[test]
    fn parse_invalid_encoding_fails() {
        let result = QueryParams::parse("name=%GG");
        assert!(matches!(result, Err(QueryError::InvalidPercentEncoding { .. })));
    }

    #[test]
    fn parse_invalid_value_char_fails() {
        let result = QueryParams::parse("name=value with space");
        assert!(matches!(result, Err(QueryError::InvalidParamValue { .. })));
    }

    #[test]
    fn display_sorted() {
        let params = QueryParams::parse("z=1&a=2").unwrap();
        // BTreeMap sorts by key
        assert_eq!(params.to_string(), "a=2&z=1");
    }

    #[test]
    fn iter_returns_all_params() {
        let params = QueryParams::parse("a=1&b=2").unwrap();
        let items: Vec<_> = params.iter().collect();
        assert_eq!(items, vec![("a", "1"), ("b", "2")]);
    }
}
