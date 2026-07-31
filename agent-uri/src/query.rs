//! Query parameters type for agent URIs.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use crate::constants::MAX_URI_LENGTH;
use crate::error::QueryError;

/// Query parameters from an agent URI.
///
/// Stores key-value pairs from the query string, sorted lexicographically
/// by key for consistent normalization. Percent escapes in values decode to
/// octets, and the complete decoded sequence must be valid UTF-8. Invalid UTF-8
/// is rejected rather than replaced. Programmatically constructed values may
/// contain any characters. [`fmt::Display`] re-encodes every value octet outside
/// the ASCII alphanumeric, `-`, `_`, and `.` set using uppercase `%XX`, so its
/// output parses to the same values.
///
/// # Reserved Parameters
///
/// - `version`: Capability version constraint (semver)
/// - `attestation`: Inline PASETO attestation token
/// - `resolver`: Hint for resolution endpoint
/// - `ttl`: Cache TTL hint in seconds
///
/// Parameters are held sorted by name, so two queries that differ only in the
/// order they were written are equal and hash equally.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
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
    /// Percent escapes decode to octets, and the complete decoded sequence must
    /// be valid UTF-8. Invalid sequences are rejected rather than replaced.
    /// Rendering with [`fmt::Display`] re-encodes every value octet outside the
    /// ASCII alphanumeric, `-`, `_`, and `.` set as uppercase `%XX`, preserving
    /// values across parse-display-parse round trips.
    /// This standalone entry point enforces the same total-URI byte limit that
    /// [`crate::AgentUri::parse`] applies.
    ///
    /// # Errors
    ///
    /// Input longer than 512 bytes ([`crate::MAX_URI_LENGTH`]) is rejected with
    /// [`QueryError::TooLong`]. Other invalid parameters return their
    /// corresponding `QueryError` variant.
    pub fn parse(input: &str) -> Result<Self, QueryError> {
        if input.len() > MAX_URI_LENGTH {
            return Err(QueryError::TooLong {
                max: MAX_URI_LENGTH,
                actual: input.len(),
            });
        }

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

    /// Returns a new query with the given parameter added or updated.
    ///
    /// The value may contain any characters. [`fmt::Display`] percent-encodes
    /// every UTF-8 octet outside the ASCII alphanumeric, `-`, `_`, and `.` set.
    ///
    /// # Errors
    ///
    /// Returns `QueryError` if the parameter name is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::QueryParams;
    ///
    /// let query = QueryParams::new();
    /// let updated = query.with_param("version", "2.0").unwrap();
    /// assert_eq!(updated.get("version"), Some("2.0"));
    ///
    /// let with_filter = updated.with_param("filter", "&b=c").unwrap();
    /// assert_eq!(with_filter.get("filter"), Some("&b=c"));
    /// let rendered = with_filter.to_string();
    /// assert!(rendered.contains("filter=%26b%3Dc"));
    /// assert_eq!(
    ///     QueryParams::parse(&rendered).unwrap().get("filter"),
    ///     Some("&b=c")
    /// );
    /// ```
    pub fn with_param(&self, key: &str, value: &str) -> Result<Self, QueryError> {
        Self::validate_param_name(key)?;

        let mut params = self.params.clone();
        params.insert(key.to_string(), value.to_string());
        Ok(Self { params })
    }

    /// Returns a new query without the given parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::QueryParams;
    ///
    /// let query = QueryParams::parse("version=2.0&ttl=300").unwrap();
    /// let updated = query.without_param("ttl");
    /// assert!(updated.get("ttl").is_none());
    /// assert_eq!(updated.get("version"), Some("2.0"));
    /// ```
    #[must_use]
    pub fn without_param(&self, key: &str) -> Self {
        let mut params = self.params.clone();
        params.remove(key);
        Self { params }
    }

    /// Returns a new query with the version parameter set.
    ///
    /// # Errors
    ///
    /// The return type is retained for API stability. This helper currently
    /// cannot fail because its fixed parameter name is valid and values may
    /// contain any characters.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::QueryParams;
    ///
    /// let query = QueryParams::new();
    /// let updated = query.with_version("2.0").unwrap();
    /// assert_eq!(updated.version(), Some("2.0"));
    /// ```
    pub fn with_version(&self, v: &str) -> Result<Self, QueryError> {
        self.with_param("version", v)
    }

    /// Returns a new query with the TTL parameter set.
    ///
    /// # Errors
    ///
    /// The return type is retained for API stability. This helper currently
    /// cannot fail because its fixed parameter name and generated value are
    /// valid.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::QueryParams;
    ///
    /// let query = QueryParams::new();
    /// let updated = query.with_ttl(300).unwrap();
    /// assert_eq!(updated.ttl(), Some(300));
    /// ```
    pub fn with_ttl(&self, ttl: u64) -> Result<Self, QueryError> {
        self.with_param("ttl", &ttl.to_string())
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
        let encoded = value.as_bytes();
        let mut decoded = Vec::with_capacity(value.len());
        let mut index = 0;

        while let Some(&byte) = encoded.get(index) {
            match byte {
                b'%' => {
                    let digits = encoded
                        .get(index + 1)
                        .copied()
                        .and_then(Self::hex_digit)
                        .zip(encoded.get(index + 2).copied().and_then(Self::hex_digit));
                    let Some((high, low)) = digits else {
                        return Err(QueryError::InvalidPercentEncoding {
                            value: value.to_string(),
                        });
                    };
                    decoded.push((high << 4) | low);
                    index += 3;
                }
                byte if Self::is_unreserved(byte) => {
                    decoded.push(byte);
                    index += 1;
                }
                _ => {
                    return Err(QueryError::InvalidParamValue {
                        name: name.to_string(),
                        value: value.to_string(),
                        reason: "contains invalid unencoded character",
                    });
                }
            }
        }

        String::from_utf8(decoded).map_err(|_| QueryError::InvalidUtf8 {
            value: value.to_string(),
        })
    }

    fn encode_value(value: &str) -> String {
        const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

        let mut encoded = String::with_capacity(value.len());
        for &byte in value.as_bytes() {
            if Self::is_unreserved(byte) {
                encoded.push(char::from(byte));
            } else {
                encoded.push('%');
                encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
                encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
            }
        }
        encoded
    }

    const fn hex_digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }

    const fn is_unreserved(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
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
                    let encoded_value = Self::encode_value(v);
                    format!("{k}={encoded_value}")
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

impl TryFrom<&str> for QueryParams {
    type Error = QueryError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl PartialOrd for QueryParams {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for QueryParams {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for QueryParams {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for QueryParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
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
    fn query_at_maximum_length_parses() {
        let input = format!("v={}", "a".repeat(MAX_URI_LENGTH - 2));

        let params = QueryParams::parse(&input).unwrap();

        assert_eq!(input.len(), MAX_URI_LENGTH);
        assert_eq!(params.get("v").unwrap().len(), MAX_URI_LENGTH - 2);
    }

    #[test]
    fn query_over_maximum_length_reports_limit_and_actual_length() {
        let input = format!("v={}", "a".repeat(MAX_URI_LENGTH - 1));

        let error = QueryParams::parse(&input).unwrap_err();
        let QueryError::TooLong { max, actual } = error else {
            panic!("expected QueryError::TooLong");
        };

        assert_eq!(max, MAX_URI_LENGTH);
        assert_eq!(actual, input.len());
    }

    #[test]
    fn query_length_cap_precedes_character_validation() {
        let input = format!("v={}", "@".repeat(MAX_URI_LENGTH));

        assert!(matches!(
            QueryParams::parse(&input),
            Err(QueryError::TooLong {
                max: MAX_URI_LENGTH,
                actual
            }) if actual == input.len()
        ));
    }

    #[test]
    fn whole_uri_length_cap_still_precedes_query_parsing() {
        let base = "agent://example.com/chat/llm_01h455vb4pex5vsknk084sn02q?v=";
        let input = format!("{base}{}", "a".repeat(MAX_URI_LENGTH + 1 - base.len()));

        let error = crate::AgentUri::parse(&input).unwrap_err();
        let crate::ParseErrorKind::TooLong { max, actual } = error.kind else {
            panic!("expected ParseErrorKind::TooLong");
        };

        assert_eq!(input.len(), MAX_URI_LENGTH + 1);
        assert_eq!(max, MAX_URI_LENGTH);
        assert_eq!(actual, input.len());
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
    fn ascii_percent_escapes_still_decode() {
        let params = QueryParams::parse("name=%41%42%43").unwrap();
        assert_eq!(params.get("name"), Some("ABC"));
    }

    #[test]
    fn percent_decoded_multibyte_sequences_are_utf8() {
        // The old code pushed each decoded byte as a char (Latin-1), producing "Ã©".
        let acute = QueryParams::parse("name=%C3%A9").unwrap();
        let euro = QueryParams::parse("name=%E2%82%AC").unwrap();
        let crab = QueryParams::parse("name=%F0%9F%A6%80").unwrap();

        assert_eq!(acute.get("name"), Some("é"));
        assert_eq!(euro.get("name"), Some("€"));
        assert_eq!(crab.get("name"), Some("🦀"));
    }

    #[test]
    fn invalid_utf8_percent_escapes_are_rejected() {
        for input in ["name=%FF", "name=%80", "name=%C3", "name=%ED%A0%80"] {
            let result = QueryParams::parse(input);

            assert!(
                matches!(result, Err(QueryError::InvalidUtf8 { .. })),
                "expected invalid UTF-8 error for {input}"
            );
        }
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
    fn malformed_percent_escapes_still_report_encoding_error() {
        for input in ["name=%GG", "name=%4"] {
            let result = QueryParams::parse(input);

            assert!(
                matches!(result, Err(QueryError::InvalidPercentEncoding { .. })),
                "expected invalid percent encoding error for {input}"
            );
        }
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
    fn display_reencodes_non_unreserved_octets() {
        let unicode = QueryParams::parse("name=%C3%A9").unwrap();
        let space = QueryParams::parse("name=%20").unwrap();

        assert_eq!(unicode.to_string(), "name=%C3%A9");
        assert_eq!(space.to_string(), "name=%20");
    }

    #[test]
    fn reserved_delimiters_survive_the_display_round_trip() {
        let params = QueryParams::parse("a=%26b%3Dc").unwrap();
        assert_eq!(params.get("a"), Some("&b=c"));
        assert_eq!(params.len(), 1);

        let rendered = params.to_string();
        assert_eq!(rendered, "a=%26b%3Dc");

        // A consumer that stores the canonical string and re-parses it must not
        // see attacker-controlled parameter splitting.
        let reparsed = QueryParams::parse(&rendered).unwrap();
        assert_eq!(reparsed.get("a"), Some("&b=c"));
        assert_eq!(reparsed.len(), 1);
    }

    #[test]
    fn with_param_accepts_values_that_parse_accepts() {
        for value in ["&b=c", "é", "a b", "?x=1", "100%"] {
            let params = QueryParams::new().with_param("v", value).unwrap();
            assert_eq!(params.get("v"), Some(value));
        }
    }

    #[test]
    fn with_param_values_round_trip_through_display() {
        for value in ["&b=c", "é", "a b", "?x=1", "100%"] {
            let params = QueryParams::new().with_param("v", value).unwrap();
            let rendered = params.to_string();
            let reparsed = QueryParams::parse(&rendered).unwrap();

            assert_eq!(reparsed.get("v"), Some(value));
            assert_eq!(reparsed.len(), 1);
        }
    }

    #[test]
    fn with_param_still_rejects_invalid_names() {
        let invalid_space = QueryParams::new().with_param("bad name", "1");
        let empty = QueryParams::new().with_param("", "1");

        assert!(matches!(
            invalid_space,
            Err(QueryError::InvalidParamName { .. })
        ));
        assert!(matches!(empty, Err(QueryError::InvalidParamName { .. })));
    }

    #[test]
    fn oversized_query_values_are_still_rejected_at_the_uri_boundary() {
        let params = QueryParams::new()
            .with_param("v", &"&".repeat(300))
            .unwrap();
        let uri = crate::AgentUri::parse("agent://example.com/chat/llm_01h455vb4pex5vsknk084sn02q")
            .unwrap();

        let error = uri.with_query(params).unwrap_err();
        assert!(matches!(
            error.kind,
            crate::ParseErrorKind::TooLong { max, actual }
                if max == crate::MAX_URI_LENGTH && actual > max
        ));
    }

    #[test]
    fn uri_with_encoded_query_round_trips() {
        let uri = crate::AgentUri::parse(
            "agent://example.com/chat/llm_01h455vb4pex5vsknk084sn02q?name=%C3%A9",
        )
        .unwrap();

        assert_eq!(uri.query().get("name"), Some("é"));

        let reparsed = crate::AgentUri::parse(uri.as_str()).unwrap();
        assert_eq!(reparsed.query().get("name"), Some("é"));
        assert_eq!(reparsed.query().to_string(), uri.query().to_string());
    }

    #[test]
    fn iter_returns_all_params() {
        let params = QueryParams::parse("a=1&b=2").unwrap();
        let items: Vec<_> = params.iter().collect();
        assert_eq!(items, vec![("a", "1"), ("b", "2")]);
    }
}
