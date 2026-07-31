//! Agent identifier type using `TypeID` format.
//!
//! # Grammar Reference
//!
//! The agent ID grammar is defined in `grammar.abnf`:
//!
//! ```abnf
//! agent-id     = agent-prefix "_" type-suffix
//! agent-prefix = type-class *( "_" type-modifier )
//! type-class   = "llm" / "rule" / "human" / "composite"
//!              / "sensor" / "actuator" / "hybrid"
//!              / extension-class
//! type-suffix  = suffix-first 25( BASE32-TYPEID )
//! suffix-first = %x30-37  ; "0" through "7"
//! ```
//!
//! Maximum agent ID length: 90 characters (63 prefix + 1 underscore + 26 suffix).

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use mti::prelude::*;

use crate::agent_prefix::AgentPrefix;
use crate::constants::{AGENT_SUFFIX_LENGTH, MAX_AGENT_ID_LENGTH, MAX_AGENT_PREFIX_LENGTH};
use crate::error::AgentIdError;

/// Base32 alphabet for `TypeID` suffix (Crockford-derived).
/// Excludes: i, l, o, u (visually ambiguous).
///
/// A `str` rather than a byte string so membership is asked of a whole
/// character. Asking it of `c as u8` truncates: `'İ'` (U+0130) becomes `0x30`,
/// which is `'0'`, and twelve of them read as twelve zeros (issue #33).
const BASE32_ALPHABET: &str = "0123456789abcdefghjkmnpqrstvwxyz";

/// The type class a prefix falls back to when sanitizing leaves nothing.
///
/// [`AgentId::new`] rewrites rather than refuses, and rewriting can consume the
/// whole input: `new("123")` has no letter to keep. A bare `TypeID` may have an
/// empty prefix, but this grammar's `agent-prefix` may not, so there is nothing
/// to fall back to except a class that says only what the input already said,
/// which is that the thing is an agent.
const FALLBACK_TYPE_CLASS: &str = "agent";

/// Rewrites any string into a prefix `agent-prefix` accepts.
///
/// The rules are the ones `mti` applies to a bare `TypeID` prefix, tightened
/// where this grammar is tighter:
///
/// - ASCII uppercase folds to lowercase; every other character outside
///   `[a-z_]` is dropped. Folding is ASCII-only on purpose: mapping `İ` to `i`
///   would let a non-ASCII character name an ASCII agent (issue #33).
/// - A run of underscores collapses to one, and a leading underscore is
///   dropped, because `type-modifier` is `1*LOWER` and an empty modifier is
///   not a modifier.
/// - The result is cut to 63 characters and then loses any trailing
///   underscore, because a prefix must end in a letter.
/// - If nothing survives, the result is [`FALLBACK_TYPE_CLASS`].
///
/// The output always parses as an [`AgentPrefix`]; `sanitizing_is_total` and
/// the `agent_id_new_never_panics` property test hold this invariant up.
fn sanitize_prefix(input: &str) -> String {
    let mut out = String::new();

    for c in input.chars().map(|c| c.to_ascii_lowercase()) {
        if out.len() == MAX_AGENT_PREFIX_LENGTH {
            break;
        }
        match c {
            'a'..='z' => out.push(c),
            '_' if !out.is_empty() && !out.ends_with('_') => out.push('_'),
            _ => {}
        }
    }

    // The loop only ever keeps an underscore that had a letter before it. The
    // letter after it is what the cut above can take away.
    while out.ends_with('_') {
        out.pop();
    }

    if out.is_empty() {
        FALLBACK_TYPE_CLASS.to_string()
    } else {
        out
    }
}

/// A validated agent identifier in `TypeID` format.
///
/// The agent ID uniquely identifies an agent and encodes:
/// - Semantic classification (the prefix)
/// - Unique identity (the `UUIDv7` suffix)
/// - Creation timestamp (encoded in `UUIDv7`)
///
/// # Format
///
/// `<prefix>_<suffix>` where:
/// - prefix: 1-63 lowercase letters and underscores
/// - suffix: 26 character base32-encoded `UUIDv7`
///
/// # Examples
///
/// ```
/// use agent_uri::AgentId;
///
/// let id = AgentId::parse("llm_01h455vb4pex5vsknk084sn02q").unwrap();
/// assert_eq!(id.prefix().as_str(), "llm");
/// assert_eq!(id.suffix(), "01h455vb4pex5vsknk084sn02q");
///
/// // Create a new agent ID
/// let id = AgentId::new("llm_chat");
/// assert_eq!(id.suffix().len(), 26);
/// ```
///
/// # Constructing one
///
/// [`AgentId::parse`] reads an existing ID. The other two mint a fresh one and
/// differ only in what they do with a prefix the grammar rejects:
/// [`AgentId::new`] rewrites it, [`AgentId::try_new`] reports it. Prefer
/// `try_new` for any prefix that did not come from your own source.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AgentId {
    prefix: AgentPrefix,
    suffix: String,
    inner: MagicTypeId,
}

impl AgentId {
    /// Creates a new agent ID with the given prefix and a fresh `UUIDv7`,
    /// sanitizing the prefix if the grammar does not already accept it.
    ///
    /// This is the split `mti` draws, and this crate mints `TypeID`s with
    /// `mti`: `create_type_id` sanitizes and `try_create_type_id` refuses.
    /// Sanitizing is described on [`AgentId::try_new`]'s counterpart below;
    /// in short, anything outside `[a-z_]` is dropped, uppercase is folded,
    /// and a prefix left with nothing becomes `agent`.
    ///
    /// # Choosing between this and [`AgentId::try_new`]
    ///
    /// Sanitizing means you get an agent ID with *a* prefix, not necessarily
    /// the one you named. That is what you want when the prefix is a label you
    /// wrote: minting an ID should not be fallible over a string literal. It is
    /// not what you want when the prefix arrived from somewhere — a peer, a
    /// config file, a URI — because a rewritten prefix is a different agent
    /// class than the one that was asked for, and silence about that is how a
    /// caller ends up registering under a name it never chose. Untrusted input
    /// belongs in [`AgentId::try_new`] or [`AgentId::parse`], which refuse.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentId;
    ///
    /// // A prefix the grammar already accepts is kept verbatim.
    /// let id = AgentId::new("llm_chat");
    /// assert_eq!(id.prefix().as_str(), "llm_chat");
    ///
    /// // Anything else is rewritten rather than refused.
    /// assert_eq!(AgentId::new("LLM Chat!").prefix().as_str(), "llmchat");
    /// assert_eq!(AgentId::new("__llm__chat__").prefix().as_str(), "llm_chat");
    /// assert_eq!(AgentId::new("123").prefix().as_str(), "agent");
    ///
    /// // Every one of them is a parsable agent ID.
    /// assert!(AgentId::parse(&AgentId::new("123").to_string()).is_ok());
    /// ```
    #[must_use]
    pub fn new(prefix: &str) -> Self {
        let sanitized = sanitize_prefix(prefix);
        let Ok(agent_prefix) = AgentPrefix::parse(&sanitized) else {
            unreachable!("sanitize_prefix returns a parsable prefix, got {sanitized:?}")
        };

        Self::mint(agent_prefix)
    }

    /// Creates a new agent ID with the given prefix and a fresh `UUIDv7`,
    /// refusing a prefix the grammar does not accept.
    ///
    /// Use this whenever the prefix came from outside your own source: it
    /// reports what [`AgentId::new`] would have quietly rewritten.
    ///
    /// # Errors
    ///
    /// Returns `AgentIdError` if the prefix is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use agent_uri::AgentId;
    ///
    /// assert!(AgentId::try_new("llm_chat").is_ok());
    /// assert!(AgentId::try_new("LLM Chat!").is_err());
    /// ```
    pub fn try_new(prefix: &str) -> Result<Self, AgentIdError> {
        let agent_prefix = AgentPrefix::parse(prefix).map_err(AgentIdError::InvalidPrefix)?;

        Ok(Self::mint(agent_prefix))
    }

    /// Mints an agent ID from a prefix that has already been validated.
    ///
    /// Both constructors end here, and nothing here can fail: the prefix has
    /// already been validated, a fresh `UUIDv7` suffix is always well formed,
    /// and `mti` assembles a `TypeID` from the two without consulting either.
    /// Minting used to go through `mti`'s fallible accessors, which gave
    /// [`AgentId::new`] a failure to `expect` on top of the one it already had.
    fn mint(prefix: AgentPrefix) -> Self {
        let suffix = TypeIdSuffix::new::<V7>();
        let suffix_string = suffix.to_string();
        // A no-op: `AgentPrefix` is strictly narrower than a `TypeID` prefix.
        // It is how a `TypeIdPrefix` is obtained without a fallible parse.
        let inner = MagicTypeId::new(prefix.as_str().create_prefix_sanitized(), suffix);

        Self {
            prefix,
            suffix: suffix_string,
            inner,
        }
    }

    /// Parses an agent ID from a string.
    ///
    /// # Errors
    ///
    /// Returns `AgentIdError` if:
    /// - The input is empty
    /// - The input exceeds 90 characters
    /// - The prefix is invalid
    /// - The suffix is invalid (not valid base32 or wrong length)
    /// - The separator is missing
    pub fn parse(input: &str) -> Result<Self, AgentIdError> {
        if input.is_empty() {
            return Err(AgentIdError::Empty);
        }

        if input.len() > MAX_AGENT_ID_LENGTH {
            return Err(AgentIdError::TooLong {
                max: MAX_AGENT_ID_LENGTH,
                actual: input.len(),
            });
        }

        // Find the last underscore (separator between prefix and suffix)
        let sep_idx = input.rfind('_').ok_or(AgentIdError::MissingSeparator)?;

        if sep_idx == 0 {
            return Err(AgentIdError::InvalidPrefix(
                crate::error::AgentPrefixError::Empty,
            ));
        }

        let prefix_str = &input[..sep_idx];
        let suffix_str = &input[sep_idx + 1..];

        // Validate prefix
        let prefix = AgentPrefix::parse(prefix_str).map_err(AgentIdError::InvalidPrefix)?;

        // Validate suffix
        Self::validate_suffix(suffix_str)?;

        // Parse as MagicTypeId
        let inner =
            MagicTypeId::from_str(input).map_err(|e| AgentIdError::TypeIdError(e.to_string()))?;

        Ok(Self {
            prefix,
            suffix: suffix_str.to_string(),
            inner,
        })
    }

    /// Returns the prefix (semantic classification).
    #[must_use]
    pub const fn prefix(&self) -> &AgentPrefix {
        &self.prefix
    }

    /// Returns the suffix (base32-encoded `UUIDv7`).
    #[must_use]
    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    /// Returns the underlying [`MagicTypeId`].
    #[must_use]
    pub const fn inner(&self) -> &MagicTypeId {
        &self.inner
    }

    /// Returns the UUID from the suffix.
    ///
    /// # Errors
    ///
    /// Returns an error if UUID extraction fails.
    pub fn uuid(&self) -> Result<uuid::Uuid, AgentIdError> {
        self.inner
            .uuid()
            .map_err(|e| AgentIdError::TypeIdError(e.to_string()))
    }

    fn validate_suffix(suffix: &str) -> Result<(), AgentIdError> {
        // Characters, not bytes. An upper bound on bytes only ever rejects more
        // than it means to, but this is an equality: a suffix of thirteen
        // two-byte characters occupies twenty-six bytes and would pass a check
        // that counted them, having answered a question nobody asked.
        if suffix.chars().count() != AGENT_SUFFIX_LENGTH {
            return Err(AgentIdError::InvalidSuffix {
                value: suffix.to_string(),
                reason: "suffix must be exactly 26 characters",
            });
        }

        // First character must be 0-7 (prevent 130-bit overflow)
        let first = suffix
            .chars()
            .next()
            .expect("already checked suffix is not empty");
        if !('0'..='7').contains(&first) {
            return Err(AgentIdError::InvalidSuffix {
                value: suffix.to_string(),
                reason: "first character must be 0-7",
            });
        }

        // All characters must be valid base32
        for c in suffix.chars() {
            if !BASE32_ALPHABET.contains(c) {
                return Err(AgentIdError::InvalidSuffix {
                    value: suffix.to_string(),
                    reason: "contains invalid base32 character",
                });
            }
        }

        Ok(())
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl FromStr for AgentId {
    type Err = AgentIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<MagicTypeId> for AgentId {
    fn as_ref(&self) -> &MagicTypeId {
        &self.inner
    }
}

impl TryFrom<&str> for AgentId {
    type Error = AgentIdError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl PartialOrd for AgentId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Orders by the rendered `prefix_suffix`, which is what
/// [`Display`](fmt::Display) writes.
///
/// The comparison is the one this always made; what is gone is the pair of
/// `String`s it used to build to make it. `MagicTypeId` keeps its own rendering
/// and hands out a borrow of it, so nothing has to be rendered again here.
/// `MagicTypeId`'s own `Ord` is not that comparison — it sorts by suffix first,
/// which would order agents by creation time rather than by class.
impl Ord for AgentId {
    fn cmp(&self, other: &Self) -> Ordering {
        let (this, that): (&str, &str) = (self.inner.as_ref(), other.inner.as_ref());
        this.cmp(that)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for AgentId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AgentId {
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
    fn create_new_id() {
        let id = AgentId::new("llm_chat");
        assert_eq!(id.prefix().as_str(), "llm_chat");
        assert_eq!(id.suffix().len(), 26);
    }

    #[test]
    fn creating_an_id_from_an_invalid_prefix_sanitizes_rather_than_panics() {
        // The whole of issue #28: this call used to be a panic, and the
        // signature never said so.
        let id = AgentId::new("LLM Chat!");
        assert_eq!(id.prefix().as_str(), "llmchat");
        assert_eq!(id.suffix().len(), AGENT_SUFFIX_LENGTH);
    }

    #[test]
    fn sanitizing_keeps_a_prefix_the_grammar_already_accepts() {
        // Sanitizing has to be the identity on valid input, or `new` would be
        // renaming agents that were named correctly.
        for prefix in [
            "llm",
            "a",
            "llm_chat",
            "llm_chat_streaming",
            "composite",
            &"a".repeat(MAX_AGENT_PREFIX_LENGTH),
        ] {
            assert_eq!(sanitize_prefix(prefix), prefix);
            assert_eq!(AgentId::new(prefix).prefix().as_str(), prefix);
        }
    }

    #[test]
    fn sanitizing_drops_what_the_grammar_has_no_room_for() {
        assert_eq!(sanitize_prefix("LLM"), "llm");
        assert_eq!(sanitize_prefix("llm-chat"), "llmchat");
        assert_eq!(sanitize_prefix("llm2chat"), "llmchat");
        assert_eq!(sanitize_prefix("llm chat"), "llmchat");
        // A run of underscores would leave an empty modifier, and
        // `type-modifier` is `1*LOWER`.
        assert_eq!(sanitize_prefix("__llm__chat__"), "llm_chat");
        // Non-ASCII is dropped, not transliterated: `İ` must not become `i`
        // and name an agent nobody asked for (issue #33).
        assert_eq!(sanitize_prefix("llm\u{0130}chat"), "llmchat");
        assert_eq!(sanitize_prefix("\u{1f300}"), FALLBACK_TYPE_CLASS);
    }

    #[test]
    fn sanitizing_a_prefix_down_to_nothing_yields_the_fallback_class() {
        for prefix in ["", "123", "!!!", "___", "-", " "] {
            assert_eq!(
                sanitize_prefix(prefix),
                FALLBACK_TYPE_CLASS,
                "{prefix:?} left something behind"
            );
            assert_eq!(AgentId::new(prefix).prefix().as_str(), FALLBACK_TYPE_CLASS);
        }
    }

    #[test]
    fn sanitizing_cuts_to_the_maximum_prefix_length() {
        let sanitized = sanitize_prefix(&"a".repeat(MAX_AGENT_PREFIX_LENGTH + 37));
        assert_eq!(sanitized.len(), MAX_AGENT_PREFIX_LENGTH);

        // The cut can strand the separator on the end, where a prefix must
        // have a letter.
        let sanitized = sanitize_prefix(&format!("{}_b", "a".repeat(MAX_AGENT_PREFIX_LENGTH)));
        assert_eq!(sanitized.len(), MAX_AGENT_PREFIX_LENGTH);
        assert!(!sanitized.ends_with('_'));
    }

    #[test]
    fn sanitizing_is_total() {
        // The invariant `new` rests on: whatever comes out parses. The
        // property test in `no_panic_proptest.rs` says the same over
        // arbitrary input; these are the cases worth naming.
        for prefix in [
            "",
            "!!!",
            "___",
            "9",
            "_a",
            "a_",
            "A__B",
            "\u{0130}",
            "\u{200b}llm",
            &"_".repeat(200),
            &format!("{}_x", "z".repeat(MAX_AGENT_PREFIX_LENGTH - 1)),
        ] {
            let sanitized = sanitize_prefix(prefix);
            assert!(
                AgentPrefix::parse(&sanitized).is_ok(),
                "{prefix:?} sanitized to {sanitized:?}, which the grammar refuses"
            );
        }
    }

    #[test]
    fn try_new_reports_what_new_would_have_rewritten() {
        assert!(AgentId::try_new("llm_chat").is_ok());
        for prefix in ["LLM Chat!", "", "123", "llm-chat"] {
            assert!(
                AgentId::try_new(prefix).is_err(),
                "{prefix:?} was accepted verbatim"
            );
        }
    }

    #[test]
    fn a_minted_id_always_parses_back() {
        // `new` returning a value the crate's own parser refuses would be a
        // quieter failure than the panic it replaced.
        for prefix in ["llm_chat", "LLM Chat!", "123", "", &"a".repeat(200)] {
            let minted = AgentId::new(prefix).to_string();
            assert!(
                AgentId::parse(&minted).is_ok(),
                "{prefix:?} minted {minted:?}, which does not parse"
            );
        }
    }

    #[test]
    fn parse_valid_id() {
        let id = AgentId::parse("llm_chat_01h455vb4pex5vsknk084sn02q").unwrap();
        assert_eq!(id.prefix().as_str(), "llm_chat");
        assert_eq!(id.suffix(), "01h455vb4pex5vsknk084sn02q");
    }

    #[test]
    fn parse_single_letter_prefix() {
        // Vectors parse-015, aid-004, and len-001 (issue #20).
        let id = AgentId::parse("a_01h455vb4pex5vsknk084sn02q").unwrap();
        assert_eq!(id.prefix().as_str(), "a");
        assert_eq!(id.suffix(), "01h455vb4pex5vsknk084sn02q");
    }

    #[test]
    fn parse_simple_prefix() {
        let id = AgentId::parse("llm_01h455vb4pex5vsknk084sn02q").unwrap();
        assert_eq!(id.prefix().as_str(), "llm");
    }

    #[test]
    fn parse_empty_fails() {
        let result = AgentId::parse("");
        assert!(matches!(result, Err(AgentIdError::Empty)));
    }

    #[test]
    fn parse_too_long_fails() {
        let long_prefix = "a".repeat(65);
        let input = format!("{long_prefix}_01h455vb4pex5vsknk084sn02q");
        let result = AgentId::parse(&input);
        assert!(matches!(result, Err(AgentIdError::TooLong { .. })));
    }

    #[test]
    fn parse_missing_separator_fails() {
        let result = AgentId::parse("llm01h455vb4pex5vsknk084sn02q");
        assert!(matches!(result, Err(AgentIdError::MissingSeparator)));
    }

    #[test]
    fn parse_invalid_prefix_fails() {
        let result = AgentId::parse("LLM_01h455vb4pex5vsknk084sn02q");
        assert!(matches!(result, Err(AgentIdError::InvalidPrefix(_))));
    }

    #[test]
    fn parse_suffix_wrong_length_fails() {
        let result = AgentId::parse("llm_01h455vb4pex");
        assert!(matches!(result, Err(AgentIdError::InvalidSuffix { .. })));
    }

    #[test]
    fn parse_suffix_invalid_first_char_fails() {
        // First char must be 0-7
        let result = AgentId::parse("llm_91h455vb4pex5vsknk084sn02q");
        assert!(matches!(result, Err(AgentIdError::InvalidSuffix { .. })));
    }

    #[test]
    fn parse_suffix_invalid_base32_char_fails() {
        // 'i' is not in base32 alphabet
        let result = AgentId::parse("llm_01h455vb4pex5vsknk084sn0iq");
        assert!(matches!(result, Err(AgentIdError::InvalidSuffix { .. })));
    }

    #[test]
    fn a_non_ascii_char_cannot_impersonate_an_alphabet_byte() {
        // 'İ' (U+0130) truncates to 0x30 under `as u8`, which is ASCII '0', a
        // member of the alphabet, so a validator that casts before comparing
        // reads it as a zero. Twenty-six characters and a valid first one, so
        // neither the length check nor the first-character check can answer
        // this: the alphabet check has to. Nothing downstream of this crate is
        // entitled to catch it for us (issue #33).
        let suffix = format!("0{}\u{0130}", "1".repeat(24));
        assert_eq!(suffix.chars().count(), AGENT_SUFFIX_LENGTH);

        let result = AgentId::parse(&format!("llm_{suffix}"));

        let Err(AgentIdError::InvalidSuffix { reason, .. }) = result else {
            panic!("a non-ASCII character in the suffix must be refused: {result:?}");
        };
        assert!(
            reason.contains("base32"),
            "refused for the wrong reason: {reason}"
        );
    }

    #[test]
    fn suffix_length_is_counted_in_characters() {
        // Fourteen characters occupying twenty-six bytes. This is what made the
        // truncation above reachable in the first place: a byte count is the
        // only reading under which this string is the right length.
        let suffix = format!("0{}1", "\u{0130}".repeat(12));
        assert_eq!(suffix.len(), AGENT_SUFFIX_LENGTH);
        assert_eq!(suffix.chars().count(), 14);

        let result = AgentId::parse(&format!("llm_{suffix}"));

        let Err(AgentIdError::InvalidSuffix { reason, .. }) = result else {
            panic!("a fourteen-character suffix must be refused: {result:?}");
        };
        assert!(
            reason.contains("26 characters"),
            "refused for the wrong reason: {reason}"
        );
    }

    #[test]
    fn roundtrip_display_parse() {
        let id1 = AgentId::new("llm_chat");
        let display = id1.to_string();
        let id2 = AgentId::parse(&display).unwrap();
        assert_eq!(id1.prefix(), id2.prefix());
        assert_eq!(id1.suffix(), id2.suffix());
    }

    #[test]
    fn ordering_is_the_order_of_the_rendered_id() {
        // The comparison no longer renders both sides to make it, so this
        // pins that it still makes the same one.
        let ids = [
            AgentId::parse("a_01h455vb4pex5vsknk084sn02q").unwrap(),
            AgentId::parse("llm_01h455vb4pex5vsknk084sn02q").unwrap(),
            AgentId::parse("llm_chat_01h455vb4pex5vsknk084sn02q").unwrap(),
            AgentId::parse("llm_01h455vb4pex5vsknk084sn03q").unwrap(),
            AgentId::parse("rule_01h455vb4pex5vsknk084sn02q").unwrap(),
        ];

        for left in &ids {
            for right in &ids {
                assert_eq!(
                    left.cmp(right),
                    left.to_string().cmp(&right.to_string()),
                    "{left} vs {right}"
                );
                assert_eq!(left.cmp(right) == Ordering::Equal, left == right);
            }
        }
    }

    #[test]
    fn ordering_is_not_the_underlying_type_id_ordering() {
        // `MagicTypeId` sorts by suffix first, which would group agents by
        // when they were created rather than by what they are.
        let older_rule = AgentId::parse("rule_01h455vb4pex5vsknk084sn02q").unwrap();
        let newer_llm = AgentId::parse("llm_01h455vb4pex5vsknk084sn03q").unwrap();

        assert!(newer_llm < older_rule);
        assert!(older_rule.inner() < newer_llm.inner());
    }
}
