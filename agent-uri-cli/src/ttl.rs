//! Humane time-to-live durations.
//!
//! Accepts compound, unit-suffixed durations such as `90d`, `12h`, `30m`, and
//! `1h30m`. A bare integer is rejected on purpose: silent unit ambiguity is how
//! an operator ships a 30-second credential meant to last 30 days.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

/// Seconds in a minute, hour, day, and week.
const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;
const WEEK: u64 = 7 * DAY;

/// A validated time-to-live for an attestation token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ttl(Duration);

impl Ttl {
    /// The shortest TTL that can be requested.
    pub const MIN_SECS: u64 = 1;

    /// The longest TTL that can be requested: one year.
    pub const MAX_SECS: u64 = 365 * DAY;

    /// The TTL used when `--ttl` is not supplied: 24 hours.
    ///
    /// This matches the default of the underlying claims builder, and is short
    /// enough that a leaked token expires within a day while still surviving a
    /// normal working cycle without a re-issue.
    pub const DEFAULT_SECS: u64 = DAY;

    /// Returns the TTL as a [`Duration`].
    pub const fn as_duration(self) -> Duration {
        self.0
    }

    /// Returns the TTL in whole seconds.
    pub const fn as_secs(self) -> u64 {
        self.0.as_secs()
    }
}

impl Default for Ttl {
    fn default() -> Self {
        Self(Duration::from_secs(Self::DEFAULT_SECS))
    }
}

/// Why a duration string could not be understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TtlError {
    /// The input was empty or entirely whitespace.
    Empty,
    /// A number was given with no unit, e.g. `90`.
    MissingUnit,
    /// A unit was given with no number, e.g. `d`.
    MissingValue,
    /// The unit character is not one of `s`, `m`, `h`, `d`, `w`.
    UnknownUnit(char),
    /// The same unit appeared twice, e.g. `1h2h`.
    DuplicateUnit(char),
    /// The duration totalled zero, e.g. `0s`.
    Zero,
    /// The duration exceeded [`Ttl::MAX_SECS`].
    TooLong(u64),
    /// The arithmetic overflowed.
    Overflow,
}

impl fmt::Display for TtlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "duration is empty; try a value like '90d', '12h', or '1h30m'"),
            Self::MissingUnit => write!(
                f,
                "duration is missing a unit; write '90d' or '90s', not a bare number"
            ),
            Self::MissingValue => write!(
                f,
                "duration is missing a number before its unit; write '90d', not 'd'"
            ),
            Self::UnknownUnit(unit) => write!(
                f,
                "unknown duration unit '{unit}'; use s (seconds), m (minutes), h (hours), d (days), or w (weeks)"
            ),
            Self::DuplicateUnit(unit) => write!(
                f,
                "duration unit '{unit}' appears more than once; combine it into a single term, e.g. '1h30m'"
            ),
            Self::Zero => write!(
                f,
                "duration is zero; a token that expires immediately is never useful"
            ),
            Self::TooLong(secs) => write!(
                f,
                "duration {secs}s exceeds the {max}s (365d) maximum; issue a shorter-lived token and rotate it",
                max = Ttl::MAX_SECS
            ),
            Self::Overflow => write!(f, "duration is too large to represent; the maximum is 365d"),
        }
    }
}

impl std::error::Error for TtlError {}

/// Converts a unit character to its length in seconds.
fn unit_seconds(unit: char) -> Result<u64, TtlError> {
    match unit {
        's' => Ok(1),
        'm' => Ok(MINUTE),
        'h' => Ok(HOUR),
        'd' => Ok(DAY),
        'w' => Ok(WEEK),
        other => Err(TtlError::UnknownUnit(other)),
    }
}

/// Accumulates one `<number><unit>` term into the running total.
fn accumulate(total: u64, value: u64, unit: char, seen: &mut Vec<char>) -> Result<u64, TtlError> {
    if seen.contains(&unit) {
        return Err(TtlError::DuplicateUnit(unit));
    }
    seen.push(unit);

    value
        .checked_mul(unit_seconds(unit)?)
        .and_then(|term| total.checked_add(term))
        .ok_or(TtlError::Overflow)
}

impl FromStr for Ttl {
    type Err = TtlError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(TtlError::Empty);
        }

        let mut total: u64 = 0;
        let mut digits = String::new();
        let mut seen: Vec<char> = Vec::new();

        for ch in trimmed.chars() {
            if ch.is_ascii_digit() {
                digits.push(ch);
            } else if ch.is_whitespace() {
                // Whitespace between terms is tolerated: "2h 30m".
            } else if digits.is_empty() {
                return Err(TtlError::MissingValue);
            } else {
                let value: u64 = digits.parse().map_err(|_| TtlError::Overflow)?;
                digits.clear();
                total = accumulate(total, value, ch, &mut seen)?;
            }
        }

        if !digits.is_empty() {
            return Err(TtlError::MissingUnit);
        }
        if total < Self::MIN_SECS {
            return Err(TtlError::Zero);
        }
        if total > Self::MAX_SECS {
            return Err(TtlError::TooLong(total));
        }

        Ok(Self(Duration::from_secs(total)))
    }
}

impl fmt::Display for Ttl {
    /// Renders the canonical compound form, e.g. `1h30m`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut remaining = self.as_secs();

        // A TTL is never zero, so at least one term is always written.
        for (unit, size) in [('w', WEEK), ('d', DAY), ('h', HOUR), ('m', MINUTE), ('s', 1)] {
            let count = remaining / size;
            if count > 0 {
                write!(f, "{count}{unit}")?;
                remaining -= count * size;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_terms() {
        assert_eq!("30s".parse::<Ttl>().unwrap().as_secs(), 30);
        assert_eq!("30m".parse::<Ttl>().unwrap().as_secs(), 1_800);
        assert_eq!("12h".parse::<Ttl>().unwrap().as_secs(), 43_200);
        assert_eq!("90d".parse::<Ttl>().unwrap().as_secs(), 90 * DAY);
        assert_eq!("2w".parse::<Ttl>().unwrap().as_secs(), 2 * WEEK);
    }

    #[test]
    fn parses_compound_terms() {
        assert_eq!("1h30m".parse::<Ttl>().unwrap().as_secs(), 5_400);
        assert_eq!("2h 30m".parse::<Ttl>().unwrap().as_secs(), 9_000);
        assert_eq!("1w2d3h".parse::<Ttl>().unwrap().as_secs(), WEEK + 2 * DAY + 3 * HOUR);
    }

    #[test]
    fn rejects_bare_number() {
        assert_eq!("90".parse::<Ttl>(), Err(TtlError::MissingUnit));
    }

    #[test]
    fn rejects_empty() {
        assert_eq!("".parse::<Ttl>(), Err(TtlError::Empty));
        assert_eq!("   ".parse::<Ttl>(), Err(TtlError::Empty));
    }

    #[test]
    fn rejects_missing_value() {
        assert_eq!("d".parse::<Ttl>(), Err(TtlError::MissingValue));
    }

    #[test]
    fn rejects_unknown_unit() {
        assert_eq!("5y".parse::<Ttl>(), Err(TtlError::UnknownUnit('y')));
    }

    #[test]
    fn rejects_duplicate_unit() {
        assert_eq!("1h2h".parse::<Ttl>(), Err(TtlError::DuplicateUnit('h')));
    }

    #[test]
    fn rejects_zero() {
        assert_eq!("0s".parse::<Ttl>(), Err(TtlError::Zero));
    }

    #[test]
    fn rejects_too_long() {
        assert!(matches!("400d".parse::<Ttl>(), Err(TtlError::TooLong(_))));
    }

    #[test]
    fn rejects_overflow() {
        // Too many digits to be a u64 at all.
        assert_eq!("99999999999999999999w".parse::<Ttl>(), Err(TtlError::Overflow));
        // Fits in a u64, but overflows once multiplied out to seconds.
        assert_eq!("99999999999999w".parse::<Ttl>(), Err(TtlError::Overflow));
    }

    #[test]
    fn a_representable_but_absurd_duration_is_too_long_rather_than_overflowing() {
        // 9999999999 weeks is representable in seconds; it is simply far past the
        // one-year ceiling, and the operator deserves to be told that, not "overflow".
        assert!(matches!("9999999999w".parse::<Ttl>(), Err(TtlError::TooLong(_))));
    }

    #[test]
    fn accepts_the_boundaries() {
        assert_eq!("1s".parse::<Ttl>().unwrap().as_secs(), Ttl::MIN_SECS);
        assert_eq!("365d".parse::<Ttl>().unwrap().as_secs(), Ttl::MAX_SECS);
    }

    #[test]
    fn display_round_trips_through_parse() {
        for input in ["30s", "1h30m", "90d", "1w2d3h", "365d"] {
            let parsed: Ttl = input.parse().unwrap();
            let reparsed: Ttl = parsed.to_string().parse().unwrap();
            assert_eq!(parsed, reparsed, "round trip failed for {input}");
        }
    }

    #[test]
    fn display_renders_compound_form() {
        assert_eq!("5400s".parse::<Ttl>().unwrap().to_string(), "1h30m");
        assert_eq!("86400s".parse::<Ttl>().unwrap().to_string(), "1d");
    }

    #[test]
    fn default_is_twenty_four_hours() {
        assert_eq!(Ttl::default().as_secs(), 86_400);
        assert_eq!(Ttl::default().to_string(), "1d");
    }

    #[test]
    fn ordering_follows_duration() {
        let short: Ttl = "1h".parse().unwrap();
        let long: Ttl = "1d".parse().unwrap();
        assert!(short < long);
    }
}
