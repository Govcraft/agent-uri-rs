//! Absolute and relative time rendering.
//!
//! Every timestamp the tool prints is shown twice: once as an RFC 3339 instant,
//! which is unambiguous, and once relative to now ("in 89 days", "3 days ago"),
//! which is what an operator actually reasons about.

use chrono::{DateTime, Utc};

/// Renders an instant as RFC 3339 with second precision.
pub fn rfc3339(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Renders a signed second-count as a human phrase relative to now.
///
/// Positive is the future (`in 89 days`), negative is the past (`3 days ago`).
/// Pure: the caller supplies the delta, so this is testable without a clock.
pub fn relative(delta_secs: i64) -> String {
    if delta_secs == 0 {
        return "now".to_string();
    }

    let magnitude = delta_secs.unsigned_abs();
    let phrase = magnitude_phrase(magnitude);

    if delta_secs > 0 {
        format!("in {phrase}")
    } else {
        format!("{phrase} ago")
    }
}

/// Renders an unsigned second-count as a coarse, pluralized quantity.
fn magnitude_phrase(secs: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;

    let (count, unit) = match secs {
        s if s < MINUTE => (s, "second"),
        s if s < HOUR => (s / MINUTE, "minute"),
        s if s < DAY => (s / HOUR, "hour"),
        s => (s / DAY, "day"),
    };

    if count == 1 {
        format!("1 {unit}")
    } else {
        format!("{count} {unit}s")
    }
}

/// Renders an instant as `<rfc3339> (<relative>)` against a supplied `now`.
pub fn absolute_and_relative(at: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let delta = (at - now).num_seconds();
    format!("{} ({})", rfc3339(at), relative(delta))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    #[test]
    fn rfc3339_renders_utc_with_second_precision() {
        assert_eq!(rfc3339(at(0)), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn future_reads_as_in() {
        assert_eq!(relative(89 * 86_400), "in 89 days");
        assert_eq!(relative(3_600), "in 1 hour");
    }

    #[test]
    fn past_reads_as_ago() {
        assert_eq!(relative(-3 * 86_400), "3 days ago");
        assert_eq!(relative(-45), "45 seconds ago");
    }

    #[test]
    fn singular_units_are_not_pluralized() {
        assert_eq!(relative(1), "in 1 second");
        assert_eq!(relative(60), "in 1 minute");
        assert_eq!(relative(86_400), "in 1 day");
        assert_eq!(relative(-86_400), "1 day ago");
    }

    #[test]
    fn zero_is_now() {
        assert_eq!(relative(0), "now");
    }

    #[test]
    fn units_step_up_at_the_boundaries() {
        assert_eq!(relative(59), "in 59 seconds");
        assert_eq!(relative(60), "in 1 minute");
        assert_eq!(relative(3_599), "in 59 minutes");
        assert_eq!(relative(3_600), "in 1 hour");
        assert_eq!(relative(86_399), "in 23 hours");
        assert_eq!(relative(86_400), "in 1 day");
    }

    #[test]
    fn absolute_and_relative_pairs_both_forms() {
        let now = at(0);
        let expiry = at(86_400);
        assert_eq!(
            absolute_and_relative(expiry, now),
            "1970-01-02T00:00:00Z (in 1 day)"
        );
    }

    #[test]
    fn expired_token_reads_in_the_past() {
        let now = at(10 * 86_400);
        let expiry = at(7 * 86_400);
        assert_eq!(
            absolute_and_relative(expiry, now),
            "1970-01-08T00:00:00Z (3 days ago)"
        );
    }
}
