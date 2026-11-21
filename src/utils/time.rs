//! Wall-clock timestamps.
//!
//! Timestamps written to the index database, the scan log and the telemetry
//! stream are RFC 3339 strings in UTC with an explicit `+00:00` offset, which
//! is the format earlier releases stored. Readers accept any RFC 3339 offset.

use std::time::SystemTime;

use jiff::Timestamp;
use jiff::tz::{Offset, TimeZone};

/// Format `ts` as RFC 3339 in UTC with a `+00:00` offset and only as many
/// fractional-second digits as the value needs.
pub fn rfc3339(ts: Timestamp) -> String {
    ts.display_with_offset(Offset::UTC).to_string()
}

/// The current time, formatted by [`rfc3339`].
pub fn now_rfc3339() -> String {
    rfc3339(Timestamp::now())
}

/// Parse an RFC 3339 timestamp with any UTC offset.
pub fn parse_rfc3339(s: &str) -> Option<Timestamp> {
    s.parse().ok()
}

/// Render a file-system time in the local time zone as
/// `YYYY-MM-DD HH:MM:SS`, for CLI listings.
pub fn local_datetime(t: SystemTime) -> String {
    match Timestamp::try_from(t) {
        Ok(ts) => ts
            .to_zoned_datetime(TimeZone::system())
            .strftime("%Y-%m-%d %H:%M:%S")
            .to_string(),
        Err(_) => String::from("unknown"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_uses_utc_offset_and_round_trips() {
        let ts: Timestamp = "2026-11-21T08:10:38.5Z".parse().unwrap();
        let s = rfc3339(ts);
        assert_eq!(s, "2026-11-21T08:10:38.5+00:00");
        assert_eq!(parse_rfc3339(&s), Some(ts));
    }

    #[test]
    fn rfc3339_omits_zero_fraction() {
        let ts: Timestamp = "2026-11-21T08:10:38Z".parse().unwrap();
        assert_eq!(rfc3339(ts), "2026-11-21T08:10:38+00:00");
    }

    #[test]
    fn parse_accepts_non_utc_offsets() {
        let a = parse_rfc3339("2026-11-21T10:10:38+02:00").unwrap();
        let b = parse_rfc3339("2026-11-21T08:10:38Z").unwrap();
        assert_eq!(a, b);
        assert_eq!(parse_rfc3339("not a time"), None);
    }
}
