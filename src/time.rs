//! Minimal UTC time helpers, so the crate needs no date/time dependency.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch (0 if the clock is before it).
pub fn now_epoch() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Format epoch seconds as an RFC 3339 UTC timestamp, e.g. `2026-10-27T01:02:03Z`.
///
/// ```
/// assert_eq!(errand_kit::time::rfc3339_utc(0), "1970-01-01T00:00:00Z");
/// assert_eq!(errand_kit::time::rfc3339_utc(1793058132), "2026-10-26T23:42:12Z");
/// ```
pub fn rfc3339_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-from-days (Howard Hinnant's algorithm), valid for the proleptic Gregorian calendar.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// The current time as an RFC 3339 UTC timestamp.
pub fn now_rfc3339() -> String {
    rfc3339_utc(now_epoch())
}
