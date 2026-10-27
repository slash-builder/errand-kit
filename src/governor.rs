//! The usage governor: a pure function of a usage snapshot.
//!
//! The engine shares a plan with the humans using it, so it yields. The rule is **fail closed**: anything other than a
//! fresh, complete, sane snapshot with every window under its ceiling means *deny*. (The Python reference engine let work
//! start when its state was stale; this module cannot, because "no information" is a deny reason of its own.)
//!
//! [`decide`] does no I/O and reads no clock: the caller supplies the report age and the current time.
//!
//! ```
//! use errand_kit::contract::LimitWindow;
//! use errand_kit::governor::{decide, GovernorConfig};
//!
//! let w = |name: &str, used: f64| LimitWindow { name: name.into(), used_fraction: Some(used), resets_at: None };
//! let cfg = GovernorConfig::default();
//!
//! assert!(decide(&[w("five_hour", 0.2), w("seven_day", 0.3)], Some(30), 0, &cfg).allow);
//! assert!(!decide(&[w("five_hour", 0.7), w("seven_day", 0.3)], Some(30), 0, &cfg).allow);
//! assert!(!decide(&[], Some(30), 0, &cfg).allow); // no snapshot: deny
//! ```

use serde::{Deserialize, Serialize};

use crate::contract::{GovernorDecision, LimitWindow};

/// The window name the five-hour ceiling applies to.
pub const FIVE_HOUR: &str = "five_hour";
/// The window name the seven-day ceiling applies to.
pub const SEVEN_DAY: &str = "seven_day";

/// Ceilings and staleness limit for [`decide`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernorConfig {
    /// Deny when the `five_hour` window's used fraction is at or above this (default 0.70).
    pub five_hour_ceiling: f64,
    /// Deny when the `seven_day` window's used fraction is at or above this (default 0.80).
    pub seven_day_ceiling: f64,
    /// Deny when the usage report is older than this many seconds (default 900).
    pub max_report_age_s: i64,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            five_hour_ceiling: 0.70,
            seven_day_ceiling: 0.80,
            max_report_age_s: 900,
        }
    }
}

fn deny(reason: impl Into<String>) -> GovernorDecision {
    let reason = reason.into();
    tracing::info!(%reason, "governor: deny");
    GovernorDecision {
        allow: false,
        reason,
    }
}

fn pct(fraction: f64) -> String {
    format!("{:.1}%", fraction * 100.0)
}

fn ceiling_ok(c: f64) -> bool {
    c.is_finite() && (0.0..=1.0).contains(&c)
}

/// Decide whether new work may start.
///
/// * `windows`: the usage snapshot (`five_hour` and `seven_day` are required; other names are validated but have no ceiling).
/// * `report_age_s`: how old the snapshot is, in seconds; `None` means the age is unknown.
/// * `now_epoch`: the current time in epoch seconds (used only to explain a window whose `resets_at` has already passed).
///
/// **Deny** (with a reason naming the cause) when: the snapshot is empty; the report age is unknown, negative (clock skew or
/// corruption) or above `cfg.max_report_age_s`; a window's `used_fraction` is unknown (`None`); a `used_fraction` is NaN,
/// infinite, negative or above 1 (corrupt); a required window is missing; a used fraction is at or above its ceiling; or the
/// config itself is invalid (a ceiling that is NaN or outside 0..=1 would otherwise silently disable the check).
///
/// A window whose `resets_at` is in the past is still judged on its reported fraction: if that is at or above the ceiling
/// the answer is deny (the data is stale and we do not guess that the window really reset). If the stale fraction is under
/// the ceiling it is allowed, because a reset can only have lowered the real usage.
///
/// Otherwise **allow**.
pub fn decide(
    windows: &[LimitWindow],
    report_age_s: Option<i64>,
    now_epoch: i64,
    cfg: &GovernorConfig,
) -> GovernorDecision {
    if !ceiling_ok(cfg.five_hour_ceiling) || !ceiling_ok(cfg.seven_day_ceiling) {
        return deny("invalid governor config: a ceiling is not a number in 0..=1");
    }
    if windows.is_empty() {
        return deny("no usage snapshot");
    }
    let age = match report_age_s {
        None => return deny("usage report age unknown"),
        Some(a) => a,
    };
    if age < 0 {
        return deny(format!(
            "usage report age is negative ({age}s): clock skew or a corrupt report"
        ));
    }
    if age > cfg.max_report_age_s {
        return deny(format!(
            "usage report is stale ({age}s old, limit {}s)",
            cfg.max_report_age_s
        ));
    }
    for w in windows {
        match w.used_fraction {
            None => return deny(format!("window {} has unknown usage", w.name)),
            Some(f) if !f.is_finite() || !(0.0..=1.0).contains(&f) => {
                return deny(format!(
                    "window {} reports a corrupt used_fraction ({f})",
                    w.name
                ));
            }
            Some(_) => {}
        }
    }
    let mut summary = Vec::new();
    for (name, ceiling) in [
        (FIVE_HOUR, cfg.five_hour_ceiling),
        (SEVEN_DAY, cfg.seven_day_ceiling),
    ] {
        // Every window of this name must be under its ceiling, so a duplicated window cannot hide a high one.
        let mut seen = false;
        for w in windows.iter().filter(|w| w.name == name) {
            seen = true;
            let used = w.used_fraction.unwrap_or(1.0); // validated above; None cannot reach here
            if used >= ceiling {
                let stale = match w.resets_at {
                    Some(r) if r < now_epoch => " (resets_at has passed, so the report is stale)",
                    _ => "",
                };
                return deny(format!(
                    "window {name} at {} (ceiling {}){stale}",
                    pct(used),
                    pct(ceiling)
                ));
            }
            summary.push(format!("{name} {}", pct(used)));
        }
        if !seen {
            return deny(format!("required window {name} is missing"));
        }
    }
    let reason = format!("{}; report {age}s old", summary.join(" / "));
    tracing::debug!(%reason, "governor: allow");
    GovernorDecision {
        allow: true,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(name: &str, used: Option<f64>, resets: Option<i64>) -> LimitWindow {
        LimitWindow {
            name: name.into(),
            used_fraction: used,
            resets_at: resets,
        }
    }
    fn ok_pair(five: f64, seven: f64) -> Vec<LimitWindow> {
        vec![
            w(FIVE_HOUR, Some(five), None),
            w(SEVEN_DAY, Some(seven), None),
        ]
    }

    struct Case {
        name: &'static str,
        windows: Vec<LimitWindow>,
        age: Option<i64>,
        allow: bool,
        reason_has: &'static str,
    }

    #[test]
    fn table() {
        let cfg = GovernorConfig::default();
        let cases = vec![
            Case {
                name: "all clear",
                windows: ok_pair(0.2, 0.3),
                age: Some(10),
                allow: true,
                reason_has: "five_hour 20.0%",
            },
            Case {
                name: "zero usage",
                windows: ok_pair(0.0, 0.0),
                age: Some(0),
                allow: true,
                reason_has: "seven_day 0.0%",
            },
            Case {
                name: "age exactly at max",
                windows: ok_pair(0.2, 0.3),
                age: Some(900),
                allow: true,
                reason_has: "report 900s old",
            },
            Case {
                name: "just under 5h ceiling",
                windows: ok_pair(0.699, 0.3),
                age: Some(1),
                allow: true,
                reason_has: "69.9%",
            },
            Case {
                name: "just under 7d ceiling",
                windows: ok_pair(0.1, 0.799),
                age: Some(1),
                allow: true,
                reason_has: "79.9%",
            },
            Case {
                name: "extra unknown window ok",
                windows: {
                    let mut v = ok_pair(0.1, 0.1);
                    v.push(w("opus", Some(0.99), None));
                    v
                },
                age: Some(1),
                allow: true,
                reason_has: "five_hour",
            },
            Case {
                name: "empty snapshot",
                windows: vec![],
                age: Some(1),
                allow: false,
                reason_has: "no usage snapshot",
            },
            Case {
                name: "empty snapshot unknown age",
                windows: vec![],
                age: None,
                allow: false,
                reason_has: "no usage snapshot",
            },
            Case {
                name: "age unknown",
                windows: ok_pair(0.1, 0.1),
                age: None,
                allow: false,
                reason_has: "age unknown",
            },
            Case {
                name: "report stale",
                windows: ok_pair(0.1, 0.1),
                age: Some(901),
                allow: false,
                reason_has: "stale",
            },
            Case {
                name: "report age negative",
                windows: ok_pair(0.1, 0.1),
                age: Some(-5),
                allow: false,
                reason_has: "negative",
            },
            Case {
                name: "five_hour missing",
                windows: vec![w(SEVEN_DAY, Some(0.1), None)],
                age: Some(1),
                allow: false,
                reason_has: "five_hour is missing",
            },
            Case {
                name: "seven_day missing",
                windows: vec![w(FIVE_HOUR, Some(0.1), None)],
                age: Some(1),
                allow: false,
                reason_has: "seven_day is missing",
            },
            Case {
                name: "only unknown windows",
                windows: vec![w("opus", Some(0.1), None)],
                age: Some(1),
                allow: false,
                reason_has: "five_hour is missing",
            },
            Case {
                name: "five_hour fraction unknown",
                windows: vec![w(FIVE_HOUR, None, None), w(SEVEN_DAY, Some(0.1), None)],
                age: Some(1),
                allow: false,
                reason_has: "five_hour has unknown usage",
            },
            Case {
                name: "seven_day fraction unknown",
                windows: vec![w(FIVE_HOUR, Some(0.1), None), w(SEVEN_DAY, None, None)],
                age: Some(1),
                allow: false,
                reason_has: "seven_day has unknown usage",
            },
            Case {
                name: "5h at ceiling",
                windows: ok_pair(0.70, 0.1),
                age: Some(1),
                allow: false,
                reason_has: "window five_hour at 70.0%",
            },
            Case {
                name: "5h above ceiling",
                windows: ok_pair(0.95, 0.1),
                age: Some(1),
                allow: false,
                reason_has: "five_hour",
            },
            Case {
                name: "7d at ceiling",
                windows: ok_pair(0.1, 0.80),
                age: Some(1),
                allow: false,
                reason_has: "window seven_day at 80.0%",
            },
            Case {
                name: "7d above ceiling",
                windows: ok_pair(0.1, 1.0),
                age: Some(1),
                allow: false,
                reason_has: "seven_day",
            },
            Case {
                name: "NaN fraction",
                windows: ok_pair(f64::NAN, 0.1),
                age: Some(1),
                allow: false,
                reason_has: "corrupt",
            },
            Case {
                name: "negative fraction",
                windows: ok_pair(0.1, -0.1),
                age: Some(1),
                allow: false,
                reason_has: "corrupt",
            },
            Case {
                name: "fraction above 1",
                windows: ok_pair(1.5, 0.1),
                age: Some(1),
                allow: false,
                reason_has: "corrupt",
            },
            Case {
                name: "infinite fraction",
                windows: ok_pair(f64::INFINITY, 0.1),
                age: Some(1),
                allow: false,
                reason_has: "corrupt",
            },
            Case {
                name: "corrupt unknown window",
                windows: {
                    let mut v = ok_pair(0.1, 0.1);
                    v.push(w("opus", Some(f64::NAN), None));
                    v
                },
                age: Some(1),
                allow: false,
                reason_has: "window opus",
            },
            Case {
                name: "duplicate window hides high one",
                windows: vec![
                    w(FIVE_HOUR, Some(0.1), None),
                    w(FIVE_HOUR, Some(0.9), None),
                    w(SEVEN_DAY, Some(0.1), None),
                ],
                age: Some(1),
                allow: false,
                reason_has: "five_hour at 90.0%",
            },
            Case {
                name: "past reset, high usage",
                windows: vec![
                    w(FIVE_HOUR, Some(0.9), Some(100)),
                    w(SEVEN_DAY, Some(0.1), None),
                ],
                age: Some(1),
                allow: false,
                reason_has: "report is stale",
            },
            Case {
                name: "past reset, low usage",
                windows: vec![
                    w(FIVE_HOUR, Some(0.1), Some(100)),
                    w(SEVEN_DAY, Some(0.1), None),
                ],
                age: Some(1),
                allow: true,
                reason_has: "five_hour 10.0%",
            },
            Case {
                name: "future reset, high usage",
                windows: vec![
                    w(FIVE_HOUR, Some(0.9), Some(10_000)),
                    w(SEVEN_DAY, Some(0.1), None),
                ],
                age: Some(1),
                allow: false,
                reason_has: "five_hour at 90.0%",
            },
        ];
        for c in cases {
            let d = decide(&c.windows, c.age, 1_000, &cfg);
            assert_eq!(
                d.allow, c.allow,
                "case {:?}: reason was {:?}",
                c.name, d.reason
            );
            assert!(
                d.reason.contains(c.reason_has),
                "case {:?}: reason {:?} lacks {:?}",
                c.name,
                d.reason,
                c.reason_has
            );
            assert!(!d.reason.is_empty());
        }
    }

    #[test]
    fn future_reset_message_is_not_marked_stale() {
        let ws = vec![
            w(FIVE_HOUR, Some(0.9), Some(10_000)),
            w(SEVEN_DAY, Some(0.1), None),
        ];
        let d = decide(&ws, Some(1), 1_000, &GovernorConfig::default());
        assert!(!d.reason.contains("stale"));
    }

    #[test]
    fn invalid_config_denies() {
        let good = ok_pair(0.1, 0.1);
        for cfg in [
            GovernorConfig {
                five_hour_ceiling: f64::NAN,
                ..GovernorConfig::default()
            },
            GovernorConfig {
                seven_day_ceiling: 1.5,
                ..GovernorConfig::default()
            },
            GovernorConfig {
                five_hour_ceiling: -0.1,
                ..GovernorConfig::default()
            },
        ] {
            let d = decide(&good, Some(1), 0, &cfg);
            assert!(!d.allow);
            assert!(d.reason.contains("invalid governor config"));
        }
    }

    #[test]
    fn custom_config_is_respected() {
        let cfg = GovernorConfig {
            five_hour_ceiling: 0.2,
            seven_day_ceiling: 0.3,
            max_report_age_s: 5,
        };
        assert!(!decide(&ok_pair(0.25, 0.1), Some(1), 0, &cfg).allow);
        assert!(!decide(&ok_pair(0.1, 0.35), Some(1), 0, &cfg).allow);
        assert!(!decide(&ok_pair(0.1, 0.1), Some(6), 0, &cfg).allow);
        assert!(decide(&ok_pair(0.1, 0.1), Some(5), 0, &cfg).allow);
    }

    #[test]
    fn defaults_match_the_spec() {
        let c = GovernorConfig::default();
        assert_eq!(
            (c.five_hour_ceiling, c.seven_day_ceiling, c.max_report_age_s),
            (0.70, 0.80, 900)
        );
    }
}
