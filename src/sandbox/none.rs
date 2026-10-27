//! The "no boundary" backend. Compiled only with the `test-sandbox` feature: a release build has no way to run a worker
//! without a verified boundary (`spec/ERRAND.md` section 4).

use crate::contract::{BoundaryReport, Check};
use crate::sandbox::Sandbox;

/// A sandbox that confines nothing. For tests only.
///
/// ```
/// # #[cfg(feature = "test-sandbox")] {
/// use errand_kit::sandbox::{none::NoSandbox, Sandbox};
/// let report = NoSandbox.verify();
/// assert_eq!(report.kind, "none");
/// assert!(report.ok);
/// assert!(!report.checks[0].required);
/// # }
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSandbox;

impl Sandbox for NoSandbox {
    fn kind(&self) -> &'static str {
        "none"
    }

    fn verify(&self) -> BoundaryReport {
        BoundaryReport {
            kind: "none".into(),
            ok: true,
            egress: "open".into(),
            checks: vec![Check {
                name: "no_boundary".into(),
                ok: true,
                required: false,
                detail: "test-only sandbox: nothing is confined, nothing is verified".into(),
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_none_ok_with_one_optional_check() {
        let r = NoSandbox.verify();
        assert_eq!(r.kind, "none");
        assert!(r.ok);
        assert_eq!(r.egress, "open");
        assert_eq!(r.checks.len(), 1);
        assert_eq!(r.checks[0].name, "no_boundary");
        assert!(!r.checks[0].required);
        assert!(r.checks[0].detail.contains("test-only"));
        assert_eq!(NoSandbox.kind(), "none");
    }

    #[test]
    fn wrap_leaves_the_command_unchanged() {
        let cmd = NoSandbox.wrap(std::process::Command::new("echo"));
        assert_eq!(cmd.get_program(), "echo");
    }
}
