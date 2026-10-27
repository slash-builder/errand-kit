//! Built-in gates. Each looks only at facts the Kit collected, never at the worker's claims.

use crate::contract::{GateResult, Verdict};
use crate::gates::patch::validate_patch;
use crate::gates::recipe::Recipe;
use crate::gates::{Gate, GateContext};
use crate::sandbox::credential_shaped;

/// The last non-empty line of `text`, with a trailing `\r` removed.
///
/// ```
/// assert_eq!(errand_kit::gates::builtin::last_nonempty_line("a\nSTATUS: OK\n\n"), Some("STATUS: OK"));
/// assert_eq!(errand_kit::gates::builtin::last_nonempty_line("  \n"), None);
/// ```
pub fn last_nonempty_line(text: &str) -> Option<&str> {
    text.lines().map(|l| l.trim_end_matches('\r')).rfind(|l| !l.trim().is_empty())
}

fn result(name: &str, kind: &str, ok: bool, hard: bool, detail: impl Into<String>) -> GateResult {
    GateResult { name: name.into(), kind: kind.into(), ok, hard, detail: detail.into() }
}

/// Phase 2 passed.
#[derive(Debug, Default, Clone)]
pub struct BoundaryGate;

impl Gate for BoundaryGate {
    fn name(&self) -> &str {
        "boundary"
    }
    fn kind(&self) -> &str {
        "boundary"
    }
    fn hard(&self) -> bool {
        true
    }
    fn check(&self, ctx: &GateContext<'_>) -> GateResult {
        match ctx.boundary {
            Some(b) if b.ok => result("boundary", "boundary", true, true, format!("{} boundary verified", b.kind)),
            Some(b) => {
                let failed: Vec<&str> = b.checks.iter().filter(|c| c.required && !c.ok).map(|c| c.name.as_str()).collect();
                result("boundary", "boundary", false, true, format!("required checks failed: {}", failed.join(", ")))
            }
            None => result("boundary", "boundary", false, true, "no boundary report"),
        }
    }
}

/// The worker held no credential-shaped variable name.
#[derive(Debug, Default, Clone)]
pub struct EnvCleanGate;

impl Gate for EnvCleanGate {
    fn name(&self) -> &str {
        "env_clean"
    }
    fn kind(&self) -> &str {
        "env_clean"
    }
    fn hard(&self) -> bool {
        true
    }
    fn check(&self, ctx: &GateContext<'_>) -> GateResult {
        let bad: Vec<&str> = ctx.worker_env.keys().map(String::as_str).filter(|k| credential_shaped(k)).collect();
        if bad.is_empty() {
            result("env_clean", "env_clean", true, true, "worker environment held no credential-shaped names")
        } else {
            result("env_clean", "env_clean", false, true, format!("credential-shaped names in the worker environment: {}", bad.join(", ")))
        }
    }
}

/// The tools the worker reported equal the tools requested.
#[derive(Debug, Clone)]
pub struct ToolsMatchGate {
    /// What was requested.
    pub requested: Vec<String>,
}

impl Gate for ToolsMatchGate {
    fn name(&self) -> &str {
        "tools_match"
    }
    fn kind(&self) -> &str {
        "tools_match"
    }
    fn hard(&self) -> bool {
        true
    }
    fn check(&self, ctx: &GateContext<'_>) -> GateResult {
        let Some(reported) = ctx.worker.and_then(|w| w.tools_reported.as_ref()) else {
            return result("tools_match", "tools_match", true, true, "worker did not report its tools (not verified)");
        };
        let mut want = self.requested.clone();
        let mut got = reported.clone();
        want.sort();
        got.sort();
        if want == got {
            result("tools_match", "tools_match", true, true, format!("tools are exactly: {}", want.join(", ")))
        } else {
            result("tools_match", "tools_match", false, true, format!("requested [{}] but the worker reported [{}]", want.join(", "), got.join(", ")))
        }
    }
}

/// The digest ends with a valid `STATUS:` line, and agrees with the verdict the task computed in code when there is one.
#[derive(Debug, Default, Clone)]
pub struct StatusLineGate;

impl Gate for StatusLineGate {
    fn name(&self) -> &str {
        "status_line"
    }
    fn kind(&self) -> &str {
        "status_line"
    }
    fn hard(&self) -> bool {
        true
    }
    fn check(&self, ctx: &GateContext<'_>) -> GateResult {
        let Some(digest) = ctx.digest else {
            return result("status_line", "status_line", false, true, "no digest");
        };
        let Some(last) = last_nonempty_line(digest) else {
            return result("status_line", "status_line", false, true, "the digest is empty");
        };
        let Some(model) = Verdict::from_status_line(last) else {
            return result("status_line", "status_line", false, true, "the digest does not end with an exact STATUS: OK or STATUS: ATTENTION line");
        };
        match ctx.code_verdict {
            Some(code) if code != model => result(
                "status_line",
                "status_line",
                false,
                true,
                format!("the model said {} but the code computed {}", model.status_line().unwrap_or("?"), code.status_line().unwrap_or("?")),
            ),
            Some(_) => result("status_line", "status_line", true, true, "the model's verdict matches the one computed in code"),
            None => result("status_line", "status_line", true, true, "valid STATUS line (no code verdict to compare)"),
        }
    }
}

/// Validate the worker's patch text against a repo-side recipe, before anything is applied.
#[derive(Debug, Clone)]
pub struct DiffScopeGate {
    /// The recipe (from the repository side, never from a tracker field).
    pub recipe: Recipe,
}

impl Gate for DiffScopeGate {
    fn name(&self) -> &str {
        "diff_scope"
    }
    fn kind(&self) -> &str {
        "diff_scope"
    }
    fn hard(&self) -> bool {
        true
    }
    fn check(&self, ctx: &GateContext<'_>) -> GateResult {
        let Some(patch) = ctx.patch else {
            return result("diff_scope", "diff_scope", true, true, "no patch");
        };
        match validate_patch(patch, &self.recipe) {
            Ok(s) => result("diff_scope", "diff_scope", true, true, format!("{} file(s), +{} -{}", s.files.len(), s.added, s.removed)),
            Err(e) => result("diff_scope", "diff_scope", false, true, e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::collections::BTreeMap;
    use std::path::Path;

    use super::*;
    use crate::contract::{BoundaryReport, Check, Risk, WorkerReport};

    fn ctx<'a>(
        env: &'a BTreeMap<String, String>,
        digest: Option<&'a str>,
        code: Option<Verdict>,
        boundary: Option<&'a BoundaryReport>,
        worker: Option<&'a WorkerReport>,
    ) -> GateContext<'a> {
        GateContext { out_dir: Path::new("/out"), risk: Risk::L0, boundary, worker, worker_env: env, digest, code_verdict: code, patch: None }
    }

    #[test]
    fn status_line_uses_only_the_last_nonempty_line() {
        let env = BTreeMap::new();
        // A STATUS line in the middle does not count; the last line wins.
        let d = "STATUS: OK\nbut actually more text follows\n";
        let r = StatusLineGate.check(&ctx(&env, Some(d), None, None, None));
        assert!(!r.ok, "{r:?}");
        let d = "text\nSTATUS: ATTENTION\n\n";
        assert!(StatusLineGate.check(&ctx(&env, Some(d), None, None, None)).ok);
    }

    #[test]
    fn status_line_must_be_exact() {
        let env = BTreeMap::new();
        for bad in ["status: ok", "STATUS: OK.", "STATUS:OK", " STATUS: OK x", "STATUS: FAILED"] {
            assert!(!StatusLineGate.check(&ctx(&env, Some(bad), None, None, None)).ok, "{bad:?}");
        }
        assert!(StatusLineGate.check(&ctx(&env, Some("x\r\nSTATUS: OK\r\n"), None, None, None)).ok);
    }

    #[test]
    fn the_code_verdict_wins_and_a_disagreeing_model_fails_the_gate() {
        let env = BTreeMap::new();
        let r = StatusLineGate.check(&ctx(&env, Some("STATUS: OK"), Some(Verdict::Attention), None, None));
        assert!(!r.ok && r.hard);
        assert!(r.detail.contains("code computed STATUS: ATTENTION"), "{}", r.detail);
        assert!(StatusLineGate.check(&ctx(&env, Some("STATUS: ATTENTION"), Some(Verdict::Attention), None, None)).ok);
    }

    #[test]
    fn env_clean_names_credentials_but_never_prints_values() {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        env.insert("CLAUDE_CODE_OAUTH_TOKEN".to_string(), "tok".to_string());
        assert!(EnvCleanGate.check(&ctx(&env, None, None, None, None)).ok);
        env.insert("AWS_SECRET_ACCESS_KEY".to_string(), "supersecretvalue".to_string());
        let r = EnvCleanGate.check(&ctx(&env, None, None, None, None));
        assert!(!r.ok);
        assert!(r.detail.contains("AWS_SECRET_ACCESS_KEY"));
        assert!(!r.detail.contains("supersecretvalue"));
    }

    #[test]
    fn tools_match_compares_as_sets() {
        let env = BTreeMap::new();
        let mk = |t: Option<Vec<&str>>| WorkerReport {
            kind: "x".into(),
            tools_requested: vec![],
            tools_reported: t.map(|v| v.into_iter().map(String::from).collect()),
            max_turns: 1,
            exit_code: Some(0),
            duration_ms: Some(1),
        };
        let g = ToolsMatchGate { requested: vec!["Read".into(), "Grep".into()] };
        assert!(g.check(&ctx(&env, None, None, None, Some(&mk(Some(vec!["Grep", "Read"]))))).ok);
        assert!(!g.check(&ctx(&env, None, None, None, Some(&mk(Some(vec!["Read", "Grep", "Bash"]))))).ok);
        assert!(!g.check(&ctx(&env, None, None, None, Some(&mk(Some(vec!["Read"]))))).ok);
        // A worker that cannot report is not a failure, but the detail says it was not verified.
        let r = g.check(&ctx(&env, None, None, None, Some(&mk(None))));
        assert!(r.ok && r.detail.contains("not verified"));
    }

    #[test]
    fn boundary_gate_names_failed_required_checks() {
        let env = BTreeMap::new();
        let b = BoundaryReport {
            kind: "container".into(),
            ok: false,
            egress: "open".into(),
            checks: vec![
                Check { name: "caps_zero".into(), ok: false, required: true, detail: "CapEff nonzero".into() },
                Check { name: "net_interfaces_minimal".into(), ok: false, required: false, detail: "x".into() },
            ],
        };
        let r = BoundaryGate.check(&ctx(&env, None, None, Some(&b), None));
        assert!(!r.ok);
        assert!(r.detail.contains("caps_zero") && !r.detail.contains("net_interfaces_minimal"));
        assert!(!BoundaryGate.check(&ctx(&env, None, None, None, None)).ok);
    }
}
