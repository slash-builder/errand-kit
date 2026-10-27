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
    text.lines()
        .map(|l| l.trim_end_matches('\r'))
        .rfind(|l| !l.trim().is_empty())
}

fn result(name: &str, kind: &str, ok: bool, hard: bool, detail: impl Into<String>) -> GateResult {
    GateResult {
        name: name.into(),
        kind: kind.into(),
        ok,
        hard,
        detail: detail.into(),
    }
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
            Some(b) if b.ok => result(
                "boundary",
                "boundary",
                true,
                true,
                format!("{} boundary verified", b.kind),
            ),
            Some(b) => {
                // Names AND details: a check's detail is written never to contain a secret value (names only), so it is safe
                // to show, and without it a refusal on a host nobody can inspect cannot be diagnosed.
                let failed: Vec<String> = b
                    .checks
                    .iter()
                    .filter(|c| c.required && !c.ok)
                    .map(|c| format!("{} ({})", c.name, c.detail))
                    .collect();
                result(
                    "boundary",
                    "boundary",
                    false,
                    true,
                    format!("required checks failed: {}", failed.join("; ")),
                )
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
        let bad: Vec<&str> = ctx
            .worker_env
            .keys()
            .map(String::as_str)
            .filter(|k| credential_shaped(k))
            .collect();
        if bad.is_empty() {
            result(
                "env_clean",
                "env_clean",
                true,
                true,
                "worker environment held no credential-shaped names",
            )
        } else {
            result(
                "env_clean",
                "env_clean",
                false,
                true,
                format!(
                    "credential-shaped names in the worker environment: {}",
                    bad.join(", ")
                ),
            )
        }
    }
}

/// The tools the worker reported equal the tools requested.
#[derive(Debug, Clone)]
pub struct ToolsMatchGate {
    /// What was requested.
    pub requested: Vec<String>,
    /// If true, a worker that reports no tool list FAILS the gate (the real worker always can; only a scripted test worker may not).
    pub require_report: bool,
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
            return result(
                "tools_match",
                "tools_match",
                !self.require_report,
                true,
                if self.require_report {
                    "the worker did not report its tools, so the allowlist could not be verified"
                } else {
                    "worker did not report its tools (not verified)"
                },
            );
        };
        let mut want = self.requested.clone();
        let mut got = reported.clone();
        want.sort();
        got.sort();
        if want == got {
            result(
                "tools_match",
                "tools_match",
                true,
                true,
                format!("tools are exactly: {}", want.join(", ")),
            )
        } else {
            result(
                "tools_match",
                "tools_match",
                false,
                true,
                format!(
                    "requested [{}] but the worker reported [{}]",
                    want.join(", "),
                    got.join(", ")
                ),
            )
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
            return result(
                "status_line",
                "status_line",
                false,
                true,
                "the digest is empty",
            );
        };
        let Some(model) = Verdict::from_status_line(last) else {
            return result(
                "status_line",
                "status_line",
                false,
                true,
                "the digest does not end with an exact STATUS: OK or STATUS: ATTENTION line",
            );
        };
        match ctx.code_verdict {
            Some(code) if code != model => result(
                "status_line",
                "status_line",
                false,
                true,
                format!(
                    "the model said {} but the code computed {}",
                    model.status_line().unwrap_or("?"),
                    code.status_line().unwrap_or("?")
                ),
            ),
            Some(_) => result(
                "status_line",
                "status_line",
                true,
                true,
                "the model's verdict matches the one computed in code",
            ),
            None => result(
                "status_line",
                "status_line",
                true,
                true,
                "valid STATUS line (no code verdict to compare)",
            ),
        }
    }
}

/// Secret-shaped strings: a prefix followed by at least `min` token characters.
const SECRET_SHAPES: &[(&str, usize, &str)] = &[
    ("sk-ant-", 16, "an Anthropic API key"),
    ("ghp_", 30, "a GitHub token"),
    ("gho_", 30, "a GitHub token"),
    ("ghs_", 30, "a GitHub token"),
    ("ghu_", 30, "a GitHub token"),
    ("github_pat_", 30, "a GitHub token"),
    ("AKIA", 16, "an AWS access key id"),
    ("ASIA", 16, "an AWS temporary access key id"),
    ("xoxb-", 10, "a Slack token"),
    ("xoxp-", 10, "a Slack token"),
    ("xoxa-", 10, "a Slack token"),
    ("xoxs-", 10, "a Slack token"),
];

/// The first secret-shaped thing in `text`, as a label (never the value).
///
/// ```
/// use errand_kit::gates::builtin::secret_shaped;
/// // Built at run time so this documentation contains no secret-shaped literal.
/// let key = format!("key {}{} here", "AKIA", "ABCDEFGHIJKLMNOP");
/// assert!(secret_shaped(&key).is_some());
/// let pem = format!("-----BEGIN RSA {}-----", "PRIVATE KEY");
/// assert!(secret_shaped(&pem).is_some());
/// assert!(secret_shaped("an ordinary sentence about keys").is_none());
/// ```
pub fn secret_shaped(text: &str) -> Option<&'static str> {
    if text.contains("PRIVATE KEY-----") && text.contains("-----BEGIN") {
        return Some("a private key block");
    }
    for (prefix, min, label) in SECRET_SHAPES {
        let mut from = 0;
        while let Some(i) = text[from..].find(prefix) {
            let start = from + i + prefix.len();
            let n = text[start..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .count();
            if n >= *min {
                return Some(label);
            }
            from = start;
        }
    }
    None
}

/// Fails if the digest or an ADDED line of the patch contains a secret-shaped string or the worker's own token. A prompt-injected
/// worker can read its token from its environment or a mounted file; this stops it reaching a ticket comment, a chat message or a
/// pushed branch. The detail names the kind of secret, never the value.
#[derive(Debug, Clone, Default)]
pub struct SecretScanGate {
    /// The worker's own token, if it has one (exact match, 8 bytes or longer).
    pub token: Option<String>,
}

impl Gate for SecretScanGate {
    fn name(&self) -> &str {
        "secret_scan"
    }
    fn kind(&self) -> &str {
        "secret_scan"
    }
    fn hard(&self) -> bool {
        true
    }
    fn check(&self, ctx: &GateContext<'_>) -> GateResult {
        let added: String = ctx
            .patch
            .map(|p| {
                p.lines()
                    .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        let digest = ctx.digest.unwrap_or_default();
        let mut found: Vec<String> = Vec::new();
        for (where_, text) in [("the digest", digest), ("the patch", added.as_str())] {
            if let Some(label) = secret_shaped(text) {
                found.push(format!("{label} in {where_}"));
            }
            if let Some(t) = &self.token {
                if t.len() >= 8 && text.contains(t.as_str()) {
                    found.push(format!("the worker's own token in {where_}"));
                }
            }
        }
        if found.is_empty() {
            result(
                "secret_scan",
                "secret_scan",
                true,
                true,
                "no secret-shaped strings in the digest or the patch's added lines",
            )
        } else {
            result("secret_scan", "secret_scan", false, true, found.join("; "))
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
            Ok(s) => result(
                "diff_scope",
                "diff_scope",
                true,
                true,
                format!("{} file(s), +{} -{}", s.files.len(), s.added, s.removed),
            ),
            Err(e) => result("diff_scope", "diff_scope", false, true, e.to_string()),
        }
    }
}

/// Run a recipe-defined command in the worker's tree, with an empty environment (only `PATH`) and a wall-clock limit.
///
/// The argv comes from the repo-side recipe, never from a tracker field or the worker. A gate command must only READ data in
/// the tree (parse a file, count lines); it must never execute a file the worker could have written.
#[derive(Debug, Clone)]
pub struct CommandGate {
    /// Position in the recipe's list, used in the gate's name.
    pub index: usize,
    /// The command and arguments.
    pub argv: Vec<String>,
    /// The directory to run in.
    pub cwd: std::path::PathBuf,
    /// Maximum wall time.
    pub timeout: std::time::Duration,
}

// NOTE: building a `CommandGate` directly skips the recipe's inspect-only check; construct gates from a validated `Recipe`.
impl Gate for CommandGate {
    fn name(&self) -> &str {
        "command"
    }
    fn kind(&self) -> &str {
        "command"
    }
    fn hard(&self) -> bool {
        true
    }
    fn check(&self, _ctx: &GateContext<'_>) -> GateResult {
        let name = format!("command_{}", self.index);
        let Some((program, args)) = self.argv.split_first() else {
            return result(&name, "command", false, true, "empty command in the recipe");
        };
        let child = std::process::Command::new(program)
            .args(args)
            .current_dir(&self.cwd)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                return result(
                    &name,
                    "command",
                    false,
                    true,
                    format!("could not start `{program}`: {e}"),
                )
            }
        };
        let deadline = std::time::Instant::now() + self.timeout;
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => {
                    return result(
                        &name,
                        "command",
                        true,
                        true,
                        format!("`{}` exited 0", self.argv.join(" ")),
                    );
                }
                Ok(Some(status)) => {
                    return result(
                        &name,
                        "command",
                        false,
                        true,
                        format!(
                            "`{}` exited {}",
                            self.argv.join(" "),
                            status.code().unwrap_or(-1)
                        ),
                    );
                }
                Ok(None) if std::time::Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return result(
                        &name,
                        "command",
                        false,
                        true,
                        format!("`{}` timed out", self.argv.join(" ")),
                    );
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
                Err(e) => {
                    return result(&name, "command", false, true, format!("wait failed: {e}"))
                }
            }
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
        GateContext {
            out_dir: Path::new("/out"),
            risk: Risk::L0,
            boundary,
            worker,
            worker_env: env,
            digest,
            code_verdict: code,
            patch: None,
        }
    }

    #[test]
    fn status_line_uses_only_the_last_nonempty_line() {
        let env = BTreeMap::new();
        // A STATUS line in the middle does not count; the last line wins.
        let d = "STATUS: OK\nbut actually more text follows\n";
        let r = StatusLineGate.check(&ctx(&env, Some(d), None, None, None));
        assert!(!r.ok, "{r:?}");
        let d = "text\nSTATUS: ATTENTION\n\n";
        assert!(
            StatusLineGate
                .check(&ctx(&env, Some(d), None, None, None))
                .ok
        );
    }

    #[test]
    fn status_line_must_be_exact() {
        let env = BTreeMap::new();
        for bad in [
            "status: ok",
            "STATUS: OK.",
            "STATUS:OK",
            " STATUS: OK x",
            "STATUS: FAILED",
        ] {
            assert!(
                !StatusLineGate
                    .check(&ctx(&env, Some(bad), None, None, None))
                    .ok,
                "{bad:?}"
            );
        }
        assert!(
            StatusLineGate
                .check(&ctx(&env, Some("x\r\nSTATUS: OK\r\n"), None, None, None))
                .ok
        );
    }

    #[test]
    fn the_code_verdict_wins_and_a_disagreeing_model_fails_the_gate() {
        let env = BTreeMap::new();
        let r = StatusLineGate.check(&ctx(
            &env,
            Some("STATUS: OK"),
            Some(Verdict::Attention),
            None,
            None,
        ));
        assert!(!r.ok && r.hard);
        assert!(
            r.detail.contains("code computed STATUS: ATTENTION"),
            "{}",
            r.detail
        );
        assert!(
            StatusLineGate
                .check(&ctx(
                    &env,
                    Some("STATUS: ATTENTION"),
                    Some(Verdict::Attention),
                    None,
                    None
                ))
                .ok
        );
    }

    #[test]
    fn env_clean_names_credentials_but_never_prints_values() {
        let mut env = BTreeMap::new();
        env.insert("PATH".to_string(), "/usr/bin".to_string());
        env.insert("CLAUDE_CODE_OAUTH_TOKEN".to_string(), "tok".to_string());
        assert!(EnvCleanGate.check(&ctx(&env, None, None, None, None)).ok);
        env.insert(
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "supersecretvalue".to_string(),
        );
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
        let g = ToolsMatchGate {
            requested: vec!["Read".into(), "Grep".into()],
            require_report: false,
        };
        assert!(
            g.check(&ctx(
                &env,
                None,
                None,
                None,
                Some(&mk(Some(vec!["Grep", "Read"])))
            ))
            .ok
        );
        assert!(
            !g.check(&ctx(
                &env,
                None,
                None,
                None,
                Some(&mk(Some(vec!["Read", "Grep", "Bash"])))
            ))
            .ok
        );
        assert!(
            !g.check(&ctx(&env, None, None, None, Some(&mk(Some(vec!["Read"])))))
                .ok
        );
        // A worker that cannot report is not a failure, but the detail says it was not verified.
        let r = g.check(&ctx(&env, None, None, None, Some(&mk(None))));
        assert!(r.ok && r.detail.contains("not verified"));
    }

    #[test]
    fn command_gate_passes_fails_and_times_out() {
        let env = BTreeMap::new();
        let mk = |argv: &[&str], ms: u64| CommandGate {
            index: 0,
            argv: argv.iter().map(|s| s.to_string()).collect(),
            cwd: std::env::temp_dir(),
            timeout: std::time::Duration::from_millis(ms),
        };
        let c = ctx(&env, None, None, None, None);
        assert!(mk(&["true"], 2000).check(&c).ok);
        let r = mk(&["false"], 2000).check(&c);
        assert!(!r.ok && r.detail.contains("exited 1"), "{r:?}");
        let r = mk(&["sleep", "5"], 150).check(&c);
        assert!(!r.ok && r.detail.contains("timed out"), "{r:?}");
        assert!(!mk(&["definitely-not-a-program-xyz"], 500).check(&c).ok);
        assert!(!mk(&[], 500).check(&c).ok);
    }

    #[test]
    fn command_gate_runs_with_an_empty_environment() {
        std::env::set_var("ERRAND_TEST_LEAK", "yes");
        let env = BTreeMap::new();
        let g = CommandGate {
            index: 1,
            argv: vec![
                "sh".into(),
                "-c".into(),
                "test -z \"$ERRAND_TEST_LEAK\"".into(),
            ],
            cwd: std::env::temp_dir(),
            timeout: std::time::Duration::from_secs(2),
        };
        assert!(
            g.check(&ctx(&env, None, None, None, None)).ok,
            "the environment must be empty"
        );
    }

    #[test]
    fn boundary_gate_names_failed_required_checks() {
        let env = BTreeMap::new();
        let b = BoundaryReport {
            kind: "container".into(),
            ok: false,
            egress: "open".into(),
            checks: vec![
                Check {
                    name: "caps_zero".into(),
                    ok: false,
                    required: true,
                    detail: "CapEff nonzero".into(),
                },
                Check {
                    name: "net_interfaces_minimal".into(),
                    ok: false,
                    required: false,
                    detail: "x".into(),
                },
            ],
        };
        let r = BoundaryGate.check(&ctx(&env, None, None, Some(&b), None));
        assert!(!r.ok);
        assert!(r.detail.contains("caps_zero") && !r.detail.contains("net_interfaces_minimal"));
        assert!(!BoundaryGate.check(&ctx(&env, None, None, None, None)).ok);
    }
}
