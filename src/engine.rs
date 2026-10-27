//! The errand engine: the six phases of `spec/ERRAND.md` section 1.
//!
//! [`run_prepare`] is phase 1 (credentials, no model). [`run_model`] is phases 2 to 5 (boundary, worker, gates, record) and
//! must run where no credential was ever present: the boundary phase proves it and refuses otherwise.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::contract::{
    BoundaryReport, GateResult, HandBack, Phase, PhaseRecord, Risk, RunRecord, Verdict, WorkerReport, SCHEMA_VERSION,
};
use crate::gates::builtin::{
    last_nonempty_line, BoundaryGate, DiffScopeGate, EnvCleanGate, StatusLineGate, ToolsMatchGate,
};
use crate::gates::patch::validate_patch;
use crate::gates::recipe::Recipe;
use crate::gates::{Gate, GateContext};
use crate::sandbox::Sandbox;
use crate::task::Task;
use crate::time::{now_epoch, now_rfc3339};
use crate::worker::{Worker, WorkerRequest};
use crate::{ErrandError, Result};

/// Exit code: the boundary refused the run.
pub const EXIT_BOUNDARY: i32 = 72;
/// Exit code: a hard gate failed or the verdict could not be established.
pub const EXIT_GATE: i32 = 73;
/// Exit code: the worker produced no usable output.
pub const EXIT_NO_DIGEST: i32 = 70;

/// Environment variables a worker may inherit from its launcher. Everything else is dropped.
pub const WORKER_ENV_ALLOWLIST: &[&str] = &["PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "TERM", "TZ"];

/// What the model phase needs besides the task.
pub struct ModelOptions<'a> {
    /// The output directory (the one `prepare` wrote into).
    pub out_dir: &'a Path,
    /// The boundary to verify.
    pub sandbox: &'a dyn Sandbox,
    /// The worker.
    pub worker: &'a dyn Worker,
    /// The worker's own token (`CLAUDE_CODE_OAUTH_TOKEN`), if it needs one.
    pub token: Option<String>,
    /// The launcher's environment (only [`WORKER_ENV_ALLOWLIST`] names are passed on).
    pub parent_env: BTreeMap<String, String>,
    /// A repo-side recipe, required for L1 and above.
    pub recipe: Option<Recipe>,
    /// Wall-clock limit for the worker.
    pub timeout: Duration,
}

/// Phase 1: run the task's `prepare.sh` with the credentials this process was given. No model runs here.
///
/// Returns the script's exit code (or `0` if the task has no prepare step). A failing prepare step is recorded by the files it
/// left behind; the model phase sees whatever was written.
pub fn run_prepare(task: &Task, out_dir: &Path) -> Result<i32> {
    std::fs::create_dir_all(out_dir).map_err(|e| ErrandError::io(out_dir, e))?;
    let Some(script) = &task.prepare else { return Ok(0) };
    let status = Command::new(script)
        .current_dir(&task.dir)
        .status()
        .map_err(|e| ErrandError::io(script.clone(), e))?;
    Ok(status.code().unwrap_or(-1))
}

/// A run id: first 16 hex digits of `sha256(task, epoch seconds, process id)`.
pub fn new_run_id(task: &str) -> String {
    let mut h = Sha256::new();
    h.update(task.as_bytes());
    h.update(now_epoch().to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    let d = h.finalize();
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Read the verdict the task computed in code (`out/status.txt`), if it wrote one.
pub fn read_code_verdict(out_dir: &Path) -> Option<Verdict> {
    let text = std::fs::read_to_string(out_dir.join("status.txt")).ok()?;
    Verdict::from_status_line(last_nonempty_line(&text)?)
}

/// Build the complete environment of the worker: only allowlisted launcher variables plus its own token.
pub fn worker_env(parent: &BTreeMap<String, String>, token: Option<&str>) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> =
        parent.iter().filter(|(k, _)| WORKER_ENV_ALLOWLIST.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
    if let Some(t) = token {
        env.insert("CLAUDE_CODE_OAUTH_TOKEN".to_string(), t.to_string());
    }
    env
}

fn phase(phase: Phase, ok: bool, started: String, note: Option<String>) -> PhaseRecord {
    PhaseRecord { phase, ok, started_at: started, finished_at: now_rfc3339(), note }
}

fn list_artifacts(out_dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(out_dir)
        .map(|rd| rd.filter_map(|e| e.ok()).filter(|e| e.path().is_file()).filter_map(|e| e.file_name().into_string().ok()).collect())
        .unwrap_or_default();
    names.retain(|n| n != "run.json" && n != "digest.md");
    names.sort();
    names
}

/// Phases 2 to 5: verify the boundary, run the worker, apply the gates, write `run.json` and `digest.md`.
///
/// Always returns a [`RunRecord`] (also written to `<out>/run.json`) unless the record itself cannot be written; a refused
/// boundary or a failed gate is a `FAILED` record, not an `Err`. The process exit code is `record.exit_code`.
pub fn run_model(task: &Task, opts: &ModelOptions<'_>) -> Result<RunRecord> {
    let out = opts.out_dir;
    std::fs::create_dir_all(out).map_err(|e| ErrandError::io(out, e))?;
    let started_at = now_rfc3339();
    let mut rec = RunRecord {
        schema_version: SCHEMA_VERSION,
        run_id: new_run_id(&task.name),
        task: task.name.clone(),
        risk: task.risk,
        started_at: started_at.clone(),
        finished_at: None,
        phases: vec![],
        boundary: None,
        worker: None,
        gates: vec![],
        verdict: Verdict::Failed,
        verdict_source: "none".into(),
        digest: None,
        artifacts: vec![],
        handback: None,
        exit_code: EXIT_GATE,
    };

    // Phase 2: the boundary. No automatic mode: a failed required check refuses the run.
    let t = now_rfc3339();
    let report: BoundaryReport = opts.sandbox.verify();
    rec.phases.push(phase(Phase::Boundary, report.ok, t, None));
    rec.boundary = Some(report.clone());
    let worker_environment = worker_env(&opts.parent_env, opts.token.as_deref());
    if !report.ok {
        let ctx = GateContext {
            out_dir: out,
            risk: task.risk,
            boundary: rec.boundary.as_ref(),
            worker: None,
            worker_env: &worker_environment,
            digest: None,
            code_verdict: None,
            patch: None,
        };
        rec.gates.push(BoundaryGate.check(&ctx));
        return finish(rec, out, EXIT_BOUNDARY);
    }

    // Risk and tools: the worker never gets more than the risk level allows.
    if task.risk == Risk::L3 || task.tools.iter().any(|t| !task.risk.tools_allowed().contains(&t.as_str())) {
        rec.gates.push(GateResult {
            name: "tools_allowed".into(),
            kind: "tools_match".into(),
            ok: false,
            hard: true,
            detail: format!("tools [{}] are not allowed at risk {}", task.tools.join(", "), task.risk),
        });
        return finish(rec, out, EXIT_GATE);
    }
    if task.risk >= Risk::L1 && opts.recipe.is_none() {
        rec.gates.push(GateResult {
            name: "recipe_present".into(),
            kind: "diff_scope".into(),
            ok: false,
            hard: true,
            detail: "an L1+ errand needs a repo-side recipe; none was provided".into(),
        });
        return finish(rec, out, EXIT_GATE);
    }

    let code_verdict = read_code_verdict(out);

    // Phase 3: the worker, with an empty environment plus the allowlist and its own token.
    let t = now_rfc3339();
    let req = WorkerRequest {
        prompt: task.prompt.clone(),
        tools: task.tools.clone(),
        max_turns: task.max_turns,
        cwd: out.to_path_buf(),
        add_dirs: vec![PathBuf::from(out)],
        env: worker_environment.clone(),
        timeout: opts.timeout,
    };
    let output = match opts.worker.run(&req) {
        Ok(o) => o,
        Err(e) => {
            rec.phases.push(phase(Phase::Worker, false, t, Some(e.to_string())));
            rec.worker = Some(WorkerReport {
                kind: opts.worker.kind().into(),
                tools_requested: task.tools.clone(),
                tools_reported: None,
                max_turns: task.max_turns,
                exit_code: None,
                duration_ms: None,
            });
            rec.gates.push(GateResult { name: "worker".into(), kind: "command".into(), ok: false, hard: true, detail: e.to_string() });
            return finish(rec, out, EXIT_NO_DIGEST);
        }
    };
    rec.phases.push(phase(Phase::Worker, output.exit_code == 0, t, None));
    let wr = WorkerReport {
        kind: opts.worker.kind().into(),
        tools_requested: task.tools.clone(),
        tools_reported: output.tools_reported.clone(),
        max_turns: task.max_turns,
        exit_code: Some(output.exit_code),
        duration_ms: Some(output.duration_ms),
    };
    rec.worker = Some(wr.clone());
    let digest_path = out.join("digest.md");
    std::fs::write(&digest_path, &output.text).map_err(|e| ErrandError::io(&digest_path, e))?;
    rec.digest = Some("digest.md".into());
    if output.text.trim().is_empty() {
        rec.gates.push(GateResult { name: "digest".into(), kind: "status_line".into(), ok: false, hard: true, detail: "the worker returned no text".into() });
        return finish(rec, out, EXIT_NO_DIGEST);
    }

    // Phase 4: gates.
    let t = now_rfc3339();
    let patch_text = if task.risk >= Risk::L1 { std::fs::read_to_string(out.join("patch.diff")).ok() } else { None };
    let ctx = GateContext {
        out_dir: out,
        risk: task.risk,
        boundary: rec.boundary.as_ref(),
        worker: Some(&wr),
        worker_env: &worker_environment,
        digest: Some(&output.text),
        code_verdict,
        patch: patch_text.as_deref(),
    };
    let mut gates: Vec<Box<dyn Gate>> = vec![
        Box::new(BoundaryGate),
        Box::new(EnvCleanGate),
        Box::new(ToolsMatchGate { requested: task.tools.clone() }),
        Box::new(StatusLineGate),
    ];
    if let Some(recipe) = &opts.recipe {
        gates.push(Box::new(DiffScopeGate { recipe: recipe.clone() }));
    }
    for g in &gates {
        rec.gates.push(g.check(&ctx));
    }
    let all_hard_ok = rec.gates.iter().filter(|g| g.hard).all(|g| g.ok);
    rec.phases.push(phase(Phase::Gates, all_hard_ok, t, None));

    // Hand-back for L1+, built from the PATCH TEXT (what the Kit parsed), not from the worker's claims.
    if let (true, Some(patch), Some(recipe)) = (task.risk >= Risk::L1, patch_text.as_deref(), opts.recipe.as_ref()) {
        if let Ok(summary) = validate_patch(patch, recipe) {
            rec.handback = Some(HandBack {
                ticket: None,
                repo: Some(recipe.repo.clone()),
                base: None,
                patch: Some("patch.diff".into()),
                files_changed: summary.files,
                summary: output.text.lines().take(12).collect::<Vec<_>>().join("\n"),
                verified: vec!["patch passed the scope and protected-path checks".into()],
                unverified: vec!["the patch has not been applied or built; no tests were run".into()],
                next_human_step: "review the patch; nothing is pushed or merged automatically".into(),
            });
        }
    }

    if !all_hard_ok {
        return finish(rec, out, EXIT_GATE);
    }

    // The verdict: the one computed in code wins; otherwise the model's last line.
    let (verdict, source) = match code_verdict {
        Some(v) => (v, "code"),
        None => {
            let v = last_nonempty_line(&output.text).and_then(Verdict::from_status_line).unwrap_or(Verdict::Failed);
            (v, "model")
        }
    };
    rec.verdict = verdict;
    rec.verdict_source = source.into();
    let code = verdict.exit_code();
    finish(rec, out, code)
}

fn finish(mut rec: RunRecord, out: &Path, exit_code: i32) -> Result<RunRecord> {
    let t = now_rfc3339();
    if exit_code == EXIT_BOUNDARY || exit_code == EXIT_GATE || exit_code == EXIT_NO_DIGEST {
        rec.verdict = Verdict::Failed;
    }
    rec.exit_code = exit_code;
    rec.finished_at = Some(now_rfc3339());
    rec.artifacts = list_artifacts(out);
    rec.phases.push(phase(Phase::Record, true, t, None));
    let path = out.join("run.json");
    let json = serde_json::to_string_pretty(&rec)?;
    std::fs::write(&path, json + "\n").map_err(|e| ErrandError::io(&path, e))?;
    Ok(rec)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::sync::Mutex;

    use super::*;
    use crate::contract::Check;
    use crate::worker::WorkerOutput;

    struct TestBoundary(bool);
    impl Sandbox for TestBoundary {
        fn kind(&self) -> &'static str {
            "container"
        }
        fn verify(&self) -> BoundaryReport {
            BoundaryReport {
                kind: "container".into(),
                ok: self.0,
                egress: "open".into(),
                checks: vec![Check { name: "caps_zero".into(), ok: self.0, required: true, detail: "test".into() }],
            }
        }
    }

    struct Canned {
        text: String,
        tools: Option<Vec<String>>,
        seen: Mutex<Vec<WorkerRequest>>,
    }
    impl Canned {
        fn new(text: &str) -> Self {
            Canned { text: text.into(), tools: None, seen: Mutex::new(vec![]) }
        }
    }
    impl Worker for Canned {
        fn kind(&self) -> &'static str {
            "fake"
        }
        fn run(&self, req: &WorkerRequest) -> Result<WorkerOutput> {
            self.seen.lock().unwrap().push(req.clone());
            Ok(WorkerOutput { text: self.text.clone(), exit_code: 0, duration_ms: 5, tools_reported: self.tools.clone() })
        }
    }

    fn task(tmp: &Path, env: &str) -> Task {
        let d = tmp.join("tasks").join("t");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("prompt.md"), "summarise").unwrap();
        std::fs::write(d.join("task.env"), env).unwrap();
        Task::load(&tmp.join("tasks"), "t").unwrap()
    }

    fn parent() -> BTreeMap<String, String> {
        [("PATH", "/usr/bin"), ("AWS_SECRET_ACCESS_KEY", "leak-me"), ("GRAFANA_PASSWORD", "leak-me-too"), ("HOME", "/home/runner")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn opts<'a>(out: &'a Path, sb: &'a dyn Sandbox, w: &'a dyn Worker, token: Option<&str>) -> ModelOptions<'a> {
        ModelOptions { out_dir: out, sandbox: sb, worker: w, token: token.map(String::from), parent_env: parent(), recipe: None, timeout: Duration::from_secs(5) }
    }

    #[test]
    fn a_clean_run_records_the_model_verdict() {
        let t = tempfile::tempdir().unwrap();
        let task = task(t.path(), "TASK_ALLOWED_TOOLS=Read,Grep,Glob\n");
        let out = t.path().join("out");
        let w = Canned::new("all fine\nSTATUS: OK\n");
        let rec = run_model(&task, &opts(&out, &TestBoundary(true), &w, Some("tok"))).unwrap();
        assert_eq!(rec.verdict, Verdict::Ok);
        assert_eq!(rec.verdict_source, "model");
        assert_eq!(rec.exit_code, 0);
        assert!(out.join("run.json").is_file() && out.join("digest.md").is_file());
        let back: RunRecord = serde_json::from_str(&std::fs::read_to_string(out.join("run.json")).unwrap()).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn the_worker_never_sees_a_credential_but_gets_its_own_token() {
        let t = tempfile::tempdir().unwrap();
        let task = task(t.path(), "TASK_ALLOWED_TOOLS=Read\n");
        let out = t.path().join("out");
        let w = Canned::new("STATUS: OK");
        run_model(&task, &opts(&out, &TestBoundary(true), &w, Some("my-token"))).unwrap();
        let seen = w.seen.lock().unwrap();
        let env = &seen[0].env;
        assert_eq!(env.get("CLAUDE_CODE_OAUTH_TOKEN").map(String::as_str), Some("my-token"));
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY") && !env.contains_key("GRAFANA_PASSWORD"));
        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
    }

    #[test]
    fn a_refused_boundary_never_starts_the_worker() {
        let t = tempfile::tempdir().unwrap();
        let task = task(t.path(), "TASK_ALLOWED_TOOLS=Read\n");
        let out = t.path().join("out");
        let w = Canned::new("STATUS: OK");
        let rec = run_model(&task, &opts(&out, &TestBoundary(false), &w, None)).unwrap();
        assert_eq!(rec.exit_code, EXIT_BOUNDARY);
        assert_eq!(rec.verdict, Verdict::Failed);
        assert!(w.seen.lock().unwrap().is_empty(), "the worker must not run");
        assert!(rec.gates.iter().any(|g| g.name == "boundary" && !g.ok));
    }

    #[test]
    fn the_code_verdict_wins_and_a_lying_model_fails_the_run() {
        let t = tempfile::tempdir().unwrap();
        let task = task(t.path(), "TASK_ALLOWED_TOOLS=Read\n");
        let out = t.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("status.txt"), "STATUS: ATTENTION\n").unwrap();
        // The model claims everything is fine; the code says otherwise.
        let w = Canned::new("nothing to see\nSTATUS: OK\n");
        let rec = run_model(&task, &opts(&out, &TestBoundary(true), &w, None)).unwrap();
        assert_eq!(rec.exit_code, EXIT_GATE);
        assert_eq!(rec.verdict, Verdict::Failed);
        assert!(rec.gates.iter().any(|g| g.name == "status_line" && !g.ok));
        // And when they agree, the source is the code.
        let w = Canned::new("look at this\nSTATUS: ATTENTION\n");
        let rec = run_model(&task, &opts(&out, &TestBoundary(true), &w, None)).unwrap();
        assert_eq!((rec.verdict, rec.verdict_source.as_str(), rec.exit_code), (Verdict::Attention, "code", 3));
    }

    #[test]
    fn a_digest_without_a_status_line_fails() {
        let t = tempfile::tempdir().unwrap();
        let task = task(t.path(), "TASK_ALLOWED_TOOLS=Read\n");
        let out = t.path().join("out");
        let w = Canned::new("I forgot the status line");
        let rec = run_model(&task, &opts(&out, &TestBoundary(true), &w, None)).unwrap();
        assert_eq!(rec.exit_code, EXIT_GATE);
    }

    #[test]
    fn a_tool_list_that_differs_from_the_request_fails_the_gate() {
        let t = tempfile::tempdir().unwrap();
        let task = task(t.path(), "TASK_ALLOWED_TOOLS=Read\n");
        let out = t.path().join("out");
        let mut w = Canned::new("STATUS: OK");
        w.tools = Some(vec!["Read".into(), "Bash".into()]);
        let rec = run_model(&task, &opts(&out, &TestBoundary(true), &w, None)).unwrap();
        assert_eq!(rec.exit_code, EXIT_GATE);
        assert!(rec.gates.iter().any(|g| g.name == "tools_match" && !g.ok));
    }

    #[test]
    fn an_l1_errand_without_a_recipe_is_refused() {
        let t = tempfile::tempdir().unwrap();
        let task = task(t.path(), "TASK_ALLOWED_TOOLS=Read,Edit\n");
        let out = t.path().join("out");
        let w = Canned::new("STATUS: OK");
        let rec = run_model(&task, &opts(&out, &TestBoundary(true), &w, None)).unwrap();
        assert_eq!(rec.exit_code, EXIT_GATE);
        assert!(w.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn worker_env_drops_everything_not_allowlisted() {
        let env = worker_env(&parent(), None);
        let keys: Vec<&str> = env.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["HOME", "PATH"]);
    }

    #[test]
    fn run_ids_differ_per_task() {
        assert_ne!(new_run_id("a"), new_run_id("b"));
        assert_eq!(new_run_id("a").len(), 16);
    }
}
