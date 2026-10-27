//! The errand engine: the six phases of `spec/ERRAND.md` section 1.
//!
//! [`run_prepare`] is phase 1 (credentials, no model). [`run_model`] is phases 2 to 5 (boundary, worker, gates, record) and
//! must run where no credential was ever present: the boundary phase proves it and refuses otherwise.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::contract::{
    BoundaryReport, GateResult, HandBack, Phase, PhaseRecord, Risk, RunRecord, Verdict,
    WorkerReport, SCHEMA_VERSION,
};
use crate::gates::builtin::{
    last_nonempty_line, BoundaryGate, CommandGate, DiffScopeGate, EnvCleanGate, SecretScanGate,
    StatusLineGate, ToolsMatchGate,
};
use crate::gates::patch::validate_patch;
use crate::gates::recipe::Recipe;
use crate::gates::{Gate, GateContext};
use crate::patchmake::{make_patch, WorkDirs};
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
pub const WORKER_ENV_ALLOWLIST: &[&str] = &[
    "PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "TERM", "TZ",
];

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
    /// For L1+: the pristine tree and the worker's tree. The Kit itself builds the patch from them in a scratch repository;
    /// it never runs git inside the worker's directory.
    pub work: Option<WorkDirs>,
    /// Extra directories the worker may read (for example a read-only folder holding the ticket text).
    pub extra_dirs: Vec<PathBuf>,
}

/// Phase 1: run the task's `prepare.sh` with the credentials this process was given. No model runs here.
///
/// Returns the script's exit code (or `0` if the task has no prepare step). A failing prepare step is recorded by the files it
/// left behind; the model phase sees whatever was written.
pub fn run_prepare(task: &Task, out_dir: &Path) -> Result<i32> {
    std::fs::create_dir_all(out_dir).map_err(|e| ErrandError::io(out_dir, e))?;
    let Some(script) = &task.prepare else {
        return Ok(0);
    };
    let status = Command::new(script)
        .current_dir(&task.dir)
        .status()
        .map_err(|e| ErrandError::io(script.clone(), e))?;
    Ok(status.code().unwrap_or(-1))
}

/// A run id: 16 hex digits of `sha256(task, epoch seconds, process id, 8 random bytes)`. The random bytes matter: in containers
/// the process id is nearly always the same, and two runs in the same second must not collide.
pub fn new_run_id(task: &str) -> String {
    let mut random = [0u8; 8];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut random);
    }
    let mut h = Sha256::new();
    h.update(task.as_bytes());
    h.update(now_epoch().to_le_bytes());
    h.update(std::process::id().to_le_bytes());
    h.update(random);
    let d = h.finalize();
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// What `out/status.txt` says about the verdict computed in code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeVerdict {
    /// The task wrote no `status.txt`: the model's last line decides.
    Absent,
    /// A valid verdict. It IS the verdict.
    Valid(Verdict),
    /// The file exists but is unreadable or malformed. The run FAILS: a broken code verdict must never hand the decision to the model.
    Invalid(String),
}

/// Read `out/status.txt`.
pub fn code_verdict_state(out_dir: &Path) -> CodeVerdict {
    match std::fs::read_to_string(out_dir.join("status.txt")) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => CodeVerdict::Absent,
        Err(e) => CodeVerdict::Invalid(format!("status.txt could not be read ({:?})", e.kind())),
        Ok(text) => match last_nonempty_line(&text).and_then(Verdict::from_status_line) {
            Some(v) => CodeVerdict::Valid(v),
            None => CodeVerdict::Invalid(
                "status.txt does not end with an exact `STATUS: OK` or `STATUS: ATTENTION` line"
                    .into(),
            ),
        },
    }
}

/// The valid code verdict, if there is one. An absent file and an INVALID file both give `None`, so a caller that needs to tell
/// them apart must use the engine, which treats an invalid file as a failure (a broken verdict is never "no verdict").
pub fn read_code_verdict(out_dir: &Path) -> Option<Verdict> {
    match code_verdict_state(out_dir) {
        CodeVerdict::Valid(v) => Some(v),
        _ => None,
    }
}

/// Replace every occurrence of each secret (8 bytes or longer) with `[REDACTED]`.
///
/// ```
/// assert_eq!(errand_kit::engine::redact("tok=abcdefgh12 end", &["abcdefgh12"]), "tok=[REDACTED] end");
/// assert_eq!(errand_kit::engine::redact("short", &["sh"]), "short");
/// ```
pub fn redact(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_string();
    for s in secrets {
        if s.len() >= 8 {
            out = out.replace(s, "[REDACTED]");
        }
    }
    out
}

/// Build the complete environment of the worker: only allowlisted launcher variables plus its own token. `home`, when given,
/// replaces `HOME`: the worker gets a fresh empty directory so no user settings, hooks or credentials in a real home can load.
pub fn worker_env(
    parent: &BTreeMap<String, String>,
    token: Option<&str>,
    home: Option<&Path>,
) -> BTreeMap<String, String> {
    let mut env: BTreeMap<String, String> = parent
        .iter()
        .filter(|(k, _)| WORKER_ENV_ALLOWLIST.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if let Some(h) = home {
        env.insert("HOME".to_string(), h.display().to_string());
    }
    if let Some(t) = token {
        env.insert("CLAUDE_CODE_OAUTH_TOKEN".to_string(), t.to_string());
    }
    env
}

fn phase(phase: Phase, ok: bool, started: String, note: Option<String>) -> PhaseRecord {
    PhaseRecord {
        phase,
        ok,
        started_at: started,
        finished_at: now_rfc3339(),
        note,
    }
}

fn list_artifacts(out_dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(out_dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.retain(|n| n != "run.json" && n != "digest.md");
    names.sort();
    names
}

/// Phases 2 to 5: verify the boundary, run the worker, apply the gates, write `run.json` and `digest.md`.
///
/// Always returns a [`RunRecord`] (also written to `<out>/run.json`) unless the record itself cannot be written; a refused
/// boundary or a failed gate is a `FAILED` record, not an `Err`. The process exit code is `record.exit_code`.
///
/// The worker gets a fresh empty `HOME` (removed afterwards). Every artifact the record points at (`patch.diff`, `digest.md`,
/// `run.json`) is written by the engine AFTER any recipe gate command has run, from values held in memory, so code a gate command
/// executed cannot change what a human is shown; the patch's SHA-256 is recorded in the hand-back.
pub fn run_model(task: &Task, opts: &ModelOptions<'_>) -> Result<RunRecord> {
    // The run id names the worker's HOME. If the operating system cannot supply randomness the name would be predictable, so refuse.
    let mut probe = [0u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut probe))
        .map_err(|e| ErrandError::io(Path::new("/dev/urandom"), e))?;
    let run_id = new_run_id(&task.name);
    let home = std::env::temp_dir().join(format!("errand-home-{run_id}"));
    // `create_dir`, not `create_dir_all`: an existing directory (planted by someone else) is an error, never reused.
    std::fs::create_dir(&home).map_err(|e| ErrandError::io(&home, e))?;
    let result = run_model_inner(task, opts, &run_id, &home);
    let _ = std::fs::remove_dir_all(&home);
    result
}

fn fail_gate(rec: &mut RunRecord, name: &str, kind: &str, detail: impl Into<String>) {
    rec.gates.push(GateResult {
        name: name.into(),
        kind: kind.into(),
        ok: false,
        hard: true,
        detail: detail.into(),
    });
}

fn run_model_inner(
    task: &Task,
    opts: &ModelOptions<'_>,
    run_id: &str,
    home: &Path,
) -> Result<RunRecord> {
    let out = opts.out_dir;
    // A recipe built in code gets the same checks as one loaded from a file.
    if let Some(r) = &opts.recipe {
        r.validate()?;
    }
    std::fs::create_dir_all(out).map_err(|e| ErrandError::io(out, e))?;
    let mut rec = RunRecord {
        schema_version: SCHEMA_VERSION,
        run_id: run_id.to_string(),
        task: task.name.clone(),
        risk: task.risk,
        started_at: now_rfc3339(),
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
    let secrets: Vec<&str> = opts.token.as_deref().into_iter().collect();

    // Phase 2: the boundary. No automatic mode: a failed required check refuses the run.
    let t = now_rfc3339();
    let report: BoundaryReport = opts.sandbox.verify();
    rec.phases.push(phase(Phase::Boundary, report.ok, t, None));
    rec.boundary = Some(report.clone());
    let worker_environment = worker_env(&opts.parent_env, opts.token.as_deref(), Some(home));
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
    if task.risk == Risk::L3
        || task
            .tools
            .iter()
            .any(|t| !task.risk.tools_allowed().contains(&t.as_str()))
    {
        fail_gate(
            &mut rec,
            "tools_allowed",
            "tools_match",
            format!(
                "tools [{}] are not allowed at risk {}",
                task.tools.join(", "),
                task.risk
            ),
        );
        return finish(rec, out, EXIT_GATE);
    }
    if task.risk >= Risk::L1 {
        // A write-capable worker needs a recipe AND its own tree. Without `work` the worker would be handed the output directory
        // (a bind mount of the CI workspace), and "no patch" would pass the scope gate.
        if opts.recipe.is_none() {
            fail_gate(
                &mut rec,
                "recipe_present",
                "diff_scope",
                "an L1+ errand needs a repo-side recipe; none was provided",
            );
            return finish(rec, out, EXIT_GATE);
        }
        if opts.work.is_none() {
            fail_gate(&mut rec, "work_dirs_present", "diff_scope", "an L1+ errand needs --base and --tree (a pristine tree and the worker's copy); a write-capable worker is never given the output directory");
            return finish(rec, out, EXIT_GATE);
        }
    }

    // The verdict computed in code. A status.txt that exists but is broken FAILS the run; it must never hand the decision to the model.
    let code_verdict = match code_verdict_state(out) {
        CodeVerdict::Absent => None,
        CodeVerdict::Valid(v) => Some(v),
        CodeVerdict::Invalid(why) => {
            fail_gate(&mut rec, "code_verdict", "status_line", why);
            return finish(rec, out, EXIT_GATE);
        }
    };

    // Phase 3: the worker, with an empty environment plus the allowlist and its own token.
    let t = now_rfc3339();
    // An L0 worker reads the output directory. An L1+ worker must NOT see it (it could overwrite files the engine reads): it gets
    // its tree as the working directory plus any explicitly provided read-only folders.
    let (cwd, add_dirs) = match &opts.work {
        Some(w) if task.risk >= Risk::L1 => {
            let mut dirs = vec![w.tree.clone()];
            dirs.extend(opts.extra_dirs.iter().cloned());
            (w.tree.clone(), dirs)
        }
        _ => (out.to_path_buf(), vec![PathBuf::from(out)]),
    };
    let req = WorkerRequest {
        prompt: task.prompt.clone(),
        tools: task.tools.clone(),
        max_turns: task.max_turns,
        cwd,
        add_dirs,
        env: worker_environment.clone(),
        timeout: opts.timeout,
    };
    let output = match opts.worker.run(&req) {
        Ok(o) => o,
        Err(e) => {
            let msg = redact(&e.to_string(), &secrets);
            rec.phases
                .push(phase(Phase::Worker, false, t, Some(msg.clone())));
            rec.worker = Some(WorkerReport {
                kind: opts.worker.kind().into(),
                tools_requested: task.tools.clone(),
                tools_reported: None,
                max_turns: task.max_turns,
                exit_code: None,
                duration_ms: None,
            });
            fail_gate(&mut rec, "worker", "command", msg);
            return finish(rec, out, EXIT_NO_DIGEST);
        }
    };
    rec.phases
        .push(phase(Phase::Worker, output.exit_code == 0, t, None));
    let wr = WorkerReport {
        kind: opts.worker.kind().into(),
        tools_requested: task.tools.clone(),
        tools_reported: output.tools_reported.clone(),
        max_turns: task.max_turns,
        exit_code: Some(output.exit_code),
        duration_ms: Some(output.duration_ms),
    };
    rec.worker = Some(wr.clone());
    // The worker's own token must not reach any artifact, even if prompt-injected text made it print the token.
    let digest = redact(&output.text, &secrets);
    let digest_path = out.join("digest.md");
    std::fs::write(&digest_path, &digest).map_err(|e| ErrandError::io(&digest_path, e))?;
    rec.digest = Some("digest.md".into());
    if digest.trim().is_empty() {
        fail_gate(
            &mut rec,
            "digest",
            "status_line",
            "the worker returned no text",
        );
        return finish(rec, out, EXIT_NO_DIGEST);
    }

    // Phase 4: gates. FIRST the patch is built and validated, in memory, before any recipe command runs.
    let t = now_rfc3339();
    let mut patch_text: Option<String> = None;
    if task.risk >= Risk::L1 {
        if let Some(dirs) = &opts.work {
            let scratch = out.join(".scratch");
            let built = make_patch(dirs, &scratch);
            let _ = std::fs::remove_dir_all(&scratch);
            match built {
                Ok(p) if p.is_empty() => {}
                Ok(p) => patch_text = Some(p),
                Err(e) => fail_gate(&mut rec, "patch_build", "diff_scope", e.to_string()),
            }
        }
    }
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
        Box::new(ToolsMatchGate {
            requested: task.tools.clone(),
            // A worker that can report its tools MUST: only the scripted test worker may stay silent.
            require_report: opts.worker.kind() != "fake",
        }),
        Box::new(StatusLineGate),
        Box::new(SecretScanGate {
            token: opts.token.clone(),
        }),
    ];
    if let Some(recipe) = &opts.recipe {
        gates.push(Box::new(DiffScopeGate {
            recipe: recipe.clone(),
        }));
    }
    for g in &gates {
        rec.gates.push(g.check(&ctx));
    }

    // Recipe gate commands run worker-written files in the worker's tree (for example `cargo test`). They run ONLY if everything
    // above passed, so rejected work is never executed, and nothing they do can change what is recorded below.
    let mut all_hard_ok = rec.gates.iter().filter(|g| g.hard).all(|g| g.ok);
    if let (true, Some(recipe), Some(w)) = (all_hard_ok, &opts.recipe, &opts.work) {
        for (i, argv) in recipe.gate_commands.iter().enumerate() {
            let g = CommandGate {
                index: i,
                argv: argv.clone(),
                cwd: w.tree.clone(),
                timeout: Duration::from_secs(60),
            };
            rec.gates.push(g.check(&ctx));
        }
        all_hard_ok = rec.gates.iter().filter(|g| g.hard).all(|g| g.ok);
    }
    rec.phases.push(phase(Phase::Gates, all_hard_ok, t, None));

    // Write the artifacts from memory, AFTER the commands: anything those commands wrote to the output directory is replaced.
    std::fs::write(&digest_path, &digest).map_err(|e| ErrandError::io(&digest_path, e))?;
    let patch_sha256 = patch_text.as_deref().map(|p| {
        let d = Sha256::digest(p.as_bytes());
        d.iter().map(|b| format!("{b:02x}")).collect::<String>()
    });
    if let Some(p) = &patch_text {
        let path = out.join("patch.diff");
        std::fs::write(&path, p).map_err(|e| ErrandError::io(&path, e))?;
    }

    // Hand-back for L1+, built from the PATCH TEXT (what the Kit parsed), not from the worker's claims.
    if let (true, Some(patch), Some(recipe)) = (
        task.risk >= Risk::L1,
        patch_text.as_deref(),
        opts.recipe.as_ref(),
    ) {
        if let Ok(summary) = validate_patch(patch, recipe) {
            rec.handback = Some(HandBack {
                ticket: None,
                repo: Some(recipe.repo.clone()),
                base: None,
                patch: Some("patch.diff".into()),
                patch_sha256,
                files_changed: summary.files,
                summary: digest.lines().take(12).collect::<Vec<_>>().join("\n"),
                verified: {
                    let mut v =
                        vec!["patch passed the scope and protected-path checks".to_string()];
                    let cmds: Vec<_> = rec
                        .gates
                        .iter()
                        .filter(|g| g.name.starts_with("command_"))
                        .collect();
                    if !cmds.is_empty() && cmds.iter().all(|g| g.ok) {
                        v.push(format!(
                            "the recipe's {} gate command(s) passed",
                            cmds.len()
                        ));
                    }
                    v
                },
                unverified: {
                    let mut u = vec![
                        "the patch has not been applied by the Kit; a consumer must verify patch.diff against patch_sha256".to_string(),
                    ];
                    if !rec.gates.iter().any(|g| g.name.starts_with("command_")) {
                        u.push(
                            "no recipe gate command ran (none defined, or an earlier gate failed)"
                                .to_string(),
                        );
                    }
                    u
                },
                next_human_step: "review the patch; nothing is pushed or merged automatically"
                    .into(),
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
            let v = last_nonempty_line(&digest)
                .and_then(Verdict::from_status_line)
                .unwrap_or(Verdict::Failed);
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
                checks: vec![Check {
                    name: "caps_zero".into(),
                    ok: self.0,
                    required: true,
                    detail: "test".into(),
                }],
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
            Canned {
                text: text.into(),
                tools: None,
                seen: Mutex::new(vec![]),
            }
        }
    }
    impl Worker for Canned {
        fn kind(&self) -> &'static str {
            "fake"
        }
        fn run(&self, req: &WorkerRequest) -> Result<WorkerOutput> {
            self.seen.lock().unwrap().push(req.clone());
            Ok(WorkerOutput {
                text: self.text.clone(),
                exit_code: 0,
                duration_ms: 5,
                tools_reported: self.tools.clone(),
            })
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
        [
            ("PATH", "/usr/bin"),
            ("AWS_SECRET_ACCESS_KEY", "leak-me"),
            ("GRAFANA_PASSWORD", "leak-me-too"),
            ("HOME", "/home/runner"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    fn opts<'a>(
        out: &'a Path,
        sb: &'a dyn Sandbox,
        w: &'a dyn Worker,
        token: Option<&str>,
    ) -> ModelOptions<'a> {
        ModelOptions {
            out_dir: out,
            sandbox: sb,
            worker: w,
            token: token.map(String::from),
            parent_env: parent(),
            recipe: None,
            timeout: Duration::from_secs(5),
            work: None,
            extra_dirs: vec![],
        }
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
        let back: RunRecord =
            serde_json::from_str(&std::fs::read_to_string(out.join("run.json")).unwrap()).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn the_worker_never_sees_a_credential_but_gets_its_own_token() {
        let t = tempfile::tempdir().unwrap();
        let task = task(t.path(), "TASK_ALLOWED_TOOLS=Read\n");
        let out = t.path().join("out");
        let w = Canned::new("STATUS: OK");
        run_model(
            &task,
            &opts(&out, &TestBoundary(true), &w, Some("my-token")),
        )
        .unwrap();
        let seen = w.seen.lock().unwrap();
        let env = &seen[0].env;
        assert_eq!(
            env.get("CLAUDE_CODE_OAUTH_TOKEN").map(String::as_str),
            Some("my-token")
        );
        assert!(
            !env.contains_key("AWS_SECRET_ACCESS_KEY") && !env.contains_key("GRAFANA_PASSWORD")
        );
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
        assert_eq!(
            (rec.verdict, rec.verdict_source.as_str(), rec.exit_code),
            (Verdict::Attention, "code", 3)
        );
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
        let env = worker_env(&parent(), None, None);
        let keys: Vec<&str> = env.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["HOME", "PATH"]);
    }

    #[test]
    fn run_ids_differ_per_task() {
        assert_ne!(new_run_id("a"), new_run_id("b"));
        assert_eq!(new_run_id("a").len(), 16);
    }

    // ---- security-review regressions -------------------------------------------------------------------------------------

    struct Writer {
        files: Vec<(String, String)>,
        text: String,
        kind: &'static str,
        seen_home: Mutex<Option<String>>,
    }
    impl Writer {
        fn new(files: &[(&str, &str)], text: &str) -> Self {
            Writer {
                files: files
                    .iter()
                    .map(|(a, b)| (a.to_string(), b.to_string()))
                    .collect(),
                text: text.into(),
                kind: "fake",
                seen_home: Mutex::new(None),
            }
        }
    }
    impl Worker for Writer {
        fn kind(&self) -> &'static str {
            self.kind
        }
        fn run(&self, req: &WorkerRequest) -> Result<WorkerOutput> {
            *self.seen_home.lock().unwrap() = req.env.get("HOME").cloned();
            for (rel, body) in &self.files {
                let p = req.cwd.join(rel);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(p, body).unwrap();
            }
            Ok(WorkerOutput {
                text: self.text.clone(),
                exit_code: 0,
                duration_ms: 1,
                tools_reported: None,
            })
        }
    }

    fn have_git() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// An L1 setup: a pristine base, the worker's tree (a copy), a recipe scoped to docs/.
    fn l1(t: &Path, gate_commands: Vec<Vec<String>>) -> (Task, WorkDirs, Recipe, PathBuf) {
        let task = task(t, "TASK_ALLOWED_TOOLS=Read,Edit\n");
        let (base, tree, out) = (t.join("base"), t.join("tree"), t.join("out"));
        for d in [&base, &tree] {
            std::fs::create_dir_all(d.join("docs")).unwrap();
            std::fs::write(d.join("docs/a.md"), "one\n").unwrap();
            std::fs::write(d.join("keep.txt"), "same\n").unwrap();
        }
        let recipe = Recipe {
            repo: "example/app".into(),
            scope: vec!["docs/**".into()],
            gate_commands,
            gate_commands_execute_tree: true, // these tests use sh/touch to model hostile gate commands
            ..Default::default()
        };
        (task, WorkDirs { base, tree }, recipe, out)
    }

    fn l1_opts<'a>(
        out: &'a Path,
        sb: &'a dyn Sandbox,
        w: &'a dyn Worker,
        work: WorkDirs,
        recipe: Recipe,
    ) -> ModelOptions<'a> {
        let mut o = opts(out, sb, w, Some("tok-0123456789"));
        o.work = Some(work);
        o.recipe = Some(recipe);
        o
    }

    #[test]
    fn b2_an_l1_run_without_work_dirs_is_refused_and_the_worker_never_runs() {
        let t = tempfile::tempdir().unwrap();
        let (task, _w, recipe, out) = l1(t.path(), vec![]);
        let w = Canned::new("STATUS: OK");
        let mut o = opts(&out, &TestBoundary(true), &w, None);
        o.recipe = Some(recipe); // a recipe, but NO work dirs
        let rec = run_model(&task, &o).unwrap();
        assert_eq!(rec.exit_code, EXIT_GATE);
        assert!(rec
            .gates
            .iter()
            .any(|g| g.name == "work_dirs_present" && !g.ok));
        assert!(
            w.seen.lock().unwrap().is_empty(),
            "the worker must not run, and must never be handed the output directory"
        );
    }

    #[test]
    fn h1_a_broken_status_txt_fails_the_run_instead_of_handing_the_verdict_to_the_model() {
        for bad in [
            "STATUS: ATTENTION (3)\n",
            "everything fine\n",
            "",
            "status: ok\n",
        ] {
            let t = tempfile::tempdir().unwrap();
            let task = task(t.path(), "TASK_ALLOWED_TOOLS=Read\n");
            let out = t.path().join("out");
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(out.join("status.txt"), bad).unwrap();
            let w = Canned::new("looks fine\nSTATUS: OK\n");
            let rec = run_model(&task, &opts(&out, &TestBoundary(true), &w, None)).unwrap();
            assert_eq!(rec.exit_code, EXIT_GATE, "{bad:?}");
            assert_eq!(rec.verdict, Verdict::Failed, "{bad:?}");
            assert!(
                rec.gates.iter().any(|g| g.name == "code_verdict" && !g.ok),
                "{bad:?}"
            );
            assert!(
                w.seen.lock().unwrap().is_empty(),
                "{bad:?}: no worker may run against an unusable code verdict"
            );
        }
    }

    #[test]
    fn h3_the_workers_token_never_reaches_an_artifact_and_the_leak_fails_the_run() {
        let t = tempfile::tempdir().unwrap();
        let task = task(t.path(), "TASK_ALLOWED_TOOLS=Read\n");
        let out = t.path().join("out");
        // A prompt-injected worker prints its own token.
        let w = Canned::new("here is my token: tok-0123456789\nSTATUS: OK\n");
        let rec = run_model(
            &task,
            &opts(&out, &TestBoundary(true), &w, Some("tok-0123456789")),
        )
        .unwrap();
        assert_eq!(rec.exit_code, EXIT_GATE);
        assert!(rec.gates.iter().any(|g| g.name == "secret_scan" && !g.ok));
        for f in ["digest.md", "run.json"] {
            let text = std::fs::read_to_string(out.join(f)).unwrap();
            assert!(
                !text.contains("tok-0123456789"),
                "{f} must not contain the token"
            );
        }
        assert!(std::fs::read_to_string(out.join("digest.md"))
            .unwrap()
            .contains("[REDACTED]"));
    }

    #[test]
    fn h3_a_secret_shaped_string_in_the_digest_fails_the_run() {
        let t = tempfile::tempdir().unwrap();
        let task = task(t.path(), "TASK_ALLOWED_TOOLS=Read\n");
        let out = t.path().join("out");
        let key = format!("{}{}", "AKIA", "ABCDEFGHIJKLMNOP"); // built at run time: no secret-shaped literal in the source
        let w = Canned::new(&format!("found {key} in the log\nSTATUS: OK\n"));
        let rec = run_model(&task, &opts(&out, &TestBoundary(true), &w, None)).unwrap();
        assert_eq!(rec.exit_code, EXIT_GATE);
        let g = rec.gates.iter().find(|g| g.name == "secret_scan").unwrap();
        assert!(
            !g.ok && !g.detail.contains(&key),
            "the detail names the kind, never the value"
        );
    }

    #[test]
    fn h4_the_worker_gets_a_fresh_empty_home_that_is_removed_afterwards() {
        let t = tempfile::tempdir().unwrap();
        let task = task(t.path(), "TASK_ALLOWED_TOOLS=Read\n");
        let out = t.path().join("out");
        let w = Writer::new(&[], "STATUS: OK\n");
        run_model(&task, &opts(&out, &TestBoundary(true), &w, None)).unwrap();
        let home = w.seen_home.lock().unwrap().clone().unwrap();
        assert_ne!(
            home, "/home/runner",
            "the launcher's HOME must not be passed through"
        );
        assert!(home.contains("errand-home-"));
        assert!(
            !Path::new(&home).exists(),
            "the scratch home is removed after the run"
        );
    }

    #[test]
    fn a_worker_that_could_report_its_tools_but_does_not_fails_the_gate() {
        let t = tempfile::tempdir().unwrap();
        let task = task(t.path(), "TASK_ALLOWED_TOOLS=Read\n");
        let out = t.path().join("out");
        let mut w = Writer::new(&[], "STATUS: OK\n");
        w.kind = "claude-cli"; // a real worker: silence is a failure
        let rec = run_model(&task, &opts(&out, &TestBoundary(true), &w, None)).unwrap();
        assert!(rec.gates.iter().any(|g| g.name == "tools_match" && !g.ok));
        assert_eq!(rec.exit_code, EXIT_GATE);
    }

    #[test]
    fn b1_recipe_commands_do_not_run_when_the_patch_was_rejected() {
        if !have_git() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let marker = t.path().join("COMMAND_RAN");
        let cmd = vec!["touch".to_string(), marker.display().to_string()];
        let (task, work, recipe, out) = l1(t.path(), vec![cmd]);
        // The worker edits a file OUTSIDE the recipe's scope: the patch is rejected.
        let w = Writer::new(&[("keep.txt", "tampered\n")], "edited\nSTATUS: OK\n");
        let rec = run_model(&task, &l1_opts(&out, &TestBoundary(true), &w, work, recipe)).unwrap();
        assert_eq!(rec.exit_code, EXIT_GATE);
        assert!(rec.gates.iter().any(|g| g.name == "diff_scope" && !g.ok));
        assert!(
            !marker.exists(),
            "worker-written code must never be executed for a rejected patch"
        );
    }

    #[test]
    fn b1_code_run_by_a_gate_command_cannot_change_the_recorded_patch() {
        if !have_git() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let out = t.path().join("out");
        // A gate command that behaves like worker-written test code: it overwrites patch.diff, digest.md and status.txt.
        let evil = format!(
            "echo EVIL > {o}/patch.diff; echo EVIL > {o}/digest.md; printf 'STATUS: OK\\n' > {o}/status.txt",
            o = out.display()
        );
        let (task, work, recipe, out) = l1(t.path(), vec![vec!["sh".into(), "-c".into(), evil]]);
        let w = Writer::new(&[("docs/a.md", "one\ntwo\n")], "added a line\nSTATUS: OK\n");
        let rec = run_model(&task, &l1_opts(&out, &TestBoundary(true), &w, work, recipe)).unwrap();
        assert_eq!(rec.exit_code, 0, "{:#?}", rec.gates);
        let patch = std::fs::read_to_string(out.join("patch.diff")).unwrap();
        assert!(
            patch.contains("+two") && !patch.contains("EVIL"),
            "patch.diff is rewritten from memory after the commands"
        );
        assert!(!std::fs::read_to_string(out.join("digest.md"))
            .unwrap()
            .contains("EVIL"));
        let hb = rec.handback.unwrap();
        let want: String = Sha256::digest(patch.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            hb.patch_sha256.as_deref(),
            Some(want.as_str()),
            "the hand-back binds the patch by hash"
        );
    }

    #[test]
    fn a_code_built_recipe_with_a_tree_executing_gate_is_refused_unless_it_opts_in() {
        let t = tempfile::tempdir().unwrap();
        let (task, work, mut recipe, out) = l1(t.path(), vec![vec!["cargo".into(), "test".into()]]);
        recipe.gate_commands_execute_tree = false;
        let w = Canned::new("STATUS: OK");
        let e =
            run_model(&task, &l1_opts(&out, &TestBoundary(true), &w, work, recipe)).unwrap_err();
        assert!(e.to_string().contains("inspect-only"), "{e}");
        assert!(w.seen.lock().unwrap().is_empty(), "the worker never ran");
    }

    #[test]
    fn n5_the_hand_back_does_not_claim_gate_commands_passed_when_none_ran() {
        if !have_git() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let (task, work, recipe, out) = l1(t.path(), vec![]);
        let w = Writer::new(&[("docs/a.md", "one\ntwo\n")], "added a line\nSTATUS: OK\n");
        let rec = run_model(&task, &l1_opts(&out, &TestBoundary(true), &w, work, recipe)).unwrap();
        let hb = rec.handback.unwrap();
        assert!(
            !hb.verified.iter().any(|v| v.contains("gate command")),
            "{:?}",
            hb.verified
        );
        assert!(hb
            .unverified
            .iter()
            .any(|u| u.contains("no recipe gate command ran")));
    }

    #[test]
    fn n5_the_hand_back_names_the_gate_commands_that_did_pass() {
        if !have_git() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let (task, work, recipe, out) = l1(t.path(), vec![vec!["true".into()]]);
        let w = Writer::new(&[("docs/a.md", "one\ntwo\n")], "added a line\nSTATUS: OK\n");
        let rec = run_model(&task, &l1_opts(&out, &TestBoundary(true), &w, work, recipe)).unwrap();
        let hb = rec.handback.unwrap();
        assert!(
            hb.verified
                .iter()
                .any(|v| v.contains("1 gate command(s) passed")),
            "{:?}",
            hb.verified
        );
    }

    #[test]
    fn run_ids_do_not_collide_even_in_the_same_second_and_process() {
        let ids: std::collections::BTreeSet<String> =
            (0..200).map(|_| new_run_id("same-task")).collect();
        assert_eq!(ids.len(), 200);
    }
}
