//! The Claude CLI worker: `claude -p` with a hard tool allowlist and an environment that is empty except for what the
//! request names.
//!
//! Observed CLI behaviour (Claude Code 2.1.311, verified 2026-10-26):
//!
//! * `--tools=<list>` restricts which built-in tools exist at all; the `system`/`init` event's `tools` array then lists
//!   exactly those (sorted alphabetically by the CLI, not in request order). `--tools=` (empty) yields `[]`.
//! * `--allowedTools` only pre-approves tools; it cannot add tools that `--tools` removed. Both are passed anyway.
//! * `--tools`, `--allowedTools` and `--add-dir` are variadic, so they are passed in `--flag=value` form and the prompt
//!   comes last after `--`; a prompt beginning with `-` is then still the prompt.
//! * `--output-format stream-json` needs `--verbose` under `-p`.
//! * The stream has `system` events (hooks, then `init`), `assistant`/`user` events and a final `result` event whose
//!   `result` field is the text and whose `is_error` says whether the run failed.
//!
//! Stream parsing policy: lines that are not JSON objects are ignored (counted and logged); a stream with no `result`
//! event is an error.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::worker::{Worker, WorkerOutput, WorkerRequest};
use crate::{ErrandError, Result};

/// How long to wait for the output readers after the process has exited or been killed. A grandchild that keeps the
/// pipe open must not hang the engine.
const DRAIN_GRACE: Duration = Duration::from_secs(2);
/// How often the exit status is polled.
const POLL: Duration = Duration::from_millis(10);
/// How much of stderr is kept for error messages.
const STDERR_TAIL: usize = 2000;

/// Runs `claude -p` with a hard tool allowlist and an empty environment plus the request's.
///
/// The program is looked up like any command; when `PATH` is not part of `request.env`, give an absolute path via
/// [`ClaudeCli::with_program`].
#[derive(Debug, Clone)]
pub struct ClaudeCli {
    program: OsString,
}

impl Default for ClaudeCli {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaudeCli {
    /// A worker that runs the `claude` binary.
    pub fn new() -> Self {
        Self {
            program: OsString::from("claude"),
        }
    }

    /// Use a different binary (an absolute path, or a stub script in tests).
    #[must_use]
    pub fn with_program(mut self, program: impl Into<OsString>) -> Self {
        self.program = program.into();
        self
    }
}

/// The argv (without the program name) for a request. Pure: it does not run anything.
///
/// The prompt is the last element, after `--`, as ONE element. Tool lists are `--tools=` and `--allowedTools=` in joined
/// form so no list element can be read as a flag. Callers must have validated tool names (see [`ClaudeCli`]'s `run`).
pub fn build_args(req: &WorkerRequest) -> Vec<OsString> {
    let list = req.tools.join(",");
    let mut args: Vec<OsString> = vec![
        "-p".into(),
        "--output-format".into(),
        "stream-json".into(),
        "--verbose".into(),
        format!("--tools={list}").into(),
        format!("--allowedTools={list}").into(),
        "--strict-mcp-config".into(),
        "--max-turns".into(),
        req.max_turns.to_string().into(),
        "--no-session-persistence".into(),
    ];
    for dir in &req.add_dirs {
        let mut a = OsString::from("--add-dir=");
        a.push(dir.as_os_str());
        args.push(a);
    }
    args.push("--".into());
    args.push(OsString::from(&req.prompt));
    args
}

/// A tool name is a plain identifier; anything else (commas, spaces, parentheses, a leading dash) could smuggle in an extra
/// tool or a flag.
fn valid_tool_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// What the stdout reader extracted.
#[derive(Debug, Default)]
struct Summary {
    tools: Option<Vec<String>>,
    result: Option<Value>,
    malformed: usize,
}

fn read_stream(r: impl Read) -> Summary {
    let mut s = Summary::default();
    let mut reader = BufReader::new(r);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            s.malformed += 1;
            continue;
        };
        if !v.is_object() {
            s.malformed += 1;
            continue;
        }
        match v.get("type").and_then(Value::as_str) {
            Some("system")
                if v.get("subtype").and_then(Value::as_str) == Some("init")
                    && s.tools.is_none() =>
            {
                s.tools = v.get("tools").and_then(Value::as_array).map(|a| {
                    a.iter()
                        .filter_map(|t| t.as_str().map(str::to_owned))
                        .collect()
                });
            }
            Some("result") => s.result = Some(v),
            _ => {}
        }
    }
    s
}

fn read_tail(mut r: impl Read) -> String {
    let mut tail: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Ok(n) = r.read(&mut chunk) {
        if n == 0 {
            break;
        }
        tail.extend_from_slice(&chunk[..n]);
        if tail.len() > STDERR_TAIL {
            let cut = tail.len() - STDERR_TAIL;
            tail.drain(..cut);
        }
    }
    String::from_utf8_lossy(&tail).trim().to_owned()
}

fn werr(msg: impl Into<String>) -> ErrandError {
    ErrandError::Worker(msg.into())
}

impl Worker for ClaudeCli {
    fn kind(&self) -> &'static str {
        "claude-cli"
    }

    fn run(&self, req: &WorkerRequest) -> Result<WorkerOutput> {
        if let Some(bad) = req.tools.iter().find(|t| !valid_tool_name(t)) {
            return Err(werr(format!(
                "invalid tool name {bad:?}: tool names must be [A-Za-z0-9_]+"
            )));
        }
        let args = build_args(req);
        tracing::info!(program = ?self.program, tools = ?req.tools, max_turns = req.max_turns, "starting claude worker");

        let start = Instant::now();
        let mut child = Command::new(&self.program)
            .args(&args)
            .current_dir(&req.cwd)
            .env_clear()
            .envs(&req.env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                werr(format!(
                    "could not start {}: {e}",
                    self.program.to_string_lossy()
                ))
            })?;

        let (out_tx, out_rx) = mpsc::channel();
        let (err_tx, err_rx) = mpsc::channel();
        if let Some(out) = child.stdout.take() {
            thread::spawn(move || {
                let _ = out_tx.send(read_stream(out));
            });
        }
        if let Some(err) = child.stderr.take() {
            thread::spawn(move || {
                let _ = err_tx.send(read_tail(err));
            });
        }

        let deadline = start + req.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break st,
                Ok(None) => {}
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(werr(format!("waiting for the worker failed: {e}")));
                }
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                tracing::warn!(
                    timeout_s = req.timeout.as_secs(),
                    "claude worker killed on timeout"
                );
                return Err(werr(format!(
                    "worker timed out after {}s and was killed",
                    req.timeout.as_secs()
                )));
            }
            thread::sleep(POLL);
        };

        let summary = out_rx.recv_timeout(DRAIN_GRACE).unwrap_or_default();
        let stderr = err_rx.recv_timeout(DRAIN_GRACE).unwrap_or_default();
        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        if summary.malformed > 0 {
            tracing::warn!(
                lines = summary.malformed,
                "ignored non-JSON lines in the worker stream"
            );
        }

        let exit_code = status.code().unwrap_or(-1);
        if !status.success() {
            return Err(werr(format!(
                "worker exited with code {exit_code}: {}",
                stderr
            )));
        }
        let Some(result) = summary.result else {
            return Err(werr(format!(
                "worker produced no result event; stderr: {stderr}"
            )));
        };
        let text = result
            .get("result")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if result.get("is_error").and_then(Value::as_bool) == Some(true) {
            return Err(werr(format!(
                "worker reported an error: {}",
                text.unwrap_or_default()
            )));
        }
        let Some(text) = text else {
            return Err(werr("result event has no text"));
        };
        Ok(WorkerOutput {
            text,
            exit_code,
            duration_ms,
            tools_reported: summary.tools,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn req(cwd: &Path) -> WorkerRequest {
        WorkerRequest {
            prompt: "do the thing".into(),
            tools: vec!["Read".into(), "Grep".into()],
            max_turns: 3,
            cwd: cwd.to_path_buf(),
            add_dirs: vec![],
            env: BTreeMap::from([("PATH".into(), "/usr/bin:/bin".into())]),
            timeout: Duration::from_secs(10),
        }
    }

    fn stub(dir: &Path, body: &str) -> ClaudeCli {
        let p = dir.join("stub.sh");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        ClaudeCli::new().with_program(p)
    }

    const GOOD: &str = r#"printf '%s\n' '{"type":"system","subtype":"init","tools":["Grep","Read"]}'
printf '%s\n' '{"type":"assistant","message":{}}'
printf '%s\n' '{"type":"result","is_error":false,"result":"all good\nSTATUS: OK"}'"#;

    fn strs(a: &[OsString]) -> Vec<String> {
        a.iter().map(|s| s.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn args_carry_exact_tool_list_and_hardening_flags() {
        let mut r = req(Path::new("/tmp"));
        r.add_dirs = vec![PathBuf::from("/a"), PathBuf::from("/b")];
        let a = strs(&build_args(&r));
        assert!(a.contains(&"--tools=Read,Grep".to_string()));
        assert!(a.contains(&"--allowedTools=Read,Grep".to_string()));
        for f in [
            "--strict-mcp-config",
            "--no-session-persistence",
            "--verbose",
            "-p",
        ] {
            assert!(a.contains(&f.to_string()), "missing {f}");
        }
        let i = a.iter().position(|x| x == "--max-turns").unwrap();
        assert_eq!(a[i + 1], "3");
        assert!(a.contains(&"--add-dir=/a".to_string()) && a.contains(&"--add-dir=/b".to_string()));
        let i = a.iter().position(|x| x == "--output-format").unwrap();
        assert_eq!(a[i + 1], "stream-json");
    }

    #[test]
    fn args_never_mention_dangerous_tools_unless_requested() {
        let a = strs(&build_args(&req(Path::new("/tmp")))).join(" ");
        for t in ["Bash", "WebFetch", "WebSearch"] {
            assert!(!a.contains(t), "{t} leaked into argv");
        }
        let mut r = req(Path::new("/tmp"));
        r.tools = vec!["Bash".into()];
        assert!(strs(&build_args(&r)).contains(&"--tools=Bash".to_string()));
    }

    #[test]
    fn empty_tool_list_is_an_explicit_empty_allowlist() {
        let mut r = req(Path::new("/tmp"));
        r.tools = vec![];
        let a = strs(&build_args(&r));
        assert!(a.contains(&"--tools=".to_string()));
    }

    #[test]
    fn prompt_is_one_final_element_after_double_dash() {
        let mut r = req(Path::new("/tmp"));
        r.prompt = "--dangerously-skip-permissions; rm -rf /\nsecond line".into();
        let a = build_args(&r);
        assert_eq!(a[a.len() - 2], OsString::from("--"));
        assert_eq!(a[a.len() - 1], OsString::from(&r.prompt));
        assert_eq!(
            a.iter()
                .filter(|x| x.to_string_lossy().contains("rm -rf"))
                .count(),
            1
        );
    }

    #[test]
    fn normal_run_parses_text_and_tools() {
        let d = tempfile::tempdir().unwrap();
        let out = stub(d.path(), GOOD).run(&req(d.path())).unwrap();
        assert_eq!(out.text, "all good\nSTATUS: OK");
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.tools_reported, Some(vec!["Grep".into(), "Read".into()]));
    }

    #[test]
    fn environment_is_cleared_to_exactly_the_request() {
        let d = tempfile::tempdir().unwrap();
        // The parent's variable must not reach the child; the stub echoes its whole environment into the result.
        std::env::set_var("ERRAND_TEST_SECRET", "hunter2");
        let body = r#"e=$(env | sort | tr '\n' '|')
printf '{"type":"result","is_error":false,"result":"%s"}\n' "$e""#;
        let mut r = req(d.path());
        r.env.insert("ONLY_THIS".into(), "yes".into());
        let out = stub(d.path(), body).run(&r).unwrap();
        assert!(!out.text.contains("ERRAND_TEST_SECRET"), "{}", out.text);
        assert!(!out.text.contains("hunter2"));
        assert!(out.text.contains("ONLY_THIS=yes"));
        assert!(out.text.contains("PATH=/usr/bin:/bin"));
        assert!(!out.text.contains("HOME="), "{}", out.text);
    }

    #[test]
    fn nonzero_exit_is_an_error_with_stderr() {
        let d = tempfile::tempdir().unwrap();
        let e = stub(d.path(), &format!("{GOOD}\necho boom >&2\nexit 7"))
            .run(&req(d.path()))
            .unwrap_err();
        let m = e.to_string();
        assert!(m.contains("code 7") && m.contains("boom"), "{m}");
    }

    #[test]
    fn timeout_kills_the_process() {
        let d = tempfile::tempdir().unwrap();
        let mut r = req(d.path());
        r.timeout = Duration::from_millis(300);
        let t = Instant::now();
        let e = stub(d.path(), "sleep 30").run(&r).unwrap_err();
        assert!(e.to_string().contains("timed out"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn malformed_lines_are_ignored() {
        let d = tempfile::tempdir().unwrap();
        let body = format!("echo 'not json'\necho '[1,2]'\n{GOOD}\necho '{{broken'");
        let out = stub(d.path(), &body).run(&req(d.path())).unwrap();
        assert_eq!(out.text, "all good\nSTATUS: OK");
    }

    #[test]
    fn missing_result_event_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let body = r#"echo '{"type":"system","subtype":"init","tools":["Read"]}'"#;
        let e = stub(d.path(), body).run(&req(d.path())).unwrap_err();
        assert!(e.to_string().contains("no result"), "{e}");
    }

    #[test]
    fn result_with_is_error_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let body = r#"echo '{"type":"result","is_error":true,"result":"Not logged in"}'"#;
        let e = stub(d.path(), body).run(&req(d.path())).unwrap_err();
        assert!(e.to_string().contains("Not logged in"), "{e}");
    }

    #[test]
    fn missing_init_gives_no_tools_reported() {
        let d = tempfile::tempdir().unwrap();
        let body = r#"echo '{"type":"result","is_error":false,"result":"x"}'"#;
        let out = stub(d.path(), body).run(&req(d.path())).unwrap();
        assert_eq!(out.tools_reported, None);
    }

    #[test]
    fn tool_names_that_could_smuggle_are_refused() {
        let d = tempfile::tempdir().unwrap();
        for bad in ["Read,Bash", "--x", "Bash(git *)", "", "Read Bash"] {
            let mut r = req(d.path());
            r.tools = vec![bad.into()];
            let e = stub(d.path(), GOOD).run(&r).unwrap_err();
            assert!(e.to_string().contains("invalid tool name"), "{bad}: {e}");
        }
    }

    #[test]
    fn missing_binary_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let e = ClaudeCli::new()
            .with_program(d.path().join("nope"))
            .run(&req(d.path()))
            .unwrap_err();
        assert!(e.to_string().contains("could not start"), "{e}");
    }

    /// Runs the real CLI once with this machine's login. Run by hand:
    /// `cargo test --all-features -- --ignored live_smoke`.
    #[test]
    #[ignore = "runs the real claude CLI and spends a few tokens"]
    fn live_smoke() {
        let d = tempfile::tempdir().unwrap();
        let mut env = BTreeMap::new();
        // The minimum the macOS keychain login needs; a container run would pass CLAUDE_CODE_OAUTH_TOKEN instead.
        for k in [
            "HOME",
            "USER",
            "LOGNAME",
            "TMPDIR",
            "PATH",
            "CLAUDE_CODE_OAUTH_TOKEN",
        ] {
            if let Ok(v) = std::env::var(k) {
                env.insert(k.to_string(), v);
            }
        }
        let r = WorkerRequest {
            prompt: "Reply with the single word pong.".into(),
            tools: vec!["Read".into()],
            max_turns: 1,
            cwd: d.path().to_path_buf(),
            add_dirs: vec![],
            env,
            timeout: Duration::from_secs(120),
        };
        let out = ClaudeCli::new().run(&r).unwrap();
        assert!(out.text.to_lowercase().contains("pong"), "{}", out.text);
        assert_eq!(out.tools_reported, Some(vec!["Read".to_string()]));
    }
}
