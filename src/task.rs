//! Task directories. A task is a directory describing a repeatable errand: `prompt.md`, `task.env`, and optionally an
//! executable `prepare.sh` and a `recipe.json`. The layout is the one the automation container already uses.

use std::path::{Path, PathBuf};

use crate::contract::Risk;
use crate::{ErrandError, Result};

/// A loaded task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    /// The task name (the directory name).
    pub name: String,
    /// The task directory.
    pub dir: PathBuf,
    /// The prompt text.
    pub prompt: String,
    /// The tool allowlist requested by the task.
    pub tools: Vec<String>,
    /// Maximum conversation turns.
    pub max_turns: u32,
    /// The risk level, derived from the tools unless `TASK_RISK` says a higher one.
    pub risk: Risk,
    /// Path of an executable `prepare.sh`, if present.
    pub prepare: Option<PathBuf>,
}

/// Parse `KEY="value"` / `KEY=value` lines (the `task.env` format); comments and blanks are ignored. Never executes anything.
///
/// ```
/// let m = errand_kit::task::parse_env("# c\nTASK_ALLOWED_TOOLS=\"Read,Grep\"\nTASK_MAX_TURNS=6\n");
/// assert_eq!(m.get("TASK_MAX_TURNS").map(String::as_str), Some("6"));
/// assert_eq!(m.get("TASK_ALLOWED_TOOLS").map(String::as_str), Some("Read,Grep"));
/// ```
pub fn parse_env(text: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim();
            let v = v.strip_prefix('"').and_then(|s| s.strip_suffix('"')).unwrap_or(v);
            out.insert(k.trim().to_string(), v.to_string());
        }
    }
    out
}

impl Task {
    /// Load `<root>/<name>`. Refuses a name that is not a plain directory name, and any tool that no risk level allows.
    pub fn load(root: &Path, name: &str) -> Result<Task> {
        if name.is_empty() || name.contains('/') || name.contains('\\') || name == "." || name == ".." {
            return Err(ErrandError::Task(format!("invalid task name: {name:?}")));
        }
        let dir = root.join(name);
        let read = |f: &str| std::fs::read_to_string(dir.join(f)).map_err(|e| ErrandError::io(dir.join(f), e));
        let prompt = read("prompt.md")?;
        let env = parse_env(&read("task.env")?);
        let tools: Vec<String> = env
            .get("TASK_ALLOWED_TOOLS")
            .map(|s| s.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect())
            .unwrap_or_default();
        let max_turns = env.get("TASK_MAX_TURNS").and_then(|s| s.parse().ok()).unwrap_or(6);
        let risk = derive_risk(&tools, env.get("TASK_RISK").map(String::as_str))?;
        let prepare = {
            let p = dir.join("prepare.sh");
            p.is_file().then_some(p)
        };
        Ok(Task { name: name.to_string(), dir, prompt, tools, max_turns, risk, prepare })
    }
}

fn derive_risk(tools: &[String], declared: Option<&str>) -> Result<Risk> {
    let fits = |r: Risk| tools.iter().all(|t| r.tools_allowed().contains(&t.as_str()));
    let derived = if fits(Risk::L0) {
        Risk::L0
    } else if fits(Risk::L1) {
        Risk::L1
    } else {
        let bad: Vec<&str> = tools.iter().map(String::as_str).filter(|t| !Risk::L1.tools_allowed().contains(t)).collect();
        return Err(ErrandError::Task(format!("tools not allowed at any risk level: {}", bad.join(", "))));
    };
    match declared {
        None => Ok(derived),
        Some("L0") if derived == Risk::L0 => Ok(Risk::L0),
        Some("L1") => Ok(Risk::L1),
        Some("L2") => Ok(Risk::L2),
        Some(other) => Err(ErrandError::Task(format!("TASK_RISK {other:?} is not valid for these tools"))),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn make(dir: &Path, env: &str, with_prepare: bool) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("prompt.md"), "do the thing").unwrap();
        std::fs::write(dir.join("task.env"), env).unwrap();
        if with_prepare {
            std::fs::write(dir.join("prepare.sh"), "#!/bin/sh\n").unwrap();
        }
    }

    #[test]
    fn loads_a_read_only_task_as_l0() {
        let t = tempfile::tempdir().unwrap();
        make(&t.path().join("a"), "TASK_ALLOWED_TOOLS=\"Read,Grep,Glob\"\nTASK_MAX_TURNS=8\n", true);
        let task = Task::load(t.path(), "a").unwrap();
        assert_eq!(task.risk, Risk::L0);
        assert_eq!(task.max_turns, 8);
        assert!(task.prepare.is_some());
        assert_eq!(task.tools, vec!["Read", "Grep", "Glob"]);
    }

    #[test]
    fn edit_tools_make_it_l1() {
        let t = tempfile::tempdir().unwrap();
        make(&t.path().join("a"), "TASK_ALLOWED_TOOLS=Read,Edit\n", false);
        assert_eq!(Task::load(t.path(), "a").unwrap().risk, Risk::L1);
    }

    #[test]
    fn bash_is_refused_at_every_level() {
        let t = tempfile::tempdir().unwrap();
        make(&t.path().join("a"), "TASK_ALLOWED_TOOLS=Read,Bash\n", false);
        let e = Task::load(t.path(), "a").unwrap_err().to_string();
        assert!(e.contains("Bash"), "{e}");
        make(&t.path().join("b"), "TASK_ALLOWED_TOOLS=WebFetch\n", false);
        assert!(Task::load(t.path(), "b").is_err());
    }

    #[test]
    fn a_lower_declared_risk_cannot_hide_write_tools() {
        let t = tempfile::tempdir().unwrap();
        make(&t.path().join("a"), "TASK_ALLOWED_TOOLS=Read,Edit\nTASK_RISK=L0\n", false);
        assert!(Task::load(t.path(), "a").is_err());
    }

    #[test]
    fn names_cannot_escape_the_root() {
        let t = tempfile::tempdir().unwrap();
        for bad in ["", ".", "..", "../x", "a/b", "a\\b"] {
            assert!(Task::load(t.path(), bad).is_err(), "{bad:?}");
        }
    }
}
