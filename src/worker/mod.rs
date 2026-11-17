//! The worker: the untrusted model run. A [`Worker`] gets a prompt, a hard tool allowlist and a scrubbed environment and
//! returns text. It never gets a credential other than its own token.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use crate::Result;

pub mod claude;
pub mod fake;

/// Everything a worker is given.
#[derive(Debug, Clone)]
pub struct WorkerRequest {
    /// The prompt text. Untrusted ticket or alert text appears here only inside delimiters, never in `tools` or argv.
    pub prompt: String,
    /// The hard tool allowlist (`--tools` for the Claude CLI). Must be a subset of the risk level's tools.
    pub tools: Vec<String>,
    /// Maximum conversation turns.
    pub max_turns: u32,
    /// Working directory.
    pub cwd: PathBuf,
    /// Extra directories the worker may read.
    pub add_dirs: Vec<PathBuf>,
    /// The complete environment of the worker process. The process is started with an empty environment plus exactly this.
    pub env: BTreeMap<String, String>,
    /// Wall-clock limit.
    pub timeout: Duration,
}

/// What a worker returned.
#[derive(Debug, Clone)]
pub struct WorkerOutput {
    /// The model's final text.
    pub text: String,
    /// The process exit code.
    pub exit_code: i32,
    /// Wall time in milliseconds.
    pub duration_ms: u64,
    /// The tools the worker reported having at start, when it can report them (checked by the `tools_match` gate).
    pub tools_reported: Option<Vec<String>>,
}

/// A way of running the untrusted model.
pub trait Worker {
    /// `claude-cli`, `fake`.
    fn kind(&self) -> &'static str;
    /// Run to completion.
    fn run(&self, req: &WorkerRequest) -> Result<WorkerOutput>;
}
