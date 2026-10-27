//! The Claude CLI worker. (To be implemented.)

use crate::worker::{Worker, WorkerOutput, WorkerRequest};
use crate::{ErrandError, Result};

/// Runs `claude -p` with a hard tool allowlist and an empty environment plus the request's.
#[derive(Debug, Default, Clone)]
pub struct ClaudeCli;

impl Worker for ClaudeCli {
    fn kind(&self) -> &'static str {
        "claude-cli"
    }
    fn run(&self, _req: &WorkerRequest) -> Result<WorkerOutput> {
        Err(ErrandError::Worker("not implemented".into()))
    }
}
