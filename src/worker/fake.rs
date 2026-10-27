//! A scripted worker for tests. (To be implemented.)

use crate::worker::{Worker, WorkerOutput, WorkerRequest};
use crate::{ErrandError, Result};

/// Returns canned output.
#[derive(Debug, Default, Clone)]
pub struct FakeWorker;

impl Worker for FakeWorker {
    fn kind(&self) -> &'static str {
        "fake"
    }
    fn run(&self, _req: &WorkerRequest) -> Result<WorkerOutput> {
        Err(ErrandError::Worker("not implemented".into()))
    }
}
