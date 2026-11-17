//! Gates: checks the *engine* owns. A gate looks at facts the Kit collected, never at the worker's claims. Any failed hard
//! gate makes the verdict `FAILED`. See `spec/ERRAND.md` section 5.

use std::collections::BTreeMap;
use std::path::Path;

use crate::contract::{BoundaryReport, GateResult, Risk, Verdict, WorkerReport};

pub mod builtin;
pub mod patch;
pub mod recipe;

/// The facts a gate may look at.
#[derive(Debug)]
pub struct GateContext<'a> {
    /// The run's output directory.
    pub out_dir: &'a Path,
    /// The risk level.
    pub risk: Risk,
    /// The boundary report (phase 2).
    pub boundary: Option<&'a BoundaryReport>,
    /// What the worker reported about itself.
    pub worker: Option<&'a WorkerReport>,
    /// The environment the worker was started with.
    pub worker_env: &'a BTreeMap<String, String>,
    /// The worker's final text.
    pub digest: Option<&'a str>,
    /// The verdict the task computed in code (`out/status.txt`), if any.
    pub code_verdict: Option<Verdict>,
    /// The worker's patch text (L1+), if any.
    pub patch: Option<&'a str>,
}

/// A check the engine owns.
pub trait Gate {
    /// Stable name.
    fn name(&self) -> &str;
    /// Kind, one of the spec's gate kinds.
    fn kind(&self) -> &str;
    /// Whether a failure makes the verdict `FAILED`.
    fn hard(&self) -> bool;
    /// Run the check.
    fn check(&self, ctx: &GateContext<'_>) -> GateResult;
}
