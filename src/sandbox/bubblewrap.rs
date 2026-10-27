//! The bubblewrap backend for a Linux host. (To be implemented.)

use crate::contract::BoundaryReport;
use crate::sandbox::Sandbox;

/// Wraps the worker in `bwrap`.
#[derive(Debug, Default, Clone)]
pub struct Bubblewrap;

impl Sandbox for Bubblewrap {
    fn kind(&self) -> &'static str {
        "bubblewrap"
    }
    fn verify(&self) -> BoundaryReport {
        BoundaryReport { kind: "bubblewrap".into(), ok: false, egress: "open".into(), checks: vec![] }
    }
}
