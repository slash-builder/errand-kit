//! The container backend: the container is the boundary; the Kit verifies and refuses. (To be implemented.)

use crate::contract::BoundaryReport;
use crate::sandbox::Sandbox;

/// Verifies it is running inside a locked-down container.
#[derive(Debug, Default, Clone)]
pub struct ContainerBoundary;

impl Sandbox for ContainerBoundary {
    fn kind(&self) -> &'static str {
        "container"
    }
    fn verify(&self) -> BoundaryReport {
        BoundaryReport { kind: "container".into(), ok: false, egress: "open".into(), checks: vec![] }
    }
}
