//! The boundary. A [`Sandbox`] verifies, before any worker starts, that the worker will run where no credential is present
//! and capabilities are gone, and refuses otherwise. There is no automatic mode: a missing sandbox is a refusal, never a
//! fall-back to "none". See `spec/ERRAND.md` section 4.

use crate::contract::BoundaryReport;

pub mod bubblewrap;
pub mod container;
#[cfg(feature = "test-sandbox")]
pub mod none;

/// Variable-name prefixes that mark a credential. A worker's environment, and every process visible to the worker, must
/// contain none of these (`CLAUDE_CODE_OAUTH_TOKEN` is the worker's own token and is deliberately not listed).
pub const CREDENTIAL_PREFIXES: &[&str] =
    &["AWS_", "GITHUB_", "GH_", "CLOUDFLARE_", "TF_", "GRAFANA_", "SOL_", "ANTHROPIC_API", "DOCKER_"];

/// True if a variable *name* looks like a credential.
///
/// ```
/// use errand_kit::sandbox::credential_shaped;
/// assert!(credential_shaped("AWS_SECRET_ACCESS_KEY"));
/// assert!(credential_shaped("GRAFANA_PASSWORD"));
/// assert!(!credential_shaped("CLAUDE_CODE_OAUTH_TOKEN"));
/// assert!(!credential_shaped("PATH"));
/// ```
pub fn credential_shaped(name: &str) -> bool {
    CREDENTIAL_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// A way of confining a worker.
pub trait Sandbox {
    /// `container`, `bubblewrap` or `none`.
    fn kind(&self) -> &'static str;

    /// Run every check and report. The caller refuses to start the worker unless `report.ok`.
    fn verify(&self) -> BoundaryReport;

    /// Wrap the worker command (for example in `bwrap`). The container backend returns the command unchanged: the
    /// container is the boundary and the Kit only verifies it.
    fn wrap(&self, cmd: std::process::Command) -> std::process::Command {
        cmd
    }
}
