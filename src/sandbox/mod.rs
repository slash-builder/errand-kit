//! The boundary. A [`Sandbox`] verifies, before any worker starts, that the worker will run where no credential is present
//! and capabilities are gone, and refuses otherwise. There is no automatic mode: a missing sandbox is a refusal, never a
//! fall-back to "none". See `spec/ERRAND.md` section 4.

use crate::contract::BoundaryReport;

pub mod bubblewrap;
pub mod container;
#[cfg(feature = "test-sandbox")]
pub mod none;

/// Variable-name prefixes that mark a credential. A worker's environment, and every process visible to the worker, must
/// contain none of these (`CLAUDE_CODE_OAUTH_TOKEN` is the worker's own token and is deliberately not matched).
pub const CREDENTIAL_PREFIXES: &[&str] = &[
    "AWS_",
    "AZURE_",
    "GCP_",
    "GOOGLE_",
    "GITHUB_",
    "GH_",
    "GITLAB_",
    "CLOUDFLARE_",
    "TF_",
    "SLACK_",
    "JIRA_",
    "ATLASSIAN_",
    "VAULT_",
    "NPM_",
    "ARM_",
    "ANTHROPIC_API",
    "OPENAI_",
    "DOCKER_",
];

/// Variable-name suffixes that mark a credential whatever the prefix (`DB_PASSWORD`, `STRIPE_SECRET_KEY`, `NPM_TOKEN`).
pub const CREDENTIAL_SUFFIXES: &[&str] = &[
    "_PASSWORD",
    "_PASSWD",
    "_SECRET",
    "_SECRET_KEY",
    "_ACCESS_KEY",
    "_API_KEY",
    "_PRIVATE_KEY",
    "_TOKEN",
];

/// Exact variable names that are credentials without a telltale prefix or suffix.
pub const CREDENTIAL_EXACT: &[&str] = &["SSH_AUTH_SOCK", "KUBECONFIG", "DATABASE_URL"];

/// The one credential-shaped name a worker is allowed: its own login token.
pub const WORKER_OWN_TOKEN: &str = "CLAUDE_CODE_OAUTH_TOKEN";

/// Extra prefixes a deployment can add without recompiling, as a comma-separated list in `ERRAND_CREDENTIAL_PREFIXES`
/// (for example `ACME_,INTERNAL_`).
fn extra_prefixes() -> Vec<String> {
    std::env::var("ERRAND_CREDENTIAL_PREFIXES")
        .map(|v| {
            v.split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// True if a variable *name* looks like a credential: it starts with a listed prefix, ends with a listed suffix, or starts with
/// a deployment-added prefix. The worker's own token is the one exception.
///
/// ```
/// use errand_kit::sandbox::credential_shaped;
/// assert!(credential_shaped("AWS_SECRET_ACCESS_KEY"));
/// assert!(credential_shaped("DB_PASSWORD"));
/// assert!(credential_shaped("NPM_TOKEN"));
/// assert!(credential_shaped("JIRA_API_TOKEN") && credential_shaped("SSH_AUTH_SOCK"));
/// assert!(!credential_shaped("CLAUDE_CODE_OAUTH_TOKEN"));
/// assert!(!credential_shaped("PATH"));
/// ```
pub fn credential_shaped(name: &str) -> bool {
    if name == WORKER_OWN_TOKEN {
        return false;
    }
    CREDENTIAL_EXACT.contains(&name)
        || CREDENTIAL_PREFIXES.iter().any(|p| name.starts_with(p))
        || CREDENTIAL_SUFFIXES.iter().any(|s| name.ends_with(s))
        || extra_prefixes()
            .iter()
            .any(|p| name.starts_with(p.as_str()))
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
