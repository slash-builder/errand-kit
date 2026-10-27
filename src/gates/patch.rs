//! Patch validation: the trusted phase decides on the patch text, before applying anything. (To be implemented.)

use crate::gates::recipe::Recipe;
use crate::{ErrandError, Result};

/// What a validated patch touches, as parsed from the patch text itself (not as claimed by the worker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchSummary {
    /// Paths the patch creates or modifies (repository-relative).
    pub files: Vec<String>,
    /// Added lines.
    pub added: usize,
    /// Removed lines.
    pub removed: usize,
}

/// Validate a unified/git patch against a recipe. Returns what it touches, or why it was refused.
pub fn validate_patch(_patch: &str, _recipe: &Recipe) -> Result<PatchSummary> {
    Err(ErrandError::Patch("not implemented".into()))
}
