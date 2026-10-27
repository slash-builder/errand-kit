//! Repo-side recipes: scope, protected-path exceptions and gate commands come from here and nowhere else. Never from a
//! tracker field or alert text. (To be implemented.)

use serde::{Deserialize, Serialize};

/// What a worker may change in one repository, and how to check it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Recipe {
    /// `owner/name`.
    pub repo: String,
    /// Globs a patch may touch (empty means nothing is allowed).
    #[serde(default)]
    pub scope: Vec<String>,
    /// Exact paths that are protected by default but allowed for this recipe.
    #[serde(default)]
    pub allow_protected: Vec<String>,
    /// Gate commands (argv), each run with no network and no credentials; exit 0 expected.
    #[serde(default)]
    pub gate_commands: Vec<Vec<String>>,
    /// Maximum files a patch may touch.
    #[serde(default)]
    pub max_files: Option<usize>,
    /// Maximum added plus removed lines.
    #[serde(default)]
    pub max_lines: Option<usize>,
}
