//! Repo-side recipes: scope, protected-path exceptions and gate commands come from here and nowhere else. Never from a
//! tracker field or alert text.
//!
//! # Glob semantics
//!
//! Every glob in this module is compiled with [`globset`] and **literal separators**: `*` and `?` never match `/`, so
//! `src/*.rs` matches `src/a.rs` but not `src/deep/a.rs`. `**` crosses directories: `src/**` matches everything under
//! `src/`, and `**/tests/**` matches `tests/x.rs` as well as `a/b/tests/x.rs` (a leading `**/` also matches zero
//! directories). Paths are repository-relative, `/`-separated and never start with `./` or `/`; the patch validator
//! rejects any other shape before a glob is consulted.
//!
//! * **Scope** globs are case-sensitive. A path that differs only by case from an in-scope path is out of scope.
//! * **Protected** globs are case-insensitive, so `JENKINSFILE` or `cargo.LOCK` cannot slip past on a case-insensitive
//!   filesystem. The cost is a few extra refusals, never an extra acceptance.
//! * `allow_protected` is **not** a glob list. Each entry is an exact, case-sensitive, repository-relative path and nothing
//!   else matches it: no prefixes, no directories, no wildcards (an entry containing a wildcard character is rejected when
//!   the recipe is loaded).

use std::io::Read;
use std::path::Path;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

use crate::{ErrandError, Result};

/// Largest recipe file [`Recipe::load`] will read.
const MAX_RECIPE_BYTES: u64 = 1024 * 1024;

/// What a worker may change in one repository, and how to check it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
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

impl Recipe {
    /// Load and validate a recipe from a JSON file. Unknown fields are rejected, globs must compile, and the file must be
    /// no larger than 1 MiB. Every failure is an [`ErrandError::Recipe`].
    pub fn load(path: impl AsRef<Path>) -> Result<Recipe> {
        let path = path.as_ref();
        let file = std::fs::File::open(path)
            .map_err(|e| ErrandError::Recipe(format!("cannot open {}: {e}", path.display())))?;
        let mut text = String::new();
        file.take(MAX_RECIPE_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|e| ErrandError::Recipe(format!("cannot read {}: {e}", path.display())))?;
        if text.len() as u64 > MAX_RECIPE_BYTES {
            return Err(ErrandError::Recipe(format!(
                "{} is larger than {MAX_RECIPE_BYTES} bytes",
                path.display()
            )));
        }
        let recipe: Recipe = serde_json::from_str(&text)
            .map_err(|e| ErrandError::Recipe(format!("{}: {e}", path.display())))?;
        recipe.validate()?;
        Ok(recipe)
    }

    /// Check the recipe is well formed: a repo name, compilable scope globs, exact-path `allow_protected` entries and
    /// non-empty gate argv. [`Recipe::load`] calls this; call it yourself for a recipe built in code.
    pub fn validate(&self) -> Result<()> {
        if self.repo.trim().is_empty() {
            return Err(ErrandError::Recipe("`repo` must not be empty".into()));
        }
        self.scope_matcher()?;
        for entry in &self.allow_protected {
            if entry.is_empty() || entry.contains(['*', '?', '[', ']', '{', '}']) {
                return Err(ErrandError::Recipe(format!(
                    "allow_protected entry `{entry}` must be an exact path, not a glob"
                )));
            }
        }
        for argv in &self.gate_commands {
            if argv.first().is_none_or(|a| a.is_empty()) {
                return Err(ErrandError::Recipe(
                    "a gate command must have a non-empty program".into(),
                ));
            }
        }
        Ok(())
    }

    /// The default protected globs: CI definitions, build scripts, lockfiles, tests, repository metadata and agent
    /// instructions. A patch touching one is refused unless the recipe lists that exact path in `allow_protected`.
    pub fn default_protected() -> Vec<String> {
        [
            "Jenkinsfile*",
            "**/Jenkinsfile*",
            ".github/**",
            ".gitlab-ci*",
            "Dockerfile*",
            "**/Dockerfile*",
            "**/*.lock",
            "**/package-lock.json",
            "**/pnpm-lock.yaml",
            "**/Cargo.lock",
            "**/tests/**",
            "**/test/**",
            "**/*_test.*",
            "**/*.test.*",
            ".git*",
            "**/.git*",
            "Makefile",
            "**/build.rs",
            "**/*.tf",
            "**/CODEOWNERS",
            "**/AGENT.md",
            "**/CLAUDE.md",
            ".claude/**",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    /// The compiled scope globs (case-sensitive, literal separators; see the module docs). An empty scope compiles to a
    /// matcher that matches nothing. An invalid glob is an [`ErrandError::Recipe`].
    pub fn scope_matcher(&self) -> Result<GlobSet> {
        build_set(&self.scope, false)
    }

    /// The compiled default protected globs (case-insensitive, literal separators; see the module docs).
    pub fn protected_matcher(&self) -> Result<GlobSet> {
        build_set(&Self::default_protected(), true)
    }

    /// Whether `path` is named, exactly and case-sensitively, in `allow_protected`.
    pub fn is_allowed_protected(&self, path: &str) -> bool {
        self.allow_protected.iter().any(|p| p == path)
    }
}

/// Compile `globs` with literal separators.
fn build_set(globs: &[String], case_insensitive: bool) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for g in globs {
        let glob = GlobBuilder::new(g)
            .literal_separator(true)
            .case_insensitive(case_insensitive)
            .build()
            .map_err(|e| ErrandError::Recipe(format!("invalid glob `{g}`: {e}")))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|e| ErrandError::Recipe(format!("cannot compile globs: {e}")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn write(dir: &tempfile::TempDir, text: &str) -> std::path::PathBuf {
        let p = dir.path().join("recipe.json");
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn loads_a_valid_recipe_with_defaults() {
        let d = tempfile::tempdir().unwrap();
        let r = Recipe::load(write(&d, r#"{"repo":"o/r","scope":["src/**"]}"#)).unwrap();
        assert_eq!(r.repo, "o/r");
        assert_eq!(r.scope, vec!["src/**"]);
        assert!(r.allow_protected.is_empty() && r.max_files.is_none() && r.max_lines.is_none());
    }

    #[test]
    fn loads_every_field() {
        let d = tempfile::tempdir().unwrap();
        let r = Recipe::load(write(
            &d,
            r#"{"repo":"o/r","scope":["a/**"],"allow_protected":["Cargo.lock"],"gate_commands":[["cargo","test"]],"max_files":3,"max_lines":40}"#,
        ))
        .unwrap();
        assert_eq!(r.allow_protected, vec!["Cargo.lock"]);
        assert_eq!(
            r.gate_commands,
            vec![vec!["cargo".to_string(), "test".to_string()]]
        );
        assert_eq!((r.max_files, r.max_lines), (Some(3), Some(40)));
    }

    #[test]
    fn rejects_unknown_fields() {
        let d = tempfile::tempdir().unwrap();
        let e = Recipe::load(write(&d, r#"{"repo":"o/r","scoPe":["**"]}"#)).unwrap_err();
        assert!(matches!(e, ErrandError::Recipe(m) if m.contains("unknown field")));
    }

    #[test]
    fn rejects_missing_file_bad_json_and_bad_globs() {
        let d = tempfile::tempdir().unwrap();
        assert!(matches!(
            Recipe::load(d.path().join("nope.json")),
            Err(ErrandError::Recipe(_))
        ));
        assert!(matches!(
            Recipe::load(write(&d, "{not json")),
            Err(ErrandError::Recipe(_))
        ));
        assert!(matches!(
            Recipe::load(write(&d, r#"{"repo":"o/r","scope":["src/[a"]}"#)),
            Err(ErrandError::Recipe(m)) if m.contains("invalid glob")
        ));
        assert!(matches!(
            Recipe::load(write(&d, r#"{"repo":" "}"#)),
            Err(ErrandError::Recipe(_))
        ));
    }

    #[test]
    fn rejects_glob_shaped_allow_protected_and_empty_gate_argv() {
        let d = tempfile::tempdir().unwrap();
        for text in [
            r#"{"repo":"o/r","allow_protected":["tests/**"]}"#,
            r#"{"repo":"o/r","allow_protected":[""]}"#,
            r#"{"repo":"o/r","gate_commands":[[]]}"#,
            r#"{"repo":"o/r","gate_commands":[[""]]}"#,
        ] {
            assert!(
                matches!(Recipe::load(write(&d, text)), Err(ErrandError::Recipe(_))),
                "{text}"
            );
        }
    }

    #[test]
    fn rejects_an_oversized_recipe() {
        let d = tempfile::tempdir().unwrap();
        let big = format!(
            r#"{{"repo":"o/r","scope":["{}"]}}"#,
            "a".repeat(MAX_RECIPE_BYTES as usize)
        );
        assert!(
            matches!(Recipe::load(write(&d, &big)), Err(ErrandError::Recipe(m)) if m.contains("larger"))
        );
    }

    #[test]
    fn default_protected_is_the_documented_list() {
        let p = Recipe::default_protected();
        assert_eq!(p.len(), 23);
        for g in [
            "Jenkinsfile*",
            ".github/**",
            "**/Cargo.lock",
            "**/tests/**",
            ".claude/**",
            "**/CLAUDE.md",
        ] {
            assert!(p.iter().any(|x| x == g), "{g}");
        }
        let r = Recipe::default();
        assert!(r.protected_matcher().is_ok());
    }

    #[test]
    fn scope_uses_literal_separators() {
        let r = Recipe {
            repo: "o/r".into(),
            scope: vec!["src/*.rs".into(), "docs/**".into()],
            ..Recipe::default()
        };
        let m = r.scope_matcher().unwrap();
        assert!(m.is_match("src/a.rs"));
        assert!(!m.is_match("src/deep/a.rs"), "`*` must not cross `/`");
        assert!(m.is_match("docs/a/b/c.md"));
        assert!(!m.is_match("SRC/a.rs"), "scope is case-sensitive");
        assert!(!m.is_match("other/a.rs"));
    }

    #[test]
    fn empty_scope_matches_nothing() {
        let m = Recipe::default().scope_matcher().unwrap();
        assert!(!m.is_match("src/a.rs") && !m.is_match("") && !m.is_match("a"));
    }

    #[test]
    fn protected_matcher_hits_the_defaults_and_ignores_case() {
        let m = Recipe::default().protected_matcher().unwrap();
        for p in [
            "Jenkinsfile",
            "ci/Jenkinsfile.dev",
            ".github/workflows/ci.yml",
            ".gitlab-ci.yml",
            "Dockerfile",
            "svc/Dockerfile.prod",
            "yarn.lock",
            "web/package-lock.json",
            "web/pnpm-lock.yaml",
            "crates/x/Cargo.lock",
            "tests/a.rs",
            "x/tests/y.rs",
            "x/test/y.rs",
            "src/a_test.go",
            "src/a.test.js",
            ".gitignore",
            "sub/.gitattributes",
            "Makefile",
            "crates/x/build.rs",
            "infra/main.tf",
            "docs/CODEOWNERS",
            "AGENT.md",
            "sub/CLAUDE.md",
            ".claude/agents/x.md",
            "JENKINSFILE",
            "cargo.LOCK",
            "makefile",
        ] {
            assert!(m.is_match(p), "{p} must be protected");
        }
        for p in [
            "src/lib.rs",
            "README.md",
            "docs/guide.md",
            "src/attest.rs",
            "contest/a.rs",
        ] {
            assert!(!m.is_match(p), "{p} must not be protected");
        }
    }

    #[test]
    fn allow_protected_is_exact_only() {
        let r = Recipe {
            allow_protected: vec!["Cargo.lock".into(), "tests".into()],
            ..Recipe::default()
        };
        assert!(r.is_allowed_protected("Cargo.lock"));
        assert!(r.is_allowed_protected("tests"));
        assert!(
            !r.is_allowed_protected("tests/a.rs"),
            "a prefix must not match"
        );
        assert!(!r.is_allowed_protected("cargo.lock"), "case-sensitive");
        assert!(!r.is_allowed_protected("sub/Cargo.lock"));
        assert!(!r.is_allowed_protected(""));
    }
}
