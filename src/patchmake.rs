//! Producing a patch from a worker's directory, without trusting it.
//!
//! A worker (an untrusted model) edits a copy of a repository. The trusted phase must turn that into a patch without ever
//! running `git` inside the worker's directory: `.git/config` can set `core.hooksPath`, `core.fsmonitor`,
//! `credential.helper` or `url.insteadOf`, any of which is code execution with whatever credentials the trusted phase holds.
//!
//! So [`make_patch`] copies the pristine `base` tree and the worker's `tree` into a fresh scratch repository it created itself
//! and diffs there, with every user, system and repository configuration switched off. Symlinks are copied as symlinks (and so
//! show up as mode `120000`, which the patch validator refuses). A `.git` entry anywhere in the worker's tree is an error.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{ErrandError, Result};

/// Directories that hold the pristine tree and the worker's tree.
#[derive(Debug, Clone)]
pub struct WorkDirs {
    /// The pristine tree (for example from `git archive`); a top-level `.git` here is skipped.
    pub base: PathBuf,
    /// The worker's edited copy. Must contain no `.git` entry at any depth.
    pub tree: PathBuf,
}

fn io(path: &Path, e: std::io::Error) -> ErrandError {
    ErrandError::io(path, e)
}

/// Recursively copy `src` into `dst`, preserving symlinks as symlinks. If `skip_top_git`, a top-level `.git` is skipped;
/// otherwise any `.git` entry is an error.
fn copy_tree(src: &Path, dst: &Path, skip_top_git: bool, top: bool) -> Result<()> {
    std::fs::create_dir_all(dst).map_err(|e| io(dst, e))?;
    for entry in std::fs::read_dir(src).map_err(|e| io(src, e))? {
        let entry = entry.map_err(|e| io(src, e))?;
        let name = entry.file_name();
        let from = entry.path();
        let to = dst.join(&name);
        if name == ".git" {
            if skip_top_git && top {
                continue;
            }
            return Err(ErrandError::Patch(format!(
                "the tree contains a .git entry at {}",
                from.display()
            )));
        }
        let ft = entry.file_type().map_err(|e| io(&from, e))?;
        if ft.is_symlink() {
            let target = std::fs::read_link(&from).map_err(|e| io(&from, e))?;
            make_symlink(&target, &to)?;
        } else if ft.is_dir() {
            copy_tree(&from, &to, skip_top_git, false)?;
        } else if ft.is_file() {
            std::fs::copy(&from, &to).map_err(|e| io(&from, e))?;
        } else {
            return Err(ErrandError::Patch(format!(
                "unsupported file type at {}",
                from.display()
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn make_symlink(target: &Path, link: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, link).map_err(|e| io(link, e))
}

#[cfg(not(unix))]
fn make_symlink(_target: &Path, link: &Path) -> Result<()> {
    Err(ErrandError::Patch(format!(
        "symlinks are not supported on this platform: {}",
        link.display()
    )))
}

fn clear_except_git(dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir).map_err(|e| io(dir, e))? {
        let entry = entry.map_err(|e| io(dir, e))?;
        if entry.file_name() == ".git" {
            continue;
        }
        let p = entry.path();
        let ft = entry.file_type().map_err(|e| io(&p, e))?;
        if ft.is_dir() && !ft.is_symlink() {
            std::fs::remove_dir_all(&p).map_err(|e| io(&p, e))?;
        } else {
            std::fs::remove_file(&p).map_err(|e| io(&p, e))?;
        }
    }
    Ok(())
}

/// Longest a single `git` call may take. The worker controls the tree, so it controls how much work git has to do.
const GIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
/// Longest output kept from a `git` call; git's own output is read from files, so a flood of warnings cannot fill a pipe and block.
const GIT_OUTPUT_CAP: u64 = 64 * 1024 * 1024;

/// A `git` invocation with every configuration source switched off, run in `repo`. Output goes to files in `scratch` (never
/// to pipes, which a verbose git can fill and deadlock on) and the call is killed after [`GIT_TIMEOUT`].
fn git(repo: &Path, scratch: &Path, args: &[&str]) -> Result<String> {
    use std::io::Read;
    let out_path = scratch.join("git.stdout");
    let err_path = scratch.join("git.stderr");
    let out_file = std::fs::File::create(&out_path).map_err(|e| io(&out_path, e))?;
    let err_file = std::fs::File::create(&err_path).map_err(|e| io(&err_path, e))?;
    let mut child = Command::new("git")
        .current_dir(repo)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", scratch)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.safecrlf=false",
            "-c",
            "core.symlinks=true",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "user.name=errand",
            "-c",
            "user.email=errand@localhost",
        ])
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(out_file)
        .stderr(err_file)
        .spawn()
        .map_err(|e| ErrandError::Patch(format!("could not run git: {e}")))?;
    let deadline = std::time::Instant::now() + GIT_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ErrandError::Patch(format!(
                    "git {} timed out after {}s",
                    args.first().copied().unwrap_or(""),
                    GIT_TIMEOUT.as_secs()
                )));
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(e) => return Err(ErrandError::Patch(format!("could not wait for git: {e}"))),
        }
    };
    let read = |p: &Path, cap: u64| -> Result<String> {
        let mut buf = Vec::new();
        std::fs::File::open(p)
            .map_err(|e| io(p, e))?
            .take(cap)
            .read_to_end(&mut buf)
            .map_err(|e| io(p, e))?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    };
    if !status.success() {
        return Err(ErrandError::Patch(format!(
            "git {} failed: {}",
            args.first().copied().unwrap_or(""),
            read(&err_path, 4096)?.trim()
        )));
    }
    read(&out_path, GIT_OUTPUT_CAP)
}

/// Build a git-format patch of the differences between `dirs.base` and `dirs.tree`, using `scratch` (an empty or absent
/// directory the caller owns) for a throwaway repository. Returns the patch text; empty if the trees are identical.
///
/// The patch uses `--no-renames` (a rename is a delete plus an add), `--binary` and `--full-index`, and no external diff
/// driver or text conversion.
pub fn make_patch(dirs: &WorkDirs, scratch: &Path) -> Result<String> {
    // The scratch directory must be FRESH. If a `.git` from an earlier (or planted) run is already there, `git init` would keep its
    // configuration, and a filter or hook configured in it would run during `git add`.
    if scratch.exists() {
        std::fs::remove_dir_all(scratch).map_err(|e| io(scratch, e))?;
    }
    let repo = scratch.join("repo");
    std::fs::create_dir_all(&repo).map_err(|e| io(&repo, e))?;
    git(&repo, scratch, &["init", "-q"])?;
    copy_tree(&dirs.base, &repo, true, true)?;
    git(&repo, scratch, &["add", "-A", "--force"])?;
    git(
        &repo,
        scratch,
        &["commit", "-q", "--allow-empty", "-m", "base"],
    )?;
    clear_except_git(&repo)?;
    copy_tree(&dirs.tree, &repo, false, true)?;
    git(&repo, scratch, &["add", "-A", "--force"])?;
    git(
        &repo,
        scratch,
        &[
            "diff",
            "--cached",
            "--binary",
            "--full-index",
            "--no-renames",
            "--no-ext-diff",
            "--no-textconv",
        ],
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn have_git() -> bool {
        Command::new("git")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn write(root: &Path, rel: &str, text: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    fn dirs(t: &Path) -> WorkDirs {
        let (b, w) = (t.join("base"), t.join("tree"));
        write(&b, "docs/a.md", "one\ntwo\n");
        write(&b, "keep.txt", "same\n");
        write(&w, "docs/a.md", "one\ntwo\n");
        write(&w, "keep.txt", "same\n");
        WorkDirs { base: b, tree: w }
    }

    #[test]
    fn a_planted_scratch_repository_is_wiped_and_cannot_run_anything() {
        if !have_git() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        let scratch = t.path().join("scratch");
        let marker = t.path().join("PWNED");
        // Plant a .git with a clean filter that would touch the marker if it ever ran.
        write(
            &scratch,
            "repo/.git/config",
            &format!(
                "[filter \"x\"]\n\tclean = touch {}\n[core]\n\tfsmonitor = touch {}\n",
                marker.display(),
                marker.display()
            ),
        );
        write(&scratch, "repo/.git/HEAD", "ref: refs/heads/main\n");
        write(&d.tree, ".gitattributes", "* filter=x\n");
        write(&d.tree, "docs/a.md", "changed\n");
        let p = make_patch(&d, &scratch).unwrap();
        assert!(p.contains("changed"));
        assert!(
            !marker.exists(),
            "a planted scratch repository must never influence the diff"
        );
    }

    #[test]
    fn identical_trees_give_an_empty_patch() {
        if !have_git() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        assert_eq!(make_patch(&d, &t.path().join("scratch")).unwrap(), "");
    }

    #[test]
    fn edits_adds_and_deletes_appear_with_repo_relative_paths() {
        if !have_git() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        write(&d.tree, "docs/a.md", "one\nTWO\nthree\n");
        write(&d.tree, "docs/new.md", "hello\n");
        std::fs::remove_file(d.tree.join("keep.txt")).unwrap();
        let p = make_patch(&d, &t.path().join("scratch")).unwrap();
        assert!(p.contains("diff --git a/docs/a.md b/docs/a.md"), "{p}");
        assert!(p.contains("+TWO") && p.contains("-two") && p.contains("+three"));
        assert!(
            p.contains("diff --git a/docs/new.md b/docs/new.md")
                && p.contains("new file mode 100644")
        );
        assert!(p.contains("deleted file mode 100644") && p.contains("a/keep.txt"));
        assert!(
            !p.contains(t.path().to_str().unwrap()),
            "no absolute path may leak into the patch"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_the_worker_makes_is_a_mode_120000_entry() {
        if !have_git() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        std::os::unix::fs::symlink("/etc/passwd", d.tree.join("docs/link")).unwrap();
        let p = make_patch(&d, &t.path().join("scratch")).unwrap();
        assert!(p.contains("new file mode 120000"), "{p}");
    }

    #[test]
    fn a_git_directory_in_the_workers_tree_is_refused_at_any_depth() {
        if !have_git() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        write(&d.tree, ".git/config", "[core]\n\thooksPath = /tmp/evil\n");
        let e = make_patch(&d, &t.path().join("s1"))
            .unwrap_err()
            .to_string();
        assert!(e.contains(".git"), "{e}");
        std::fs::remove_dir_all(d.tree.join(".git")).unwrap();
        write(&d.tree, "docs/sub/.git/HEAD", "ref: refs/heads/x\n");
        assert!(make_patch(&d, &t.path().join("s2")).is_err());
    }

    #[test]
    fn a_top_level_git_directory_in_the_pristine_base_is_skipped() {
        if !have_git() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        write(&d.base, ".git/HEAD", "ref: refs/heads/main\n");
        assert_eq!(make_patch(&d, &t.path().join("scratch")).unwrap(), "");
    }

    #[test]
    fn worker_git_config_cannot_influence_the_diff_or_run_anything() {
        if !have_git() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        // A hostile .gitattributes with an external diff driver and a filter must not execute; the marker file proves it.
        let marker = t.path().join("PWNED");
        write(
            &d.tree,
            ".gitattributes",
            "*.md diff=evil filter=evil
",
        );
        write(&d.tree, "docs/a.md", "changed\n");
        write(
            &d.tree,
            ".git-evil-note",
            &format!("textconv would run: touch {}\n", marker.display()),
        );
        let p = make_patch(&d, &t.path().join("scratch")).unwrap();
        assert!(p.contains("changed"));
        assert!(
            !marker.exists(),
            "nothing from the worker's tree may execute"
        );
    }

    #[test]
    fn n4_a_flood_of_git_warnings_cannot_hang_the_builder() {
        if !have_git() {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let d = dirs(t.path());
        // Thousands of files under `* text eol=crlf` make git warn about line endings once per file: far more than a pipe holds.
        write(&d.tree, ".gitattributes", "* text eol=crlf\n");
        for i in 0..4000 {
            write(&d.tree, &format!("docs/many/f{i}.txt"), "a\nb\n");
        }
        let start = std::time::Instant::now();
        let p = make_patch(&d, &t.path().join("scratch")).unwrap();
        assert!(p.contains("docs/many/f0.txt"));
        assert!(start.elapsed() < std::time::Duration::from_secs(100));
    }
}
