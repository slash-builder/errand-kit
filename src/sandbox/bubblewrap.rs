//! The bubblewrap backend for a Linux host: argument construction plus a presence and user-namespace check.
//!
//! The masking follows a reviewed design: the root is bound read-only and
//! `/run`, `/var/log`, `/var/lib/docker`, `/var/lib/lxd`, `/mnt`, `/media`, `/srv`, `/root` and `/home` are each replaced by an
//! empty tmpfs, so the container runtime socket, the user D-Bus, SSH and keyring agents, other users' homes and the logs
//! are invisible. Only the DNS resolver directory is bound back. Network stays shared (egress is open and the record says so).
//!
//! The environment is cleared (`--clearenv`) and rebuilt from explicit `--setenv` arguments. A credential-shaped name
//! ([`credential_shaped`]) is never passed in, whatever the config or the wrapped command asks for.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::contract::{BoundaryReport, Check};
use crate::sandbox::{credential_shaped, Sandbox};

/// Directories replaced by an empty tmpfs, in a fixed order.
pub const DEFAULT_MASKED: &[&str] = &[
    "/run",
    "/var/log",
    "/var/lib/docker",
    "/var/lib/lxd",
    "/mnt",
    "/media",
    "/srv",
    "/root",
    "/home",
];

/// How `bwrap` is invoked.
#[derive(Debug, Clone)]
pub struct BubblewrapConfig {
    /// The `bwrap` binary: a bare name is searched on `PATH`, anything with a separator is used as given.
    pub bwrap_path: PathBuf,
    /// What is bound read-only at `/` (normally `/`).
    pub ro_root: PathBuf,
    /// Directories replaced by an empty tmpfs.
    pub masked: Vec<PathBuf>,
    /// When true (the default) a mask whose directory does not exist on the host is left out: `bwrap` cannot create a
    /// mount point inside a read-only bind.
    pub mask_only_existing: bool,
    /// Extra directories bound read-write at the same path. Missing directories are skipped by `bwrap` only if you list
    /// them yourself; they are passed as given.
    pub extra_rw: Vec<PathBuf>,
    /// Names of host environment variables copied into the sandbox. Credential-shaped names are dropped.
    pub env_passthrough: Vec<String>,
    /// Explicit variables set inside the sandbox. Credential-shaped names are dropped.
    pub set_env: BTreeMap<String, String>,
}

impl Default for BubblewrapConfig {
    fn default() -> Self {
        let mut set_env = BTreeMap::new();
        set_env.insert("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned());
        set_env.insert("HOME".to_owned(), "/tmp".to_owned());
        Self {
            bwrap_path: PathBuf::from("bwrap"),
            ro_root: PathBuf::from("/"),
            masked: DEFAULT_MASKED.iter().map(PathBuf::from).collect(),
            mask_only_existing: true,
            extra_rw: Vec::new(),
            env_passthrough: Vec::new(),
            set_env,
        }
    }
}

/// Wraps the worker in `bwrap`.
///
/// ```
/// use std::ffi::OsString;
/// use errand_kit::sandbox::bubblewrap::Bubblewrap;
/// let args = Bubblewrap::default().build_args("echo".as_ref(), &[OsString::from("hi")]);
/// assert!(args.iter().any(|a| a == "--die-with-parent"));
/// assert_eq!(args[args.len() - 2], OsString::from("echo"));
/// assert_eq!(args[args.len() - 1], OsString::from("hi"));
/// ```
#[derive(Debug, Default, Clone)]
pub struct Bubblewrap {
    config: BubblewrapConfig,
}

impl Bubblewrap {
    /// Build with an explicit configuration.
    pub fn new(config: BubblewrapConfig) -> Self {
        Self { config }
    }

    /// The configuration in use.
    pub fn config(&self) -> &BubblewrapConfig {
        &self.config
    }

    /// The `bwrap` arguments (without the `bwrap` binary itself) that run `program args...` in the sandbox, in a fixed
    /// order: root, masks, resolver, `/tmp` `/dev` `/proc`, namespaces and lifetime flags, extra binds, environment, then
    /// `--` and the program. Passthrough values are read from this process's environment.
    ///
    /// Nothing is executed. Every path and argument is a single element, so a path with spaces stays one argument.
    pub fn build_args(&self, program: &OsStr, args: &[OsString]) -> Vec<OsString> {
        self.build_args_in(program, args, None, &[], &|n| std::env::var_os(n))
    }

    /// As [`Bubblewrap::build_args`] with a working directory, extra explicit variables and an injectable environment
    /// lookup (so tests do not depend on the real environment).
    fn build_args_in(
        &self,
        program: &OsStr,
        args: &[OsString],
        cwd: Option<&Path>,
        cmd_env: &[(OsString, OsString)],
        lookup: &dyn Fn(&str) -> Option<OsString>,
    ) -> Vec<OsString> {
        let c = &self.config;
        let mut a: Vec<OsString> = Vec::new();
        let mut push = |parts: &[&OsStr]| a.extend(parts.iter().map(|p| (*p).to_owned()));

        push(&["--ro-bind".as_ref(), c.ro_root.as_os_str(), "/".as_ref()]);
        for m in &c.masked {
            if c.mask_only_existing && !m.exists() {
                continue;
            }
            push(&["--tmpfs".as_ref(), m.as_os_str()]);
        }
        // Name resolution still has to work (egress is open), so the resolver directory is bound back over the /run mask.
        push(&[
            "--ro-bind-try".as_ref(),
            "/run/systemd/resolve".as_ref(),
            "/run/systemd/resolve".as_ref(),
        ]);
        push(&["--tmpfs".as_ref(), "/tmp".as_ref()]);
        push(&["--dev".as_ref(), "/dev".as_ref()]);
        push(&["--proc".as_ref(), "/proc".as_ref()]);
        // Everything unshared (user, ipc, pid, uts, cgroup, net) and then the network shared again: egress stays open.
        push(&["--unshare-all".as_ref(), "--share-net".as_ref()]);
        push(&["--die-with-parent".as_ref(), "--new-session".as_ref()]);
        for d in &c.extra_rw {
            push(&["--bind".as_ref(), d.as_os_str(), d.as_os_str()]);
        }

        // Environment: cleared, then explicit. Later sources win; credential-shaped names never get in.
        let mut env: BTreeMap<OsString, OsString> = BTreeMap::new();
        let mut take = |name: &OsStr, value: OsString, source: &str| {
            let n = name.to_string_lossy();
            if n.is_empty() || n.contains('=') || n.contains('\0') {
                return;
            }
            if credential_shaped(&n) {
                // The name only, never the value.
                tracing::warn!(name = %n, source, "credential-shaped variable not passed into the sandbox");
                return;
            }
            env.insert(name.to_owned(), value);
        };
        for (k, v) in &c.set_env {
            take(k.as_ref(), OsString::from(v), "config");
        }
        for k in &c.env_passthrough {
            if let Some(v) = lookup(k) {
                take(k.as_ref(), v, "passthrough");
            }
        }
        for (k, v) in cmd_env {
            take(k, v.clone(), "command");
        }
        push(&["--clearenv".as_ref()]);
        for (k, v) in &env {
            push(&["--setenv".as_ref(), k.as_os_str(), v.as_os_str()]);
        }
        if let Some(dir) = cwd {
            push(&["--chdir".as_ref(), dir.as_os_str()]);
        }

        push(&["--".as_ref(), program]);
        a.extend(args.iter().cloned());
        a
    }

    /// Resolve the configured `bwrap` binary to a file, or `None`.
    fn locate(&self) -> Option<PathBuf> {
        let p = &self.config.bwrap_path;
        if p.components().count() > 1 || p.is_absolute() {
            return p.is_file().then(|| p.clone());
        }
        let path = std::env::var_os("PATH")?;
        std::env::split_paths(&path)
            .map(|d| d.join(p))
            .find(|c| c.is_file())
    }

    /// Run the presence and user-namespace checks on any host (no Linux-only guard); [`Sandbox::verify`] applies it.
    fn verify_inner(&self) -> BoundaryReport {
        let mut checks = Vec::new();
        let found = self.locate();
        checks.push(Check {
            name: "bwrap_present".into(),
            ok: found.is_some(),
            required: true,
            detail: match &found {
                Some(p) => format!("found {}", p.display()),
                None => format!("{} not found", self.config.bwrap_path.display()),
            },
        });
        let userns = match &found {
            None => Check {
                name: "userns_usable".into(),
                ok: false,
                required: true,
                detail: "skipped: bwrap is not present".into(),
            },
            Some(bin) => {
                let out = Command::new(bin)
                    .args(["--unshare-all", "--ro-bind", "/", "/", "true"])
                    .env_clear()
                    .stdin(Stdio::null())
                    .output();
                match out {
                    Ok(o) if o.status.success() => Check {
                        name: "userns_usable".into(),
                        ok: true,
                        required: true,
                        detail: "bwrap --unshare-all --ro-bind / / true succeeded".into(),
                    },
                    Ok(o) => {
                        let err = String::from_utf8_lossy(&o.stderr);
                        let first: String =
                            err.lines().next().unwrap_or("").chars().take(200).collect();
                        Check {
                            name: "userns_usable".into(),
                            ok: false,
                            required: true,
                            detail: format!("bwrap exited with {}: {first}", o.status),
                        }
                    }
                    Err(e) => Check {
                        name: "userns_usable".into(),
                        ok: false,
                        required: true,
                        detail: format!("could not run bwrap: {}", e.kind()),
                    },
                }
            }
        };
        checks.push(userns);
        finish(checks)
    }
}

fn finish(checks: Vec<Check>) -> BoundaryReport {
    let ok = checks.iter().filter(|c| c.required).all(|c| c.ok);
    BoundaryReport {
        kind: "bubblewrap".into(),
        ok,
        egress: "open".into(),
        checks,
    }
}

impl Sandbox for Bubblewrap {
    fn kind(&self) -> &'static str {
        "bubblewrap"
    }

    fn verify(&self) -> BoundaryReport {
        if !cfg!(target_os = "linux") {
            return finish(vec![Check {
                name: "linux_only".into(),
                ok: false,
                required: true,
                detail: "bubblewrap needs Linux user namespaces".into(),
            }]);
        }
        let report = self.verify_inner();
        for c in report.checks.iter().filter(|c| !c.ok) {
            tracing::warn!(check = %c.name, detail = %c.detail, "bubblewrap check failed");
        }
        report
    }

    /// Run the original program through `bwrap`. The returned command has an empty environment apart from `PATH` (used
    /// to find `bwrap`); the worker's environment is whatever [`BubblewrapConfig`] and the original command's explicit
    /// `env(..)` calls name, minus credential-shaped names.
    fn wrap(&self, cmd: Command) -> Command {
        let args: Vec<OsString> = cmd.get_args().map(OsStr::to_owned).collect();
        let cmd_env: Vec<(OsString, OsString)> = cmd
            .get_envs()
            .filter_map(|(k, v)| v.map(|v| (k.to_owned(), v.to_owned())))
            .collect();
        let bwrap_args = self.build_args_in(
            cmd.get_program(),
            &args,
            cmd.get_current_dir(),
            &cmd_env,
            &|n| std::env::var_os(n),
        );
        let bin = self
            .locate()
            .unwrap_or_else(|| self.config.bwrap_path.clone());
        let mut out = Command::new(bin);
        out.args(bwrap_args).env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            out.env("PATH", path);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    fn strs(v: &[OsString]) -> Vec<String> {
        v.iter().map(|s| s.to_string_lossy().into_owned()).collect()
    }

    fn cfg_no_exist_check() -> BubblewrapConfig {
        BubblewrapConfig {
            mask_only_existing: false,
            ..BubblewrapConfig::default()
        }
    }

    fn no_env(_: &str) -> Option<OsString> {
        None
    }

    fn position(a: &[String], needle: &str) -> usize {
        a.iter()
            .position(|x| x == needle)
            .unwrap_or_else(|| panic!("{needle} missing from {a:?}"))
    }

    #[test]
    fn argument_order_is_root_masks_flags_env_program() {
        let bw = Bubblewrap::new(cfg_no_exist_check());
        let a = strs(&bw.build_args_in("prog".as_ref(), &[os("a1"), os("a2")], None, &[], &no_env));
        assert_eq!(&a[..3], ["--ro-bind", "/", "/"]);
        let run = position(&a, "/run");
        let home = position(&a, "/home");
        assert_eq!(a[run - 1], "--tmpfs");
        assert_eq!(a[home - 1], "--tmpfs");
        assert!(run < home, "masks keep their order");
        // The resolver bind comes after the /run mask so it shows through.
        assert!(position(&a, "--ro-bind-try") > run);
        let share = position(&a, "--share-net");
        assert_eq!(a[share - 1], "--unshare-all");
        assert!(a.contains(&"--die-with-parent".to_owned()));
        assert!(a.contains(&"--new-session".to_owned()));
        assert!(position(&a, "--clearenv") > share);
        let sep = position(&a, "--");
        assert!(position(&a, "--clearenv") < sep);
        assert_eq!(&a[sep + 1..], ["prog", "a1", "a2"]);
        assert!(
            !a.contains(&"--unshare-net".to_owned()),
            "egress stays open"
        );
    }

    #[test]
    fn default_masks_cover_the_documented_list() {
        let bw = Bubblewrap::new(cfg_no_exist_check());
        let a = strs(&bw.build_args_in("p".as_ref(), &[], None, &[], &no_env));
        for m in [
            "/run",
            "/var/log",
            "/var/lib/docker",
            "/var/lib/lxd",
            "/mnt",
            "/media",
            "/srv",
            "/root",
            "/home",
        ] {
            let i = position(&a, m);
            assert_eq!(a[i - 1], "--tmpfs", "{m} is masked");
        }
    }

    #[test]
    fn missing_masks_are_skipped_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let present = dir.path().join("present");
        std::fs::create_dir(&present).unwrap();
        let missing = dir.path().join("missing");
        let cfg = BubblewrapConfig {
            masked: vec![present.clone(), missing.clone()],
            ..BubblewrapConfig::default()
        };
        let a = Bubblewrap::new(cfg).build_args("p".as_ref(), &[]);
        assert!(a.iter().any(|x| x == present.as_os_str()));
        assert!(!a.iter().any(|x| x == missing.as_os_str()));
    }

    #[test]
    fn environment_does_not_leak_into_arguments() {
        let secret = "s3cr3t-value-123";
        let lookup = |n: &str| match n {
            "AWS_SECRET_ACCESS_KEY" | "LANG" | "UNLISTED" => Some(os(secret)),
            _ => None,
        };
        let cfg = BubblewrapConfig {
            env_passthrough: vec!["LANG".into()],
            mask_only_existing: false,
            ..Default::default()
        };
        let a = Bubblewrap::new(cfg).build_args_in("p".as_ref(), &[], None, &[], &lookup);
        let joined = strs(&a);
        // Only the listed name is copied (LANG carries the value by design); the others are absent, name and value.
        assert!(joined.iter().any(|x| x == "LANG"));
        assert!(!joined
            .iter()
            .any(|x| x == "UNLISTED" || x == "AWS_SECRET_ACCESS_KEY"));
        assert_eq!(joined.iter().filter(|x| x.as_str() == secret).count(), 1);
    }

    #[test]
    fn credential_shaped_names_are_never_set() {
        let mut cfg = cfg_no_exist_check();
        cfg.env_passthrough = vec!["GITHUB_TOKEN".into(), "GH_TOKEN".into(), "TERM".into()];
        cfg.set_env
            .insert("AWS_ACCESS_KEY_ID".into(), "AKIAEXAMPLE".into());
        let lookup = |_: &str| Some(os("value-that-must-not-appear"));
        let cmd_env = [
            (os("DOCKER_HOST"), os("tcp://x")),
            (os("CLAUDE_CODE_OAUTH_TOKEN"), os("tok")),
        ];
        let a = Bubblewrap::new(cfg).build_args_in("p".as_ref(), &[], None, &cmd_env, &lookup);
        let s = strs(&a);
        for banned in [
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "DOCKER_HOST",
            "AKIAEXAMPLE",
            "tcp://x",
        ] {
            assert!(!s.iter().any(|x| x == banned), "{banned} leaked");
        }
        // The worker's own token, and an ordinary passthrough, are allowed.
        assert!(s.iter().any(|x| x == "CLAUDE_CODE_OAUTH_TOKEN"));
        assert!(s.iter().any(|x| x == "TERM"));
    }

    #[test]
    fn explicit_setenv_values_follow_their_names() {
        let bw = Bubblewrap::new(cfg_no_exist_check());
        let a = strs(&bw.build_args_in("p".as_ref(), &[], None, &[], &no_env));
        let i = position(&a, "PATH");
        assert_eq!(a[i - 1], "--setenv");
        assert_eq!(a[i + 1], "/usr/local/bin:/usr/bin:/bin");
    }

    #[test]
    fn command_env_overrides_config() {
        let bw = Bubblewrap::new(cfg_no_exist_check());
        let a = strs(&bw.build_args_in(
            "p".as_ref(),
            &[],
            None,
            &[(os("HOME"), os("/work"))],
            &no_env,
        ));
        let i = position(&a, "HOME");
        assert_eq!(a[i + 1], "/work");
        assert_eq!(a.iter().filter(|x| x.as_str() == "HOME").count(), 1);
    }

    #[test]
    fn paths_with_spaces_stay_one_argument() {
        let cfg = BubblewrapConfig {
            extra_rw: vec![PathBuf::from("/data/my work dir")],
            mask_only_existing: false,
            ..Default::default()
        };
        let bw = Bubblewrap::new(cfg);
        let a = bw.build_args_in(
            "/opt/my tool/run".as_ref(),
            &[os("--flag=a b"), os("c d")],
            Some(Path::new("/data/my work dir")),
            &[],
            &no_env,
        );
        let s = strs(&a);
        let i = position(&s, "--bind");
        assert_eq!(
            &s[i..i + 3],
            ["--bind", "/data/my work dir", "/data/my work dir"]
        );
        let c = position(&s, "--chdir");
        assert_eq!(s[c + 1], "/data/my work dir");
        let sep = position(&s, "--");
        assert_eq!(&s[sep + 1..], ["/opt/my tool/run", "--flag=a b", "c d"]);
    }

    #[test]
    fn extra_rw_binds_come_before_the_environment() {
        let cfg = BubblewrapConfig {
            extra_rw: vec![PathBuf::from("/out")],
            mask_only_existing: false,
            ..Default::default()
        };
        let s = strs(&Bubblewrap::new(cfg).build_args_in("p".as_ref(), &[], None, &[], &no_env));
        assert!(position(&s, "--bind") < position(&s, "--clearenv"));
    }

    #[test]
    fn program_that_looks_like_a_flag_stays_after_the_separator() {
        let s = strs(&Bubblewrap::default().build_args("--unshare-net".as_ref(), &[]));
        let sep = position(&s, "--");
        assert_eq!(s[sep + 1], "--unshare-net");
        assert_eq!(s.len(), sep + 2);
    }

    #[test]
    fn wrap_runs_the_original_program_through_bwrap() {
        let bw = Bubblewrap::new(BubblewrapConfig {
            bwrap_path: PathBuf::from("/nonexistent/bwrap"),
            mask_only_existing: false,
            ..Default::default()
        });
        let mut inner = Command::new("echo");
        inner
            .arg("hello world")
            .env("TERM", "xterm")
            .env("GH_TOKEN", "ghp_nope")
            .current_dir("/tmp");
        let wrapped = bw.wrap(inner);
        assert_eq!(wrapped.get_program(), "/nonexistent/bwrap");
        let args = strs(&wrapped.get_args().map(OsStr::to_owned).collect::<Vec<_>>());
        let sep = position(&args, "--");
        assert_eq!(&args[sep + 1..], ["echo", "hello world"]);
        assert!(args.iter().any(|x| x == "TERM"));
        assert!(!args.iter().any(|x| x == "GH_TOKEN" || x == "ghp_nope"));
        assert_eq!(args[position(&args, "--chdir") + 1], "/tmp");
        // The bwrap process itself starts with a cleared environment (PATH aside).
        let envs: Vec<_> = wrapped
            .get_envs()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect();
        assert!(envs.iter().all(|k| k == "PATH"));
    }

    #[test]
    fn verify_reports_missing_bwrap() {
        let bw = Bubblewrap::new(BubblewrapConfig {
            bwrap_path: PathBuf::from("/nonexistent/bwrap"),
            ..Default::default()
        });
        let r = bw.verify_inner();
        assert_eq!(r.kind, "bubblewrap");
        assert!(!r.ok);
        assert_eq!(r.egress, "open");
        let names: Vec<_> = r.checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["bwrap_present", "userns_usable"]);
        assert!(r.checks.iter().all(|c| c.required && !c.ok));
    }

    #[test]
    fn verify_passes_when_the_probe_succeeds() {
        // /usr/bin/true ignores its arguments, standing in for a working bwrap.
        let t = Path::new("/usr/bin/true");
        if !t.is_file() {
            return;
        }
        let r = Bubblewrap::new(BubblewrapConfig {
            bwrap_path: t.into(),
            ..Default::default()
        })
        .verify_inner();
        assert!(r.ok, "{r:?}");
        assert!(r.checks.iter().all(|c| c.ok && c.required));
    }

    #[test]
    fn verify_fails_userns_when_the_probe_fails() {
        let f = Path::new("/usr/bin/false");
        if !f.is_file() {
            return;
        }
        let r = Bubblewrap::new(BubblewrapConfig {
            bwrap_path: f.into(),
            ..Default::default()
        })
        .verify_inner();
        assert!(!r.ok);
        assert!(r.checks[0].ok, "present");
        assert!(!r.checks[1].ok, "namespaces not usable");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn verify_refuses_off_linux() {
        let r = Bubblewrap::default().verify();
        assert!(!r.ok);
        assert_eq!(r.checks.len(), 1);
        assert_eq!(r.checks[0].name, "linux_only");
        assert!(r.checks[0].required);
    }

    #[test]
    fn kind_is_bubblewrap() {
        assert_eq!(Bubblewrap::default().kind(), "bubblewrap");
    }
}
