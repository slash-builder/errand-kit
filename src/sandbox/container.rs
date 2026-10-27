//! The container backend: the container is the boundary; the Kit verifies and refuses.
//!
//! [`ContainerBoundary::verify`] reads `/proc` and the mount table and reports named [`Check`]s (`spec/ERRAND.md`
//! section 4). A failed *required* check makes `report.ok` false and the caller refuses the run. The medium-reliability
//! checks (cgroup limits, network interfaces) are reported but never refuse on their own.
//!
//! A hostile launcher can fake `/proc`; these checks catch a broken launcher, not a malicious one. Egress is open and
//! cannot be verified closed, so the report always says `egress: "open"`.
//!
//! Every filesystem location is injectable through [`ContainerRoots`] so the checks are tested against fake `/proc` trees.
//! Credential-shaped variables are reported by **name only**; a value is never read into a report, a log line or a
//! `Debug` output.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::contract::{BoundaryReport, Check};
use crate::sandbox::{credential_shaped, Sandbox, CREDENTIAL_PREFIXES, CREDENTIAL_SUFFIXES};

/// Directories under which a writable mount is allowed by default.
pub const DEFAULT_WRITABLE_ALLOWLIST: &[&str] = &["/tmp", "/home/runner", "/out", "/work"];

/// Where the checks look. [`ContainerRoots::real`] is the live system; tests point these at a temporary directory laid out
/// like `/proc`.
#[derive(Debug, Clone)]
pub struct ContainerRoots {
    /// The `/proc` directory (`self/status`, `<pid>/environ`, `net/dev`).
    pub proc_root: PathBuf,
    /// The mount table (normally `/proc/self/mountinfo`).
    pub mountinfo: PathBuf,
    /// The filesystem root: the write probe is created here, and the socket and cgroup paths are resolved under it.
    pub fs_root: PathBuf,
    /// The environment to inspect for `DOCKER_HOST` (normally this process's own).
    pub env: BTreeMap<String, String>,
    /// Mount points (and everything under them) that may be writable. They must also be `nosuid,nodev`.
    pub writable_allowlist: Vec<String>,
}

impl ContainerRoots {
    /// The real system paths and this process's environment.
    ///
    /// ```
    /// use errand_kit::sandbox::container::ContainerRoots;
    /// let r = ContainerRoots::real();
    /// assert_eq!(r.fs_root.to_str(), Some("/"));
    /// assert!(r.writable_allowlist.iter().any(|p| p == "/tmp"));
    /// ```
    pub fn real() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
            fs_root: PathBuf::from("/"),
            env: std::env::vars_os()
                .map(|(k, v)| {
                    (
                        k.to_string_lossy().into_owned(),
                        v.to_string_lossy().into_owned(),
                    )
                })
                .collect(),
            writable_allowlist: DEFAULT_WRITABLE_ALLOWLIST
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        }
    }
}

/// Verifies it is running inside a locked-down container.
///
/// ```
/// use errand_kit::sandbox::{container::ContainerBoundary, Sandbox};
/// let report = ContainerBoundary::new().verify();
/// assert_eq!(report.kind, "container");
/// assert_eq!(report.egress, "open");
/// // On a developer laptop this is a refusal; inside the locked-down container it passes.
/// assert!(!report.checks.is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct ContainerBoundary {
    roots: ContainerRoots,
}

impl Default for ContainerBoundary {
    fn default() -> Self {
        Self::new()
    }
}

impl ContainerBoundary {
    /// Check the real system.
    pub fn new() -> Self {
        Self {
            roots: ContainerRoots::real(),
        }
    }

    /// Check the given roots (for tests and for unusual layouts).
    pub fn with_roots(roots: ContainerRoots) -> Self {
        Self { roots }
    }

    /// Run every check against the configured roots **without** the Linux-only guard that [`Sandbox::verify`] applies.
    ///
    /// This exists so the checks can be exercised against a fake tree on any host. On a real run use
    /// [`Sandbox::verify`].
    pub fn verify_roots(&self) -> BoundaryReport {
        let r = &self.roots;
        let mounts = read_mounts(&r.mountinfo);
        let checks = vec![
            check_ids(&r.proc_root),
            check_caps(&r.proc_root),
            check_status_field(&r.proc_root, "no_new_privs", "NoNewPrivs", "1"),
            check_status_field(&r.proc_root, "seccomp_filter", "Seccomp", "2"),
            check_root_readonly(&mounts),
            check_root_write_fails(&r.fs_root),
            check_writable_mounts(&mounts, &r.writable_allowlist),
            check_writable_mount_flags(&mounts, &r.writable_allowlist),
            check_container_sockets(&r.fs_root, &r.env),
            check_proc_environ(&r.proc_root),
            check_cgroup(&r.fs_root, "cgroup_memory_limited", "memory.max"),
            check_cgroup(&r.fs_root, "cgroup_pids_limited", "pids.max"),
            check_net_interfaces(&r.proc_root),
        ];
        finish(checks)
    }
}

impl Sandbox for ContainerBoundary {
    fn kind(&self) -> &'static str {
        "container"
    }

    fn verify(&self) -> BoundaryReport {
        if !cfg!(target_os = "linux") {
            return finish(vec![Check {
                name: "linux_only".into(),
                ok: false,
                required: true,
                detail: "the container backend is Linux-only: /proc and the mount table are the evidence".into(),
            }]);
        }
        let report = self.verify_roots();
        for c in report.checks.iter().filter(|c| c.required && !c.ok) {
            tracing::warn!(check = %c.name, detail = %c.detail, "container boundary check failed");
        }
        report
    }
}

/// Assemble a report: `ok` only if every required check passed.
fn finish(checks: Vec<Check>) -> BoundaryReport {
    let ok = checks.iter().filter(|c| c.required).all(|c| c.ok);
    BoundaryReport {
        kind: "container".into(),
        ok,
        egress: "open".into(),
        checks,
    }
}

fn check(name: &str, required: bool, ok: bool, detail: impl Into<String>) -> Check {
    Check {
        name: name.into(),
        ok,
        required,
        detail: detail.into(),
    }
}

// ---- /proc/self/status -----------------------------------------------------------------------------------------------

/// The value text of `Key:` in a `/proc/<pid>/status`-style file.
fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k == key).then(|| v.trim())
    })
}

fn read_status(proc_root: &Path) -> Result<String, String> {
    let p = proc_root.join("self/status");
    fs::read_to_string(&p).map_err(|e| format!("cannot read {}: {}", p.display(), e.kind()))
}

fn check_ids(proc_root: &Path) -> Check {
    let status = match read_status(proc_root) {
        Ok(s) => s,
        Err(e) => return check("uid_nonzero", true, false, e),
    };
    let mut problems = Vec::new();
    let mut seen = Vec::new();
    for key in ["Uid", "Gid"] {
        match status_field(&status, key) {
            None => problems.push(format!("{key} line missing")),
            Some(v) => {
                let ids: Vec<&str> = v.split_whitespace().collect();
                if ids.len() != 4 {
                    problems.push(format!("{key} has {} values, expected 4", ids.len()));
                    continue;
                }
                for (slot, id) in ["real", "effective", "saved", "fs"].iter().zip(&ids) {
                    match id.parse::<u64>() {
                        Ok(0) => problems.push(format!("{key} {slot} is 0")),
                        Ok(_) => {}
                        Err(_) => problems.push(format!("{key} {slot} is not a number")),
                    }
                }
                seen.push(format!("{key}={}", ids.join("/")));
            }
        }
    }
    if problems.is_empty() {
        check("uid_nonzero", true, true, seen.join(" "))
    } else {
        check("uid_nonzero", true, false, problems.join("; "))
    }
}

fn check_caps(proc_root: &Path) -> Check {
    let status = match read_status(proc_root) {
        Ok(s) => s,
        Err(e) => return check("caps_zero", true, false, e),
    };
    let mut problems = Vec::new();
    for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        match status_field(&status, key) {
            None => problems.push(format!("{key} missing")),
            Some(v) => match u64::from_str_radix(v, 16) {
                Ok(0) => {}
                Ok(_) => problems.push(format!("{key}={v}")),
                Err(_) => problems.push(format!("{key} unparseable")),
            },
        }
    }
    if problems.is_empty() {
        check(
            "caps_zero",
            true,
            true,
            "CapInh, CapPrm, CapEff, CapBnd and CapAmb are all zero",
        )
    } else {
        check(
            "caps_zero",
            true,
            false,
            format!("capabilities present: {}", problems.join(", ")),
        )
    }
}

fn check_status_field(proc_root: &Path, name: &str, key: &str, want: &str) -> Check {
    let status = match read_status(proc_root) {
        Ok(s) => s,
        Err(e) => return check(name, true, false, e),
    };
    match status_field(&status, key) {
        Some(v) if v == want => check(name, true, true, format!("{key}: {v}")),
        Some(v) => check(name, true, false, format!("{key}: {v}, expected {want}")),
        None => check(name, true, false, format!("{key} line missing")),
    }
}

// ---- mounts ------------------------------------------------------------------------------------------------------------

#[derive(Debug)]
struct Mount {
    point: String,
    options: BTreeSet<String>,
    fstype: String,
}

/// Decode the `\040`-style octal escapes `mountinfo` uses for spaces and other awkward bytes.
fn unescape_mount(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            let v = u32::from(b[i + 1] - b'0') * 64
                + u32::from(b[i + 2] - b'0') * 8
                + u32::from(b[i + 3] - b'0');
            out.push(u8::try_from(v & 0xff).unwrap_or(b'?'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse `/proc/self/mountinfo`. `None` if the file is unreadable; unparseable lines are skipped.
fn read_mounts(path: &Path) -> Option<Vec<Mount>> {
    let text = fs::read_to_string(path).ok()?;
    let mut mounts = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        // id parent maj:min root mountpoint options [optional...] - fstype source superoptions
        let Some(dash) = f.iter().skip(6).position(|t| *t == "-").map(|i| i + 6) else {
            continue;
        };
        if f.len() < 6 || dash + 1 >= f.len() {
            continue;
        }
        mounts.push(Mount {
            point: unescape_mount(f[4]),
            options: f[5].split(',').map(str::to_owned).collect(),
            fstype: f[dash + 1].to_owned(),
        });
    }
    Some(mounts)
}

fn check_root_readonly(mounts: &Option<Vec<Mount>>) -> Check {
    let Some(mounts) = mounts else {
        return check("root_readonly", true, false, "mount table unreadable");
    };
    // The last "/" entry is the one on top.
    match mounts.iter().rev().find(|m| m.point == "/") {
        None => check(
            "root_readonly",
            true,
            false,
            "no mount for / in the mount table",
        ),
        Some(m) if m.options.contains("ro") => {
            check("root_readonly", true, true, "/ is mounted ro")
        }
        Some(_) => check("root_readonly", true, false, "/ is mounted read-write"),
    }
}

static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn check_root_write_fails(fs_root: &Path) -> Check {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let probe = fs_root.join(format!(
        ".errand-boundary-probe-{}-{nanos}-{n}",
        std::process::id()
    ));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(f) => {
            drop(f);
            let removed = fs::remove_file(&probe).is_ok();
            check(
                "root_write_fails",
                true,
                false,
                format!(
                    "a file could be created in {} (probe {})",
                    fs_root.display(),
                    if removed {
                        "removed"
                    } else {
                        "COULD NOT BE REMOVED"
                    }
                ),
            )
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => check(
            "root_write_fails",
            true,
            false,
            format!(
                "{} does not exist, so the write probe proves nothing",
                fs_root.display()
            ),
        ),
        Err(e) => check(
            "root_write_fails",
            true,
            true,
            format!("write to {} refused: {}", fs_root.display(), e.kind()),
        ),
    }
}

/// True if `path` is `base` or below it, by path component.
fn under(path: &str, base: &str) -> bool {
    let base = base.trim_end_matches('/');
    path == base
        || path
            .strip_prefix(base)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn check_writable_mounts(mounts: &Option<Vec<Mount>>, allowlist: &[String]) -> Check {
    let name = "writable_mounts_allowlisted";
    let Some(mounts) = mounts else {
        return check(name, true, false, "mount table unreadable");
    };
    let mut problems = Vec::new();
    let mut allowed = 0usize;
    for m in mounts.iter().filter(|m| m.options.contains("rw")) {
        if is_pseudo(m) {
            continue;
        }
        if allowlist.iter().any(|a| under(&m.point, a)) {
            allowed += 1;
        } else {
            problems.push(format!("{} is writable and not allowlisted", m.point));
        }
    }
    if problems.is_empty() {
        check(
            name,
            true,
            true,
            format!("{allowed} writable mount(s), all allowlisted"),
        )
    } else {
        check(name, true, false, problems.join("; "))
    }
}

/// Writable allowlisted mounts without `nosuid,nodev`. Reported but NOT required: a host bind mount (for example the
/// CI workspace behind `/out`) often lacks them, and with every capability dropped (no `mknod`) and `no-new-privileges`
/// (no setuid escalation), which are required checks of their own, the flags add little. Seen on Linux CI agents.
fn check_writable_mount_flags(mounts: &Option<Vec<Mount>>, allowlist: &[String]) -> Check {
    let name = "writable_mounts_nosuid_nodev";
    let Some(mounts) = mounts else {
        return check(name, false, false, "mount table unreadable");
    };
    let mut lacking = Vec::new();
    for m in mounts.iter().filter(|m| m.options.contains("rw")) {
        if is_pseudo(m) || !allowlist.iter().any(|a| under(&m.point, a)) {
            continue;
        }
        let missing: Vec<&str> = ["nosuid", "nodev"]
            .into_iter()
            .filter(|o| !m.options.contains(*o))
            .collect();
        if !missing.is_empty() {
            lacking.push(format!("{} lacks {}", m.point, missing.join(",")));
        }
    }
    if lacking.is_empty() {
        check(
            name,
            false,
            true,
            "all writable allowlisted mounts are nosuid,nodev",
        )
    } else {
        check(name, false, false, lacking.join("; "))
    }
}

/// Mounts at or under `/proc`, `/sys` or `/dev` of a pseudo filesystem type are exempt from the allowlist. A real
/// filesystem bind-mounted under `/dev` is not.
fn is_pseudo(m: &Mount) -> bool {
    (under(&m.point, "/proc") || under(&m.point, "/sys") || under(&m.point, "/dev"))
        && is_pseudo_fstype(&m.fstype)
}

fn is_pseudo_fstype(t: &str) -> bool {
    matches!(
        t,
        "proc"
            | "sysfs"
            | "cgroup"
            | "cgroup2"
            | "tmpfs"
            | "devtmpfs"
            | "devpts"
            | "mqueue"
            | "securityfs"
            | "debugfs"
            | "tracefs"
            | "bpf"
            | "pstore"
            | "configfs"
            | "fusectl"
            | "selinuxfs"
            | "efivarfs"
    )
}

// ---- sockets -----------------------------------------------------------------------------------------------------------

fn exists_nofollow(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

fn check_container_sockets(fs_root: &Path, env: &BTreeMap<String, String>) -> Check {
    let name = "no_container_sockets";
    let rel = |p: &str| fs_root.join(p.trim_start_matches('/'));
    let mut found: Vec<String> = Vec::new();
    for p in ["/var/run/docker.sock", "/run/docker.sock"] {
        if exists_nofollow(&rel(p)) {
            found.push(p.to_owned());
        }
    }
    if let Ok(rd) = fs::read_dir(rel("/run/containerd")) {
        for e in rd.flatten() {
            found.push(format!(
                "/run/containerd/{}",
                e.file_name().to_string_lossy()
            ));
        }
    }
    if let Ok(rd) = fs::read_dir(rel("/run")) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n.starts_with("podman") {
                found.push(format!("/run/{n}"));
            }
        }
    }
    found.sort();
    // The name only: DOCKER_HOST can carry credentials in its value.
    if env.contains_key("DOCKER_HOST") {
        found.push("DOCKER_HOST is set".to_owned());
    }
    if found.is_empty() {
        check(
            name,
            true,
            true,
            "no container runtime socket and DOCKER_HOST unset",
        )
    } else {
        check(name, true, false, format!("found: {}", found.join(", ")))
    }
}

// ---- /proc/*/environ ---------------------------------------------------------------------------------------------------

/// Upper bound on bytes read from one `environ`.
const ENVIRON_CAP: u64 = 4 * 1024 * 1024;

/// A report-safe label for a credential-shaped `environ` entry: the variable name, never any part of a value. An entry whose
/// name is not a plain identifier (or has no `=`, so the whole entry might be a value) is reduced to the matching prefix.
fn safe_label(entry: &[u8]) -> Option<String> {
    let name_bytes = match entry.iter().position(|b| *b == b'=') {
        Some(i) => &entry[..i],
        None => entry,
    };
    let lossy = String::from_utf8_lossy(name_bytes);
    if !credential_shaped(&lossy) {
        return None;
    }
    let plain = entry.contains(&b'=')
        && name_bytes.len() <= 128
        && name_bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_');
    if plain {
        return Some(lossy.into_owned());
    }
    // The name is not a plain identifier, so it might carry part of a value: report only the rule it matched, never the bytes.
    let rule = CREDENTIAL_PREFIXES
        .iter()
        .find(|p| lossy.starts_with(**p))
        .map(|p| format!("{p}..."))
        .or_else(|| {
            CREDENTIAL_SUFFIXES
                .iter()
                .find(|s| lossy.ends_with(**s))
                .map(|s| format!("...{s}"))
        })
        .unwrap_or_else(|| "credential-shaped".to_string());
    Some(format!("{rule} <unprintable name>"))
}

fn check_proc_environ(proc_root: &Path) -> Check {
    let name = "proc_environ_clean";
    let rd = match fs::read_dir(proc_root) {
        Ok(rd) => rd,
        Err(e) => {
            return check(
                name,
                true,
                false,
                format!("cannot list {}: {}", proc_root.display(), e.kind()),
            )
        }
    };
    let mut pids: Vec<(String, PathBuf)> = rd
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            (!n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())).then(|| (n, e.path()))
        })
        .collect();
    pids.sort();
    let (mut readable, mut unreadable) = (0usize, 0usize);
    let mut hits: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (pid, dir) in &pids {
        let mut buf = Vec::new();
        let read = fs::File::open(dir.join("environ"))
            .and_then(|f| f.take(ENVIRON_CAP).read_to_end(&mut buf));
        if read.is_err() {
            unreadable += 1;
            continue;
        }
        readable += 1;
        for entry in buf.split(|b| *b == 0).filter(|e| !e.is_empty()) {
            if let Some(label) = safe_label(entry) {
                hits.entry(label).or_default().insert(pid.clone());
            }
        }
        // `buf` held values; do not let it outlive this iteration.
        drop(buf);
    }
    if !hits.is_empty() {
        let list: Vec<String> = hits
            .iter()
            .map(|(n, p)| {
                format!(
                    "{n} (pid {})",
                    p.iter().cloned().collect::<Vec<_>>().join(",")
                )
            })
            .collect();
        return check(
            name,
            true,
            false,
            format!(
                "credential-shaped variable names present: {}; {readable} environ file(s) scanned",
                list.join(", ")
            ),
        );
    }
    if readable == 0 {
        return check(
            name,
            true,
            false,
            format!(
                "no process environ was readable ({unreadable} unreadable): nothing was proven"
            ),
        );
    }
    let note = if unreadable > 0 {
        format!("; {unreadable} not readable (other users)")
    } else {
        String::new()
    };
    check(
        name,
        true,
        true,
        format!("{readable} environ file(s) scanned, no credential-shaped names{note}"),
    )
}

// ---- medium-reliability checks (reported, never refuse) --------------------------------------------------------------

fn check_cgroup(fs_root: &Path, name: &str, file: &str) -> Check {
    let p = fs_root.join("sys/fs/cgroup").join(file);
    match fs::read_to_string(&p) {
        Err(e) => check(
            name,
            false,
            false,
            format!(
                "cannot read {} (cgroup v2 expected): {}",
                p.display(),
                e.kind()
            ),
        ),
        Ok(v) => {
            let v = v.trim();
            if v == "max" || v.is_empty() {
                check(name, false, false, format!("{file} is unlimited"))
            } else {
                check(name, false, true, format!("{file} = {v}"))
            }
        }
    }
}

fn check_net_interfaces(proc_root: &Path) -> Check {
    let name = "net_interfaces_minimal";
    let p = proc_root.join("net/dev");
    let text = match fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) => {
            return check(
                name,
                false,
                false,
                format!("cannot read {}: {}", p.display(), e.kind()),
            )
        }
    };
    let ifaces: Vec<&str> = text
        .lines()
        .skip(2)
        .filter_map(|l| l.split_once(':').map(|(n, _)| n.trim()))
        .filter(|n| !n.is_empty())
        .collect();
    // The kernel creates fallback tunnel devices in every network namespace when their modules are loaded (Docker Desktop's
    // VM does); they are down, carry no traffic and are not a sign of a shared network namespace.
    const FALLBACK: &[&str] = &[
        "tunl0", "gre0", "gretap0", "erspan0", "ip_vti0", "ip6_vti0", "sit0", "ip6tnl0", "ip6gre0",
    ];
    let others = ifaces
        .iter()
        .filter(|n| **n != "lo" && !FALLBACK.contains(*n))
        .count();
    if others <= 1 {
        check(
            name,
            false,
            true,
            format!("interfaces: {}", ifaces.join(", ")),
        )
    } else {
        check(
            name,
            false,
            false,
            format!("{others} non-loopback interfaces: {}", ifaces.join(", ")),
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use tempfile::TempDir;

    const STATUS_CLEAN: &str = "Name:\tworker\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n\
CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\n\
CapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n";

    const MOUNTINFO_CLEAN: &str = "\
24 1 0:21 / / ro,relatime - overlay overlay rw,lowerdir=/a\n\
25 24 0:22 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n\
26 24 0:23 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755\n\
27 26 0:24 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k\n\
28 24 0:25 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro\n\
29 24 8:1 /tmp /tmp rw,nosuid,nodev,relatime - ext4 /dev/sda1 rw\n\
30 24 8:1 /out /out rw,nosuid,nodev,relatime - ext4 /dev/sda1 rw\n\
31 24 8:1 /home /home/runner rw,nosuid,nodev,relatime - ext4 /dev/sda1 rw\n";

    /// A fake host: a `/proc` laid out like the real one, a mount table, a filesystem root and the allowlist.
    struct Fake {
        dir: TempDir,
        env: BTreeMap<String, String>,
    }

    impl Fake {
        /// A tree in which every check passes.
        fn clean() -> Self {
            let f = Self {
                dir: tempfile::tempdir().unwrap(),
                env: BTreeMap::new(),
            };
            f.write("proc/self/status", STATUS_CLEAN);
            f.write(
                "proc/1/environ",
                "PATH=/usr/bin\0HOME=/tmp\0CLAUDE_CODE_OAUTH_TOKEN=tok-123\0",
            );
            f.write("proc/42/environ", "LANG=C\0");
            f.write(
                "proc/net/dev",
                "Inter-|   Receive\n face |bytes\n    lo: 1 2\n  eth0: 3 4\n",
            );
            f.write("mountinfo", MOUNTINFO_CLEAN);
            f.write("root/sys/fs/cgroup/memory.max", "536870912\n");
            f.write("root/sys/fs/cgroup/pids.max", "256\n");
            // The fake filesystem root is made read-only so the write probe is refused, as on a real ro rootfs.
            f.set_root_readonly(true);
            f
        }

        fn write(&self, rel: &str, body: &str) {
            let p = self.dir.path().join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, body).unwrap();
        }

        fn root(&self) -> PathBuf {
            self.dir.path().join("root")
        }

        fn set_root_readonly(&self, ro: bool) {
            use std::os::unix::fs::PermissionsExt;
            let mode = if ro { 0o555 } else { 0o755 };
            fs::set_permissions(self.root(), fs::Permissions::from_mode(mode)).unwrap();
        }

        fn boundary(&self) -> ContainerBoundary {
            ContainerBoundary::with_roots(ContainerRoots {
                proc_root: self.dir.path().join("proc"),
                mountinfo: self.dir.path().join("mountinfo"),
                fs_root: self.root(),
                env: self.env.clone(),
                writable_allowlist: DEFAULT_WRITABLE_ALLOWLIST
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
            })
        }

        fn report(&self) -> BoundaryReport {
            self.boundary().verify_roots()
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            // Let TempDir clean up a root we made read-only.
            self.set_root_readonly(false);
        }
    }

    fn get<'a>(r: &'a BoundaryReport, name: &str) -> &'a Check {
        r.checks
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no check {name}"))
    }

    /// Running as uid 0 ignores directory permissions, so the read-only-root probe cannot be simulated there.
    fn running_as_root() -> bool {
        fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| status_field(&s, "Uid").map(|v| v.split_whitespace().next() == Some("0")))
            .unwrap_or(false)
    }

    fn assert_only_fails(r: &BoundaryReport, name: &str) {
        for c in &r.checks {
            assert_eq!(c.ok, c.name != name, "{}: {} ({})", c.name, c.ok, c.detail);
        }
    }

    #[test]
    fn clean_tree_passes_with_every_named_check() {
        if running_as_root() {
            return;
        }
        let r = Fake::clean().report();
        assert!(r.ok, "{r:#?}");
        assert_eq!(r.kind, "container");
        assert_eq!(r.egress, "open");
        let names: Vec<_> = r.checks.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "uid_nonzero",
                "caps_zero",
                "no_new_privs",
                "seccomp_filter",
                "root_readonly",
                "root_write_fails",
                "writable_mounts_allowlisted",
                "writable_mounts_nosuid_nodev",
                "no_container_sockets",
                "proc_environ_clean",
                "cgroup_memory_limited",
                "cgroup_pids_limited",
                "net_interfaces_minimal"
            ]
        );
        let optional = [
            "writable_mounts_nosuid_nodev",
            "cgroup_memory_limited",
            "cgroup_pids_limited",
            "net_interfaces_minimal",
        ];
        for c in &r.checks {
            assert_eq!(
                c.required,
                !optional.contains(&c.name.as_str()),
                "{}",
                c.name
            );
            assert!(c.ok, "{}: {}", c.name, c.detail);
        }
    }

    #[test]
    fn uid_zero_in_any_slot_fails() {
        for line in [
            "Uid:\t0\t1000\t1000\t1000",
            "Uid:\t1000\t0\t1000\t1000",
            "Uid:\t1000\t1000\t0\t1000",
            "Uid:\t1000\t1000\t1000\t0",
        ] {
            let f = Fake::clean();
            f.write(
                "proc/self/status",
                &STATUS_CLEAN.replace("Uid:\t1000\t1000\t1000\t1000", line),
            );
            let c = f.report();
            let c = get(&c, "uid_nonzero");
            assert!(!c.ok && c.required, "{line}");
        }
    }

    #[test]
    fn gid_zero_fails() {
        let f = Fake::clean();
        f.write(
            "proc/self/status",
            &STATUS_CLEAN.replace("Gid:\t1000\t1000\t1000\t1000", "Gid:\t1000\t1000\t1000\t0"),
        );
        let r = f.report();
        assert!(!get(&r, "uid_nonzero").ok);
        assert!(!r.ok);
    }

    #[test]
    fn short_or_missing_id_lines_fail() {
        let f = Fake::clean();
        f.write(
            "proc/self/status",
            &STATUS_CLEAN.replace("Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000"),
        );
        assert!(!get(&f.report(), "uid_nonzero").ok);
        f.write("proc/self/status", "NoNewPrivs:\t1\nSeccomp:\t2\n");
        assert!(!get(&f.report(), "uid_nonzero").ok);
    }

    #[test]
    fn each_capability_set_must_be_zero() {
        for key in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
            let f = Fake::clean();
            let from = format!("{key}:\t0000000000000000");
            let to = format!("{key}:\t00000000a80425fb");
            f.write("proc/self/status", &STATUS_CLEAN.replace(&from, &to));
            let r = f.report();
            let c = get(&r, "caps_zero");
            assert!(!c.ok && c.required, "{key}");
            assert!(c.detail.contains(key), "{}", c.detail);
            assert!(!r.ok);
        }
    }

    #[test]
    fn missing_capability_line_fails() {
        let f = Fake::clean();
        f.write(
            "proc/self/status",
            &STATUS_CLEAN.replace("CapAmb:\t0000000000000000\n", ""),
        );
        assert!(!get(&f.report(), "caps_zero").ok);
    }

    #[test]
    fn no_new_privs_must_be_one() {
        let f = Fake::clean();
        f.write(
            "proc/self/status",
            &STATUS_CLEAN.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        );
        let r = f.report();
        assert!(!get(&r, "no_new_privs").ok && get(&r, "no_new_privs").required);
        assert!(!r.ok);
    }

    #[test]
    fn seccomp_must_be_filter_mode() {
        for v in ["0", "1"] {
            let f = Fake::clean();
            f.write(
                "proc/self/status",
                &STATUS_CLEAN.replace("Seccomp:\t2", &format!("Seccomp:\t{v}")),
            );
            let r = f.report();
            assert!(!get(&r, "seccomp_filter").ok, "Seccomp {v}");
            assert!(!r.ok);
        }
    }

    #[test]
    fn unreadable_status_fails_the_status_checks() {
        let f = Fake::clean();
        fs::remove_file(f.dir.path().join("proc/self/status")).unwrap();
        let r = f.report();
        for n in ["uid_nonzero", "caps_zero", "no_new_privs", "seccomp_filter"] {
            assert!(!get(&r, n).ok, "{n}");
        }
    }

    #[test]
    fn writable_root_fails_root_readonly() {
        let f = Fake::clean();
        f.write(
            "mountinfo",
            &MOUNTINFO_CLEAN.replace("/ / ro,relatime", "/ / rw,relatime"),
        );
        let r = f.report();
        assert!(!get(&r, "root_readonly").ok && get(&r, "root_readonly").required);
        assert!(!r.ok);
    }

    #[test]
    fn a_later_rw_mount_over_root_wins() {
        let f = Fake::clean();
        let extra = "99 24 0:50 / / rw,relatime - overlay overlay rw\n";
        f.write("mountinfo", &format!("{MOUNTINFO_CLEAN}{extra}"));
        assert!(!get(&f.report(), "root_readonly").ok);
    }

    #[test]
    fn missing_mount_table_fails_both_mount_checks() {
        let f = Fake::clean();
        fs::remove_file(f.dir.path().join("mountinfo")).unwrap();
        let r = f.report();
        assert!(!get(&r, "root_readonly").ok);
        assert!(!get(&r, "writable_mounts_allowlisted").ok);
    }

    #[test]
    fn writable_root_filesystem_fails_the_write_probe_and_cleans_up() {
        if running_as_root() {
            return;
        }
        let f = Fake::clean();
        f.set_root_readonly(false);
        let r = f.report();
        let c = get(&r, "root_write_fails");
        assert!(!c.ok && c.required, "{}", c.detail);
        assert!(c.detail.contains("removed"), "{}", c.detail);
        assert!(!r.ok);
        assert_eq!(
            fs::read_dir(f.root())
                .unwrap()
                .filter(|e| e.as_ref().is_ok_and(|e| e
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".errand-boundary-probe")))
                .count(),
            0
        );
    }

    #[test]
    fn readonly_root_refuses_the_probe() {
        if running_as_root() {
            return;
        }
        let r = Fake::clean().report();
        let c = get(&r, "root_write_fails");
        assert!(c.ok, "{}", c.detail);
        assert!(c.detail.contains("refused"));
    }

    #[test]
    fn missing_fs_root_does_not_count_as_a_refused_write() {
        let f = Fake::clean();
        let mut roots = ContainerRoots::real();
        roots.fs_root = f.dir.path().join("no/such/root");
        roots.proc_root = f.dir.path().join("proc");
        roots.mountinfo = f.dir.path().join("mountinfo");
        let r = ContainerBoundary::with_roots(roots).verify_roots();
        let c = get(&r, "root_write_fails");
        assert!(!c.ok && c.detail.contains("proves nothing"), "{}", c.detail);
    }

    #[test]
    fn unallowlisted_writable_mount_fails() {
        let f = Fake::clean();
        let extra = "40 24 8:2 / /data rw,nosuid,nodev - ext4 /dev/sdb rw\n";
        f.write("mountinfo", &format!("{MOUNTINFO_CLEAN}{extra}"));
        let r = f.report();
        let c = get(&r, "writable_mounts_allowlisted");
        assert!(!c.ok && c.required);
        assert!(c.detail.contains("/data"), "{}", c.detail);
        assert!(!r.ok);
    }

    #[test]
    fn a_missing_nosuid_nodev_is_reported_but_does_not_refuse_the_run() {
        for (opts, missing) in [
            ("rw,relatime", "nosuid,nodev"),
            ("rw,nosuid,relatime", "nodev"),
            ("rw,nodev,relatime", "nosuid"),
        ] {
            let f = Fake::clean();
            let extra = format!("40 24 8:1 /w /work {opts} - ext4 /dev/sda1 rw\n");
            f.write("mountinfo", &format!("{MOUNTINFO_CLEAN}{extra}"));
            let r = f.report();
            // The allowlist check still passes, the run is not refused, and the flags check says what is missing.
            assert!(get(&r, "writable_mounts_allowlisted").ok, "{opts}");
            assert!(r.ok, "{opts}: {r:#?}");
            let c = get(&r, "writable_mounts_nosuid_nodev");
            assert!(!c.ok && !c.required, "{opts}");
            assert!(c.detail.contains(missing), "{}", c.detail);
        }
    }

    #[test]
    fn allowlist_matches_by_path_component() {
        let f = Fake::clean();
        // /tmpfoo is not under /tmp.
        let extra = "40 24 8:1 /x /tmpfoo rw,nosuid,nodev - ext4 /dev/sda1 rw\n";
        f.write("mountinfo", &format!("{MOUNTINFO_CLEAN}{extra}"));
        assert!(!get(&f.report(), "writable_mounts_allowlisted").ok);
        // A mount below an allowlisted directory is allowed.
        let f = Fake::clean();
        let extra = "40 24 8:1 /x /tmp/sub rw,nosuid,nodev - ext4 /dev/sda1 rw\n";
        f.write("mountinfo", &format!("{MOUNTINFO_CLEAN}{extra}"));
        assert!(get(&f.report(), "writable_mounts_allowlisted").ok);
    }

    #[test]
    fn real_filesystem_under_dev_is_not_exempt() {
        let f = Fake::clean();
        let extra = "40 24 8:2 / /dev/sneaky rw,nosuid,nodev - ext4 /dev/sdb rw\n";
        f.write("mountinfo", &format!("{MOUNTINFO_CLEAN}{extra}"));
        let c = f.report();
        let c = get(&c, "writable_mounts_allowlisted");
        assert!(!c.ok && c.detail.contains("/dev/sneaky"), "{}", c.detail);
    }

    #[test]
    fn custom_allowlist_is_honoured() {
        let f = Fake::clean();
        let extra = "40 24 8:2 / /data rw,nosuid,nodev - ext4 /dev/sdb rw\n";
        f.write("mountinfo", &format!("{MOUNTINFO_CLEAN}{extra}"));
        let mut roots = ContainerRoots::real();
        roots.proc_root = f.dir.path().join("proc");
        roots.mountinfo = f.dir.path().join("mountinfo");
        roots.fs_root = f.root();
        roots.writable_allowlist = vec![
            "/tmp".into(),
            "/out".into(),
            "/home/runner".into(),
            "/data".into(),
        ];
        let r = ContainerBoundary::with_roots(roots).verify_roots();
        assert!(get(&r, "writable_mounts_allowlisted").ok);
    }

    #[test]
    fn mount_points_with_escaped_spaces_are_decoded() {
        assert_eq!(unescape_mount("/a\\040b"), "/a b");
        assert_eq!(unescape_mount("/plain"), "/plain");
        assert_eq!(unescape_mount("/trailing\\"), "/trailing\\");
        let f = Fake::clean();
        let extra = "40 24 8:1 /x /tmp/my\\040dir rw,nosuid,nodev - ext4 /dev/sda1 rw\n";
        f.write("mountinfo", &format!("{MOUNTINFO_CLEAN}{extra}"));
        assert!(get(&f.report(), "writable_mounts_allowlisted").ok);
    }

    #[test]
    fn container_sockets_each_fail() {
        for rel in [
            "var/run/docker.sock",
            "run/docker.sock",
            "run/containerd/containerd.sock",
            "run/podman/podman.sock",
            "run/podman.sock",
        ] {
            let f = Fake::clean();
            f.set_root_readonly(false);
            f.write(&format!("root/{rel}"), "");
            f.set_root_readonly(true);
            let r = f.report();
            let c = get(&r, "no_container_sockets");
            assert!(!c.ok && c.required, "{rel}");
            assert!(!r.ok);
        }
    }

    #[test]
    fn dangling_docker_socket_symlink_counts() {
        use std::os::unix::fs::symlink;
        let f = Fake::clean();
        f.set_root_readonly(false);
        fs::create_dir_all(f.root().join("var/run")).unwrap();
        symlink("/nowhere", f.root().join("var/run/docker.sock")).unwrap();
        f.set_root_readonly(true);
        assert!(!get(&f.report(), "no_container_sockets").ok);
    }

    #[test]
    fn docker_host_fails_without_printing_its_value() {
        let mut f = Fake::clean();
        f.env
            .insert("DOCKER_HOST".into(), "tcp://user:hunter2@host:2375".into());
        let r = f.report();
        let c = get(&r, "no_container_sockets");
        assert!(!c.ok);
        assert!(c.detail.contains("DOCKER_HOST"));
        assert!(!serde_json::to_string(&r).unwrap().contains("hunter2"));
    }

    #[test]
    fn credential_name_in_another_pid_fails_and_the_value_never_appears() {
        let f = Fake::clean();
        f.write(
            "proc/777/environ",
            "PATH=/bin\0AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI-super-secret\0GH_TOKEN=ghp_topsecret\0",
        );
        let r = f.report();
        let c = get(&r, "proc_environ_clean");
        assert!(!c.ok && c.required);
        assert!(c.detail.contains("AWS_SECRET_ACCESS_KEY") && c.detail.contains("GH_TOKEN"));
        assert!(c.detail.contains("777"));
        assert!(!r.ok);
        let json = serde_json::to_string(&r).unwrap();
        let debug = format!("{r:?} {r:#?}");
        for secret in [
            "wJalrXUtnFEMI",
            "super-secret",
            "ghp_topsecret",
            "topsecret",
        ] {
            assert!(!json.contains(secret), "{secret} in JSON");
            assert!(!debug.contains(secret), "{secret} in Debug");
        }
    }

    #[test]
    fn the_workers_own_oauth_token_is_not_a_credential_name() {
        let f = Fake::clean();
        f.write("proc/5/environ", "CLAUDE_CODE_OAUTH_TOKEN=tok\0");
        let r = f.report();
        assert!(get(&r, "proc_environ_clean").ok);
    }

    #[test]
    fn every_listed_prefix_is_caught() {
        for name in [
            "AWS_X",
            "GITHUB_X",
            "GH_X",
            "CLOUDFLARE_X",
            "TF_X",
            "SLACK_X",
            "OPENAI_X",
            "GOOGLE_X",
            "ANTHROPIC_API_KEY",
            "DOCKER_X",
            "DB_PASSWORD",
            "STRIPE_SECRET_KEY",
            "NPM_TOKEN",
            "SERVICE_API_KEY",
        ] {
            let f = Fake::clean();
            f.write("proc/9/environ", &format!("{name}=v\0"));
            let r = f.report();
            let c = get(&r, "proc_environ_clean");
            assert!(!c.ok, "{name}");
            assert!(c.detail.contains(name), "{}", c.detail);
        }
    }

    #[test]
    fn credential_name_in_own_environ_fails() {
        let f = Fake::clean();
        f.write("proc/1/environ", "TF_VAR_x=secret-value\0");
        let r = f.report();
        assert!(!get(&r, "proc_environ_clean").ok);
        assert!(!serde_json::to_string(&r).unwrap().contains("secret-value"));
    }

    #[test]
    fn malformed_entries_never_leak_a_value() {
        let f = Fake::clean();
        // No '=' (the whole entry may be a value) and a name with unprintable bytes.
        f.write(
            "proc/8/environ",
            "AWS_this-looks-like-a-pasted-secret\0GH_\"quoted;rm -rf\"=v\0",
        );
        let r = f.report();
        let c = get(&r, "proc_environ_clean");
        assert!(!c.ok);
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("pasted-secret"));
        assert!(!json.contains("rm -rf"));
        assert!(c.detail.contains("AWS_") && c.detail.contains("GH_"));
    }

    #[test]
    fn non_numeric_proc_entries_are_not_scanned() {
        let f = Fake::clean();
        f.write("proc/self/environ", "AWS_X=1\0");
        f.write("proc/thread-self/environ", "AWS_X=1\0");
        assert!(get(&f.report(), "proc_environ_clean").ok);
    }

    #[test]
    fn nothing_readable_proves_nothing() {
        let f = Fake::clean();
        fs::remove_file(f.dir.path().join("proc/1/environ")).unwrap();
        fs::remove_file(f.dir.path().join("proc/42/environ")).unwrap();
        let r = f.report();
        let c = get(&r, "proc_environ_clean");
        assert!(
            !c.ok && c.detail.contains("nothing was proven"),
            "{}",
            c.detail
        );
    }

    #[test]
    fn unreadable_environ_files_are_counted_not_fatal() {
        let f = Fake::clean();
        fs::create_dir_all(f.dir.path().join("proc/300")).unwrap(); // pid dir without an environ file
        let r = f.report();
        let c = get(&r, "proc_environ_clean");
        assert!(c.ok, "{}", c.detail);
        assert!(c.detail.contains("1 not readable"), "{}", c.detail);
    }

    #[test]
    fn non_required_failures_leave_ok_true() {
        if running_as_root() {
            return;
        }
        let f = Fake::clean();
        f.write("root/sys/fs/cgroup/memory.max", "max\n");
        f.write("root/sys/fs/cgroup/pids.max", "max\n");
        f.write("proc/net/dev", "h\nh\n lo: 1\n eth0: 1\n eth1: 1\n");
        f.set_root_readonly(true);
        let r = f.report();
        assert!(r.ok, "{r:#?}");
        for n in [
            "cgroup_memory_limited",
            "cgroup_pids_limited",
            "net_interfaces_minimal",
        ] {
            let c = get(&r, n);
            assert!(!c.ok && !c.required, "{n}");
        }
    }

    #[test]
    fn missing_cgroup_and_net_files_are_reported_not_fatal() {
        if running_as_root() {
            return;
        }
        let f = Fake::clean();
        fs::remove_dir_all(f.root().join("sys")).ok();
        fs::remove_file(f.dir.path().join("proc/net/dev")).unwrap();
        let r = f.report();
        assert!(r.ok, "{r:#?}");
        assert!(!get(&r, "cgroup_memory_limited").ok);
        assert!(!get(&r, "net_interfaces_minimal").ok);
    }

    #[test]
    fn kernel_fallback_tunnel_devices_are_not_counted() {
        let f = Fake::clean();
        f.write(
            "proc/net/dev",
            "h\nh\n lo: 1\n tunl0: 0\n gre0: 0\n gretap0: 0\n erspan0: 0\n ip_vti0: 0\n ip6_vti0: 0\n sit0: 0\n ip6tnl0: 0\n ip6gre0: 0\n eth0: 1\n",
        );
        let r = f.report();
        assert!(get(&r, "net_interfaces_minimal").ok);
    }

    #[test]
    fn loopback_only_is_minimal() {
        let f = Fake::clean();
        f.write("proc/net/dev", "h\nh\n    lo: 1 2\n");
        assert!(get(&f.report(), "net_interfaces_minimal").ok);
    }

    #[test]
    fn a_required_failure_alone_refuses_the_run() {
        if running_as_root() {
            return;
        }
        let f = Fake::clean();
        f.write(
            "proc/self/status",
            &STATUS_CLEAN.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        );
        let r = f.report();
        assert!(!r.ok);
        assert_only_fails(&r, "no_new_privs");
    }

    #[test]
    fn report_round_trips_as_json() {
        let r = Fake::clean().report();
        let json = serde_json::to_string(&r).unwrap();
        let back: BoundaryReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn off_linux_verify_is_a_single_required_refusal() {
        let r = ContainerBoundary::new().verify();
        assert!(!r.ok);
        assert_eq!(r.checks.len(), 1);
        assert!(r.checks[0].required && !r.checks[0].ok);
        assert!(r.checks[0].detail.contains("Linux-only"));
        // Even a perfect fake tree cannot make a non-Linux host pass through the public entry point.
        let r = Fake::clean().boundary().verify();
        assert!(!r.ok);
    }

    #[test]
    fn kind_is_container_and_wrap_is_identity() {
        let b = ContainerBoundary::new();
        assert_eq!(b.kind(), "container");
        let cmd = b.wrap(std::process::Command::new("echo"));
        assert_eq!(cmd.get_program(), "echo");
    }
}
