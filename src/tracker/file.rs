//! A tracker backed by a directory of JSON tickets.
//!
//! Layout under `root`:
//!
//! * `tickets/<KEY>.json`: `{key, summary, body, labels, repo}`; labels are rewritten into this file atomically
//!   (write a temp file, then rename).
//! * `comments/<KEY>.log`: one JSON string per line, appended.
//!
//! A ticket key must match `^[A-Za-z][A-Za-z0-9]*-[0-9]+$` (ASCII only) before it is used to build any path, so a key can
//! never traverse out of `root`. Missing or unparsable files are errors; the only "empty" case is a ticket that has no
//! comment log yet. There is no cross-process locking: one writer per root is assumed.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::tracker::memory::is_ready;
use crate::tracker::{Ticket, Tracker};
use crate::{ErrandError, Result};

/// Whether `key` matches `^[A-Za-z][A-Za-z0-9]*-[0-9]+$` (ASCII only; no trailing newline tolerated).
///
/// ```
/// use errand_kit::tracker::file::is_valid_key;
/// assert!(is_valid_key("SOF-12"));
/// assert!(!is_valid_key("../x"));
/// assert!(!is_valid_key(""));
/// assert!(!is_valid_key("SOF-1\n"));
/// ```
pub fn is_valid_key(key: &str) -> bool {
    let Some((head, digits)) = key.split_once('-') else {
        return false;
    };
    let mut chars = head.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
    first_ok
        && chars.all(|c| c.is_ascii_alphanumeric())
        && !digits.is_empty()
        && digits.chars().all(|c| c.is_ascii_digit())
}

#[derive(Debug, Serialize, Deserialize)]
struct TicketFile {
    key: String,
    summary: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    labels: Vec<String>,
    #[serde(default)]
    repo: Option<String>,
}

impl From<TicketFile> for Ticket {
    fn from(f: TicketFile) -> Self {
        Ticket {
            key: f.key,
            summary: f.summary,
            body: f.body,
            labels: f.labels,
            repo: f.repo,
        }
    }
}

impl From<&Ticket> for TicketFile {
    fn from(t: &Ticket) -> Self {
        TicketFile {
            key: t.key.clone(),
            summary: t.summary.clone(),
            body: t.body.clone(),
            labels: t.labels.clone(),
            repo: t.repo.clone(),
        }
    }
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `bytes` to `path` atomically: a uniquely named temp file in the same directory, synced, then renamed over it.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.{}.{n}.tmp", std::process::id()));
    let result = (|| {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(ErrandError::io(path, e));
    }
    Ok(())
}

/// Tickets as files under a directory.
#[derive(Debug, Clone)]
pub struct FileTracker {
    /// The root directory (holds `tickets/` and `comments/`).
    pub root: PathBuf,
}

impl FileTracker {
    /// A tracker rooted at `root`. Nothing is created until a ticket is written.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn check_key(key: &str) -> Result<()> {
        if is_valid_key(key) {
            Ok(())
        } else {
            Err(ErrandError::Tracker(format!(
                "invalid ticket key {key:?}: must match ^[A-Za-z][A-Za-z0-9]*-[0-9]+$"
            )))
        }
    }

    fn ticket_path(&self, key: &str) -> Result<PathBuf> {
        Self::check_key(key)?;
        Ok(self.root.join("tickets").join(format!("{key}.json")))
    }

    fn comments_path(&self, key: &str) -> Result<PathBuf> {
        Self::check_key(key)?;
        Ok(self.root.join("comments").join(format!("{key}.log")))
    }

    fn read_ticket_file(path: &Path, expected_key: &str) -> Result<TicketFile> {
        let text = fs::read_to_string(path).map_err(|e| ErrandError::io(path, e))?;
        let file: TicketFile = serde_json::from_str(&text)?;
        if file.key != expected_key {
            return Err(ErrandError::Tracker(format!(
                "ticket file {} holds key {:?}, expected {expected_key:?}",
                path.display(),
                file.key
            )));
        }
        Ok(file)
    }

    fn write_ticket_file(&self, file: &TicketFile) -> Result<()> {
        let path = self.ticket_path(&file.key)?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| ErrandError::io(dir, e))?;
        }
        let mut bytes = serde_json::to_vec_pretty(file)?;
        bytes.push(b'\n');
        write_atomic(&path, &bytes)
    }

    /// Create or replace a ticket file (used to seed a tracker). The key is validated.
    pub fn write_ticket(&self, ticket: &Ticket) -> Result<()> {
        self.write_ticket_file(&TicketFile::from(ticket))
    }

    /// Read one ticket. An unknown key is an error.
    pub fn ticket(&self, key: &str) -> Result<Ticket> {
        let path = self.ticket_path(key)?;
        Ok(Self::read_ticket_file(&path, key)?.into())
    }

    /// All comments on `key`, oldest first. A ticket with no comment log yet has none; an unknown ticket is an error.
    pub fn comments(&self, key: &str) -> Result<Vec<String>> {
        let ticket_path = self.ticket_path(key)?;
        if !ticket_path.is_file() {
            return Err(ErrandError::Tracker(format!("unknown ticket {key:?}")));
        }
        let log = self.comments_path(key)?;
        let text = match fs::read_to_string(&log) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(ErrandError::io(&log, e)),
        };
        text.lines()
            .map(|line| serde_json::from_str::<String>(line).map_err(ErrandError::from))
            .collect()
    }
}

impl Tracker for FileTracker {
    fn ready(&self) -> Result<Vec<Ticket>> {
        let dir = self.root.join("tickets");
        let entries = fs::read_dir(&dir).map_err(|e| ErrandError::io(&dir, e))?;
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| ErrandError::io(&dir, e))?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default()
                .to_string();
            if !is_valid_key(&stem) {
                tracing::warn!(path = %path.display(), "file tracker: skipping json file whose name is not a ticket key");
                continue;
            }
            let ticket: Ticket = Self::read_ticket_file(&path, &stem)?.into();
            if is_ready(&ticket.labels) {
                out.push(ticket);
            }
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }

    fn comments_contain(&self, key: &str, marker: &str) -> Result<bool> {
        Ok(self.comments(key)?.iter().any(|c| c.contains(marker)))
    }

    fn post_comment(&self, key: &str, body: &str) -> Result<()> {
        let ticket_path = self.ticket_path(key)?;
        if !ticket_path.is_file() {
            return Err(ErrandError::Tracker(format!("unknown ticket {key:?}")));
        }
        let log = self.comments_path(key)?;
        if let Some(dir) = log.parent() {
            fs::create_dir_all(dir).map_err(|e| ErrandError::io(dir, e))?;
        }
        let mut line = serde_json::to_string(body)?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&log)
            .map_err(|e| ErrandError::io(&log, e))?;
        // One write call per line, then sync: a crash leaves either the whole line or (rarely) a torn one that reads as an error.
        f.write_all(line.as_bytes())
            .map_err(|e| ErrandError::io(&log, e))?;
        f.sync_all().map_err(|e| ErrandError::io(&log, e))?;
        Ok(())
    }

    fn add_label(&self, key: &str, label: &str) -> Result<()> {
        let path = self.ticket_path(key)?;
        let mut file = Self::read_ticket_file(&path, key)?;
        if file.labels.iter().any(|l| l == label) {
            return Ok(());
        }
        file.labels.push(label.to_string());
        self.write_ticket_file(&file)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn ticket(key: &str, labels: &[&str]) -> Ticket {
        Ticket {
            key: key.into(),
            summary: format!("sum {key}"),
            body: "body".into(),
            labels: labels.iter().map(|s| s.to_string()).collect(),
            repo: Some("o/r".into()),
        }
    }

    fn tracker() -> (tempfile::TempDir, FileTracker) {
        let dir = tempfile::tempdir().unwrap();
        let t = FileTracker::new(dir.path());
        (dir, t)
    }

    #[test]
    fn key_validation_table() {
        for good in ["SOF-1", "a-0", "AB12-345", "x9-10"] {
            assert!(is_valid_key(good), "{good}");
        }
        for bad in [
            "",
            "-1",
            "SOF-",
            "SOF",
            "1A-1",
            "../x",
            "/etc/passwd",
            "SOF-1/../x",
            "SOF-1\n",
            "SOF--1",
            "S OF-1",
            "SOF-1a",
            "A-B-1",
            "SÖF-1",
            "SOF-\u{0661}",
            "..",
        ] {
            assert!(!is_valid_key(bad), "{bad:?}");
        }
    }

    #[test]
    fn traversal_and_bad_keys_are_rejected_everywhere() {
        let (_d, t) = tracker();
        t.write_ticket(&ticket("SOF-1", &[])).unwrap();
        for bad in ["../x", "/abs/path", "", "SOF-1/../../x"] {
            assert!(t.comments_contain(bad, "m").is_err(), "{bad:?}");
            assert!(t.post_comment(bad, "x").is_err(), "{bad:?}");
            assert!(t.add_label(bad, "x").is_err(), "{bad:?}");
            assert!(t.ticket(bad).is_err(), "{bad:?}");
            assert!(t.write_ticket(&ticket(bad, &[])).is_err(), "{bad:?}");
        }
        // nothing was created outside tickets/ and comments/
        let names: Vec<_> = fs::read_dir(&t.root)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            names.iter().all(|n| n == "tickets" || n == "comments"),
            "{names:?}"
        );
    }

    #[test]
    fn ticket_round_trip() {
        let (_d, t) = tracker();
        let tk = ticket("SOF-1", &["errand-ready"]);
        t.write_ticket(&tk).unwrap();
        assert_eq!(t.ticket("SOF-1").unwrap(), tk);
    }

    #[test]
    fn ready_rule_and_order() {
        let (_d, t) = tracker();
        t.write_ticket(&ticket("B-2", &["errand-ready"])).unwrap();
        t.write_ticket(&ticket("A-1", &["errand-ready", "x"]))
            .unwrap();
        t.write_ticket(&ticket("C-3", &["errand-ready", "errand-claimed"]))
            .unwrap();
        t.write_ticket(&ticket("D-4", &["errand-ready", "needs-human"]))
            .unwrap();
        t.write_ticket(&ticket("E-5", &[])).unwrap();
        let keys: Vec<_> = t.ready().unwrap().into_iter().map(|t| t.key).collect();
        assert_eq!(keys, vec!["A-1", "B-2"]);
    }

    #[test]
    fn ready_without_tickets_dir_is_an_error() {
        let (_d, t) = tracker();
        assert!(t.ready().is_err());
    }

    #[test]
    fn ready_errors_on_corrupt_ticket_and_key_mismatch() {
        let (_d, t) = tracker();
        t.write_ticket(&ticket("A-1", &["errand-ready"])).unwrap();
        fs::write(t.root.join("tickets/B-2.json"), "{not json").unwrap();
        assert!(t.ready().is_err());
        fs::write(
            t.root.join("tickets/B-2.json"),
            r#"{"key":"Z-9","summary":"s"}"#,
        )
        .unwrap();
        assert!(t.ready().is_err());
    }

    #[test]
    fn ready_skips_non_ticket_names_and_temp_files() {
        let (_d, t) = tracker();
        t.write_ticket(&ticket("A-1", &["errand-ready"])).unwrap();
        fs::write(t.root.join("tickets/notes.json"), "garbage").unwrap();
        fs::write(t.root.join("tickets/.A-1.json.1.0.tmp"), "garbage").unwrap();
        assert_eq!(t.ready().unwrap().len(), 1);
    }

    #[test]
    fn add_label_persists_and_is_idempotent() {
        let (_d, t) = tracker();
        t.write_ticket(&ticket("A-1", &["errand-ready"])).unwrap();
        t.add_label("A-1", "errand-claimed").unwrap();
        t.add_label("A-1", "errand-claimed").unwrap();
        assert_eq!(
            t.ticket("A-1").unwrap().labels,
            vec!["errand-ready", "errand-claimed"]
        );
        assert!(t.ready().unwrap().is_empty());
        let leftovers: Vec<_> = fs::read_dir(t.root.join("tickets"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(leftovers, vec!["A-1.json"], "no temp files left behind");
    }

    #[test]
    fn add_label_on_missing_ticket_errors() {
        let (_d, t) = tracker();
        t.write_ticket(&ticket("A-1", &[])).unwrap();
        assert!(t.add_label("A-2", "x").is_err());
    }

    #[test]
    fn comments_append_and_search() {
        let (_d, t) = tracker();
        t.write_ticket(&ticket("A-1", &[])).unwrap();
        assert!(
            !t.comments_contain("A-1", "[errand:z]").unwrap(),
            "no log yet is not an error"
        );
        assert!(t.comments("A-1").unwrap().is_empty());
        t.post_comment("A-1", "line one\nwith \"quotes\"").unwrap();
        t.post_comment("A-1", "two [errand:z]").unwrap();
        assert!(t.comments_contain("A-1", "[errand:z]").unwrap());
        assert!(!t.comments_contain("A-1", "[errand:y]").unwrap());
        assert_eq!(
            t.comments("A-1").unwrap(),
            vec!["line one\nwith \"quotes\"", "two [errand:z]"]
        );
        let raw = fs::read_to_string(t.root.join("comments/A-1.log")).unwrap();
        assert_eq!(
            raw.lines().count(),
            2,
            "multi-line body stays on one log line"
        );
    }

    #[test]
    fn comments_on_unknown_ticket_error() {
        let (_d, t) = tracker();
        t.write_ticket(&ticket("A-1", &[])).unwrap();
        assert!(t.comments_contain("A-2", "m").is_err());
        assert!(t.post_comment("A-2", "x").is_err());
        assert!(!t.root.join("comments/A-2.log").exists());
    }

    #[test]
    fn corrupt_comment_log_is_an_error_not_empty() {
        let (_d, t) = tracker();
        t.write_ticket(&ticket("A-1", &[])).unwrap();
        fs::create_dir_all(t.root.join("comments")).unwrap();
        fs::write(t.root.join("comments/A-1.log"), "not a json string\n").unwrap();
        assert!(t.comments_contain("A-1", "m").is_err());
    }
}
