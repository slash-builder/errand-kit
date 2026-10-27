//! The outbox: idempotent, read-back delivery.
//!
//! Every external post is an [`OutboxEntry`] with `id = sha256(run_id, op, target)` and the marker `[errand:<id>]`.
//! Delivery asks the tracker whether the marker already exists, posts only if not, and records delivery only after reading
//! the marker back. An unreadable or corrupt store sends nothing.
//!
//! Why the order matters (the bug this replaces): the Python engine replayed an entry after a delivery it had *counted* as
//! failed, and one Jira comment was posted five times. Here a failure never changes what is true on the tracker: the next
//! run starts by asking the tracker, so a post that landed but reported an error is found by its marker and not repeated.
//!
//! ```
//! use errand_kit::outbox::{marker, op_id, Outbox};
//! use errand_kit::tracker::{memory::MemoryTracker, Ticket};
//!
//! let dir = std::env::temp_dir().join(format!("errand-outbox-doc-{}", std::process::id()));
//! let outbox = Outbox::open(&dir).unwrap();
//! let tracker = MemoryTracker::with_tickets(vec![Ticket {
//!     key: "SOF-1".into(), summary: "s".into(), body: String::new(), labels: vec![], repo: None,
//! }]);
//! let entry = outbox.enqueue("run-1", "digest", "SOF-1", "comment", "all good").unwrap();
//! assert_eq!(entry.id, op_id("run-1", "digest", "SOF-1"));
//! let report = outbox.deliver(&tracker).unwrap();
//! assert_eq!(report.delivered, 1);
//! assert!(tracker.comments("SOF-1")[0].ends_with(&marker(&entry.id)));
//! // a second delivery posts nothing
//! assert_eq!(outbox.deliver(&tracker).unwrap().delivered, 0);
//! assert_eq!(tracker.comments("SOF-1").len(), 1);
//! # let _ = std::fs::remove_dir_all(&dir);
//! ```

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use crate::contract::OutboxEntry;
use crate::time::now_rfc3339;
use crate::tracker::Tracker;
use crate::{ErrandError, Result};

/// The only entry kind this outbox can deliver (through [`Tracker::post_comment`]).
pub const KIND_COMMENT: &str = "comment";

/// The idempotency id of an operation: lowercase hex SHA-256 over the three fields, each prefixed with its length as a
/// big-endian `u64`, so `("a","bc","t")` and `("ab","c","t")` hash differently.
///
/// ```
/// use errand_kit::outbox::op_id;
/// assert_eq!(op_id("r", "o", "t").len(), 64);
/// assert_ne!(op_id("a", "bc", "t"), op_id("ab", "c", "t"));
/// ```
pub fn op_id(run_id: &str, op: &str, target: &str) -> String {
    let mut h = Sha256::new();
    for field in [run_id, op, target] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field.as_bytes());
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The marker appended to a delivered comment so the tracker can be asked whether it is already there: `[errand:<id>]`.
///
/// ```
/// assert_eq!(errand_kit::outbox::marker("abc"), "[errand:abc]");
/// ```
pub fn marker(id: &str) -> String {
    format!("[errand:{id}]")
}

/// Escape text for Slack (`mrkdwn`) so untrusted content cannot ping people or inject links.
///
/// * `&`, `<` and `>` become `&amp;`, `&lt;` and `&gt;` (the three entities Slack requires). This alone turns
///   `<!channel>`, `<!here>`, `<@U123>` and `<https://x|y>` into inert text.
/// * Every `@` becomes the fullwidth commercial at `\u{FF20}`, so a bare `@channel`, `@here` or `@name` cannot trigger a
///   mention even if the poster later enables name linking.
/// * A `!` that directly follows a `<` in the input (the special-mention form `<!here>`, `<!subteam^ID>`) becomes the
///   fullwidth exclamation mark `\u{FF01}`. Other `!` characters are left alone so ordinary prose is not mangled.
///
/// The result contains no zero-width characters. Turning unfurling off is the poster's job (`unfurl_links` /
/// `unfurl_media` = false in the request); this function only handles the text.
///
/// ```
/// use errand_kit::outbox::slack_escape;
/// assert_eq!(slack_escape("a & b < c > d"), "a &amp; b &lt; c &gt; d");
/// assert_eq!(slack_escape("<!channel>"), "&lt;\u{FF01}channel&gt;");
/// assert_eq!(slack_escape("@here"), "\u{FF20}here");
/// assert_eq!(slack_escape("done!"), "done!");
/// ```
pub fn slack_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut prev = '\0';
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '@' => out.push('\u{FF20}'),
            '!' if prev == '<' => out.push('\u{FF01}'),
            other => out.push(other),
        }
        prev = c;
    }
    out
}

/// What one call to [`Outbox::deliver`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeliveryReport {
    /// Entries newly posted and confirmed by read-back.
    pub delivered: usize,
    /// Entries whose marker was already on the tracker, so nothing was posted; they are now marked delivered.
    pub skipped_already_present: usize,
    /// Entries left pending (a tracker error, an unconfirmed read-back, an unsupported kind, or a failure to record).
    pub failed: usize,
    /// One item per failed entry.
    pub errors: Vec<DeliveryError>,
}

/// A failed delivery of one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryError {
    /// The entry id.
    pub id: String,
    /// The entry target.
    pub target: String,
    /// What went wrong.
    pub error: String,
}

enum Outcome {
    Posted,
    AlreadyPresent,
}

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn is_hex_id(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A directory of `<id>.json` files, each an [`OutboxEntry`].
#[derive(Debug)]
pub struct Outbox {
    dir: PathBuf,
    /// Serialises enqueue/deliver within this process.
    lock: Mutex<()>,
}

impl Outbox {
    /// Open the store at `dir`, creating the directory if it is absent. An existing store that cannot be read, or that holds
    /// a corrupt entry, is an error: nothing may be sent from a store whose state is unknown.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Outbox> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(|e| {
            ErrandError::Outbox(format!(
                "cannot create or open store {}: {e}",
                dir.display()
            ))
        })?;
        let outbox = Outbox {
            dir,
            lock: Mutex::new(()),
        };
        outbox.load_all()?;
        Ok(outbox)
    }

    fn guard(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.lock
            .lock()
            .map_err(|_| ErrandError::Outbox("outbox lock poisoned".into()))
    }

    fn entry_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    fn read_entry(&self, path: &Path, expected_id: &str) -> Result<OutboxEntry> {
        let text = fs::read_to_string(path)
            .map_err(|e| ErrandError::Outbox(format!("cannot read {}: {e}", path.display())))?;
        let entry: OutboxEntry = serde_json::from_str(&text)
            .map_err(|e| ErrandError::Outbox(format!("corrupt entry {}: {e}", path.display())))?;
        if entry.id != expected_id {
            return Err(ErrandError::Outbox(format!(
                "corrupt entry {}: it holds id {:?}",
                path.display(),
                entry.id
            )));
        }
        Ok(entry)
    }

    /// Read every entry. Any unreadable or corrupt `*.json` file fails the whole load.
    fn load_all(&self) -> Result<Vec<OutboxEntry>> {
        let rd = fs::read_dir(&self.dir).map_err(|e| {
            ErrandError::Outbox(format!("cannot read store {}: {e}", self.dir.display()))
        })?;
        let mut out = Vec::new();
        for item in rd {
            let item = item.map_err(|e| {
                ErrandError::Outbox(format!("cannot read store {}: {e}", self.dir.display()))
            })?;
            let path = item.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue; // temp files and foreign files are not entries
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            if !is_hex_id(stem) {
                return Err(ErrandError::Outbox(format!(
                    "unexpected file in store: {}",
                    path.display()
                )));
            }
            out.push(self.read_entry(&path, stem)?);
        }
        out.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    /// Write `entry` over its file atomically (temp file, sync, rename).
    fn save(&self, entry: &OutboxEntry) -> Result<()> {
        let path = self.entry_path(&entry.id);
        let tmp = self.write_tmp(entry)?;
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = fs::remove_file(&tmp);
            return Err(ErrandError::io(&path, e));
        }
        Ok(())
    }

    fn write_tmp(&self, entry: &OutboxEntry) -> Result<PathBuf> {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .dir
            .join(format!(".{}.{}.{n}.tmp", entry.id, std::process::id()));
        let mut bytes = serde_json::to_vec_pretty(entry)?;
        bytes.push(b'\n');
        let result = (|| {
            let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()
        })();
        if let Err(e) = result {
            let _ = fs::remove_file(&tmp);
            return Err(ErrandError::io(&tmp, e));
        }
        Ok(tmp)
    }

    /// Queue a post. Idempotent on `(run_id, op, target)`: a second call returns the existing entry unchanged (even if
    /// `kind` or `body` differ) and writes nothing.
    pub fn enqueue(
        &self,
        run_id: &str,
        op: &str,
        target: &str,
        kind: &str,
        body: &str,
    ) -> Result<OutboxEntry> {
        let _g = self.guard()?;
        let id = op_id(run_id, op, target);
        let path = self.entry_path(&id);
        match fs::metadata(&path) {
            Ok(_) => return self.read_entry(&path, &id),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(ErrandError::Outbox(format!(
                    "cannot stat {}: {e}",
                    path.display()
                )))
            }
        }
        let entry = OutboxEntry {
            id: id.clone(),
            target: target.to_string(),
            kind: kind.to_string(),
            body: body.to_string(),
            run_id: run_id.to_string(),
            created_at: now_rfc3339(),
            delivered_at: None,
            attempts: 0,
            last_error: None,
        };
        // hard_link fails if the name exists, so a concurrent enqueue from another process cannot be overwritten.
        let tmp = self.write_tmp(&entry)?;
        let linked = fs::hard_link(&tmp, &path);
        let _ = fs::remove_file(&tmp);
        match linked {
            Ok(()) => {
                tracing::debug!(%id, %target, "outbox: enqueued");
                Ok(entry)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => self.read_entry(&path, &id),
            Err(e) => Err(ErrandError::io(&path, e)),
        }
    }

    /// Undelivered entries, oldest first (by `created_at`, which has one-second resolution; ties are ordered by id).
    pub fn pending(&self) -> Result<Vec<OutboxEntry>> {
        let _g = self.guard()?;
        Ok(self
            .load_all()?
            .into_iter()
            .filter(|e| e.delivered_at.is_none())
            .collect())
    }

    /// Deliver every pending entry through `tracker`.
    ///
    /// The whole store is read first; if that fails nothing is sent and the error is returned. For each pending entry:
    /// 1. ask `tracker.comments_contain(target, marker)`; if present, mark it delivered **without posting**;
    /// 2. otherwise post `body`, a newline and the marker;
    /// 3. read back with `comments_contain`, and set `delivered_at` only if the marker is now there.
    ///
    /// Any error (including a post that returned an error, or a read-back that did not see the marker) leaves the entry
    /// pending with `attempts` incremented and `last_error` set. It is never re-posted blindly: the next call begins with
    /// step 1, which finds the marker if the earlier post did land.
    ///
    /// Only entries of kind [`KIND_COMMENT`] can be delivered; any other kind fails with a recorded error.
    pub fn deliver(&self, tracker: &dyn Tracker) -> Result<DeliveryReport> {
        let _g = self.guard()?;
        let entries: Vec<OutboxEntry> = self
            .load_all()?
            .into_iter()
            .filter(|e| e.delivered_at.is_none())
            .collect();
        let mut report = DeliveryReport::default();
        for mut entry in entries {
            let outcome = Self::deliver_one(tracker, &entry);
            let message = match &outcome {
                Ok(Outcome::Posted) => {
                    entry.attempts += 1;
                    entry.delivered_at = Some(now_rfc3339());
                    entry.last_error = None;
                    None
                }
                Ok(Outcome::AlreadyPresent) => {
                    entry.delivered_at = Some(now_rfc3339());
                    entry.last_error = None;
                    None
                }
                Err(msg) => {
                    entry.attempts += 1;
                    entry.last_error = Some(msg.clone());
                    Some(msg.clone())
                }
            };
            let recorded = self.save(&entry);
            match (outcome, message, recorded) {
                (Ok(Outcome::Posted), _, Ok(())) => report.delivered += 1,
                (Ok(Outcome::AlreadyPresent), _, Ok(())) => report.skipped_already_present += 1,
                (Ok(_), _, Err(e)) => {
                    // The tracker has it but we could not record that. It stays pending; the next run's marker check
                    // finds it and will not post again.
                    tracing::warn!(id = %entry.id, error = %e, "outbox: delivered but could not record");
                    report.failed += 1;
                    report.errors.push(DeliveryError {
                        id: entry.id.clone(),
                        target: entry.target.clone(),
                        error: format!("delivered but could not be recorded: {e}"),
                    });
                }
                (Err(_), msg, saved) => {
                    if let Err(e) = saved {
                        tracing::warn!(id = %entry.id, error = %e, "outbox: could not record failure");
                    }
                    let error = msg.unwrap_or_default();
                    tracing::warn!(id = %entry.id, target = %entry.target, %error, "outbox: delivery failed");
                    report.failed += 1;
                    report.errors.push(DeliveryError {
                        id: entry.id.clone(),
                        target: entry.target.clone(),
                        error,
                    });
                }
            }
        }
        Ok(report)
    }

    fn deliver_one(
        tracker: &dyn Tracker,
        entry: &OutboxEntry,
    ) -> std::result::Result<Outcome, String> {
        if entry.kind != KIND_COMMENT {
            return Err(format!("unsupported entry kind {:?}", entry.kind));
        }
        let mark = marker(&entry.id);
        if tracker
            .comments_contain(&entry.target, &mark)
            .map_err(|e| format!("pre-check failed: {e}"))?
        {
            return Ok(Outcome::AlreadyPresent);
        }
        tracker
            .post_comment(&entry.target, &format!("{}\n{mark}", entry.body))
            .map_err(|e| format!("post failed: {e}"))?;
        if tracker
            .comments_contain(&entry.target, &mark)
            .map_err(|e| format!("read-back failed: {e}"))?
        {
            Ok(Outcome::Posted)
        } else {
            Err("posted but the marker was not found on read-back".to_string())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::tracker::memory::MemoryTracker;
    use crate::tracker::Ticket;
    use std::sync::atomic::AtomicUsize;

    fn ticket(key: &str) -> Ticket {
        Ticket {
            key: key.into(),
            summary: "s".into(),
            body: String::new(),
            labels: vec![],
            repo: None,
        }
    }
    fn mem() -> MemoryTracker {
        MemoryTracker::with_tickets(vec![ticket("A-1"), ticket("A-2")])
    }
    fn store() -> (tempfile::TempDir, Outbox) {
        let d = tempfile::tempdir().unwrap();
        let o = Outbox::open(d.path().join("outbox")).unwrap();
        (d, o)
    }

    /// Failure-injection wrapper around [`MemoryTracker`].
    #[derive(Default)]
    struct Flaky {
        inner: MemoryTracker,
        /// Number of upcoming posts that land and then report an error (the Python bug's trigger).
        post_lands_then_errors: AtomicUsize,
        /// Number of upcoming posts that fail without landing.
        post_fails_cleanly: AtomicUsize,
        /// Zero-based index of the `comments_contain` call that lies (returns false), if any.
        lie_on_call: Mutex<Option<usize>>,
        calls: AtomicUsize,
    }
    impl Flaky {
        fn new() -> Self {
            Flaky {
                inner: mem(),
                ..Default::default()
            }
        }
        fn take(counter: &AtomicUsize) -> bool {
            counter
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
        }
    }
    impl Tracker for Flaky {
        fn ready(&self) -> Result<Vec<Ticket>> {
            self.inner.ready()
        }
        fn comments_contain(&self, key: &str, marker: &str) -> Result<bool> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            let real = self.inner.comments_contain(key, marker)?;
            let mut lie = self.lie_on_call.lock().unwrap();
            if *lie == Some(n) {
                *lie = None;
                return Ok(false);
            }
            Ok(real)
        }
        fn post_comment(&self, key: &str, body: &str) -> Result<()> {
            if Self::take(&self.post_fails_cleanly) {
                return Err(ErrandError::Tracker("503 before landing".into()));
            }
            self.inner.post_comment(key, body)?;
            if Self::take(&self.post_lands_then_errors) {
                return Err(ErrandError::Tracker("timeout after landing".into()));
            }
            Ok(())
        }
        fn add_label(&self, key: &str, label: &str) -> Result<()> {
            self.inner.add_label(key, label)
        }
    }

    #[test]
    fn ids_differ_across_runs_ops_targets_and_field_boundaries() {
        let base = op_id("r1", "digest", "A-1");
        assert_eq!(base, op_id("r1", "digest", "A-1"));
        assert!(is_hex_id(&base));
        let others = [
            op_id("r2", "digest", "A-1"),
            op_id("r1", "alert", "A-1"),
            op_id("r1", "digest", "A-2"),
            op_id("r1digest", "", "A-1"),
            op_id("r", "1digest", "A-1"),
        ];
        for o in &others {
            assert_ne!(&base, o);
        }
        assert_ne!(op_id("a", "bc", "t"), op_id("ab", "c", "t"));
        assert_ne!(op_id("", "", "ab"), op_id("", "a", "b"));
        assert_eq!(marker("x"), "[errand:x]");
    }

    #[test]
    fn op_id_known_vector() {
        // sha256 of 8-byte BE length + bytes for each of "", "", "" = sha256 of 24 zero bytes
        let mut h = Sha256::new();
        h.update([0u8; 24]);
        let want: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(op_id("", "", ""), want);
    }

    #[test]
    fn enqueue_is_idempotent() {
        let (_d, o) = store();
        let a = o.enqueue("r", "digest", "A-1", "comment", "first").unwrap();
        let b = o
            .enqueue("r", "digest", "A-1", "comment", "DIFFERENT")
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(b.body, "first");
        assert_eq!(o.pending().unwrap().len(), 1);
        o.enqueue("r", "digest", "A-2", "comment", "x").unwrap();
        assert_eq!(o.pending().unwrap().len(), 2);
        let files: Vec<_> = fs::read_dir(&o.dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            files.iter().all(|f| f.ends_with(".json")),
            "no temp files left: {files:?}"
        );
    }

    #[test]
    fn open_creates_the_directory_and_reopens() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a/b/outbox");
        let o = Outbox::open(&p).unwrap();
        o.enqueue("r", "o", "A-1", "comment", "x").unwrap();
        let o2 = Outbox::open(&p).unwrap();
        assert_eq!(o2.pending().unwrap().len(), 1);
    }

    #[test]
    fn deliver_posts_body_newline_marker_and_marks_delivered() {
        let (_d, o) = store();
        let t = mem();
        let e = o.enqueue("r", "digest", "A-1", "comment", "hello").unwrap();
        let rep = o.deliver(&t).unwrap();
        assert_eq!(
            (rep.delivered, rep.skipped_already_present, rep.failed),
            (1, 0, 0)
        );
        assert_eq!(t.comments("A-1"), vec![format!("hello\n[errand:{}]", e.id)]);
        assert!(o.pending().unwrap().is_empty());
        let stored: OutboxEntry =
            serde_json::from_str(&fs::read_to_string(o.entry_path(&e.id)).unwrap()).unwrap();
        assert!(stored.delivered_at.is_some());
        assert_eq!(stored.attempts, 1);
        assert_eq!(stored.last_error, None);
        // idempotent
        let rep2 = o.deliver(&t).unwrap();
        assert_eq!(rep2, DeliveryReport::default());
        assert_eq!(t.comments("A-1").len(), 1);
    }

    #[test]
    fn already_present_marker_is_skipped_without_posting() {
        let (_d, o) = store();
        let t = mem();
        let e = o.enqueue("r", "digest", "A-1", "comment", "hello").unwrap();
        t.post_comment("A-1", &format!("earlier\n{}", marker(&e.id)))
            .unwrap();
        let rep = o.deliver(&t).unwrap();
        assert_eq!(
            (rep.delivered, rep.skipped_already_present, rep.failed),
            (0, 1, 0)
        );
        assert_eq!(t.comments("A-1").len(), 1);
        assert!(o.pending().unwrap().is_empty());
    }

    #[test]
    fn python_bug_post_succeeds_but_errors_then_five_redeliveries_make_one_comment() {
        let (_d, o) = store();
        let t = Flaky::new();
        t.post_lands_then_errors.store(1, Ordering::SeqCst);
        let e = o
            .enqueue("r", "digest", "A-1", "comment", "report")
            .unwrap();

        let first = o.deliver(&t).unwrap();
        assert_eq!((first.delivered, first.failed), (0, 1));
        assert!(first.errors[0].error.contains("post failed"));
        let pending = o.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].attempts, 1);
        assert!(pending[0]
            .last_error
            .as_deref()
            .unwrap()
            .contains("timeout"));

        let mut skipped = 0;
        for _ in 0..5 {
            skipped += o.deliver(&t).unwrap().skipped_already_present;
        }
        assert_eq!(skipped, 1);
        assert_eq!(t.inner.comments("A-1").len(), 1, "exactly one comment");
        assert!(t.inner.comments("A-1")[0].contains(&marker(&e.id)));
        assert!(o.pending().unwrap().is_empty());
    }

    #[test]
    fn post_that_never_landed_is_retried_and_lands_once() {
        let (_d, o) = store();
        let t = Flaky::new();
        t.post_fails_cleanly.store(2, Ordering::SeqCst);
        o.enqueue("r", "digest", "A-1", "comment", "report")
            .unwrap();
        for _ in 0..2 {
            assert_eq!(o.deliver(&t).unwrap().failed, 1);
            assert!(t.inner.comments("A-1").is_empty());
        }
        assert_eq!(o.deliver(&t).unwrap().delivered, 1);
        for _ in 0..3 {
            o.deliver(&t).unwrap();
        }
        assert_eq!(t.inner.comments("A-1").len(), 1);
        let stored: OutboxEntry = serde_json::from_str(
            &fs::read_to_string(o.dir.join(format!("{}.json", op_id("r", "digest", "A-1"))))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(stored.attempts, 3);
        assert_eq!(stored.last_error, None);
    }

    #[test]
    fn lying_read_back_does_not_double_post_on_the_next_run() {
        let (_d, o) = store();
        let t = Flaky::new();
        // call 0 = pre-check (true state: absent), post lands, call 1 = read-back, which lies once
        *t.lie_on_call.lock().unwrap() = Some(1);
        o.enqueue("r", "digest", "A-1", "comment", "report")
            .unwrap();
        let first = o.deliver(&t).unwrap();
        assert_eq!((first.delivered, first.failed), (0, 1));
        assert!(first.errors[0].error.contains("read-back"));
        assert_eq!(t.inner.comments("A-1").len(), 1);
        assert_eq!(
            o.pending().unwrap().len(),
            1,
            "unconfirmed, so still pending"
        );
        let second = o.deliver(&t).unwrap();
        assert_eq!(
            (
                second.delivered,
                second.skipped_already_present,
                second.failed
            ),
            (0, 1, 0)
        );
        assert_eq!(t.inner.comments("A-1").len(), 1, "no double post");
    }

    #[test]
    fn pre_check_error_leaves_entry_pending_and_posts_nothing() {
        let (_d, o) = store();
        let t = mem(); // no ticket A-9: comments_contain errors
        o.enqueue("r", "digest", "A-9", "comment", "x").unwrap();
        let rep = o.deliver(&t).unwrap();
        assert_eq!(rep.failed, 1);
        assert!(rep.errors[0].error.contains("pre-check failed"));
        assert_eq!(rep.errors[0].target, "A-9");
        let p = o.pending().unwrap();
        assert_eq!((p.len(), p[0].attempts), (1, 1));
    }

    #[test]
    fn failure_on_one_entry_does_not_block_others() {
        let (_d, o) = store();
        let t = mem();
        o.enqueue("r", "digest", "A-9", "comment", "bad").unwrap();
        o.enqueue("r", "digest", "A-1", "comment", "good").unwrap();
        let rep = o.deliver(&t).unwrap();
        assert_eq!((rep.delivered, rep.failed), (1, 1));
        assert_eq!(t.comments("A-1").len(), 1);
    }

    #[test]
    fn unsupported_kind_fails_without_posting() {
        let (_d, o) = store();
        let t = mem();
        o.enqueue("r", "label", "A-1", "label", "x").unwrap();
        let rep = o.deliver(&t).unwrap();
        assert_eq!(rep.failed, 1);
        assert!(rep.errors[0].error.contains("unsupported"));
        assert!(t.comments("A-1").is_empty());
    }

    #[test]
    fn corrupt_store_on_open_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("outbox");
        fs::create_dir_all(&p).unwrap();
        fs::write(
            p.join(format!("{}.json", op_id("r", "o", "A-1"))),
            "{ not json",
        )
        .unwrap();
        assert!(matches!(Outbox::open(&p), Err(ErrandError::Outbox(_))));
    }

    #[test]
    fn store_that_is_a_file_is_an_error() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("outbox");
        fs::write(&p, "i am a file").unwrap();
        assert!(Outbox::open(&p).is_err());
    }

    #[test]
    fn corruption_after_open_sends_nothing() {
        let (_d, o) = store();
        let t = mem();
        o.enqueue("r", "digest", "A-1", "comment", "good").unwrap();
        // a second entry gets corrupted behind our back
        let victim = op_id("r", "other", "A-2");
        fs::write(o.entry_path(&victim), "{\"id\": truncated").unwrap();
        assert!(matches!(o.deliver(&t), Err(ErrandError::Outbox(_))));
        assert!(t.comments("A-1").is_empty());
        assert!(t.comments("A-2").is_empty());
        assert!(o.pending().is_err());
        assert!(
            o.enqueue("r", "other", "A-2", "comment", "x").is_err(),
            "enqueue over a corrupt entry must not paper over it"
        );
    }

    #[test]
    fn entry_whose_id_does_not_match_its_file_is_corrupt() {
        let (_d, o) = store();
        let t = mem();
        let e = o.enqueue("r", "digest", "A-1", "comment", "x").unwrap();
        let mut moved = e.clone();
        moved.id = op_id("r", "digest", "A-2");
        fs::write(o.entry_path(&e.id), serde_json::to_string(&moved).unwrap()).unwrap();
        assert!(o.deliver(&t).is_err());
        assert!(t.comments("A-1").is_empty());
    }

    #[test]
    fn stray_json_file_in_store_is_an_error_but_temp_files_are_ignored() {
        let (_d, o) = store();
        fs::write(o.dir.join(".abc.1.0.tmp"), "junk").unwrap();
        assert!(o.pending().unwrap().is_empty());
        fs::write(o.dir.join("notes.json"), "junk").unwrap();
        assert!(o.pending().is_err());
    }

    #[test]
    fn pending_is_oldest_first() {
        let (_d, o) = store();
        let mut ids = Vec::new();
        for (i, ts) in [
            "2026-10-26T10:00:03Z",
            "2026-10-26T10:00:01Z",
            "2026-10-26T10:00:02Z",
        ]
        .iter()
        .enumerate()
        {
            let mut e = o
                .enqueue("r", &format!("op{i}"), "A-1", "comment", "x")
                .unwrap();
            e.created_at = (*ts).to_string();
            o.save(&e).unwrap();
            ids.push(e.created_at);
        }
        let got: Vec<_> = o
            .pending()
            .unwrap()
            .into_iter()
            .map(|e| e.created_at)
            .collect();
        assert_eq!(
            got,
            vec![
                "2026-10-26T10:00:01Z",
                "2026-10-26T10:00:02Z",
                "2026-10-26T10:00:03Z"
            ]
        );
    }

    #[test]
    fn works_with_the_file_tracker() {
        let d = tempfile::tempdir().unwrap();
        let ft = crate::tracker::file::FileTracker::new(d.path().join("tr"));
        ft.write_ticket(&ticket("A-1")).unwrap();
        let o = Outbox::open(d.path().join("outbox")).unwrap();
        o.enqueue("r", "digest", "A-1", "comment", "hi").unwrap();
        assert_eq!(o.deliver(&ft).unwrap().delivered, 1);
        assert_eq!(o.deliver(&ft).unwrap().delivered, 0);
        assert_eq!(ft.comments("A-1").unwrap().len(), 1);
    }

    #[test]
    fn slack_escape_table() {
        let cases = [
            ("plain text", "plain text"),
            ("a & b", "a &amp; b"),
            ("1 < 2 > 0", "1 &lt; 2 &gt; 0"),
            ("&amp;", "&amp;amp;"),
            ("<!channel>", "&lt;\u{FF01}channel&gt;"),
            ("<!here|x>", "&lt;\u{FF01}here|x&gt;"),
            ("<!subteam^S1>", "&lt;\u{FF01}subteam^S1&gt;"),
            ("<@U123>", "&lt;\u{FF20}U123&gt;"),
            (
                "@channel @here @everyone",
                "\u{FF20}channel \u{FF20}here \u{FF20}everyone",
            ),
            (
                "<https://evil.example|click>",
                "&lt;https://evil.example|click&gt;",
            ),
            ("done! really!", "done! really!"),
            ("", ""),
        ];
        for (input, want) in cases {
            assert_eq!(slack_escape(input), want, "input {input:?}");
        }
    }

    #[test]
    fn slack_escape_output_has_no_raw_specials() {
        let nasty = "<!channel> <!here> <@U1> @channel &<>!@ <!>";
        let out = slack_escape(nasty);
        assert!(!out.contains('<') && !out.contains('>') && !out.contains('@'));
        assert!(!out.contains("<!"));
        assert!(!out.chars().any(|c| matches!(
            c,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}'
        )));
        // every '&' that remains starts one of the three entities
        for (i, _) in out.match_indices('&') {
            let rest = &out[i..];
            assert!(
                rest.starts_with("&amp;") || rest.starts_with("&lt;") || rest.starts_with("&gt;"),
                "{rest:?}"
            );
        }
    }
}
