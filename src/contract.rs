//! The data contract. Every type here is serialised to JSON, has a generated JSON Schema in `schema/`, and is covered by the
//! shared fixtures in `fixtures/`. Other implementations and consumers (for example a Dart client app) are
//! tested against the same files.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Version of the contract. Bumped on any change that is not backwards compatible.
pub const SCHEMA_VERSION: u32 = 1;

/// How much a worker may do. See `spec/ERRAND.md` section 2.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[non_exhaustive]
pub enum Risk {
    /// Report only: `Read`, `Grep`, `Glob`.
    L0,
    /// Propose a change as a patch; nothing is pushed.
    L1,
    /// The trusted phase may open a pull request from a validated patch.
    L2,
    /// Never automatic.
    L3,
}

impl fmt::Display for Risk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Risk::L0 => "L0",
            Risk::L1 => "L1",
            Risk::L2 => "L2",
            Risk::L3 => "L3",
        })
    }
}

impl Risk {
    /// The tools a worker at this level may be given (a hard allowlist; see the spec).
    ///
    /// ```
    /// use errand_kit::contract::Risk;
    /// assert!(Risk::L0.tools_allowed().contains(&"Read"));
    /// assert!(!Risk::L0.tools_allowed().contains(&"Edit"));
    /// assert!(Risk::L3.tools_allowed().is_empty());
    /// ```
    pub fn tools_allowed(&self) -> &'static [&'static str] {
        match self {
            Risk::L0 => &["Read", "Grep", "Glob"],
            Risk::L1 | Risk::L2 => &["Read", "Grep", "Glob", "Edit", "Write"],
            _ => &[],
        }
    }
}

/// The outcome of an errand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[non_exhaustive]
pub enum Verdict {
    /// Nothing needs a human.
    #[serde(rename = "OK")]
    Ok,
    /// Something needs a human.
    #[serde(rename = "ATTENTION")]
    Attention,
    /// The errand machinery itself failed (boundary refused, hard gate failed, worker produced nothing).
    #[serde(rename = "FAILED")]
    Failed,
}

impl Verdict {
    /// The process exit code for this verdict: 0, 3 and 73.
    pub fn exit_code(&self) -> i32 {
        match self {
            Verdict::Ok => 0,
            Verdict::Attention => 3,
            Verdict::Failed => 73,
        }
    }

    /// The `STATUS:` line a digest must end with, if this verdict can be stated in one.
    ///
    /// ```
    /// use errand_kit::contract::Verdict;
    /// assert_eq!(Verdict::Ok.status_line(), Some("STATUS: OK"));
    /// assert_eq!(Verdict::Failed.status_line(), None);
    /// ```
    pub fn status_line(&self) -> Option<&'static str> {
        match self {
            Verdict::Ok => Some("STATUS: OK"),
            Verdict::Attention => Some("STATUS: ATTENTION"),
            Verdict::Failed => None,
        }
    }

    /// Parse an exact `STATUS: OK` or `STATUS: ATTENTION` line.
    ///
    /// ```
    /// use errand_kit::contract::Verdict;
    /// assert_eq!(Verdict::from_status_line("STATUS: ATTENTION"), Some(Verdict::Attention));
    /// assert_eq!(Verdict::from_status_line("status: ok"), None);
    /// ```
    pub fn from_status_line(line: &str) -> Option<Verdict> {
        match line.trim_end_matches('\r') {
            "STATUS: OK" => Some(Verdict::Ok),
            "STATUS: ATTENTION" => Some(Verdict::Attention),
            _ => None,
        }
    }
}

/// One of the six phases of an errand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Phase {
    /// Credentialed data gathering.
    Prepare,
    /// Boundary verification.
    Boundary,
    /// The untrusted worker.
    Worker,
    /// Engine-owned gates.
    Gates,
    /// Writing the run record.
    Record,
}

/// How a phase ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PhaseRecord {
    /// Which phase.
    pub phase: Phase,
    /// Whether it completed without error.
    pub ok: bool,
    /// Start time, RFC 3339 UTC.
    pub started_at: String,
    /// End time, RFC 3339 UTC.
    pub finished_at: String,
    /// A short human note; never a secret.
    #[serde(default)]
    pub note: Option<String>,
}

/// One boundary check and its result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Check {
    /// Stable machine name, e.g. `caps_zero`.
    pub name: String,
    /// Whether the check passed.
    pub ok: bool,
    /// Whether a failure refuses the run (`true`) or is only reported.
    pub required: bool,
    /// What was observed. Names only for anything credential-shaped; never a value.
    pub detail: String,
}

/// What the sandbox verified before the worker started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BoundaryReport {
    /// `container`, `bubblewrap` or `none` (the last only in test builds).
    pub kind: String,
    /// True only if every required check passed.
    pub ok: bool,
    /// Egress as the Kit can know it: always `open` today; it cannot be verified closed.
    pub egress: String,
    /// The individual checks.
    pub checks: Vec<Check>,
}

/// What the worker was and what it did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WorkerReport {
    /// `claude-cli`, `fake`, ...
    pub kind: String,
    /// The tools requested (the hard allowlist).
    pub tools_requested: Vec<String>,
    /// The tools the worker reported having, when it can report them.
    #[serde(default)]
    pub tools_reported: Option<Vec<String>>,
    /// Maximum conversation turns.
    pub max_turns: u32,
    /// Process exit code, if it ran.
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// Wall time in milliseconds, if it ran.
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

/// The result of one gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GateResult {
    /// Stable name, e.g. `status_line`.
    pub name: String,
    /// Kind of gate: `boundary`, `tools_match`, `status_line`, `env_clean`, `diff_scope`, `command`.
    pub kind: String,
    /// Whether it passed.
    pub ok: bool,
    /// Whether a failure makes the verdict `FAILED`.
    pub hard: bool,
    /// What was observed.
    pub detail: String,
}

/// What an L1+ worker hands back for a human (or the trusted phase) to review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HandBack {
    /// The ticket key this concerns, if any.
    #[serde(default)]
    pub ticket: Option<String>,
    /// The repository the patch applies to (`owner/name`).
    #[serde(default)]
    pub repo: Option<String>,
    /// The base commit the patch was made against.
    #[serde(default)]
    pub base: Option<String>,
    /// Relative path of the patch file inside the run's output directory.
    #[serde(default)]
    pub patch: Option<String>,
    /// SHA-256 (hex) of the patch text the Kit built and validated. A consumer MUST verify the file it is about to apply against
    /// this value: the output directory is writable by code the recipe's gate commands may have run.
    #[serde(default)]
    pub patch_sha256: Option<String>,
    /// Files the patch touches, as parsed from the patch text by the Kit (not as claimed by the worker).
    pub files_changed: Vec<String>,
    /// What the worker says it did. Untrusted prose.
    pub summary: String,
    /// What the Kit itself verified.
    pub verified: Vec<String>,
    /// What could not be verified.
    pub unverified: Vec<String>,
    /// The one thing a human should do next.
    pub next_human_step: String,
}

/// The record of one errand, written as `run.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunRecord {
    /// Contract version.
    pub schema_version: u32,
    /// A unique id for this run.
    pub run_id: String,
    /// The task name.
    pub task: String,
    /// The risk level it ran at.
    pub risk: Risk,
    /// Start time, RFC 3339 UTC.
    pub started_at: String,
    /// End time, RFC 3339 UTC.
    #[serde(default)]
    pub finished_at: Option<String>,
    /// The phases that ran.
    pub phases: Vec<PhaseRecord>,
    /// The boundary report, if phase 2 ran.
    #[serde(default)]
    pub boundary: Option<BoundaryReport>,
    /// The worker report, if phase 3 ran.
    #[serde(default)]
    pub worker: Option<WorkerReport>,
    /// Gate results.
    pub gates: Vec<GateResult>,
    /// The verdict.
    pub verdict: Verdict,
    /// Where the verdict came from: `code` (a status file written by the task) or `model` (the digest's last line).
    pub verdict_source: String,
    /// The digest file, relative to the output directory.
    #[serde(default)]
    pub digest: Option<String>,
    /// Other output files, relative to the output directory.
    #[serde(default)]
    pub artifacts: Vec<String>,
    /// The hand-back, for L1+.
    #[serde(default)]
    pub handback: Option<HandBack>,
    /// The process exit code the run ends with.
    pub exit_code: i32,
}

/// A message waiting to be delivered to a tracker or chat, exactly once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OutboxEntry {
    /// `sha256(run_id, op, target)` in hex; also the idempotency marker `[errand:<id>]`.
    pub id: String,
    /// Where it goes (a ticket key, a channel id).
    pub target: String,
    /// What kind of post: `comment`, `label`, ...
    pub kind: String,
    /// The text to post, before the marker is appended.
    pub body: String,
    /// The run that produced it.
    pub run_id: String,
    /// Creation time, RFC 3339 UTC.
    pub created_at: String,
    /// Delivery time, set only after the tracker confirmed it.
    #[serde(default)]
    pub delivered_at: Option<String>,
    /// How many delivery attempts were made.
    #[serde(default)]
    pub attempts: u32,
    /// The last delivery error, if any.
    #[serde(default)]
    pub last_error: Option<String>,
}

/// One usage window as reported by the plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LimitWindow {
    /// `five_hour` or `seven_day`.
    pub name: String,
    /// Fraction used, 0.0 to 1.0, or `null` if unknown.
    #[serde(default)]
    pub used_fraction: Option<f64>,
    /// When the window resets, epoch seconds.
    #[serde(default)]
    pub resets_at: Option<i64>,
}

/// The governor's decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct GovernorDecision {
    /// Whether new work may start.
    pub allow: bool,
    /// Why (always filled; a deny names the window or the staleness).
    pub reason: String,
}

/// The engine part of the queue snapshot a client app reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueueEngine {
    /// The engine process is alive.
    pub live: bool,
    /// The engine is paused.
    pub paused: bool,
    /// Outbox entries not yet delivered.
    pub outbox_pending: u32,
    /// `live` or a test mode name.
    pub mode: String,
}

/// The usage limits part of the queue snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct QueueLimits {
    /// Five-hour window fraction used, or `null`.
    #[serde(default)]
    pub five_hour: Option<f64>,
    /// Seven-day window fraction used, or `null`.
    #[serde(default)]
    pub seven_day: Option<f64>,
    /// `ok`, `paused`, `unknown`, ...
    #[serde(default)]
    pub status: Option<String>,
    /// Reset time, epoch seconds.
    #[serde(default)]
    pub resets_at: Option<i64>,
    /// Age of the usage report, seconds.
    #[serde(default)]
    pub report_age_s: Option<i64>,
    /// The ceilings the engine pauses at, when it reports them.
    #[serde(default)]
    pub ceilings: Option<QueueCeilings>,
}

/// The usage ceilings the engine pauses at.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct QueueCeilings {
    /// Five-hour ceiling, 0.0 to 1.0.
    #[serde(default)]
    pub five_hour: Option<f64>,
    /// Seven-day ceiling, 0.0 to 1.0.
    #[serde(default)]
    pub seven_day: Option<f64>,
}

/// A repository the engine can take work for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueueRepo {
    /// `owner/name`.
    pub name: String,
    /// Display name.
    #[serde(default)]
    pub label: Option<String>,
    /// Whether the engine may implement (not only refine) work here.
    #[serde(default)]
    pub can_implement: bool,
    /// Whether the repository is enabled.
    #[serde(default)]
    pub enabled: bool,
}

/// A recent run, as a client app lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueueRun {
    /// Run id.
    pub id: String,
    /// The ticket key.
    pub key: String,
    /// The lane it ran in.
    #[serde(default)]
    pub lane: Option<String>,
    /// The executor.
    #[serde(default)]
    pub executor: Option<String>,
    /// The run's state.
    #[serde(default)]
    pub state: Option<String>,
}

/// Whether the engine can host chat sessions, and what is missing. No secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueueChat {
    /// Chat is switched on.
    #[serde(default)]
    pub enabled: bool,
    /// `present` or `missing`.
    #[serde(default)]
    pub credential: Option<String>,
    /// `clean`, `findings` or `unknown`.
    #[serde(default)]
    pub workspace: Option<String>,
    /// Number of workspace findings.
    #[serde(default)]
    pub findings: u32,
    /// Live chat sessions.
    #[serde(default)]
    pub live_sessions: u32,
    /// Enabled, credentialed and clean.
    #[serde(default)]
    pub ready: bool,
}

/// A pull request attached to a ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueuePr {
    /// The PR URL.
    pub url: String,
    /// The PR number.
    pub number: u64,
    /// `open`, `merged`, `closed`.
    pub state: String,
    /// True if review blocked it.
    #[serde(default)]
    pub review_blocked: bool,
    /// Head commit.
    #[serde(default)]
    pub sha: Option<String>,
}

/// A ticket as a client app shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueueTicket {
    /// The ticket key, e.g. `QR-12`.
    pub key: String,
    /// Title (replaced for restricted tickets).
    pub summary: String,
    /// Tracker status.
    #[serde(default)]
    pub status: Option<String>,
    /// Project key.
    #[serde(default)]
    pub project: Option<String>,
    /// Issue type.
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    /// Labels.
    #[serde(default)]
    pub labels: Vec<String>,
    /// Repository `owner/name`, if known.
    #[serde(default)]
    pub repo: Option<String>,
    /// Restricted tickets show only their key.
    #[serde(default)]
    pub restricted: bool,
    /// One of the lifecycle stages (`not-approved`, `queued`, `working`, `refinement-ready`, `needs-you`,
    /// `awaiting-merge-approval`, `merge-approved`, `review-blocked`, `done`).
    pub stage: String,
    /// Human text for the stage.
    #[serde(default)]
    pub stage_text: Option<String>,
    /// Actions the viewer may take now.
    #[serde(default)]
    pub actions: Vec<String>,
    /// The attached PR.
    #[serde(default)]
    pub pr: Option<QueuePr>,
    /// True if the ticket needs a repository before it can be readied.
    #[serde(default)]
    pub needs_repo: bool,
    /// A repository the engine suggests for this ticket.
    #[serde(default)]
    pub suggested_repo: Option<String>,
}

/// The snapshot the engine publishes and a client app reads (`queue.json`). Unknown fields are ignored; optional fields are `null`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct QueueSnapshot {
    /// Engine state.
    pub engine: QueueEngine,
    /// Usage limits.
    pub limits: QueueLimits,
    /// Repositories the engine can take work for.
    #[serde(default)]
    pub repos: Vec<QueueRepo>,
    /// Tickets.
    pub tickets: Vec<QueueTicket>,
    /// Recent runs.
    #[serde(default)]
    pub runs: Vec<QueueRun>,
    /// An error from reading the board, if any.
    #[serde(default)]
    pub board_error: Option<String>,
    /// Chat readiness; absent on engines that predate it (a client treats that as unknown).
    #[serde(default)]
    pub chat: Option<QueueChat>,
    /// When the snapshot was published, epoch seconds. A NUMBER: real engines write a fractional clock reading.
    pub published_at: f64,
}
