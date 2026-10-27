//! Trackers: where tickets come from and where results go. The Kit never trusts tracker text as instructions.

use crate::Result;

pub mod file;
pub mod memory;

/// A unit of requested work as read from a tracker. All text fields are untrusted data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    /// Key, e.g. `SOF-12`.
    pub key: String,
    /// Title.
    pub summary: String,
    /// Description (untrusted).
    pub body: String,
    /// Labels.
    pub labels: Vec<String>,
    /// Repository `owner/name`, if the ticket names one.
    pub repo: Option<String>,
}

/// A source of tickets and a place to post results.
pub trait Tracker {
    /// Tickets that are ready for an errand.
    fn ready(&self) -> Result<Vec<Ticket>>;
    /// Whether any comment on `key` contains `marker` (the read-back that makes posting idempotent).
    fn comments_contain(&self, key: &str, marker: &str) -> Result<bool>;
    /// Post a comment.
    fn post_comment(&self, key: &str, body: &str) -> Result<()>;
    /// Add a label.
    fn add_label(&self, key: &str, label: &str) -> Result<()>;
}
