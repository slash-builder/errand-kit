//! A tracker backed by a directory of JSON tickets. (To be implemented.)

use crate::tracker::{Ticket, Tracker};
use crate::{ErrandError, Result};

/// Tickets as files under a directory.
#[derive(Debug, Clone)]
pub struct FileTracker {
    /// The root directory.
    pub root: std::path::PathBuf,
}

impl Tracker for FileTracker {
    fn ready(&self) -> Result<Vec<Ticket>> {
        Err(ErrandError::Tracker("not implemented".into()))
    }
    fn comments_contain(&self, _key: &str, _marker: &str) -> Result<bool> {
        Err(ErrandError::Tracker("not implemented".into()))
    }
    fn post_comment(&self, _key: &str, _body: &str) -> Result<()> {
        Err(ErrandError::Tracker("not implemented".into()))
    }
    fn add_label(&self, _key: &str, _label: &str) -> Result<()> {
        Err(ErrandError::Tracker("not implemented".into()))
    }
}
