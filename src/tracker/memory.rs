//! An in-memory tracker for tests. (To be implemented.)

use crate::tracker::{Ticket, Tracker};
use crate::{ErrandError, Result};

/// A tracker that lives in memory.
#[derive(Debug, Default)]
pub struct MemoryTracker;

impl Tracker for MemoryTracker {
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
