//! An in-memory tracker, for tests and for consumers that want a fake.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use crate::tracker::{Ticket, Tracker};
use crate::{ErrandError, Result};

/// The label that marks a ticket as ready for an errand.
pub const READY_LABEL: &str = "errand-ready";
/// The label that marks a ticket as already claimed by an errand; such a ticket is never ready.
pub const CLAIMED_LABEL: &str = "errand-claimed";
/// The label that parks a ticket for a human; such a ticket is never ready.
pub const NEEDS_HUMAN_LABEL: &str = "needs-human";

/// Whether a ticket with these labels is ready: it has [`READY_LABEL`] and neither [`CLAIMED_LABEL`] nor
/// [`NEEDS_HUMAN_LABEL`]. Shared by every tracker so the rule cannot drift between them.
///
/// ```
/// use errand_kit::tracker::memory::is_ready;
/// let l = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
/// assert!(is_ready(&l(&["errand-ready"])));
/// assert!(!is_ready(&l(&["errand-ready", "needs-human"])));
/// assert!(!is_ready(&l(&[])));
/// ```
pub fn is_ready(labels: &[String]) -> bool {
    let has = |wanted: &str| labels.iter().any(|l| l == wanted);
    has(READY_LABEL) && !has(CLAIMED_LABEL) && !has(NEEDS_HUMAN_LABEL)
}

#[derive(Debug, Default)]
struct State {
    /// Tickets in insertion order.
    tickets: Vec<Ticket>,
    comments: HashMap<String, Vec<String>>,
}

impl State {
    fn ticket_mut(&mut self, key: &str) -> Result<&mut Ticket> {
        self.tickets
            .iter_mut()
            .find(|t| t.key == key)
            .ok_or_else(|| ErrandError::Tracker(format!("unknown ticket {key:?}")))
    }
}

/// A tracker that lives in memory. Interior mutability (a `Mutex`) lets it be used through `&dyn Tracker`.
///
/// ```
/// use errand_kit::tracker::{memory::MemoryTracker, Ticket, Tracker};
/// let t = MemoryTracker::with_tickets(vec![Ticket {
///     key: "SOF-1".into(), summary: "s".into(), body: "b".into(), labels: vec!["errand-ready".into()], repo: None,
/// }]);
/// assert_eq!(t.ready().unwrap().len(), 1);
/// t.post_comment("SOF-1", "hello [errand:x]").unwrap();
/// assert!(t.comments_contain("SOF-1", "[errand:x]").unwrap());
/// ```
#[derive(Debug, Default)]
pub struct MemoryTracker {
    state: Mutex<State>,
}

impl MemoryTracker {
    /// An empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// A tracker holding these tickets (in this order).
    pub fn with_tickets(tickets: Vec<Ticket>) -> Self {
        Self {
            state: Mutex::new(State {
                tickets,
                comments: HashMap::new(),
            }),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| ErrandError::Tracker("memory tracker lock poisoned".into()))
    }

    /// The comments posted on `key`, oldest first. Empty for a ticket with no comments **and** for an unknown key
    /// (this is a test accessor; the [`Tracker`] methods report an unknown key as an error).
    pub fn comments(&self, key: &str) -> Vec<String> {
        self.lock()
            .map(|s| s.comments.get(key).cloned().unwrap_or_default())
            .unwrap_or_default()
    }

    /// The labels on `key`. Empty for a ticket with no labels and for an unknown key.
    pub fn labels(&self, key: &str) -> Vec<String> {
        self.lock()
            .map(|s| {
                s.tickets
                    .iter()
                    .find(|t| t.key == key)
                    .map(|t| t.labels.clone())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }
}

impl Tracker for MemoryTracker {
    fn ready(&self) -> Result<Vec<Ticket>> {
        Ok(self
            .lock()?
            .tickets
            .iter()
            .filter(|t| is_ready(&t.labels))
            .cloned()
            .collect())
    }

    fn comments_contain(&self, key: &str, marker: &str) -> Result<bool> {
        let state = self.lock()?;
        if !state.tickets.iter().any(|t| t.key == key) {
            return Err(ErrandError::Tracker(format!("unknown ticket {key:?}")));
        }
        Ok(state
            .comments
            .get(key)
            .is_some_and(|cs| cs.iter().any(|c| c.contains(marker))))
    }

    fn post_comment(&self, key: &str, body: &str) -> Result<()> {
        let mut state = self.lock()?;
        state.ticket_mut(key)?;
        state
            .comments
            .entry(key.to_string())
            .or_default()
            .push(body.to_string());
        Ok(())
    }

    fn add_label(&self, key: &str, label: &str) -> Result<()> {
        let mut state = self.lock()?;
        let ticket = state.ticket_mut(key)?;
        if !ticket.labels.iter().any(|l| l == label) {
            ticket.labels.push(label.to_string());
        }
        Ok(())
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
            repo: None,
        }
    }

    #[test]
    fn ready_filters_by_labels() {
        let t = MemoryTracker::with_tickets(vec![
            ticket("A-1", &["errand-ready"]),
            ticket("A-2", &["errand-ready", "errand-claimed"]),
            ticket("A-3", &["errand-ready", "needs-human"]),
            ticket("A-4", &[]),
            ticket("A-5", &["other", "errand-ready"]),
        ]);
        let keys: Vec<_> = t.ready().unwrap().into_iter().map(|t| t.key).collect();
        assert_eq!(keys, vec!["A-1", "A-5"]);
    }

    #[test]
    fn claiming_removes_from_ready() {
        let t = MemoryTracker::with_tickets(vec![ticket("A-1", &["errand-ready"])]);
        t.add_label("A-1", "errand-claimed").unwrap();
        assert!(t.ready().unwrap().is_empty());
        assert_eq!(t.labels("A-1"), vec!["errand-ready", "errand-claimed"]);
    }

    #[test]
    fn add_label_is_idempotent() {
        let t = MemoryTracker::with_tickets(vec![ticket("A-1", &[])]);
        t.add_label("A-1", "x").unwrap();
        t.add_label("A-1", "x").unwrap();
        assert_eq!(t.labels("A-1"), vec!["x"]);
    }

    #[test]
    fn comments_round_trip_and_marker_search() {
        let t = MemoryTracker::with_tickets(vec![ticket("A-1", &[]), ticket("A-2", &[])]);
        assert!(!t.comments_contain("A-1", "[errand:z]").unwrap());
        t.post_comment("A-1", "one").unwrap();
        t.post_comment("A-1", "two [errand:z]").unwrap();
        assert!(t.comments_contain("A-1", "[errand:z]").unwrap());
        assert!(!t.comments_contain("A-2", "[errand:z]").unwrap());
        assert_eq!(t.comments("A-1"), vec!["one", "two [errand:z]"]);
        assert!(t.comments("A-2").is_empty());
    }

    #[test]
    fn unknown_ticket_is_an_error_not_empty() {
        let t = MemoryTracker::new();
        assert!(t.comments_contain("NOPE-1", "m").is_err());
        assert!(t.post_comment("NOPE-1", "x").is_err());
        assert!(t.add_label("NOPE-1", "x").is_err());
        assert!(t.ready().unwrap().is_empty());
    }
}
