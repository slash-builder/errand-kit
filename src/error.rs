//! The error type shared by the whole crate.

use std::path::PathBuf;

/// Everything that can go wrong in an errand, as a value the caller can match on.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ErrandError {
    /// A file or directory could not be read or written.
    #[error("io error at {path}: {source}")]
    Io {
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// JSON could not be parsed or produced.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    /// The task directory is missing something or malformed.
    #[error("task error: {0}")]
    Task(String),
    /// The sandbox refused to start the worker (a failed boundary check).
    #[error("boundary refused: {0}")]
    BoundaryRefused(String),
    /// The worker could not be run or returned nothing usable.
    #[error("worker error: {0}")]
    Worker(String),
    /// A patch or path failed validation.
    #[error("invalid patch: {0}")]
    Patch(String),
    /// A tracker operation failed.
    #[error("tracker error: {0}")]
    Tracker(String),
    /// The outbox store could not be read; nothing is sent in that state.
    #[error("outbox error: {0}")]
    Outbox(String),
    /// A recipe is missing or malformed.
    #[error("recipe error: {0}")]
    Recipe(String),
}

/// `Result` with [`ErrandError`].
pub type Result<T> = std::result::Result<T, ErrandError>;

impl ErrandError {
    /// Wrap an `std::io::Error` with the path it concerns.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io { path: path.into(), source }
    }
}
