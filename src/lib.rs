//! # Errand Kit
//!
//! Gated, sandboxed agent runs. An *errand* is a bounded piece of delegated work: prepare with credentials, then run an untrusted
//! worker in a place the Kit has **verified** holds none of them, with a hard tool allowlist; check engine-owned gates, record the
//! result, and wait for a human before anything is applied. The verdict is computed in code, never by the model alone.
//!
//! ## Module map
//!
//! * [`contract`]: the data contract (run record, hand-back, boundary report, outbox entry, queue snapshot). Its JSON Schemas ship in
//!   the package (`schema/`), generated from these types.
//! * [`engine`]: the phases (`run_prepare`, `run_model`). [`task`] loads a task directory.
//! * [`sandbox`]: the boundary. `container` verifies a locked-down container and refuses otherwise; `bubblewrap` wraps the worker on a
//!   Linux host. There is no automatic mode: a missing sandbox is a refusal.
//! * [`worker`]: the untrusted model run (`ClaudeCli`, and a scripted `FakeWorker` for tests).
//! * [`gates`]: checks the engine owns, including the patch validator and recipes. [`patchmake`] builds a patch from a worker's tree
//!   without running git inside it.
//! * [`outbox`], [`tracker`], [`governor`]: idempotent delivery, ticket sources, and a fail-closed usage limit.
//!
//! The `errand` command-line tool drives the same pieces; see the README. The `test-sandbox` cargo feature adds a no-op sandbox for
//! tests only. The full contract is reproduced in the [`spec`] module below.
//!
//! ```
//! use errand_kit::contract::{Risk, Verdict};
//! assert_eq!(Risk::L0.to_string(), "L0");
//! assert_eq!(Verdict::Ok.exit_code(), 0);
//! assert_eq!(Verdict::Attention.exit_code(), 3);
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod contract;
pub mod engine;
pub mod error;
pub mod gates;
pub mod governor;
pub mod outbox;
pub mod patchmake;
pub mod sandbox;
pub mod schema;
pub mod task;
pub mod time;
pub mod tracker;
pub mod worker;

pub use error::{ErrandError, Result};

#[doc = include_str!("../spec/ERRAND.md")]
pub mod spec {}
