//! # Errand Kit
//!
//! Gated, sandboxed agent runs. An *errand* is a bounded piece of delegated work: prepare with credentials, drop them,
//! verify the boundary, run an untrusted worker with a hard tool allowlist, check engine-owned gates, record the result,
//! and wait for a human before anything is applied. The verdict is computed in code, never by the model alone.
//!
//! The contract is in `spec/ERRAND.md`; the JSON Schemas in `schema/` are generated from [`contract`]; the shared
//! conformance cases are in `fixtures/` and every implementation and consumer must pass them.
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
pub mod sandbox;
pub mod schema;
pub mod task;
pub mod time;
pub mod tracker;
pub mod worker;

pub use error::{ErrandError, Result};
