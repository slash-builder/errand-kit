//! The outbox: idempotent, read-back delivery. (To be implemented.)
//!
//! Every external post is an [`OutboxEntry`](crate::contract::OutboxEntry) with `id = sha256(run_id, op, target)` and the
//! marker `[errand:<id>]`. Delivery asks the tracker whether the marker exists, posts only if not, and records delivery only
//! after confirming. An unreadable store sends nothing.
