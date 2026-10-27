# Errand Kit

Gated, sandboxed agent runs. Credentials are dropped, the verdict is computed in code, and the hand-back waits for consent.

An *errand* is a bounded piece of delegated work: **prepare** with credentials, **verify the boundary**, run an untrusted
**worker** with a hard tool allowlist and no credentials, check engine-owned **gates**, **record** the result, and wait for a
human before anything is applied. The contract is in [`spec/ERRAND.md`](spec/ERRAND.md); JSON Schemas in `schema/` are generated
from the Rust types; shared conformance cases are in `fixtures/` and every implementation and consumer must pass them.

> **Status: draft 0.1, private.** Internal-first: this repository is private until the contract is stable. Published crate name
> will be `slashbuilder-errand-kit`.

Consumers: the Dispatcher service (a Linux host, `bubblewrap`), the automation container (Jenkins, the container is the
boundary), and Courier (reads the queue snapshot, writes consent; never runs a worker).

Licence: Apache-2.0.
