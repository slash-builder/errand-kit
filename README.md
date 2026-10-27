# Errand Kit

Gated, sandboxed agent runs. Credentials are dropped, the verdict is computed in code, and the hand-back waits for consent.

An *errand* is a bounded piece of delegated work: **prepare** with credentials, **verify the boundary**, run an untrusted
**worker** with a hard tool allowlist and no credentials, check engine-owned **gates**, **record** the result, and wait for a
human before anything is applied. The Kit owns that lifecycle and its data contract. It does not own UI, model hosting, memory or
CI job definitions.

> **Status: alpha (0.1).** The public API and the contract may change before 1.0. Minimum supported Rust version: 1.94.

## Install

```sh
cargo install slashbuilder-errand-kit          # the `errand` command
cargo add slashbuilder-errand-kit              # the library (`use errand_kit::...`)
```

## Use

A task is a directory: `prompt.md`, `task.env` (the tool allowlist and turn limit) and an optional `prepare.sh`. Credentialed
data gathering and the model run in **separate containers**:

```sh
errand run prepare my-task --tasks-root tasks --out out     # has the credentials; no model
errand run model   my-task --tasks-root tasks --out out     # no credentials; refuses if it sees one
errand verify-boundary                                      # print the boundary report as JSON
errand schema --out schema                                  # write the JSON Schemas of the contract
```

`errand run model` verifies the boundary, runs the worker, checks the gates and writes `out/run.json` and `out/digest.md`. If the
task's prepare step wrote `out/status.txt` (`STATUS: OK` or `STATUS: ATTENTION`) that file is the verdict and the digest's last
line must match it exactly. For a write-capable (L1) task, pass `--base`, `--tree` and `--recipe`: the Kit builds the patch itself
from a pristine tree and the worker's copy, validates it against the recipe and returns it. It never pushes.

From Rust, the same pieces are available as a library:

```rust
use errand_kit::contract::{Risk, Verdict};
use errand_kit::sandbox::credential_shaped;
use errand_kit::gates::builtin::last_nonempty_line;

assert!(credential_shaped("AWS_SECRET_ACCESS_KEY"));              // the worker must never see this
assert_eq!(Risk::L0.tools_allowed(), ["Read", "Grep", "Glob"]);   // a hard allowlist, by risk level
let digest = "all fine\nSTATUS: OK\n";
let verdict = last_nonempty_line(digest).and_then(Verdict::from_status_line);
assert_eq!(verdict, Some(Verdict::Ok));                            // only the LAST line counts
```

## Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 3 | ATTENTION: something needs a human |
| 64 | any other error (usage, I/O, task, recipe, tracker) |
| 70 | the worker produced no digest |
| 72 | the boundary refused the run |
| 73 | a hard gate failed, the verdict disagreed with the code's, or the digest had no valid `STATUS:` line |

## Threat model, in one paragraph

The worker is a language model and is assumed prompt-injectable: anything it reads (a ticket, a log, a file) may be hostile. The Kit
assumes the launcher is honest. It proves that no credential-shaped variable name is present in any process of the worker's
container, that the process is non-root with no capabilities and `no-new-privileges`, that the root filesystem is read-only and that
no container-runtime socket is reachable. It gives the worker only a hard tool allowlist, computes the verdict in code, and builds and
validates any patch itself before a human sees it.

## What is not guaranteed

* **A recipe gate command that runs code from the worker's tree (`cargo test`, `npm test`, `make`) re-opens the shell-plus-egress
  risk.** It runs in the Kit's own context, beside the worker's token and with the container's open egress, so a worker that adds a
  test that reads the token and sends it out defeats the allowlist, redaction and the secret scan. For that reason a recipe may use
  only the inspect-only programs (`test`, `grep`, `diff`, `jq`, ...) unless it sets `gate_commands_execute_tree: true`, and you
  should set that only when the recipe's `scope` cannot hold executable code, or when the egress is closed. Running such commands
  in a separate, network-less, credential-less phase is future work.
* The patch's SHA-256 is recorded in the output directory, which a detached process started by a gate command could rewrite. The
  `errand` binary also prints `errand: patch_sha256=<hash>` on its own standard error; a trusted phase should compare that line
  with `patch.diff` rather than trusting only the files.
* The outbox has no cross-process lock; two processes sharing one outbox directory can duplicate a delivery.
* A secret-shaped string (other than the worker's own token) found in the digest fails the run but is not redacted from the digest,
  which the CLI also prints. Treat a failed run's output as sensitive.
* **Network egress is open and cannot be verified closed.** Every run record says `egress: "open"`. A worker with a shell and open
  egress could exfiltrate, which is why no risk level grants a shell.
* The container checks catch a broken launcher, not a malicious one: a hostile launcher can fake `/proc`.
* The bubblewrap backend constructs arguments; it is not exercised against a real `bwrap` in this release.
* Risk level L2 (push a branch and open a pull request) is specified but **not implemented** in this release.

## The contract

`spec/ERRAND.md` is the contract; `schema/` holds the JSON Schemas generated from the Rust types (a test keeps them in sync) and
`fixtures/` holds the shared conformance cases every implementation and consumer must pass.

Licence: Apache-2.0.
