# Errand Kit: the contract

**Status: draft 0.1 (2026-10-26).** An *errand* is a bounded piece of delegated work that runs under limits and comes back
with a hand-back for a human. This document is the contract; `schema/` holds the JSON Schemas generated from the Rust types,
and `fixtures/` holds the shared conformance cases that every implementation and every consumer must pass (the App Context Kit
method: the suite is the product, the prose is commentary).

Consumers: the Dispatcher service, the automation container (Jenkins), and Courier (which only reads the queue snapshot and
writes consent commands; it never runs a worker). Language: Rust; Courier consumes the schemas and fixtures.

## 1. The lifecycle: one errand, six phases

| # | Phase | Holds credentials | Who runs it | Output |
|---|---|---|---|---|
| 1 | **prepare** | yes | trusted | files in `out/`, optionally `out/status.txt` (the verdict, computed in code) |
| 2 | **boundary** | n/a | the Kit | `BoundaryReport`; a failed check refuses the run (exit 72) |
| 3 | **worker** | **no** | untrusted model | a digest, or for L1+ a patch |
| 4 | **gates** | no | the Kit | `GateResult`s; a hard failure is `FAILED` |
| 5 | **record** | no | the Kit | `run.json`, `digest.md`, artifacts |
| 6 | **consent** | n/a | a human | the only way anything is applied, pushed or merged |

**Phases 1 and 3 never share a process tree or a container.** Unsetting a variable is not a boundary: the environment a process
started with stays readable in `/proc/<pid>/environ`, and a model with a Grep or Read-by-shell tool returns it (verified
2026-10-26: Claude's Grep returned a variable the script had unset). So the worker runs where no credential was ever present,
and phase 2 *proves* that instead of assuming it.

## 2. Risk levels

| Level | Meaning | Worker tools (hard allowlist) | What may leave the run |
|---|---|---|---|
| **L0** | report only | `Read`, `Grep`, `Glob` | a digest and a verdict |
| **L1** | propose a change | L0 plus `Edit`, `Write` | a **patch** and a hand-back; nothing is pushed |
| **L2** | open a PR | as L1 | the *trusted* phase applies the validated patch to a fresh clone it made itself, pushes a branch and opens a PR |
| **L3** | never automatic | none | parked for a human; the engine never executes it |

No worker gets `Bash`, `WebFetch`, `WebSearch` or any MCP tool until there is an egress broker (open egress plus a shell is an
exfiltration channel). Merging, consent labels, CI definitions, infrastructure-as-code applies, gate recipes, secrets and the
Kit's own repository are **never** automated at any level.

## 3. The verdict is computed in code

A task's prepare step may write `out/status.txt` containing exactly `STATUS: OK` or `STATUS: ATTENTION`. When it exists it
**is** the verdict. The model's digest must end (last non-empty line, nowhere else) with the same line; a mismatch fails the run
(exit 73) and the code's value is the one recorded. When the task cannot compute a verdict, the digest's last line is used and
must be exactly `STATUS: OK` or `STATUS: ATTENTION`. Exit codes: `0` OK, `3` ATTENTION, `64` usage, `70` no digest, `71` no valid
STATUS line, `72` boundary refused, `73` verdict mismatch or a hard gate failed, `80`+ environment.

## 4. The boundary (phase 2)

A `Sandbox` verifies before any worker starts and **there is no automatic mode**: a missing sandbox is a refusal, never a
fall-back to none. `sandbox-none` exists only behind the `test-sandbox` feature.

**`container` backend** (the container is the boundary; the Kit verifies and refuses):
reliable checks, all required: `/proc/self/status` shows all `Uid`/`Gid` non-zero, `CapEff`/`CapPrm`/`CapInh`/`CapAmb`/`CapBnd`
all zero, `NoNewPrivs: 1`, `Seccomp: 2`; `/` is mounted read-only and every writable mount is on an allowlist and `nosuid,nodev`;
a write to `/` fails with `EROFS`; no socket at `/var/run/docker.sock`, `/run/containerd/*` or `/run/podman`, and `DOCKER_HOST`
is unset; **no process in the container has a credential-shaped variable name in `/proc/*/environ`** (names only, never
values). Medium-reliability checks, reported but not sufficient alone: cgroup v2 `memory.max` and `pids.max` are not `max`;
`/proc/net/dev` shows only `lo` and one interface. Not trusted at all: `/.dockerenv`, the hostname, cgroup path names. A hostile
launcher can fake `/proc`; these checks catch a broken launcher, not a malicious one, and the record says so. Egress is open and
cannot be verified closed: the run record states `egress: "open"`.

**`bubblewrap` backend** (a Linux host): argument construction only; masks the home directory, `/run`, `/var/lib/docker`, secrets.

## 5. Gates (phase 4)

Every gate returns a `GateResult { name, kind, ok, hard, detail }`; any failed hard gate makes the verdict `FAILED`.

* `boundary`: phase 2 passed.
* `tools_match`: the tool list the worker reported at start equals the requested list.
* `status_line`: section 3.
* `env_clean`: the worker's environment held no credential-shaped name.
* `diff_scope` (L1+): runs on the **patch text**, before anything is applied. Rejects: symlinks (mode `120000`), mode changes,
  submodule/gitlink entries (`160000`), paths containing `..` or starting with `/`, anything under `.git/`, any path outside the
  recipe's scope globs, and any path matching the **protected** globs (tests, CI definitions, `Jenkinsfile*`, `.github/`,
  `Dockerfile*`, build scripts, lockfiles, `.git*`) unless the recipe names that path explicitly.
* `command`: run a recipe-defined argv in a sandbox with no network and no credentials; exit 0 expected.

**Scope globs, protected-glob exceptions and gate commands come only from a repo-side recipe (`recipes/<repo>.toml`), never from
a tracker field or alert text.** Ticket and alert text is data: it goes into the prompt between delimiters and is never
interpolated into argv, a path or a gate.

## 6. The trusted phase accepts a patch and a hand-back, nothing else

It never opens, reads config from, or runs anything inside the worker's directory (`.git/config` can set `core.hooksPath`,
`core.fsmonitor`, `credential.helper`, `url.insteadOf`). It validates the patch (section 5), clones fresh, applies with
`git apply`, re-runs the gates itself, then pushes. A pushed branch is run by CI before any human merges, so CI definitions are
protected paths.

## 7. Outbox: idempotent, read-back

Every external post is an `OutboxEntry` with `id = sha256(run_id, op, target)` and carries the marker `[errand:<id>]`. Delivery
first asks the tracker whether a comment with that marker exists; it posts only if not, and marks the entry delivered only after
confirming it. If the outbox store is unreadable nothing is sent. Slack text is escaped (`&`, `<`, `>`, `@`, `!`) with
unfurling off before posting.

## 8. Governor

Pure function of a snapshot of usage windows: `allow` unless a window's `used_fraction` is at or above its ceiling (defaults
0.70 for five hours, 0.80 for seven days). **A stale (older than the configured age), missing or unreadable snapshot means
deny.**

## 9. Courier contract: the queue snapshot

`QueueSnapshot` formalises the engine's existing `queue.json` (see the Dispatcher's `docs/COURIER-CONTRACT.md`) so Courier's
parser and the engine are tested against the same fixtures. Unknown fields are ignored; absent optional fields are `null`.

## 10. Non-goals

UI, pairing, Jenkins job definitions, model hosting, memory, and any decision about *which* work to do (that is the tracker and
the human).
