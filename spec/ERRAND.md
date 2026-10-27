# Errand Kit: the contract

**Status: alpha (0.1).** The contract may change before 1.0. An *errand* is a bounded piece of delegated work that runs under limits and comes back
with a hand-back for a human. This document is the contract; `schema/` holds the JSON Schemas generated from the Rust types,
and `fixtures/` holds the shared conformance cases that every implementation and every consumer must pass (the App Context Kit
method: the suite is the product, the prose is commentary).

Consumers: a long-running service that works a queue, a container that runs scheduled tasks, and a client app that only reads the
queue snapshot and writes consent commands (it never runs a worker). Language: Rust; other languages consume the schemas and fixtures.

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
| **L2** | open a PR | as L1 | the *trusted* phase applies the validated patch to a fresh clone it made itself, pushes a branch and opens a PR. **Specified, not implemented in this release:** the Kit provides the patch builder and validator; the push and PR step belongs to the host and is not in the CLI |
| **L3** | never automatic | none | parked for a human; the engine never executes it |

No worker gets `Bash`, `WebFetch`, `WebSearch` or any MCP tool until there is an egress broker (open egress plus a shell is an
exfiltration channel). The worker is started with an empty environment, a fresh empty `HOME`, project and local settings DISABLED
(a repository's own `.claude/settings.json` can define hooks, which are shell commands: verified, with default settings a project
hook ran inside the worker), and slash commands disabled. An L1+ errand REQUIRES a recipe and its own tree; a write-capable worker
is never given the output directory. Merging, consent labels, CI definitions, infrastructure-as-code applies, gate recipes, secrets and the
Kit's own repository are **never** automated at any level.

## 3. The verdict is computed in code

A task's prepare step may write `out/status.txt` containing exactly `STATUS: OK` or `STATUS: ATTENTION`. When it exists it
**is** the verdict. The model's digest must end (last non-empty line, nowhere else) with the same line; a mismatch fails the run
(exit 73) and the verdict is `FAILED`. When the task cannot compute a verdict, the digest's last line is used and must be exactly
`STATUS: OK` or `STATUS: ATTENTION`; anything else is `FAILED`.

**Exit codes of the CLI:** `0` OK; `3` ATTENTION; `64` any other error (usage, I/O, task, recipe, tracker); `70` the worker produced
no digest; `72` the boundary refused the run; `73` a hard gate failed, the verdict disagreed with the code's, or the digest had no
valid STATUS line.

## 4. The boundary (phase 2)

A `Sandbox` verifies before any worker starts and **there is no automatic mode**: a missing sandbox is a refusal, never a
fall-back to none. `sandbox-none` exists only behind the `test-sandbox` feature.

**`container` backend** (the container is the boundary; the Kit verifies and refuses). Required checks, all of which must pass:
`/proc/self/status` shows all `Uid`/`Gid` non-zero, `CapEff`/`CapPrm`/`CapInh`/`CapAmb`/`CapBnd` all zero, `NoNewPrivs: 1`,
`Seccomp: 2`; `/` is mounted read-only; **a write to `/` is refused as a read-only filesystem (`EROFS`)**, a plain permission error
proves nothing because a non-root user is refused on a read-write root too; every writable mount is on an allowlist; no
container-runtime socket exists at a well-known path **or anywhere in the writable directories**, and `DOCKER_HOST` is unset; **no
well-known credential file exists** (cloud credentials, `.netrc`, `.git-credentials`, SSH keys, the Kubernetes service-account
token, and anything in `/run/secrets` other than the worker's own token file); and **no process in the container has a
credential-shaped variable name in `/proc/*/environ`**, names only, never values. A process whose environment cannot be read
(another user, `hidepid`) also refuses the run, because the Kit cannot prove it holds no credential.

A name is credential-shaped if it starts with a listed prefix (`AWS_`, `GITHUB_`, `JIRA_`, `SLACK_`, ...), ends with a listed suffix
(`_PASSWORD`, `_SECRET`, `_TOKEN`, `_API_KEY`, ...), is a listed exact name (`SSH_AUTH_SOCK`, `KUBECONFIG`), or starts with a prefix
a deployment adds in `ERRAND_CREDENTIAL_PREFIXES`. The worker's own `CLAUDE_CODE_OAUTH_TOKEN` is the one exception.

Reported but not required: `nosuid,nodev` on the writable mounts (with every capability dropped and `no-new-privileges`, which are
required, a data bind mount without them is not an escape path); cgroup v2 `memory.max` and `pids.max` set; a minimal set of
network interfaces. Not trusted at all: `/.dockerenv`, the hostname, cgroup path names. A hostile launcher can fake `/proc`; these
checks catch a broken launcher, not a malicious one, and the record says so. Egress is open and cannot be verified closed: the run
record states `egress: "open"`.

**`bubblewrap` backend** (a Linux host): argument construction only; masks the home directory, `/run`, `/var/lib/docker`, secrets.

## 5. Gates (phase 4)

Every gate returns a `GateResult { name, kind, ok, hard, detail }`; any failed hard gate makes the verdict `FAILED`.

* `boundary`: phase 2 passed.
* `tools_match`: the tool list the worker reported at start equals the requested list.
* `status_line`: section 3.
* `secret_scan`: neither the digest nor an ADDED line of the patch contains a secret-shaped string (cloud keys, tokens, private-key
  blocks) or the worker's own token. The artifacts are written with the token redacted regardless.
* `env_clean`: the worker's environment held no credential-shaped name.
* `diff_scope` (L1+): runs on the **patch text**, before anything is applied. Rejects: symlinks (mode `120000`), mode changes,
  submodule/gitlink entries (`160000`), paths containing `..` or starting with `/`, anything under `.git/`, any path outside the
  recipe's scope globs, and any path matching the **protected** globs (tests, CI definitions, `Jenkinsfile*`, `.github/`,
  `Dockerfile*`, build scripts, lockfiles, `.git*`) unless the recipe names that path explicitly.
* `command`: run a recipe-defined argv in the worker's tree with an empty environment and a time limit; exit 0 expected. **These run
  files the worker may have written (for example `cargo test`), so they run ONLY after every other hard gate has passed, never on a
  rejected patch, and nothing they do can change what is recorded:** the patch is built and validated in memory first, and
  `patch.diff`, `digest.md` and `run.json` are written by the engine afterwards. A recipe may use only inspect-only programs (`test`, `grep`, `diff`, `jq`, ...) unless it sets `gate_commands_execute_tree: true`: a command that executes tree code runs in the Kit's context beside the worker's token with open egress, so it re-opens the shell-plus-egress risk and is opt-in, never default; opt in only when egress is closed (a narrow scope is not enough: doctests run from Markdown).

**Scope globs, protected-glob exceptions and gate commands come only from a repo-side recipe (`recipes/<repo>.toml`), never from
a tracker field or alert text.** Ticket and alert text is data: it goes into the prompt between delimiters and is never
interpolated into argv, a path or a gate.

## 6. The trusted phase accepts a patch and a hand-back, nothing else

It never opens, reads config from, or runs anything inside the worker's directory (`.git/config` can set `core.hooksPath`,
`core.fsmonitor`, `credential.helper`, `url.insteadOf`). It verifies `patch.diff` against `handback.patch_sha256`, validates the patch (section 5), clones fresh, applies with
`git apply`, re-checks the resulting file modes (a pure rename carries no mode line), then pushes. **It never re-runs recipe gate
commands**: that would execute worker-written code on a host that holds a push credential. A pushed branch is run by CI before any human merges, so CI definitions are
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

## 9. Client contract: the queue snapshot

`QueueSnapshot` is the file (`queue.json`) a running engine publishes for a client app to show. Its JSON Schema and fixtures let an
engine and a client in different languages be tested against the same files. Unknown fields are ignored; absent optional fields are `null`.

## 10. Non-goals

UI, pairing, CI job definitions, model hosting, memory, and any decision about *which* work to do (that is the tracker and
the human).
