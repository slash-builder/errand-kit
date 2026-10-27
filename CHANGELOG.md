# Changelog

All notable changes to this crate are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the crate follows [Semantic Versioning](https://semver.org/) (pre-1.0: a breaking change bumps the minor version).

## [0.1.0] - unreleased

### Added
- The contract: `spec/ERRAND.md`, six JSON Schemas generated from the Rust types, and shared conformance fixtures.
- The engine: prepare, boundary, worker, gates and record phases; the verdict computed in code wins.
- A container boundary verifier (nine required checks, three reported-only), a bubblewrap backend, and a test-only no-sandbox backend.
- A Claude CLI worker with a cleared environment and a hard tool allowlist checked against what the CLI reports, and a scripted fake worker.
- An idempotent outbox with read-back delivery, a fail-closed usage governor, and file and in-memory trackers.
- A patch validator (symlinks, modes, binary, path tricks, protected and out-of-scope paths, size) and a patch builder that never runs
  git inside the worker's directory.
- The `errand` command-line tool.
- Recipe gate commands are limited to inspect-only programs unless the recipe sets `gate_commands_execute_tree`.
