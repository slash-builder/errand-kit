# Contributing to Errand Kit

Thanks for your interest. Contributions are welcome: bug reports, feature requests, documentation improvements and code patches.

## Quick reference

| Item | Value |
|---|---|
| Licence | Apache-2.0 |
| Sign-off | `git commit -s` (Developer Certificate of Origin) |
| Required approver | A code owner: see [`.github/CODEOWNERS`](.github/CODEOWNERS) |
| CI | GitHub Actions, on every pull request |
| Conduct | [Contributor Covenant 2.1](CODE_OF_CONDUCT.md); reports to `conduct@slashbuilder.com` |
| Security | [SECURITY.md](SECURITY.md); never a public issue |

## Before you start

Open an issue first for substantial design changes: new public API surfaces, breaking changes, new dependencies, and anything that
touches the trust boundary (the sandbox backends, the gates, the verdict, the outbox). Small changes (typos, doc fixes, small bug
fixes) can go straight to a pull request.

### Kit-specific invariants

* A change to the contract (`src/contract.rs`) must regenerate the schemas (`ERRAND_UPDATE_SCHEMAS=1 cargo test schema`) and add or
  update a fixture.
* The library has no `unsafe`, no `unwrap`, `expect` or `panic!` outside tests, and logs through `tracing`.

## Local development

```sh
cargo build
cargo test
bash scripts/ci.sh        # everything CI runs: fmt, clippy -D warnings, tests, docs, cargo-deny, hygiene, package dry run
```

Requires Rust 1.94 or newer (the declared `rust-version`). `scripts/ci.sh` needs `cargo-deny` (`cargo install cargo-deny --locked`);
it skips that step with a warning if the tool is missing. The tests need `git` on the `PATH`. Nothing else is needed: no private
registry, no credentials, no network access beyond downloading crates.

## Code style

* `cargo fmt --all` must produce no diff.
* `cargo clippy --all-targets --all-features -- -D warnings` must pass with zero warnings.

## Continuous integration

Every pull request runs, on GitHub Actions: the gates in `scripts/ci.sh` on the declared Rust version (formatting, clippy, docs,
tests, `cargo-deny`, the hygiene check and a package dry run), tests on Linux (x86-64 and arm64) and macOS, the
minimum-supported-Rust check, `cargo-semver-checks`, and a DCO check. A non-blocking job also runs clippy and the tests on the
current stable compiler as an early warning.

Releases are automated with [release-plz](https://release-plz.dev): pushes to `main` open or update a release pull request that bumps the version and changelog from Conventional Commit titles (`feat:`, `fix:`, a `!` for a breaking change) and checks the bump with `cargo-semver-checks`. Merging that pull request releases the crate: a tag `vX.Y.Z` equal to the crate version, published to crates.io by trusted publishing from a protected environment.

## Pull request process

1. Fork the repository and create a branch from `main`.
2. Make your changes and sign off each commit with `git commit -s`.
3. Run `bash scripts/ci.sh` and confirm it passes.
4. Open a pull request against `main` and address review feedback. A code owner must approve before merge.
5. The maintainer merges (squash by default).

## Sign your commits (DCO)

This project uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/).
By adding a `Signed-off-by` line you certify that you wrote the change or have the right to submit it
under the project's licence (Apache-2.0).

```sh
git commit -s -m "your message"      # adds: Signed-off-by: Your Name <you@example.com>
git rebase --signoff main            # add the line to commits you already made
```

Use your real name and a working email address. A check on every pull request fails if any
non-merge commit is missing the line.

Under section 5 of the Apache License 2.0, a contribution you submit is licensed under the same
terms as the project unless you state otherwise. There is no separate contributor agreement.
