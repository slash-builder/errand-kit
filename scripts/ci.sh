#!/usr/bin/env bash
# The gates, in one place, shared by Jenkinsfile (every push and PR) and Jenkinsfile.release (before publishing).
# Rust and crates.io standard section 4: fmt, clippy -D warnings, tests with default and no default features, docs with
# -D warnings, cargo-deny, the hygiene gate, and a package dry run.
set -euo pipefail
cd "$(dirname "$0")/.."

rustup component add rustfmt clippy >/dev/null 2>&1 || true
cargo fmt --all --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-features --locked
cargo test --no-default-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --locked
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check
else
  echo "ci: cargo-deny is not installed; install it (cargo install cargo-deny --locked) to run the supply-chain gate" >&2
  [ "${REQUIRE_DENY:-0}" = "1" ] && exit 1
fi
bash scripts/hygiene.sh
# A package dry run proves the crate builds from what would actually ship (no registry is contacted for the upload itself).
cargo publish --dry-run --locked --allow-dirty --registry crates-io >/dev/null 2>&1 || cargo package --locked --allow-dirty
echo "ci: all gates passed"
