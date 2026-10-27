#!/usr/bin/env bash
# Hygiene gate (Rust and crates.io standard, section 4 gate 8): nothing internal may ship.
# Scans exactly what `cargo package` would ship, plus the tracked-file rules. Exit 1 with the offending lines on any hit.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0

# 1. Tracked files that must never exist in a published Kit.
bad="$(git ls-files | grep -E '(^|/)(AGENT\.md|CLAUDE\.md|\.gitmodules|\.claude/)' || true)"
if [ -n "$bad" ]; then echo "hygiene: forbidden tracked files:"; echo "$bad"; fail=1; fi

# 2. Internal names in anything that ships (the cargo `include` allow-list: src/ spec/ schema/ fixtures/ README LICENSE CHANGELOG).
# Hostnames, private repositories, host names of internal machines, personal paths, secret-shaped strings.
pattern='softsurve\.com|lockamy-studios|quickring/|dlockamy|jbot@|sol/master|/Users/|/home/jbot|jenkins\.|nexus\.|\.slack\.com|AKIA[0-9A-Z]{12,}|ghp_[A-Za-z0-9]{20,}|xox[bp]-[A-Za-z0-9-]{10,}|sk-ant-[A-Za-z0-9_-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----'
hits="$(grep -rIn -E "$pattern" src spec schema fixtures README.md CHANGELOG.md 2>/dev/null | grep -v -E '^src/.*(// |//! |/// ).*example\.com' || true)"
if [ -n "$hits" ]; then echo "hygiene: internal or secret-shaped strings in shipped content:"; echo "$hits" | cut -c1-200; fail=1; fi

# 3. The package must contain only what the allow-list says.
extra="$(cargo package --list --locked --allow-dirty 2>/dev/null | grep -v -E '^(src/|spec/|schema/|fixtures/|README\.md$|LICENSE$|CHANGELOG\.md$|Cargo\.toml$|Cargo\.toml\.orig$|Cargo\.lock$|\.cargo_vcs_info\.json$)' || true)"
if [ -n "$extra" ]; then echo "hygiene: unexpected files in the package:"; echo "$extra"; fail=1; fi

[ "$fail" = 0 ] && echo "hygiene: ok"
exit "$fail"
