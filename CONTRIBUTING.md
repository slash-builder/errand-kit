# Contributing

* Sign off every commit (`git commit -s`): the project uses the Developer Certificate of Origin.
* Run `bash scripts/ci.sh` before opening a pull request. It runs fmt, clippy with `-D warnings`, the tests (default and no default
  features), the docs with warnings denied, `cargo-deny`, the hygiene gate and a package dry run.
* A change to the contract (`src/contract.rs`) must regenerate the schemas (`ERRAND_UPDATE_SCHEMAS=1 cargo test schema`) and add or
  update a fixture.
* The library has no `unsafe`, no `unwrap`, `expect` or `panic!` outside tests, and logs through `tracing`.
