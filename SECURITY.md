# Security policy

Report a vulnerability privately. Use GitHub's "Report a vulnerability" (private security advisories) on this repository, or email
the maintainers listed in `Cargo.toml`'s repository. Please do not open a public issue for a suspected vulnerability.

In scope: anything that lets an untrusted worker, ticket text or patch escape the boundary, read a credential, forge a verdict, widen
its scope, write outside its tree, make the trusted phase run worker-controlled code, or make the outbox post more than once; and
anything that makes the container verifier report `ok` when it is not or leak a credential value into a report.

Out of scope (documented limits): open network egress, a hostile launcher faking `/proc`, and the unimplemented L2 push step.
