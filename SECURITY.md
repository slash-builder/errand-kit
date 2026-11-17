# Security policy

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.** Report it privately, by either of these:

1. **GitHub private vulnerability reporting:** use the "Report a vulnerability" button on the [Security tab of this repository](https://github.com/slash-builder/errand-kit/security/advisories/new). Only the maintainer and you see the report.
2. **Email:** security@slashbuilder.com, for when GitHub's form is not an option for you.

Please include:

* what you found and where (file, command or page);
* the commit of `main` you looked at (`git rev-parse HEAD`) and your operating system;
* steps to reproduce it, or a short proof of concept;
* what you think the impact is, and whether anyone else knows.

## What to expect

You get an **acknowledgement within 7 days**, from a person. Nothing else is promised: this project has one maintainer, no paid support and no fixed fix time. If the report is valid, the reply says what happens next; if it is not, it says why.

## Supported versions

This project is pre-1.0. **Only the latest release and the latest commit of `main` are supported.** Older versions get no fixes; update to the latest release.

## Scope

In scope: the code, the spec and the documentation in **this repository**: the Rust crate (library and `errand` CLI). In particular, anything that lets an untrusted worker, ticket text or patch escape the boundary, read a credential, forge a verdict, widen its scope, write outside its tree, make the trusted phase run worker-controlled code, or make the outbox post more than once; and anything that makes the container verifier report `ok` when it is not or leak a credential value into a report.

Out of scope (documented limits, see the README): open network egress, a hostile launcher faking `/proc`, and the unimplemented L2 push step. Also out of scope: third-party services and software (GitHub, Docker, bubblewrap, the Claude CLI, Rust and their packages) and any other software the Kit can be used with. A problem there belongs with its owners. If you are not sure where something belongs, report it here, privately.
