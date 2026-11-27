# Contributing to INFERNEX

Thanks for helping build INFERNEX.

## Product direction

INFERNEX is a native-first cybersecurity platform written in Rust. We are implementing our own networking, cryptography, file integrity, diagnostics and defensive security modules in this repository.

Native features are the product. Third-party programs may be supported as optional compatibility integrations, but wrappers around external tools are not a substitute for native implementations.

## Before coding

Read [docs/WORKSTREAMS.md](docs/WORKSTREAMS.md) and choose one task card. The roadmap defines file ownership, exact scope and acceptance criteria so parallel contributors and coding agents do not overwrite one another.

## Engineering principles

- Build real, testable functionality; do not add placeholder commands that imply features exist.
- Keep modules independently testable with small, documented public APIs.
- Validate all inputs and fail safely on malformed or ambiguous data.
- Use bounded memory, timeouts and resource limits.
- Preserve Windows and Linux support.
- Use established cryptographic standards and reviewed crates; never invent cryptographic primitives.
- Active network features must use explicit targets and enforce local authorization scope before opening sockets.
- Document limitations honestly.
- Do not claim third-party code or capabilities as INFERNEX-authored.
- Review licenses and required notices before copying, modifying, bundling or redistributing external software.

## Parallel ownership

- Core maintainer: `src/main.rs`, `src/net.rs`, dependency manifests, CI, CLI integration and releases.
- Crypto contributor: `src/crypto.rs` only, on a dedicated branch.
- Scope module is integrated; changes to `src/scope.rs` require a separately assigned task.

Avoid editing another workstream's files. Coordinate through pull requests and documented module APIs. Do not merge your own feature branch unless explicitly authorized by the repository maintainer.

## Development checks

Install stable Rust, then run:

```sh
cargo test --all-targets
cargo build --release
```

Format touched Rust files with `cargo fmt` and verify with `cargo fmt --check`. Report exact results. If a command could not be run, say so rather than implying success.

## Dependencies

Do not add dependencies without review. A proposal should include the exact crate and version, purpose, license, maintenance/security considerations, MSRV impact and why the standard library or existing dependencies are insufficient.

## Pull requests

A useful PR includes:
- The task card being completed.
- User-visible behavior and example commands, if applicable.
- Public API and module boundaries.
- Tests covering normal, boundary and failure cases.
- Platform compatibility notes.
- Security implications and known limitations.
- Dependency/license details where applicable.
- Exact commands run and their results.

Keep each PR focused on one task card. Open against `main`; do not merge it yourself.

## Responsible use

INFERNEX is for systems and networks you own or are explicitly authorized to assess. Never include credentials, private keys, tokens, personal data or real target information in issues, commits or test fixtures.

## Licensing contributions

By intentionally submitting a contribution for inclusion in INFERNEX, you agree that the contribution is offered under the repository's dual license, `MIT OR Apache-2.0`, unless you clearly state otherwise at the time of submission. You retain copyright in your contribution. Do not submit code, documentation, or other material unless you have the right to license it under these terms. Brand assets and trademarks are not covered by the software license.
