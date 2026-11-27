# Contributing to INFERNEX

Thanks for helping build INFERNEX.

## Product direction

INFERNEX is a native-first cybersecurity platform written in Rust. We want to implement our own networking, cryptography, file integrity, diagnostics and defensive security modules in this repository.

Native features are the product. Third-party programs may be supported as optional compatibility integrations, but wrappers around external tools are not a substitute for native implementations.

## Engineering principles

- Build real, testable functionality; do not add placeholder commands that imply features exist.
- Keep modules independently testable with small, documented public APIs.
- Validate all inputs and fail safely on malformed or ambiguous data.
- Use bounded memory, timeouts and resource limits.
- Preserve Windows and Linux support.
- Use established cryptographic standards and reviewed crates; never invent cryptographic primitives.
- Active network features must use explicit targets and respect authorization scope.
- Document limitations honestly.
- Do not claim third-party code or capabilities as INFERNEX-authored.
- Review licenses and required notices before copying, modifying, bundling or redistributing external software.

## Parallel ownership

See [docs/WORKSTREAMS.md](docs/WORKSTREAMS.md) before starting work.

Current ownership:
- Core maintainer: CLI, networking, dependency manifests, integration and releases.
- Crypto contributor: `src/crypto.rs` and module-local tests.
- Scope contributor: `src/scope.rs` and module-local tests, when assigned.

Avoid editing another workstream's files. Coordinate through pull requests and documented module APIs. Do not merge your own feature branch unless explicitly authorized by the repository maintainer.

## Development checks

Install stable Rust, then run:

```sh
cargo fmt --check
cargo test --all-targets
cargo build --release
```

Report exact results. If a command could not be run, say so rather than implying success.

## Dependencies

Do not add dependencies without review. A proposal should include the exact crate and version, purpose, license, maintenance/security considerations and why the standard library or existing dependencies are insufficient.

## Pull requests

A useful PR includes:
- User-visible behavior and example commands.
- Public API and module boundaries.
- Tests covering normal, boundary and failure cases.
- Platform compatibility notes.
- Security implications and known limitations.
- Dependency/license details where applicable.

## Responsible use

INFERNEX is for systems and networks you own or are explicitly authorized to assess. Never include credentials, private keys, tokens, personal data or real target information in issues, commits or test fixtures.
