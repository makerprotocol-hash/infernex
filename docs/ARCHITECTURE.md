# INFERNEX architecture

## Product direction

INFERNEX is a **native-first, all-in-one cybersecurity command platform** written in Rust. Its built-in commands and modules are the product. It must remain useful without Nmap, Metasploit, Wireshark, SQLmap or other separately installed security programs.

Optional adapters may be retained for compatibility, but they are secondary. Native implementations must be independently testable, documented and maintained in this repository. We will build capability incrementally rather than claim parity with mature external suites.

## Current code boundaries

- **CLI/core — `src/main.rs`:** argument parsing, REPL, help, version, config, command routing, current native networking implementation and compatibility adapters. Networking is not yet extracted into a dedicated module.
- **Native crypto — `src/crypto.rs`:** typed SHA-256/SHA-512 operations, streaming file hashing, checksum verification and module-local tests. Byte-slice hashing helpers are merged. Explicit file-integrity manifest APIs are in open contributor PR #4 and are not yet part of main.
- **Native scope — `src/scope.rs`:** local authorization inventory, IP/CIDR/hostname matching and fail-closed matching logic.
- **Native networking — `src/net.rs`:** owns pure, side-effect-free networking primitives: TCP port/range validation, service-banner classification, and IPv4/IPv6 private/link-local classification. Active socket operations and CLI wrappers remain in `src/main.rs` for the next extraction step.
- **Optional compatibility adapters:** separately installed external programs, clearly marked optional and never a dependency for native commands.
- **Packaging:** Windows/Linux builds, installer, updates and uninstall support.

## Native module contracts

Each native module must:
- Expose a small typed Rust API with documented input, output and error behavior.
- Avoid shell evaluation and unsafe string-to-command construction.
- Use bounded memory, timeouts and resource limits where relevant.
- Validate inputs and fail closed on malformed or ambiguous data.
- Include unit tests for normal cases, boundary cases and failures.
- Support Windows and Linux or document a specific platform limitation.
- Never imply that a port number alone proves a service identity.

## Networking safety

Active TCP and UDP operations require explicit targets present in the local authorization scope. The scope implementation supports exact IPs, IPv4/IPv6 CIDRs and exact hostnames; it does not infer permission from DNS results, wildcards or subdomains. No silent target discovery, CIDR expansion, stealth, evasion or unbounded scans. Scanner results are observations, not proof of authorization or vulnerability. Distinguish open, refused and inconclusive/no-response states.

The first modularization step is complete: pure networking primitives and their unit tests live in `src/net.rs`. The NET-01B extraction is in progress: bounded DNS resolution, TCP connect, and one-datagram UDP exchange APIs now live in `src/net.rs`, with loopback tests for TCP and UDP. CLI wrappers retain output formatting and scope enforcement; service-identification socket orchestration remains in `src/main.rs`. These are narrow diagnostics, not broad protocol coverage.

## Cryptography safety

Use established, reviewed cryptographic crates and standard constructions. Never invent ciphers or password KDFs. File encryption must use authenticated encryption, secure OS randomness, bounded KDF parameters, versioned formats and safe output handling. Authentication failure must not release plaintext. No encryption/decryption command is currently implemented.

## Third-party software

Each optional adapter must document its upstream project, supported version range, installation method, license, required notices and redistribution conditions. Bundling or modifying a tool requires license review. Do not remove required copyright or attribution notices.

## Testing and integration

- Run `cargo test --all-targets` and `cargo build --release` on Windows and Linux through CI.
- Run `cargo fmt --check` only after formatting all touched Rust files; do not report it as passing unless it was run.
- Contributors work in isolated branches and avoid shared integration files.
- The maintainer reviews module APIs, dependency changes, platform behavior and safety invariants before merging.
