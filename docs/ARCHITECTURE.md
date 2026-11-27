# INFERNEX architecture

## Product direction

INFERNEX is a **native-first, all-in-one cybersecurity command platform** written in Rust. Its built-in commands and modules are the product. It must remain useful without Nmap, Metasploit, Wireshark, SQLmap or other separately installed security programs.

Optional adapters may be retained for compatibility, but they are secondary. Native implementations must be independently testable, documented and maintained in this repository. We will build capability incrementally rather than claim parity with mature external suites.

## Intended layers

1. **CLI/core** — argument parsing, REPL, help, version, config, logging, error handling and command routing.
2. **Native networking** — DNS, address and CIDR utilities, local network diagnostics, bounded TCP connect scanning, protocol-aware service identification and network inventory.
3. **Native cryptography** — streaming hashes, checksum verification, authenticated file encryption/decryption and safe file-format handling.
4. **Native security modules** — future independently implemented defensive assessment tools with strict target scope, safe defaults and explicit actions.
5. **Optional compatibility adapters** — separately installed external programs, clearly marked optional and never a dependency for native commands.
6. **Packaging** — Windows/Linux builds, installer, updates and uninstall support.

## Module ownership

- Core/CLI: `src/main.rs` currently owns command routing and REPL behavior; split it into focused modules incrementally.
- Native crypto: `src/crypto.rs` owns streaming SHA-256/SHA-512 hashing and checksum verification, exposed through a small typed API and module-local tests.
- Native scope: `src/scope.rs` owns the local authorization inventory and fail-closed matching logic.
- Native networking: extract the current networking implementation from the CLI into `src/net.rs` without weakening scope checks or changing established command behavior.
- Coordinate parallel contributors by assigning separate modules/branches; do not let multiple contributors edit the same integration files concurrently.
- Integrate modules through reviewed public APIs and keep dependency changes explicit.

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

Active network operations must require explicit target input and eventually be checked against a user-maintained authorization scope. No silent target discovery, CIDR expansion, stealth, evasion, or unbounded scans. Scanner results are observations, not proof of authorization or vulnerability. Distinguish open, refused and inconclusive/no-response states.

## Cryptography safety

Use established, reviewed cryptographic crates and standard constructions. Never invent ciphers or password KDFs. File encryption must use authenticated encryption, secure OS randomness, bounded KDF parameters, versioned formats and safe output handling. Authentication failure must not release plaintext.

## Third-party software

Each optional adapter must document its upstream project, supported version range, installation method, license, required notices and redistribution conditions. Bundling or modifying a tool requires license review. Do not remove required copyright or attribution notices.

## Current native capabilities

- Interactive Rust CLI and persistent configuration.
- Streaming SHA-256 and SHA-512 file hashing and checksum verification.
- System DNS resolution and offline IPv4/IPv6 CIDR inspection.
- IPv4/IPv6 address classification.
- Explicit single-port TCP connectivity check.
- Bounded native TCP connect scanner for one literal IP and at most 256 ports per invocation.

These are foundational capabilities, not a claim that INFERNEX is already a complete security suite.
