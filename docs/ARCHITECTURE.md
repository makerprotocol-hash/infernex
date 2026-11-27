# INFERNEX architecture

## Product direction

INFERNEX is a **native-first, all-in-one cybersecurity command platform** written in Rust. Its built-in commands and modules are the product. It must remain useful without Nmap, Metasploit, Wireshark, SQLmap or other separately installed security programs.

Optional adapters may be retained for compatibility, but they are secondary. Native implementations must be independently testable, documented and maintained in this repository. We will build capability incrementally rather than claim parity with mature external suites.

## Current code boundaries

- **CLI/core — `src/main.rs`:** argument parsing, REPL, help, version, config, thin native network command routing, and compatibility adapters.
- **Native crypto — `src/crypto.rs`:** typed SHA-256/SHA-512 operations, streaming file hashing, checksum verification, byte-slice hashing helpers, explicit caller-supplied file-integrity manifests and module-local tests.
- **Native scope — `src/scope.rs`:** local authorization inventory, IP/CIDR/hostname matching and fail-closed matching logic.
- **Native networking — `src/net.rs`:** owns pure networking primitives and bounded DNS, TCP, UDP, service-identification, read-only local interface inventory, and route-inventory APIs. Interface enumeration uses the cross-platform `if-addrs` wrapper. Route inventory currently parses Linux kernel procfs snapshots for IPv4 and IPv6; Windows native route enumeration remains pending. The CLI retains output formatting and enforces explicit scope before active operations.
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

The NET-01 extraction is complete: DNS resolution, bounded TCP connect, one-datagram UDP exchange, and bounded service-identification socket orchestration live in `src/net.rs`. CLI wrappers retain output formatting and enforce explicit authorization scope before active operations. Loopback tests cover TCP, UDP, and service identification. Read-only local IPv4/IPv6 interface inventory is available through `nex net interfaces`. The initial Linux-only route inventory is being implemented through `nex net routes`; Windows API support remains a tracked follow-up. These are narrow diagnostics, not broad protocol coverage.

## Cryptography safety

Use established, reviewed cryptographic crates and standard constructions. Never invent ciphers or password KDFs. File encryption must use authenticated encryption, secure OS randomness, bounded KDF parameters, versioned formats and safe output handling. Authentication failure must not release plaintext. No encryption/decryption command is currently implemented.

## Third-party software

Each optional adapter must document its upstream project, supported version range, installation method, license, required notices and redistribution conditions. Bundling or modifying a tool requires license review. Do not remove required copyright or attribution notices.

## Testing and integration

- Run `cargo test --all-targets` and `cargo build --release` on Windows and Linux through CI.
- Run `cargo fmt --check` only after formatting all touched Rust files; do not report it as passing unless it was run.
- Contributors work in isolated branches and avoid shared integration files.
- The maintainer reviews module APIs, dependency changes, platform behavior and safety invariants before merging.
