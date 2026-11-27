# INFERNEX Parallel Engineering Workstreams

INFERNEX is moving to a **native-first, all-in-one cybersecurity platform**. Its core capabilities must be implemented and maintained in this repository. Third-party integrations may remain optional compatibility adapters, but native commands must not require them.

This file defines parallel code ownership to prevent conflicting edits.

## Core maintainer — CLI, networking and platform (approximately 60%)

Owns:
- `src/main.rs`: CLI dispatcher, REPL, help, command integration
- `src/net.rs` (new): native networking, DNS, TCP connect scanning, service identification, network diagnostics
- `Cargo.toml` and `Cargo.lock`: dependency decisions and integration
- Engine adapters and eventual removal/reclassification of external-tool-dependent features
- Themes, aliases, global configuration, release workflows
- Shared architecture, integration, review and merges

### Networking roadmap

Build original INFERNEX implementations, with clear safe limits and tests:
1. Native host/IP parsing, DNS resolution and local network information
2. TCP connect scanner with strict bounded ranges and timeouts
3. Service identification from observed protocol responses (not just port-number guesses)
4. Network inventory and structured output
5. Additional protocol diagnostics, with authorization scope enforced before active network actions

Do not claim full Nmap equivalence. Implement and document each protocol/feature ourselves.

## Second contributor — Cryptography and file integrity (approximately 40%)

Own and implement the native cryptography feature in:

- `src/crypto.rs` — all implementation and unit tests for this feature

Do not edit `src/main.rs`, `src/net.rs`, `Cargo.toml`, `Cargo.lock`, workflows, or files owned by the core maintainer. The maintainer will connect the finished module to CLI commands after reviewing its API. If a new cryptographic crate is needed, propose the exact crate, version, license and reason in the PR; do not change Cargo files.

### Product goal

Build INFERNEX's own **Crypto & File Integrity Toolkit**. This is for legitimate file integrity, encryption, decryption and recovery of data the user owns or is authorized to handle. Do not build password cracking, credential theft, ransomware, stealth, or bypasses for access controls.

### Phase 1 — implement now using existing dependencies

Use the existing `sha2` dependency and Rust standard library where possible.

1. A typed algorithm enum for SHA-256 and SHA-512.
2. Streaming file hashing (bounded memory; never load entire large files).
3. Checksum verification with strict hex length/character validation and case-insensitive digest comparison.
4. Hash byte-slice helpers for unit tests and future internal use.
5. Useful typed errors for file I/O, unsupported algorithms and invalid expected digests.
6. Deterministic output/API that the CLI can consume without knowing implementation details.
7. Tests: known vectors, empty file, large/multi-buffer file, binary data, invalid checksums, wrong checksum, missing/unreadable file where portable.

### Phase 2 — propose authenticated file encryption/decryption

Design a safe file-encryption format, but do not add dependencies or claim encryption is implemented until the maintainer approves the dependency proposal.

The proposal should use established authenticated encryption (AES-256-GCM or ChaCha20-Poly1305) and a password KDF (Argon2id), with:
- Random salt and nonce from a cryptographically secure OS RNG
- Authenticated metadata and versioned file format
- Strict parameter bounds to prevent malicious KDF resource exhaustion
- No hard-coded keys, homemade ciphers, or unauthenticated encryption
- Atomic output writes and no overwrite by default
- Clear failure behavior: authentication failure must not produce a plaintext output file
- Tests for round-trip, wrong password, modified ciphertext, truncated files, malformed headers, and resource-bound validation
- A documented warning that losing the password means the data may be unrecoverable

The feature must encrypt/decrypt user-supplied files only. Do not implement disk-wide encryption, background encryption, destructive deletion, stealth, or automatic file discovery.

### Public API and CLI proposal

Expose a clean module API with equivalents of:
- `hash_file(path, algorithm)`
- `verify_file(path, algorithm, expected_hex)`
- Later, after crypto design approval: `encrypt_file(input, output, password)` and `decrypt_file(input, output, password)`

The core maintainer owns CLI integration, for example:
- `nex crypto hash sha256 <file>`
- `nex crypto hash sha512 <file>`
- `nex crypto verify sha256 <file> <digest>`
- Later: `nex crypto encrypt <input> <output>` and `nex crypto decrypt <input> <output>`

### Branch and delivery

1. Pull latest `main`.
2. Create branch `feature/native-crypto-toolkit`.
3. Implement only `src/crypto.rs` and tests inside that module.
4. Do not edit the CLI or dependency manifests.
5. Run `cargo fmt --check` and `cargo test`; report exact output and do not claim tests passed if not run.
6. Open a pull request against `main`; do not merge it.
7. In the PR explain API, format decisions, cryptographic design, dependency proposals (if any), test coverage and limitations.

## Shared rules

- Native INFERNEX code is the product; third-party engines are optional and must never be silently required by native commands.
- Keep module boundaries clean; coordinate through public APIs and pull requests.
- No unreviewed dependency changes.
- No target scanning beyond explicit user-supplied scope; active networking safeguards are owned by the core maintainer.
- Cross-platform Windows/Linux behavior is required.
- Do not claim feature completeness or compatibility with established commercial/open-source suites without evidence.
