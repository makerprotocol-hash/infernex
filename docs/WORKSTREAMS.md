# INFERNEX engineering roadmap and workstreams

INFERNEX is a **native-first, all-in-one cybersecurity platform**. Native implementations in this repository are the product. External tools may remain optional compatibility adapters, never a required foundation.

This document is also the task handoff for human contributors and coding agents. Pick one task card, follow its file boundaries, open a focused pull request, and stop rather than modifying another workstream's files.

## Ownership and file boundaries

### Core maintainer — CLI, networking and integration

Owns:
- `src/main.rs` — CLI dispatcher, REPL, help and integration.
- `src/net.rs` — new networking module and its tests.
- `Cargo.toml`, `Cargo.lock` — dependency review and integration.
- `.github/workflows/**` — CI and release workflows.
- `README.md`, architecture, command reference and release documentation.
- Reviews and merges all contributor PRs.

### Crypto contributor — module-only work

Owns:
- `src/crypto.rs` and tests inside that module, on a dedicated feature branch.

Must not edit:
- `src/main.rs`, `src/net.rs`, `src/scope.rs`, `Cargo.toml`, `Cargo.lock`, CI workflows or maintainer-owned documentation.

The crypto contributor proposes dependencies in the PR but does not add them without approval.

## How coding agents should work

Give the agent one task card from this file. Include these operating rules in its prompt:

1. Fetch/pull the latest `main` before starting.
2. Create a new branch named exactly as the task card specifies; never commit directly to `main`.
3. Read the owned module and its tests before editing.
4. Change only the files listed in that card. If another file appears necessary, stop and explain why in the PR rather than editing it.
5. Do not rewrite unrelated code or reformat the entire repository.
6. Add tests for success, invalid input, boundary and error behavior.
7. Run `cargo test --all-targets`; report the exact result. Run `cargo fmt --check` only if the touched Rust files are formatted; do not claim checks that were not run.
8. Open a PR against `main`, summarize the API, changed files, tests and limitations. Do not merge it.
9. Never claim a feature is complete because a stub, design note or untested function exists.
10. Do not add dependencies, modify manifests, or implement unsafe/unauthorized functionality without maintainer approval.

## Active contributor task cards

### NET-01A — extract pure networking primitives

**Status:** Implemented on main in commits `7025925` and `4f30748`.

- Added `src/net.rs` for TCP port/range validation, banner classification, and IP range classification.
- Moved the associated unit tests into the networking module.
- CLI behavior and active network operations remain in `src/main.rs`; this is the first incremental extraction, not completion of NET-01.

### NET-01B — extract network command operations

**Status:** Complete — DNS resolution, bounded TCP connect, one-datagram UDP exchange, and bounded service-identification orchestration are delegated to `src/net.rs`.

### NET-02A — local interface inventory

**Status:** In progress — read-only IPv4/IPv6 interface address inventory is implemented with the cross-platform `if-addrs` OS API wrapper; route/default-gateway inventory remains separate.

- Move DNS, TCP, UDP, and service-identification operations behind typed functions in `src/net.rs`.
- Keep CLI output and authorization-scope checks at the command boundary or pass an explicit authorization decision into the engine.
- Preserve current limits, timeouts, and command behavior; add loopback integration tests before removing old wrappers.
- Current extraction adds TCP/UDP loopback coverage and rejects URL/path input before DNS lookup.



### CRYPTO-03 — byte-slice digest helper

**Status:** Implemented on main in commit `a9afa67`; byte-slice SHA-256/SHA-512 helper and tests are available in the crypto module. PR #12 was closed without merging because this functionality was already present on main.

- Owned file: `src/crypto.rs`.
- Add/test a public byte-slice hash helper using existing SHA-256/SHA-512 algorithms.
- No CLI, dependency or manifest changes.

### CRYPTO-04 — explicit file integrity manifests

**Status:** Implemented on main through merged PR #6 (`f2aea0a`). The in-memory API hashes only caller-supplied paths; it does not walk directories or define a persistence format. PR #11 was closed without merging because this implementation was already present on main.

- Owned file: `src/crypto.rs`.
- Build and verify manifests only from explicit caller-supplied file paths.
- Do not add directory walking, automatic discovery, file modification or a persistence format without separate design review.
- Keep path and I/O failures explicit; test modified files and malformed digests.

### CRYPTO-05 — encryption design proposal

**Status:** Design proposal merged on main through PR #5 (`eb4e5a7`); implementation is not started. The merged proposal is a design decision, not an encryption feature.

- Do not write encryption code or change dependencies.
- Submit a design document in the PR description, not a code change.
- Evaluate an established AEAD (AES-256-GCM or ChaCha20-Poly1305) and Argon2id password KDF.
- Specify secure OS randomness, versioned/authenticated metadata, parameter limits, atomic no-overwrite output, wrong-password/tamper behavior, and tests.
- List exact crates, versions, licenses, MSRV and maintenance/security posture for maintainer approval.

### NET-01 — extract native networking module

**Owner:** Core maintainer. **Status:** Next integration task.

- Move networking parsing, pure helpers and command logic from `src/main.rs` into `src/net.rs` incrementally.
- Preserve command names, output meaning, timeouts, input limits and authorization checks.
- Keep scope checks in front of every active socket operation.
- Add module-local tests for port/range parsing, CIDR helpers and service banner classification.
- Do not add dependencies for the initial extraction.

### NET-02 — local interface inventory

**Status:** Planned.

- Implement read-only local interface enumeration for Windows and Linux.
- Do not transmit packets or require elevated privileges.
- Report interface name, address, prefix/netmask and up/down state where portable.
- Document fields unavailable on a platform; test parsers independently.

### NET-03 — DNS record diagnostics

**Status:** Planned.

- Design bounded DNS query support for explicit record types (A, AAAA, MX, TXT, NS, CNAME).
- Use a reviewed dependency only after maintainer approval; otherwise document standard-library limitations.
- Bound response size and timeouts; test malformed/truncated responses.
- DNS answers must never grant authorization scope.

### NET-04 — TLS certificate inspection

**Status:** Planned.

- Inspect one explicitly supplied hostname/IP and port.
- No scanning or automatic host discovery.
- Report peer certificate metadata and validation outcome distinctly; never claim trust solely from a readable certificate.
- Propose dependencies first; include timeout and certificate-chain tests.

### NET-05 — structured output

**Status:** Planned.

- Add machine-readable JSON output for selected read-only commands first.
- Keep human-readable output as default.
- Define stable schema/version and escaping; do not leak secrets or environment variables.

## Product milestones

1. **Foundation:** CLI, config, aliases, scope inventory, SHA-256/SHA-512 and basic network diagnostics. (Partially complete; continue tests and module extraction.)
2. **Native networking:** module extraction, local interface inventory, DNS record diagnostics, TLS inspection and structured output.
3. **Crypto/file integrity:** byte helpers and explicit manifests; then separately reviewed authenticated file encryption design and implementation.
4. **Defensive modules:** add narrowly scoped, documented native diagnostics with safe defaults and independent tests.
5. **Distribution:** finalize licensing, release signing, checksums, installer, upgrade and uninstall workflows.

A milestone is complete only when code, tests, documentation and cross-platform CI agree.

## Shared rules

- Native commands must not silently call external tools.
- Active network actions require explicit targets in local authorization scope.
- No stealth, evasion, credential theft, ransomware, destructive automation or unbounded scanning.
- Keep dependencies minimal and reviewed.
- Support Windows and Linux or document limitations.
- Do not claim parity with mature security suites without evidence.


## Master roadmap

Use [docs/ROADMAP.md](ROADMAP.md) as the long-term product plan. This file tracks near-term workstream ownership and task execution; the master roadmap defines the full engine scope and milestones.
