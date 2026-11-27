# INFERNEX

<p align="center">
  <img src="assets/Infernex_%20Portal%20of%20Cybersecurity.png" alt="INFERNEX official fiery portal banner" width="100%" />
</p>

<p align="center">
  <img src="assets/Fiery%20Cyberpunk%20X%20Emblem.png" alt="INFERNEX official red-orange X emblem" width="180" />
</p>

**A native-first cybersecurity command environment. One terminal. Independent engines. Built in Rust.**

INFERNEX is an all-in-one command-line platform for authorized security research, defensive assessment and lab work. Its executable is `nex`.

Our direction is to build capabilities inside this repository: networking, cryptography, file integrity, diagnostics and defensive security modules. Optional compatibility adapters may exist, but native commands must not depend on separately installed security suites.

## Project status

INFERNEX is an early, actively developed foundation—not yet a complete security suite or a replacement for mature specialist tools.

### Implemented native capabilities

- Interactive command prompt and one-shot CLI.
- Persistent aliases, quote-aware command parsing and bounded alias expansion.
- Prompt themes and `NO_COLOR` support.
- Read-only configuration and environment diagnostics.
- System DNS hostname resolution.
- Offline IPv4/IPv6 CIDR calculations and IP address classification.
- Single-port TCP connectivity diagnostics.
- Bounded native TCP connect scanning: one literal IP and at most 256 consecutive ports per invocation.
- Native service identification from observed application banners, with bounded reads and scope enforcement.
- One-endpoint native UDP diagnostic: one fixed datagram, bounded response and timeout; no response is inconclusive.
- Persistent authorization scope for exact IPs, IPv4/IPv6 CIDRs and exact hostnames, with deny-by-default checks for active network operations.
- Streaming SHA-256 and SHA-512 file hashing and checksum verification.
- Explicit file-integrity manifest APIs for caller-supplied paths (in-memory; no implicit directory traversal).
- Read-only local IPv4/IPv6 interface address inventory.

### In progress

- Complete the next networking inventory step: read-only route and default-gateway reporting for Windows and Linux.
- Continue bounded DNS record diagnostics, TLS inspection and structured output design.

### Completed foundation work

- Networking operations (DNS, bounded TCP, one-datagram UDP and service identification) are extracted into `src/net.rs`.
- Explicit file-integrity manifest APIs are implemented for caller-supplied paths.
- Read-only local IPv4/IPv6 interface address inventory is available through `nex net interfaces`.

Authenticated file encryption remains a design/approval task; no encryption command is implemented yet.

### Planned

- Reviewed authenticated file encryption/decryption using established cryptography.
- Additional native defensive diagnostics and protocol modules.
- Packaging, installer, update and uninstall workflows.

A roadmap item is not an implemented feature. See [the command reference](docs/COMMANDS.md) for current behavior.

## Native-first principles

- Implement core capabilities in this repository; do not require Nmap, Metasploit, Wireshark, SQLmap or other external security programs for native commands.
- Prefer small, independently testable Rust modules with documented APIs.
- Validate inputs and use bounded memory, timeouts and resource limits.
- Make active network operations explicit and authorization-scope-aware.
- Use established cryptographic constructions; never invent ciphers.
- Support Windows and Linux, documenting platform limitations.
- Do not claim parity with mature security suites without evidence.

## Brand identity

The angular red-orange **X** is the official INFERNEX mark. The official PNG emblem and portal banner are stored in `assets/`; the SVG logo and banner remain available as lightweight vector alternatives.

## Active roadmap

The roadmap is part of the product, not just a planning document. Run `nex roadmap` in the terminal for current delivery stages, or `nex roadmap show` for the complete master plan. The active roadmap is also maintained in [docs/ROADMAP.md](docs/ROADMAP.md).

## Build from source

Install the stable Rust toolchain, then run:

```sh
cargo test --all-targets
cargo build --release
```

Run `cargo fmt --check` after formatting the touched Rust files. The executable is produced as `target/release/nex.exe` on Windows and `target/release/nex` on Linux.

## Native commands

```text
nex
nex help
nex version
nex doctor
nex config show
nex scope add 192.0.2.10
nex scope list
nex scope check 192.0.2.10
nex net resolve example.com
nex net cidr 192.0.2.17/24
nex net inspect 192.0.2.10
nex net port 192.0.2.10 443
nex net scan 192.0.2.10 1 128
nex net service 192.0.2.10 22
nex net udp 192.0.2.10 53
nex hash sha256 ./download.zip
nex hash sha512 ./download.zip
nex hash verify sha256 ./download.zip <expected-64-character-hex>
nex hash verify sha512 ./download.zip <expected-128-character-hex>
nex theme list
nex alias list
```

Active network commands require targets recorded in the local authorization scope. The scope inventory is a user-maintained record, not proof of legal permission. The TCP scanner is a straightforward connect scanner, not a stealth scanner. It accepts one literal IP address (not a hostname or CIDR), scans at most 256 ports per invocation and reports inconclusive connection outcomes distinctly. The UDP diagnostic sends one fixed datagram to one explicitly selected endpoint; it is not a UDP scanner. Only use network features against systems you own or are explicitly authorized to assess.

## Optional compatibility integrations

Some legacy commands can pass arguments to separately installed third-party programs. These are optional compatibility features, not native INFERNEX capabilities. They are not bundled, and native networking/hash commands do not depend on them.

We do not claim third-party functionality as our own. Any future bundling or modification requires license, attribution and redistribution review.

## Documentation

- [Command reference](docs/COMMANDS.md)
- [Architecture and native module boundaries](docs/ARCHITECTURE.md)
- [Parallel engineering workstreams and contributor task cards](docs/WORKSTREAMS.md)
- [Release and installation plan](docs/RELEASES.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

INFERNEX is under active development. Release licensing and redistribution terms must be finalized before public distribution.


## Project roadmap

See the [INFERNEX Master Roadmap](docs/ROADMAP.md) for the full native-engine vision, delivery milestones, security boundaries, and contributor task queue.

## License

The INFERNEX source code and documentation are dual-licensed. You may choose either:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

This is expressed as `MIT OR Apache-2.0` in the Cargo package metadata. Contributions intentionally submitted for inclusion are offered under the same terms, unless the contributor clearly states otherwise. Contributors retain copyright in their contributions.

**Brand assets are separate.** The INFERNEX name, X emblem, portal/banner artwork and other brand assets in `assets/` are not covered by the software licenses above. All rights to those assets are reserved unless a specific asset file states otherwise. The software license does not grant permission to use INFERNEX trademarks or imply endorsement.

