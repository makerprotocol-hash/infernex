# INFERNEX

**A native cybersecurity platform. One command environment. Built in Rust.**

INFERNEX is an all-in-one command-line platform for authorized security research, defensive assessment and lab work. Its executable is `nex`.

Our direction is to build the capabilities ourselves inside this project: networking, cryptography, file integrity, diagnostics and defensive security modules. Native commands must work without separately installed security suites. Optional compatibility adapters may exist, but they are not the product's foundation.

## Project status

INFERNEX is an early, actively developed foundation—not yet a complete security suite.

### Native capabilities currently implemented

- Interactive command prompt and one-shot CLI.
- Persistent aliases with bounded expansion and argument-preserving behavior.
- Prompt themes and `NO_COLOR` support.
- Read-only configuration and environment diagnostics.
- System DNS hostname resolution.
- Offline IPv4/IPv6 CIDR calculations and IP address classification.
- Single-port TCP connectivity diagnostics.
- Bounded native TCP connect scanning: one literal IP address and at most 256 consecutive ports per invocation.
- Streaming SHA-256 and SHA-512 file hashing and checksum verification.

### In development / planned

- Native networking module and protocol-aware service identification.
- User-maintained authorization scope and asset inventory.
- Native cryptography module expansion, including a reviewed authenticated file-encryption design.
- Unified structured output and additional defensive modules.
- Packaging, installer and update workflow.

A planned feature is not an implemented feature. See the command reference for what works today.

## Native-first principles

- Implement core capabilities in this repository; do not require Nmap, Metasploit, Wireshark, SQLmap or other external security programs for native commands.
- Prefer small, independently testable Rust modules with documented APIs.
- Validate inputs and use bounded memory, timeouts and resource limits.
- Make active network operations explicit and scope-aware.
- Use established cryptographic constructions; never invent ciphers.
- Support Windows and Linux, documenting platform limitations.
- Do not claim parity with mature security suites without evidence.

## Build from source

Install the stable Rust toolchain, then run:

```sh
cargo fmt --check
cargo test --all-targets
cargo build --release
```

The executable is produced as `target/release/nex.exe` on Windows and `target/release/nex` on Linux.

## Native commands

```text
nex
nex help
nex version
nex doctor
nex config show
nex net resolve example.com
nex net cidr 192.0.2.17/24
nex net inspect 192.168.1.10
nex net port example.com 443
nex net scan 192.0.2.10 1 128
nex hash sha256 ./download.zip
nex hash sha512 ./download.zip
nex hash verify sha256 ./download.zip <expected-64-character-hex>
nex hash verify sha512 ./download.zip <expected-128-character-hex>
nex theme list
nex theme set ember
nex alias list
```

The TCP scanner is a straightforward connect scanner, not a stealth scanner. It accepts one literal IP address (not a hostname or CIDR), scans at most 256 ports per invocation and reports inconclusive connection outcomes distinctly. Only use network features against systems you own or are explicitly authorized to assess.

## Optional compatibility integrations

Some legacy commands can pass arguments to separately installed third-party programs. These are optional compatibility features, not native INFERNEX capabilities. They are not bundled, and native networking/hash commands do not depend on them.

We do not claim third-party functionality as our own. Any future bundling or modification requires license, attribution and redistribution review.

## Documentation

- [Command reference](docs/COMMANDS.md)
- [Architecture and native module boundaries](docs/ARCHITECTURE.md)
- [Parallel engineering workstreams](docs/WORKSTREAMS.md)
- [Release and installation plan](docs/RELEASES.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

INFERNEX is under active development. Release licensing and redistribution terms must be finalized before public distribution.
