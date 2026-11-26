# INFERNEX

**One command environment. Familiar security-tool syntax. Original tools.**

INFERNEX is a Windows- and Linux-oriented cybersecurity command environment for authorized security research, defensive assessment, and lab work.

The executable is **`nex`**. The goal is to bring original tools and optional third-party engines behind one entry point while preserving familiar upstream arguments wherever practical.

## Current status

The Rust core now includes:
- An interactive prompt when launched with `nex`.
- One-shot commands such as `nex help` and `nex nmap -sV <authorized-target>`.
- A small registry of optional external engine adapters.
- Engine availability checks through `nex engines check`.
- Basic theme preference storage (`ember`, `spectrum`, `mono`).
- Basic environment diagnostics and installation guidance.
- Native system-DNS hostname resolution.
- Native streaming SHA-256 file hashing and checksum verification.
- Initial unit tests and Windows/Linux CI configuration.

This is an early foundation. External engines are **not bundled or automatically installed**, and the theme system currently saves a preference rather than rendering a fully customizable terminal. The installer, updater, richer configuration, and additional original security modules remain future work. SHA-256 hashing is the first native integrity utility.

## Build from source

Install the stable Rust toolchain, then run:

```powershell
cargo build --release
cargo test --all-targets
```

The executable is produced as `target/release/nex.exe` on Windows and `target/release/nex` on Linux.

## First commands

```text
nex
nex help
nex doctor
nex net resolve example.com
nex hash sha256 ./download.zip
nex hash verify sha256 ./download.zip <expected-64-character-hex>
nex engines
nex engines check
nex theme list
nex theme set ember
nex nmap -sV 192.0.2.10
nex metasploit
nex tshark -i 1
```

Engine commands require the corresponding upstream program to be installed and available on PATH. `nex install <engine>` currently provides guidance only; it does not install software automatically.

## Design principles

- One entry point and consistent core experience.
- Preserve original tool flags and positional arguments.
- Build original INFERNEX tools alongside integrations.
- Respect third-party licenses, notices, and trademarks.
- Use only on systems and networks you own or are explicitly authorized to assess.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

The core license and third-party redistribution policy will be finalized before a public release.
