# INFERNEX

**One command environment. Familiar security-tool syntax. Original tools.**

INFERNEX is a Windows- and Linux-oriented cybersecurity command environment for authorized security research, defensive assessment, and lab work.

The executable is **`nex`**. The goal is to build a native-first security command environment. Optional third-party adapters may remain for compatibility, but native INFERNEX modules are the product foundation.

## Current status

The Rust core now includes:
- An interactive prompt when launched with `nex`.
- One-shot commands such as `nex help` and `nex nmap -sV <authorized-target>`.
- A small registry of optional external engine adapters.
- Engine availability checks through `nex engines check`.
- Persistent terminal themes (`ember`, `spectrum`, `mono`) applied to the interactive prompt.
- Expanded read-only environment diagnostics, including platform, config, color, and optional-engine status.
- Read-only configuration inspection that reports the active theme and alias count without exposing alias values.
- A consent-gated Linux Nmap installer for APT, DNF, YUM, Pacman, and Zypper; Windows receives official installer guidance.
- Native system-DNS hostname resolution, offline IPv4/IPv6 CIDR range inspection, local IP address classification, bounded single-port TCP connectivity checks, and a native TCP connect scanner limited to 256 ports per invocation.
- Native streaming SHA-256 and SHA-512 file integrity hashing and checksum verification.
- Persistent user-defined command aliases with bounded expansion, quoted-argument preservation, and no shell evaluation.
- Optional ANSI color suppression through the standard `NO_COLOR` environment variable.
- Initial unit tests and Windows/Linux CI configuration.

This is an early foundation. External engines are **not bundled or automatically installed**. Themes currently style the interactive prompt; full terminal-wide theming is still future work. The installer, updater, and additional original security modules remain future work.

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
nex engines
nex engines check
nex theme list
nex theme set ember
nex alias add quickscan nmap -sV 192.0.2.10
nex alias list
nex quickscan
nex nmap -sV 192.0.2.10
nex metasploit
nex tshark -i 1
```

Engine commands require the corresponding upstream program to be installed and discoverable. INFERNEX checks PATH and the standard Windows Nmap installation directories. `nex install nmap` can invoke a supported Linux package manager only after displaying the exact command and receiving an explicit `YES`; on Windows it provides official installer guidance. Other engines remain guidance-only.

## Design principles

- One entry point and consistent core experience.
- Preserve original tool flags and positional arguments.
- Prioritize original INFERNEX tools; integrations are optional, never required for native commands.
- Respect third-party licenses, notices, and trademarks.
- Use only on systems and networks you own or are explicitly authorized to assess.

## Documentation

- [Command reference](docs/COMMANDS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

The core license and third-party redistribution policy will be finalized before a public release.
