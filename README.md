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
- Persistent terminal themes (`ember`, `spectrum`, `mono`) applied to the interactive prompt.
- Basic environment diagnostics and engine-specific information.
- A consent-gated Linux Nmap installer for APT, DNF, YUM, Pacman, and Zypper; Windows receives official installer guidance.
- Native system-DNS hostname resolution and offline IPv4/IPv6 CIDR range inspection.
- Native streaming SHA-256 file integrity hashing and checksum verification.
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
nex net resolve example.com
nex net cidr 192.0.2.17/24
nex hash sha256 ./download.zip
nex hash verify sha256 ./download.zip <expected-64-character-hex>
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

Engine commands require the corresponding upstream program to be installed and available on PATH. `nex install nmap` can invoke a supported Linux package manager only after displaying the exact command and receiving an explicit `YES`; on Windows it provides official installer guidance. Other engines remain guidance-only.

## Design principles

- One entry point and consistent core experience.
- Preserve original tool flags and positional arguments.
- Build original INFERNEX tools alongside integrations.
- Respect third-party licenses, notices, and trademarks.
- Use only on systems and networks you own or are explicitly authorized to assess.

## Documentation

- [Command reference](docs/COMMANDS.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

The core license and third-party redistribution policy will be finalized before a public release.
