# INFERNEX

**One command environment. Familiar security-tool syntax. Original tools.**

INFERNEX is a Windows-first, unified cybersecurity command environment for authorized security research, defensive assessment, and lab work.

The executable is **`nex`**. INFERNEX aims to bring original tools and integrated third-party engines behind one consistent entry point while preserving familiar arguments wherever practical.

## Project status

INFERNEX is at the foundation stage. The initial core is being built before external engines and advanced modules are added. Do not assume a listed or planned integration is already available.

## Design principles

- **One entry point:** users launch `nex`.
- **Familiar syntax:** pass through existing tool flags and arguments rather than forcing experienced users to relearn them.
- **Original capabilities:** build native INFERNEX tools, not only wrappers.
- **Consistent experience:** common configuration, logging, help, diagnostics, and output conventions.
- **Respect upstream projects:** preserve required licenses, notices, trademarks, and source-offer obligations. INFERNEX will not misrepresent third-party software as original work.
- **Safe by design:** intended for systems, networks, and labs the user owns or is explicitly authorized to assess.

## Command examples (planned)

```powershell
nex help
nex version
nex theme list
nex theme set ember
nex nmap -sV 192.0.2.10
nex metasploit
nex tshark -i 1
```

The last three commands require the corresponding external engine to be separately installed and available on PATH. Engine integrations will be introduced and documented individually.

## Build from source

Requirements: a current stable Rust toolchain.

```powershell
cargo build
cargo run -- help
cargo test
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## License

The INFERNEX core license will be selected before the first public release. Third-party components retain their own licenses and notices.
