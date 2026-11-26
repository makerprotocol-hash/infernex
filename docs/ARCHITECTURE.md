# INFERNEX architecture

## Current foundation

The initial executable is a small Rust CLI named `nex`. It owns the entry point, built-in commands, configuration location, and process dispatch.

## Current native modules

- `hash sha256 <file>` streams a file through SHA-256 without loading the whole file into memory.
- `hash verify sha256 <file> <expected>` compares a computed digest against a 64-character hexadecimal checksum.
- `net resolve <hostname>` uses the operating system resolver and displays unique returned IP addresses.

These utilities are local integrity and basic network-diagnostic features. They do not perform remote exploitation or silently initiate scans.

## Intended layers

1. **CLI/core** — argument parsing, help, version, diagnostics, config, logging, error handling.
2. **Native modules** — original INFERNEX implementations with documented input/output contracts.
3. **Engine adapters** — optional integrations for independently installed third-party tools.
4. **Presentation** — consistent status messages and structured output where adapters can safely normalize it.
5. **Packaging** — Windows installer, dependency checks, updates, and uninstall support.

## Compatibility rule

For pass-through commands, arguments must be forwarded as argument values, not concatenated into a shell command. Preserve upstream flags and positional arguments. Interactive programs may retain their own TUI until a dedicated adapter exists; the core must not claim to have replaced upstream branding or console behavior when it has not.

## Third-party software

Each adapter must document the upstream project, supported version range, installation method, license, required notices, and any redistribution conditions. Bundling or modifying a tool requires a license review first. Do not remove required copyright or attribution notices.

## Security boundaries

INFERNEX is for authorized security research and defensive assessment. Modules should make target scope visible, avoid silently expanding scope, and provide safe defaults. Destructive or exploit-validation actions require clear user intent and explicit target context.
