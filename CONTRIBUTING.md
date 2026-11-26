# Contributing

Thanks for your interest in INFERNEX.

## Principles

- Keep the command interface predictable and document every command and option.
- Preserve upstream CLI arguments for pass-through integrations.
- Prefer original, testable modules where practical.
- Do not claim third-party code or functionality as INFERNEX-authored.
- Review the applicable license before copying, modifying, or redistributing an external tool.
- Keep security testing scoped to authorized environments.

## Development

Install stable Rust, then run:

```powershell
cargo fmt --check
cargo test
cargo run -- help
```

Before proposing a new engine adapter, document its upstream project, supported versions, license, executable name, and expected behavior when the engine is missing.
