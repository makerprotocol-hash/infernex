# Release and installation plan

## Release artifacts

The release workflow builds standalone NEX binaries for:
- Windows x86-64 (MSVC)
- Linux x86-64 (GNU)
- Linux ARM64 (GNU)

Artifacts are attached to workflow runs. A tagged release process and signed checksums must be added before recommending downloads to end users.

## Installation principles

- Install only from the official INFERNEX GitHub release channel.
- Verify checksums and, once available, signatures before execution.
- Never run a downloaded installer with elevated privileges by default.
- Show the exact third-party package source and proposed package-manager command before installing an engine.
- Require explicit confirmation for system package changes.
- Never silently replace an existing third-party installation.
- Keep INFERNEX core updates separate from external engine updates.

## Current limitation

The release workflow is infrastructure only. It does not yet publish a GitHub Release or provide a bootstrap installer. The `nex install` command currently displays guidance and does not install external tools.
