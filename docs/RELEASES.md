# Release and distribution plan

## Current status

INFERNEX is under active development. CI and release-build workflows provide cross-platform build infrastructure; they do not by themselves mean that a stable, supported release or installer is available.

The release workflow is intended to build:
- Windows x86-64 (MSVC)
- Linux x86-64 (GNU)
- Linux ARM64 (GNU)

Artifacts from workflow runs are build outputs, not automatically published, signed end-user releases. For source builds and safe PC testing, follow [the installation and test guide](INSTALL.md).

## Before public distribution

- Finalize the core license and third-party notices.
- Publish tagged GitHub Releases with clear version notes.
- Generate and publish cryptographic checksums for every artifact.
- Establish a signing strategy and verify signatures in documented instructions.
- Test installation and upgrade paths on supported platforms.
- Provide uninstall and rollback guidance.
- Document supported OS versions and known limitations.

## Installation principles

- Distribute only through the official INFERNEX release channel.
- Verify checksums and signatures when available.
- Never require elevated privileges by default.
- Show package sources and exact commands before system package changes.
- Require explicit confirmation for privileged installation actions.
- Never silently replace an existing installation.
- Keep INFERNEX core updates separate from optional external integrations.

## Third-party integrations

Optional compatibility integrations are installed and updated independently. INFERNEX must not silently bundle, replace or update them. Any redistribution requires license and attribution review.
