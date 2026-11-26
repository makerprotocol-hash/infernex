# INFERNEX Parallel Workstreams

This document assigns non-overlapping areas so contributors can work in parallel.

## Core maintainer workstream

The core maintainer owns:
- `src/main.rs` and the main command dispatcher / REPL
- `Cargo.toml` and dependency decisions
- Engine execution and engine-manager implementation
- Core configuration and alias behavior
- Shared architecture changes and merges to `main`

Do not edit these files from the documentation/QA workstream unless the maintainer explicitly asks.

## Second contributor workstream: installation, onboarding, and QA

The second contributor owns documentation and test planning, not the Rust CLI implementation.

### Deliverables
1. `docs/INSTALLATION-PLAN.md`
   - Describe a safe first-run setup for Windows and Linux.
   - Compare available package-manager routes for Nmap and other optional engines.
   - Cite official upstream documentation for package IDs, commands, licensing, and platform support.
   - Clearly distinguish verified facts from proposals that still need testing.
   - Require explicit user consent before installing software; no silent elevation or system changes.
2. `docs/FIRST-RUN-GUIDE.md`
   - Explain how a new user obtains, builds, launches, and updates INFERNEX.
   - Include Windows PowerShell and Linux shell examples.
   - Explain that optional third-party engines are separate installs and are not bundled by INFERNEX.
   - Keep every command aligned with the current README and command reference.
3. `docs/MANUAL-TEST-PLAN.md`
   - Create a practical Windows/Linux test matrix for the currently implemented commands.
   - Include expected results, prerequisites, and clear pass/fail checkboxes.
   - Cover missing optional engines, paths containing spaces, malformed input, config persistence, aliases, hashing, and DNS resolution where those features exist.
   - Do not claim tests were executed; mark them as planned until someone runs them.

### Ownership boundaries
- Work only in `docs/**` for this assignment.
- Do not change `src/**`, `Cargo.toml`, `Cargo.lock`, or GitHub workflows.
- Do not duplicate existing command documentation; improve clarity and fill genuine gaps.
- Do not invent package IDs, download URLs, checksums, or test results.
- Do not implement automatic installers or run package managers as part of documentation work.

## Collaboration workflow

1. Pull the latest `main` before starting.
2. Create a dedicated branch, for example `docs/second-contributor-onboarding`.
3. Keep commits focused and limited to the assigned files.
4. Open a pull request against `main`.
5. In the pull request, list files changed, sources consulted, and any unresolved questions.
6. The core maintainer reviews and merges the pull request. Never push directly to `main`.

## Definition of done

The work is complete when all three documents exist, match the current repository behavior, use official sources for external installation details, and contain no unverified claims.
