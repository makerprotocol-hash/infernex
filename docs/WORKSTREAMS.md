# INFERNEX Parallel Engineering Workstreams

This is a code-ownership agreement for parallel development. The second contributor owns a substantial product feature, not documentation-only work.

## Core maintainer (approximately 70%)

Owns:
- `src/main.rs`: CLI dispatcher, REPL, prompts, command integration
- `Cargo.toml` and dependency decisions
- Engine manager, engine execution, installation workflow
- Themes, aliases, global configuration
- Shared architecture, release workflows, final integration and merges

## Second contributor (approximately 30%): Authorized Scope & Asset Manager

Own and implement a complete, independently testable module in:

- `src/scope.rs` — all implementation and unit tests for this feature

Do not edit `src/main.rs`, `Cargo.toml`, `Cargo.lock`, workflows, or files owned by the core maintainer. The maintainer will connect the finished module to the CLI after reviewing its public API.

### Product goal

Build INFERNEX's local **Authorized Scope & Asset Manager**. It helps a user record which IP addresses, CIDR networks, and hostnames they are authorized to assess, inspect the inventory, and check whether a proposed target is inside the recorded scope.

This is a real core product feature: validation, persistence, matching, safe failure behavior, and tests—not just a document or mockup.

### Required functionality

Implement a public Rust API in `src/scope.rs` that supports:

1. Add a scope entry:
   - IPv4 address, IPv6 address
   - IPv4 CIDR and IPv6 CIDR
   - Exact hostname (case-insensitive; normalize a trailing dot)
   - Reject URLs, paths, ports, malformed CIDRs, empty values, and unsupported wildcard patterns.
2. List all entries in a stable, deterministic order.
3. Remove an existing entry using normalized matching.
4. Check a candidate target:
   - IP address matches an exact IP entry or a containing CIDR.
   - Hostname matches an exact hostname entry only.
   - A hostname must not be treated as authorized merely because DNS currently resolves it to an allowed IP.
   - Never infer authorization from a partial string match.
5. Persist entries locally in a simple, documented, line-based format.
   - Use a predictable per-user config location, with an environment-variable override such as `INFERNEX_SCOPE_FILE` for tests and advanced users.
   - Create parent directories when needed.
   - Handle missing files as an empty scope.
   - Preserve valid entries and report malformed stored lines clearly; do not silently broaden scope.
   - Write updates safely (temporary file then rename where practical).
6. Return useful typed errors/results so the main CLI can display friendly messages.
7. Include unit tests for IPv4, IPv6, CIDR boundaries, hostname normalization, invalid inputs, duplicate entries, add/remove persistence, missing files, malformed storage, and negative authorization checks.

### Public API expectation

Choose a clean API that the CLI can call without knowing storage details. At minimum expose equivalents of:
- `add(value: &str) -> Result<...>`
- `remove(value: &str) -> Result<...>`
- `list() -> Result<Vec<...>>`
- `check(target: &str) -> Result<bool, ...>`

You may improve the names and types, but document the API in module-level comments. Prefer the Rust standard library; if an additional dependency is genuinely necessary, propose it in the pull request rather than editing Cargo files.

### Safety and correctness requirements

- Scope is a user-maintained authorization record, not proof of legal permission.
- Default behavior must be deny: unknown, malformed, or unreadable scope data is never considered authorized.
- No scanning, probing, network connections, DNS lookups, subprocesses, or automatic target discovery in this module.
- No wildcard domains, implicit subdomain matching, or fuzzy matching.
- Do not log secrets or overwrite unrelated configuration.
- Keep it cross-platform (Windows and Linux).

### Branch and delivery

1. Pull the latest `main`.
2. Create branch `feature/authorized-scope-manager`.
3. Implement only `src/scope.rs` plus tests contained in that module.
4. Run `cargo fmt --check` and `cargo test` locally; report exact results, and clearly say if you could not run them.
5. Open a pull request against `main`. Do not merge it.
6. In the PR description, explain the data format, public API, security decisions, test coverage, and any limitations.

### Definition of done

The module compiles with the existing project, is independently testable, has robust persistence and strict target matching, and is ready for the core maintainer to wire into commands such as:

- `nex scope add 192.0.2.0/24`
- `nex scope add lab.example`
- `nex scope list`
- `nex scope remove 192.0.2.0/24`
- `nex scope check 192.0.2.15`

The core maintainer owns those CLI command changes and integration.
