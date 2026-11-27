# NET-02B — Route and default-gateway inventory

**Status:** Partially implemented on main — Linux IPv4/IPv6 route inventory is available; Windows native route enumeration remains planned.
**Owner:** Core maintainer.
**Target platforms:** Windows and Linux.

## Goal

Extend the existing read-only `net interfaces` inventory with a separate command that reports the operating system's routing table and default gateways. This task must not transmit packets, change routes, enable interfaces, or require administrator privileges for ordinary read access.

## Proposed command and output

- Add `nex net routes` as a read-only command.
- Report address family, destination prefix, next hop/gateway, interface identifier, route metric, and default-route status where the platform exposes them.
- Represent an on-link route explicitly rather than inventing a gateway address.
- Sort output deterministically and clearly label fields unavailable on a platform.
- Keep interface-address inventory (`nex net interfaces`) independent from route inventory; an interface being present does not imply it is the active default route.

## Platform implementation review

### Linux — implemented

- Read-only snapshots are parsed from `/proc/net/route` and `/proc/net/ipv6_route`; no dependency or external command is required.
- IPv4 destination, gateway and mask fields are decoded from the kernel's little-endian hexadecimal representation; route metrics are parsed in their procfs decimal representation.
- IPv6 destination prefixes, next hops, metrics and interface names are parsed from fixed-width procfs fields.
- Malformed rows, invalid prefix lengths, non-contiguous IPv4 masks, and missing procfs files return explicit errors.
- Do not parse human-formatted output from `ip route` or shell out to external utilities.

### Windows — planned

- Add the Windows IP Helper routing-table API (`GetIpForwardTable2` / `FreeMibTable`) through a narrowly scoped, reviewed FFI or approved Windows API crate.
- Correctly handle IPv4 and IPv6 rows, interface indices, next-hop addresses, route metrics, API errors, and allocation cleanup.
- Until this adapter is implemented, `nex net routes` returns an explicit unsupported-platform error on Windows.
- Do not parse localized `route print` output or invoke PowerShell/cmd.

## Dependency and safety constraints

- Do not add or update dependencies until the maintainer reviews exact crate names, versions, licenses, MSRV, platform feature flags, and maintenance/security posture.
- Keep all route discovery passive and read-only. No probing, packet transmission, route mutation, or automatic target authorization.
- Avoid unsafe code where a maintained safe API is available. Any required unsafe FFI must be isolated, documented, and reviewed.
- Do not change `src/scope.rs` or weaken authorization checks for existing active network commands.

## Acceptance criteria

1. Linux implementation returns the documented route model; Windows parity is a remaining requirement.
2. IPv4 and IPv6 default routes are represented correctly.
3. Multiple default routes and route metrics are preserved rather than silently collapsed.
4. Missing permissions, unavailable APIs, absent procfs files, malformed records, and unsupported fields produce explicit, non-panicking outcomes.
5. Parser/unit tests cover valid, malformed, boundary, duplicate, and empty inputs.
6. Platform integration tests verify route enumeration without changing system state; tests must not assume a particular gateway exists in every CI runner.
7. `cargo test --all-targets` and the repository's Windows/Linux CI matrix pass.
8. CLI help, `docs/COMMANDS.md`, architecture documentation, and `docs/ROADMAP.md` agree with the implemented behavior.

## Out of scope

- Adding, deleting, or modifying routes.
- Network discovery or gateway reachability tests.
- Selecting a preferred route for active scans.
- Treating a discovered route or gateway as authorization scope.
- External command execution or localized command-output parsing.

## Delivery sequence

1. Approve the platform API/dependency design.
2. Implement and test the shared route data model and platform adapters.
3. Add `nex net routes` and deterministic output.
4. Update command, architecture, and roadmap documentation only after implementation and CI pass.

Until those steps are complete, route/default-gateway inventory remains **Planned**.