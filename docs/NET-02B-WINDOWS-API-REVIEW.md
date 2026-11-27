# NET-02B-WIN — Windows route inventory API review

**Status:** API selected for a narrowly scoped implementation prototype; Windows code is not implemented yet.
**Scope:** Read-only IPv4/IPv6 route-table enumeration for `nex net routes`.
**Related task:** [NET-02B route inventory](NET-02B-ROUTE-INVENTORY.md).

## Decision

Use the Windows IP Helper API `GetIpForwardTable2(AF_UNSPEC, ...)` and release the returned allocation with `FreeMibTable`. This is the supported Vista-and-later API for retrieving both IPv4 and IPv6 route rows. Do not parse `route print`, PowerShell, or localized command output.

The API returns `MIB_IPFORWARD_TABLE2` containing `MIB_IPFORWARD_ROW2` rows. The row supplies destination prefix, next hop, interface index, and route metric. A zero destination prefix and zero prefix length identify a default route. Windows may return multiple default routes; preserve them all.

## Dependency candidate

- Candidate: `windows-sys = 0.61.2`, target-specific under `[target.'cfg(windows)'.dependencies]`.
- Candidate feature modules: `Win32_NetworkManagement_IpHelper` and `Win32_Networking_WinSock`.
- Published crate metadata lists MIT OR Apache-2.0 licensing and a `windows-link ^0.2.1` dependency.
- This is a proposal, not an approved manifest change. Before implementation, verify the exact generated Rust signatures/constants/struct layout against the selected crate version, supported Rust version/MSRV, transitive dependency lockfile changes, and CI compatibility. Keep the dependency Windows-only.

## Memory and unsafe-code boundary

The Windows API returns a system-allocated table pointer. The implementation must:

1. Initialize the output pointer to null and check the API return code before dereferencing it.
2. Wrap the non-null table pointer immediately in a private RAII guard whose `Drop` calls `FreeMibTable` exactly once.
3. Validate the table pointer, entry count, and row access assumptions before iterating. Do not assume rows are tightly packed without following the binding's documented layout.
4. Keep pointer arithmetic, union access, and FFI calls inside one small private `#[cfg(windows)]` adapter. Document each unsafe operation's preconditions.
5. Copy all required row data into owned Rust values before the guard is dropped. No raw pointer escapes the adapter.
6. Never call route mutation APIs such as `CreateIpForwardEntry2`, `SetIpForwardEntry2`, or `DeleteIpForwardEntry2`.

If the chosen binding cannot make the table iteration and union access reviewable, stop and compare the maintained `windows` crate or a different safe abstraction before proceeding. Do not broaden unsafe code across `src/net.rs`.

## Mapping into the shared route model

- Convert the destination prefix address and prefix length into `RouteEntry.destination` and `prefix_len`.
- Convert an unspecified next-hop address to `None`; otherwise preserve the IP address.
- Preserve `MIB_IPFORWARD_ROW2.InterfaceIndex` as a visible stable identifier such as `ifindex:12` unless a separately reviewed native mapping to a friendly interface name is added. Do not silently invent a name.
- Preserve the row's route `Metric` exactly. Windows documents this as the route metric offset; it is not necessarily the complete effective metric because the interface metric is separate. The CLI/docs should call this the route metric, not claim it is the complete path cost.
- Mark a default route only when the destination address is unspecified and prefix length is zero.
- Preserve duplicates and multiple defaults. Apply the shared deterministic sort after merging platform results.

## Error behavior

- Map non-success API status codes to an `io::Error` with the numeric Windows error code retained in the message.
- Treat a successful call with a null table pointer as invalid data.
- A no-routes result should produce an empty vector if the API returns a documented not-found status for that case; distinguish it from unsupported API/stack and other failures.
- Always free a successfully returned table, including if row conversion fails partway through.
- Do not require administrator privileges for ordinary read-only enumeration; report OS errors rather than prompting for elevation.

## Test plan

- Unit-test pure conversion helpers for IPv4 and IPv6 prefixes, unspecified and non-unspecified next hops, default and non-default routes, interface-index formatting, and metric preservation.
- Test empty table / no routes, malformed prefix lengths, unsupported address family, API failure, and null-pointer handling where these can be isolated safely.
- Add a Windows-only integration test that calls the read-only API and asserts only structural invariants (valid address family/prefix lengths and deterministic conversion). Do not assume a default gateway exists in CI.
- Keep Linux parser tests unchanged and passing.
- Run `cargo fmt --check` and `cargo test --all-targets` on Ubuntu and Windows CI. The maintainer should also run `nex net routes` on a real Windows PC and compare the output with Windows' own network configuration before marking parity implemented.

## References

- Microsoft: [GetIpForwardTable2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2)
- Microsoft: [MIB_IPFORWARD_ROW2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2)
- Microsoft: [MIB_IPFORWARD_TABLE2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_table2)
- docs.rs: [windows-sys 0.61.2 IP Helper module](https://docs.rs/windows-sys/0.61.2/windows_sys/Win32/NetworkManagement/IpHelper/index.html)

## Explicitly not done

This review does not implement the Windows adapter, approve a dependency update, or claim Windows route inventory works. Those remain open until code review, Windows CI, and maintainer testing pass.
