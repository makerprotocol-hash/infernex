# Command reference

The examples below assume the executable is named `nex`. This page distinguishes implemented commands from planned interfaces.

## Implemented core commands

| Command | Purpose |
|---|---|
| `nex` | Open the interactive prompt |
| `nex help` | Show available commands |
| `nex version` | Show core version |
| `nex doctor` | Read-only platform, config, color and optional integration diagnostics |
| `nex config show` | Show configuration location, theme and alias count |
| `nex config path` | Print configuration file path |
| `nex theme list` | List prompt themes |
| `nex theme set <theme>` | Save and apply a prompt theme |
| `nex alias list` | List aliases |
| `nex alias add <name> <command> [args...]` | Save an alias |
| `nex alias remove <name>` | Remove an alias |

## Native file integrity

Calculate streaming file digests:

```sh
nex hash sha256 ./release.zip
nex hash sha512 ./release.zip
```

Verify against a trusted, independently obtained checksum:

```sh
nex hash verify sha256 ./release.zip <64-character-hex-digest>
nex hash verify sha512 ./release.zip <128-character-hex-digest>
```

A matching digest confirms byte-for-byte consistency with the expected digest. It does not identify who created the file. Obtain expected checksums from an authenticated source.

## Authorization scope

Manage the local, user-maintained list of targets you are authorized to assess:

```sh
nex scope add 192.0.2.10
nex scope add 192.0.2.0/24
nex scope add lab.example
nex scope list
nex scope check 192.0.2.15
nex scope remove 192.0.2.10
```

IPv4/IPv6 addresses match exactly or through a containing CIDR. Hostnames match only their exact normalized name; no wildcard, subdomain or DNS-derived authorization is inferred. The inventory is a local record of your authorization, not proof of legal permission. Malformed or unreadable scope storage causes active operations to be refused. Override its file location with `INFERNEX_SCOPE_FILE`.

Identify a service from its observed application response on one explicitly supplied IP and port:

```sh
nex net service 192.0.2.10 22
nex net service 192.0.2.10 80
```

This makes one bounded TCP connection, reads at most 512 banner bytes, and sends a minimal HTTP HEAD request only on selected conventional cleartext HTTP ports. It recognizes protocol signatures such as SSH, HTTP, SMTP, FTP, POP3 and IMAP. Port numbers alone are not treated as proof of service identity. Missing or encrypted banners may remain unidentified. The target must be in the authorization scope.

## Native network diagnostics

Resolve a hostname using the system DNS resolver:

```sh
nex net resolve example.com
```

Inspect a CIDR range locally without sending packets:

```sh
nex net cidr 192.0.2.17/24
nex net cidr 2001:db8:abcd::1/48
```

Inspect an IP address locally:

```sh
nex net inspect 192.168.1.10
nex net inspect fd00::1
```

Check one TCP port:

```sh
nex net port example.com 443
```

The command uses a bounded connection timeout per resolved address. A failed connection does not prove that a service is absent; filtering and routing can also block it.

Scan a bounded TCP port range on one explicitly supplied IP:

```sh
nex net scan 192.0.2.10 1 128
```

The native connect scanner accepts a literal IPv4 or IPv6 address, not a hostname or CIDR. It scans at most 256 consecutive ports per invocation, sequentially, with a 350 ms timeout per port. It reports successful connections as `OPEN`, connection refusals as `CLOSED`, and other failures as `NO RESPONSE`. No-response is inconclusive and may reflect filtering or routing. This is not a stealth or evasion scan.

Only use active network commands against systems you own or have explicit permission to assess. Authorization scope management is being developed; do not interpret a successful connection as permission.

## Optional compatibility integrations

Legacy pass-through commands may be available for selected third-party programs:

```sh
nex nmap -sV 192.0.2.10
nex tshark -i 1
nex metasploit
```

These require the corresponding upstream program to be installed separately. They are not native INFERNEX modules, are not bundled and are not required by native commands. Availability depends on the local installation.

## Prompt appearance and aliases

The `ember`, `spectrum` and `mono` themes currently change the interactive prompt color, not every terminal application. Set a non-empty `NO_COLOR` environment variable to disable ANSI colors.

PowerShell:

```powershell
$env:NO_COLOR = "1"
nex
```

Linux:

```sh
NO_COLOR=1 nex
```

Aliases preserve individual arguments and are expanded without shell evaluation. Expansion is limited to eight levels.

## Planned command interfaces

The following are design targets, not promises that these commands work today:

```text
nex net services <authorized-ip>
nex scope add <ip-or-cidr-or-hostname>
nex scope list
nex scope check <target>
nex crypto encrypt <input> <output>
nex crypto decrypt <input> <output>
nex modules
```

Commands will be documented as implemented only after code, tests and CLI integration are complete.
