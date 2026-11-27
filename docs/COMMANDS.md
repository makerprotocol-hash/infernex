# Command reference

The examples below assume the executable is named `nex`. This page lists commands currently routed by the CLI; roadmap interfaces are clearly separated at the end.

## Core commands

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
nex scope add 192.0.2.10
nex net port 192.0.2.10 443
```

The command uses a bounded connection timeout per resolved address. The exact hostname or IP must be in scope. A failed connection does not prove that a service is absent; filtering and routing can also block it.

Scan a bounded TCP port range on one explicitly supplied IP:

```sh
nex net scan 192.0.2.10 1 128
```

The native connect scanner accepts a literal IPv4 or IPv6 address, not a hostname or CIDR. It scans at most 256 consecutive ports per invocation, sequentially, with a 350 ms timeout per port. It reports successful connections as `OPEN`, connection refusals as `CLOSED`, and other failures as `NO RESPONSE`. No-response is inconclusive and may reflect filtering or routing. This is not a stealth or evasion scan.

Identify a service from its observed application response on one explicitly supplied IP and port:

```sh
nex net service 192.0.2.10 22
nex net service 192.0.2.10 80
```

This makes one bounded TCP connection, reads at most 512 banner bytes, and sends a minimal HTTP HEAD request only on selected conventional cleartext HTTP ports. It recognizes protocol signatures such as SSH, HTTP, SMTP, FTP, POP3, IMAP and Redis-compatible RESP. Port numbers alone are not treated as proof of service identity. Missing or encrypted banners may remain unidentified.

Check one explicitly selected UDP endpoint:

```sh
nex net udp 192.0.2.10 53
```

The native diagnostic requires the literal IP to be in authorization scope, sends one fixed 23-byte diagnostic datagram, and waits up to two seconds for a response (maximum 512 response bytes). A response confirms that something replied; no response is inconclusive because UDP services commonly ignore unknown datagrams and filtering may intervene. This is a single endpoint check, not a UDP port scanner.

All active network commands require explicit targets in the authorization scope. Only use them against systems you own or have explicit permission to assess. Scope entries are a local user-managed safeguard, not legal authorization.

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

## Planned interfaces — not implemented CLI commands

The following are roadmap targets only. Do not assume they work until implementation, tests, CLI routing and documentation are merged:

```text
nex crypto manifest create <algorithm> <file>...
nex crypto manifest verify <manifest>
nex crypto encrypt <input> <output>
nex crypto decrypt <input> <output>
nex net interfaces
nex net dns <hostname> <record-type>
nex net tls <ip-or-host> <port>
nex output --format json
nex modules
```
