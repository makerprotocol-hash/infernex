# Command reference

The examples below assume the INFERNEX executable is installed as `nex`.

## Core

| Command | Purpose |
|---|---|
| `nex` | Open the interactive prompt |
| `nex help` | Show available commands |
| `nex version` | Show the core version |
| `nex doctor` | Display platform, config, color, and optional-engine diagnostics |
| `nex config show` | Show configuration location, theme, and alias count |
| `nex config path` | Print the configuration file path |
| `nex engines` | List optional integrations |
| `nex engines check` | Check whether integration executables are on PATH |
| `nex engines info <engine>` | Show an integration's details and availability |
| `nex theme list` | List available prompt themes |
| `nex theme set ember` | Save and apply a prompt theme |
| `nex alias list` | List saved command aliases |
| `nex alias add <name> <command> [args...]` | Save a command alias |
| `nex alias remove <name>` | Remove a saved alias |

## Native integrity tools

Calculate a file's SHA-256 digest:

```sh
nex hash sha256 ./release.zip
```

Verify a file against a trusted, independently obtained checksum:

```sh
nex hash verify sha256 ./release.zip <64-character-hex-digest>
```

A matching digest confirms byte-for-byte consistency with the expected digest. It does not prove who created the file; obtain expected checksums from an authenticated, trusted source.

## Native network diagnostics

Resolve a hostname through the system-configured DNS resolver:

```sh
nex net resolve example.com
```

## Optional external engines

Pass-through commands retain upstream arguments:

```sh
nex nmap -sV 192.0.2.10
nex tshark -i 1
nex metasploit
```

External programs must be installed separately and available on PATH. INFERNEX does not update external programs. `nex install <engine>` provides installation support for Nmap on Linux and upstream guidance for other cases. The Nmap Linux flow detects a supported package manager, displays the exact command, and requires you to type `YES` before starting it. It invokes the package manager through direct process arguments (not a shell); `sudo` may request your password. On Windows, use the official Nmap installer and review its Npcap options.

Only test systems and networks you own or are explicitly authorized to assess.

## Prompt appearance

The `ember`, `spectrum`, and `mono` themes change the interactive prompt color. Set the standard `NO_COLOR` environment variable to a non-empty value to disable ANSI colors:

PowerShell:
```powershell
$env:NO_COLOR = "1"
nex
```

Linux:
```sh
NO_COLOR=1 nex
```

## Aliases

Aliases preserve individual arguments, including arguments containing spaces and Windows paths:

```sh
nex alias add report nmap -oN "scan report.txt" 192.0.2.10
nex report
```

Aliases are expanded as argument lists and are never evaluated by a shell. Expansion is limited to eight levels.

## Engine details and installation

Inspect one integration:

```sh
nex engines info nmap
```

On supported Linux distributions, the Nmap installer recognizes APT, DNF, YUM, Pacman, or Zypper. It asks for an explicit `YES` before running the corresponding package-manager command with elevated privileges. Review the command and trust your configured repositories before approving it. If you decline, no package manager is started.

On Windows, INFERNEX currently provides official download guidance rather than launching an installer automatically. Nmap's official Windows installer may offer Npcap and other components; review those choices during setup.

Official installation references:
- Nmap Linux installation: https://nmap.org/book/inst-linux.html
- Nmap Windows installation: https://nmap.org/book/inst-windows.html
- Nmap downloads: https://nmap.org/download.html

Inspect a CIDR range locally without sending network traffic:

```sh
nex net cidr 192.0.2.17/24
nex net cidr 2001:db8:abcd::1/48
```

The command reports the normalized network, mask, first and last addresses, and total address count. For IPv4 it also reports the traditional usable-host count (with /31 and /32 handled as special cases). It does not probe or scan the range.

Inspect an address locally (no packets are sent):

```sh
nex net inspect 192.168.1.10
nex net inspect fd00::1
```

The output reports the address family and standard loopback, private, link-local, multicast, unspecified, and (for IPv4) broadcast classifications. These labels describe address properties only; they do not prove that a host is reachable, safe, or authorized.

## Diagnostics

Run `nex doctor` to display the core version, operating system and architecture, config-file location, color-output state, and the number of optional engines detected on `PATH`. Missing engines are listed with their upstream project links. Diagnostics are read-only and do not install software or change system settings.

## Configuration inspection

```sh
nex config show
nex config path
```

`config show` reports the active theme and number of saved aliases without printing alias values. `config path` prints the configuration file location. Both commands are read-only.
