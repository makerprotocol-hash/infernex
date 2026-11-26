# Command reference

The examples below assume the INFERNEX executable is installed as `nex`.

## Core

| Command | Purpose |
|---|---|
| `nex` | Open the interactive prompt |
| `nex help` | Show available commands |
| `nex version` | Show the core version |
| `nex doctor` | Display basic environment diagnostics |
| `nex engines` | List optional integrations |
| `nex engines check` | Check whether integration executables are on PATH |
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

External programs must be installed separately and available on PATH. INFERNEX does not currently install or update those programs. Run `nex install <engine>` to display the integration's official upstream source and platform-specific guidance; it does not execute an installer.

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
