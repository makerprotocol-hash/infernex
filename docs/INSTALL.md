# Install and test INFERNEX

This guide builds the current INFERNEX source on Windows or Linux. It does not describe a signed installer: official end-user installers and signed release packages are not published yet.

## 1. Requirements

- Windows 10/11 x64 or a supported modern Linux x86-64 system.
- A stable Rust toolchain (install with [rustup](https://rustup.rs/)).
- Git.
- On Windows, the Visual Studio C++ Build Tools with the **Desktop development with C++** workload (MSVC linker and Windows SDK).

Open a new terminal after installing Rust and verify:

```sh
rustc --version
cargo --version
git --version
```

## 2. Get the source

```sh
git clone https://github.com/makerprotocol-hash/infernex.git
cd infernex
git checkout main
```

For a specific reviewed release, use its published tag instead of `main`. Do not treat an unreviewed feature branch as a stable release.

## 3. Build and test

Run the test suite first:

```sh
cargo test --all-targets
```

Build the optimized executable:

```sh
cargo build --release
```

The binary is:

- Windows: `target\release\nex.exe`
- Linux: `target/release/nex`

You can run it directly from the repository:

**PowerShell**
```powershell
.\target\release\nex.exe help
```

**Linux**
```sh
./target/release/nex help
```

To make `nex` available in your current terminal without copying it into a system directory:

**PowerShell**
```powershell
$env:PATH = "$(Resolve-Path .\target\release);$env:PATH"
nex version
```

**Linux**
```sh
export PATH="$(pwd)/target/release:$PATH"
nex version
```

The PATH change above applies only to the current terminal session.

## 4. Safe first-run test checklist

Start with local/read-only commands:

```text
nex version
nex help
nex doctor
nex roadmap
nex config show
nex theme list
nex alias list
nex net interfaces
nex hash sha256 <path-to-a-test-file>
nex hash sha512 <path-to-a-test-file>
```

Platform note: `nex net routes` currently reads the Linux IPv4/IPv6 route tables. Windows route inventory is not implemented yet and is expected to return an explicit unsupported-platform message.

Test file hashing with a disposable text file. Compare INFERNEX's output with the operating system's independent hash utility:

**PowerShell**
```powershell
Set-Content -NoNewline .\infernex-test.txt "INFERNEX test"
Get-FileHash .\infernex-test.txt -Algorithm SHA256
.\target\release\nex.exe hash sha256 .\infernex-test.txt
```

**Linux**
```sh
printf 'INFERNEX test' > infernex-test.txt
sha256sum infernex-test.txt
./target/release/nex hash sha256 ./infernex-test.txt
```

The digest values should match. You can also test verification by copying the independently generated digest and running:

```text
nex hash verify sha256 <path-to-test-file> <64-character-expected-digest>
```

## 5. Network diagnostics — use loopback first

Read-only local inventory:

```text
nex net interfaces
nex net routes
nex net cidr 127.0.0.1/8
nex net inspect 127.0.0.1
nex net resolve localhost
```

Active TCP/UDP diagnostics require the exact target to be present in your local authorization scope. For a safe first test, use only your own machine:

```text
nex scope add 127.0.0.1
nex scope list
nex scope check 127.0.0.1
nex net port 127.0.0.1 1
nex net scan 127.0.0.1 1 16
```

A refused connection or no response is a valid diagnostic outcome; it does not indicate a broken installation. The scan is limited to 16 loopback ports in this example. Remove the temporary scope entry when finished:

```text
nex scope remove 127.0.0.1
```

Do not test public systems, other devices, or networks unless you own them or have explicit permission. A scope entry is a local safeguard, not proof of legal authorization.

## 6. Windows and Linux feature status

| Capability | Windows | Linux |
|---|---|---|
| CLI, help, config, themes, aliases | Available | Available |
| SHA-256/SHA-512 file hashing and verification | Available | Available |
| Local interface inventory | Available | Available |
| Local route inventory | Not implemented | Available |
| DNS resolution | Available | Available |
| Bounded TCP/UDP diagnostics | Available, subject to scope | Available, subject to scope |
| Native DNS record queries and TLS inspection | Planned | Planned |

This table describes the current documented implementation, not a promise that every command has been independently tested on your computer.

## 7. Report a test result

When reporting a problem, include:

- Windows/Linux version and CPU architecture.
- `rustc --version` and `cargo --version`.
- Exact command entered.
- Full error output (remove private IPs, hostnames, usernames, and other sensitive details first).
- Whether `cargo test --all-targets` passed.

Do not send passwords, API keys, private keys, authorization tokens, or private configuration files.

## 8. Remove a source build

Delete the cloned `infernex` directory. If you added the build directory to PATH using the session-only commands above, close that terminal; no persistent PATH change was made. Remove any temporary test files and scope entries you created.

INFERNEX does not currently provide a dedicated installer or self-update/uninstall command for system-wide installations.
