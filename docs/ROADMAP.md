# INFERNEX Master Roadmap

> **Vision:** Build a native-first, all-in-one cybersecurity terminal with independently implemented engines for networking, cryptography, security assessment, analysis, and defensive operations.
>
> **Status policy:** A roadmap item is not a shipped feature. Only mark work **Implemented** after the code exists, tests pass, and the command/documentation agree. This roadmap describes direction, not a claim that every capability already exists.

## 1. Product principles

1. **Native-first engines.** INFERNEX should implement and maintain its own core networking, protocol, crypto, parsing, analysis, and workflow engines.
2. **One coherent terminal.** Capabilities should share a consistent CLI, configuration, scope model, output format, logging, and plugin interface.
3. **External tools are optional.** Compatibility adapters may call tools such as Nmap or Wireshark when a user chooses, but native INFERNEX functionality must not depend on them.
4. **Authorization before active testing.** Active network and security tests must be limited to explicitly authorized targets and controlled lab environments.
5. **Safe-by-design research.** Vulnerability research should emphasize detection, reproducibility, controlled proof-of-concept validation, remediation, and education. No stealth, persistence, credential theft, destructive payloads, or uncontrolled exploitation.
6. **Cross-platform engineering.** Target Windows and Linux first; design interfaces so macOS and other platforms can be added without rewriting engines.
7. **Observable and testable.** Every engine needs unit tests, integration tests where practical, clear errors, bounded resource use, and documented limitations.
8. **Honest maturity labels.** Use Implemented, In Progress, Planned, and Experimental consistently.

## 2. Current foundation

The following are present in the current project baseline; consult the command reference for exact syntax and limitations.

- Rust CLI and interactive terminal/REPL.
- Help, version, doctor, themes, aliases, and configuration inspection.
- Explicit target-scope inventory with IP, CIDR, and exact-hostname matching.
- Native DNS resolution, CIDR parsing, and IP inspection.
- Bounded native TCP connect scan and single-port TCP check.
- Basic native service/banner identification.
- One-datagram native UDP diagnostic.
- Native SHA-256 and SHA-512 file hashing and verification.
- A separate crypto module with byte-slice hashing support.
- Optional third-party compatibility adapters.

**Important:** The existing network commands are foundational diagnostics, not a full network scanner, packet engine, vulnerability scanner, or exploitation framework.

## 3. Engine roadmap

### A. Networking and protocol engine

**Goal:** Build an independently maintained networking stack for discovery, diagnostics, protocol inspection, and authorized assessment.

- [x] Basic DNS resolution and IP/CIDR utilities.
- [x] Bounded TCP connect scan with strict limits.
- [x] Single-target TCP port check.
- [x] Basic banner-based service identification.
- [x] Single-endpoint UDP diagnostic.
- [ ] Extract networking implementation from the CLI into a dedicated `src/net/` module.
- [ ] Local interface and route inventory, implemented with reviewed cross-platform APIs.
- [ ] DNS record queries (A, AAAA, CNAME, MX, TXT, NS, SOA) with timeouts and clear resolver behavior.
- [ ] Reverse DNS and forward/reverse consistency checks.
- [ ] IPv4/IPv6 subnet calculations and safe host-range planning.
- [ ] Configurable, rate-limited TCP discovery profiles with hard maximums and scope enforcement.
- [ ] UDP protocol probes for a small, documented set of common services; no arbitrary amplification.
- [ ] Better service fingerprint database with evidence, confidence, and versioned signatures.
- [ ] Native TLS handshake inspection: certificate chain, expiry, SANs, protocol and cipher metadata.
- [ ] HTTP inspection engine: methods, headers, redirects, cookies, security headers, response limits.
- [ ] Native HTTP client with strict timeouts, size limits, redirect policy, and proxy configuration.
- [ ] Network path diagnostics and route visibility.
- [ ] Packet capture abstraction and offline PCAP reader; live capture only where platform permissions and safe scope allow.
- [ ] Protocol decoders for Ethernet, ARP, IPv4/IPv6, TCP, UDP, DNS, HTTP, TLS metadata, DHCP, and selected common protocols.
- [ ] Network inventory snapshots and diffing.
- [ ] Export results as JSON, CSV, and human-readable reports.

**Acceptance criteria:** bounded concurrency and timeouts; cancellation; scope checks before active traffic; deterministic tests using loopback fixtures; no stealth/evasion modes.

### B. Cryptography, hashing, and data protection engine

**Goal:** A trustworthy native crypto toolkit with clear separation between secure primitives and educational demonstrations.

- [x] SHA-256 and SHA-512 file hashing and verification.
- [x] Byte-slice hashing helper.
- [x] Explicit file-integrity manifest APIs for caller-supplied paths (in-memory manifest; no implicit directory traversal or persistence format).
- [ ] Add SHA-3 and BLAKE2/BLAKE3 only after dependency and implementation review.
- [ ] HMAC generation and verification.
- [ ] HKDF key derivation.
- [ ] Secure random generation using operating-system cryptographic randomness.
- [ ] Password hashing using a modern memory-hard password hashing scheme; never invent a custom password hash.
- [ ] Encoding/decoding utilities (hex, Base64, URL encoding) clearly separated from encryption.
- [ ] File encryption/decryption using authenticated encryption and safe key/nonce handling.
- [ ] Key generation, import/export, metadata, and permission-safe storage.
- [ ] Digital signatures and signature verification.
- [ ] Certificate and public-key inspection.
- [ ] File integrity manifests with explicit paths, per-file algorithms, and verification reports.
- [ ] Crypto policy checks and weak/obsolete algorithm warnings.
- [ ] Optional educational cryptanalysis demonstrations on toy data and user-provided samples.

**Acceptance criteria:** known-answer test vectors, negative tests, tamper detection, no home-grown production cryptographic primitives, no silent key loss, and explicit warnings for educational/legacy algorithms.

### C. Vulnerability assessment and security auditing engine

**Goal:** Detect and explain security weaknesses on authorized systems without turning the terminal into an uncontrolled attack tool.

- [ ] Structured finding model: title, severity, evidence, affected asset, confidence, references, remediation.
- [ ] Local host security posture checks.
- [ ] Safe network configuration checks.
- [ ] TLS and certificate configuration audit.
- [ ] HTTP security-header and cookie audit.
- [ ] Web application passive checks.
- [ ] Authenticated checks only through explicit user-provided authorization and documented credentials handling.
- [ ] Configuration and dependency file auditing.
- [ ] Known-vulnerability matching against maintained advisory data, with source and timestamp.
- [ ] Software and service inventory correlation.
- [ ] False-positive management and finding suppression with audit trail.
- [ ] Report generation and remediation guidance.

**Acceptance criteria:** checks are documented, non-destructive by default, rate-limited, reproducible, and tied to evidence rather than assumptions.

### D. Exploit research and validation lab

**Goal:** Support security researchers and developers in understanding and validating vulnerabilities in systems they own or are explicitly authorized to test.

- [ ] Vulnerability taxonomy and reference library (CWE/CVE concepts).
- [ ] Safe proof-of-concept templates that run only against local fixtures or explicitly scoped lab targets.
- [ ] Reproducible test harness with snapshots, logs, and cleanup.
- [ ] Input-validation and parser test harnesses.
- [ ] Fuzzing harness for local binaries, parsers, and user-supplied test targets.
- [ ] Crash triage, minimization, and sanitizer-output parsing.
- [ ] Patch-diff and regression validation workflows.
- [ ] Exploitability education using deliberately vulnerable local examples.
- [ ] Safe payload simulation and non-destructive validation checks.
- [ ] Mitigation verification and regression test generation.

**Out of scope:** stealth or evasion, persistence, worms, destructive payloads, credential theft, mass exploitation, unauthorized target exploitation, and automated weaponization. The project should help users find, understand, reproduce safely, and fix vulnerabilities.

### E. Web application security engine

- [ ] Native HTTP request/response inspection.
- [ ] Site mapping restricted to explicitly scoped origins, with depth/rate/size limits.
- [ ] TLS, headers, cookies, redirect, and CORS checks.
- [ ] Form and input inventory without submitting destructive payloads.
- [ ] Passive detection for common misconfigurations.
- [ ] Safe injection validation against local training apps and controlled fixtures.
- [ ] API endpoint inventory from user-provided OpenAPI specifications and authorized traffic.
- [ ] Authentication/session configuration review.
- [ ] Report with request evidence and remediation.

### F. Wireless and local-network security

- [ ] Wireless adapter and capability inventory.
- [ ] Passive nearby-network visibility where supported by OS permissions and local law.
- [ ] Wi-Fi configuration and encryption posture education.
- [ ] Local ARP/neighbour inventory with scope controls.
- [ ] Rogue configuration and exposure checks using passive or explicitly authorized methods.
- [ ] Lab-only wireless protocol learning modules.

**Boundary:** no deauthentication, jamming, unauthorized interception, or credential capture.

### G. Host, endpoint, and operating-system security

- [ ] Cross-platform system inventory.
- [ ] Process, service, startup, and listening-socket inventory.
- [ ] File permission and sensitive-configuration checks.
- [ ] Patch/update posture checks.
- [ ] Firewall and host-network configuration review.
- [ ] Local log collection and filtering.
- [ ] Baseline comparison and drift detection.
- [ ] Hardening recommendations for Windows and Linux.
- [ ] Optional response playbooks requiring confirmation before changes.

### H. Digital forensics and incident response

- [ ] Read-only evidence acquisition workflows.
- [ ] File metadata and hash evidence records.
- [ ] Timeline construction from supported log formats.
- [ ] Log parsing and event correlation.
- [ ] PCAP and network-session analysis.
- [ ] File-type identification and metadata inspection.
- [ ] Evidence manifest, chain-of-custody notes, and export.
- [ ] Incident case folders and analyst notes.
- [ ] Forensic report generation.

### I. Reverse engineering and malware analysis (defensive)

- [ ] File metadata and format identification.
- [ ] Strings, imports, sections, and hashes for supported executable formats.
- [ ] Static indicators and rule-based triage.
- [ ] YARA-compatible rule evaluation if licensing and implementation are reviewed.
- [ ] Safe archive and document inspection with decompression limits.
- [ ] Offline sample analysis workflow.
- [ ] Controlled sandbox integration as optional, isolated infrastructure.
- [ ] IOC extraction and defensive reporting.

**Boundary:** defensive analysis only; do not add malware deployment, persistence, stealth, or evasion features.

### J. Identity, credentials, and access auditing

- [ ] Local account and group posture checks.
- [ ] Password policy and MFA configuration review where authorized.
- [ ] SSH key and certificate inventory.
- [ ] Permission and privilege review.
- [ ] Secret scanning in user-selected repositories and files, with redaction by default.
- [ ] Credential exposure reporting without collecting or exfiltrating secrets.
- [ ] Safe password-strength education using locally supplied test inputs.

### K. Cloud, containers, and infrastructure security

- [ ] Cloud configuration file and IaC static checks.
- [ ] Container image metadata and configuration audit.
- [ ] Kubernetes manifest and RBAC configuration checks.
- [ ] Secret and permission misconfiguration detection.
- [ ] SBOM generation and dependency inventory.
- [ ] Supply-chain and signature verification.
- [ ] Optional cloud-provider integrations using least-privilege, read-only permissions by default.

### L. Automation, scripting, and extensibility

- [ ] Stable internal engine API.
- [ ] Versioned plugin interface with permissions and capability declarations.
- [ ] Reusable scan/audit profiles.
- [ ] Workflow composition and saved jobs.
- [ ] JSON input/output contract for automation.
- [ ] Scripting support only after permission, sandboxing, and audit design.
- [ ] Optional integrations kept separate from native engines.
- [ ] Plugin signing, provenance, and compatibility checks.

### M. Reporting, UX, and platform quality

- [ ] Consistent output levels: human, JSON, and machine-readable.
- [ ] Severity and confidence model.
- [ ] Evidence-linked HTML/Markdown/JSON reports.
- [ ] Session history and reproducible command logs with secret redaction.
- [ ] Configuration validation and migration.
- [ ] Interactive help, completion, and contextual suggestions.
- [ ] Localization and accessible terminal output.
- [ ] Windows/Linux CI matrix and supported-version policy.
- [ ] Performance benchmarks and resource limits.
- [ ] Release signing, checksums, SBOM, and reproducible-build improvements.
- [ ] User documentation, tutorials, and safe lab exercises.

## 4. Delivery milestones

Milestones are dependency-aware targets, not calendar promises.

### M0 — Reliable core (current foundation)
- Stabilize CLI, configuration, scope, crypto module, and tests.
- Keep documentation synchronized with actual behavior.
- Keep the merged crypto manifest and authenticated-encryption design aligned with implementation, tests, and documentation.

### M1 — Modular engine architecture
- Complete extraction of networking operations from `main.rs` into `src/net/` (pure primitives are already in `src/net.rs`).
- Establish shared error, output, configuration, and target types.
- Keep CLI command handlers thin.
- Add loopback-based integration tests and Windows/Linux CI coverage.

### M2 — Native network diagnostics
- Interface/route inventory, richer DNS, TLS inspection, HTTP inspection.
- Improve service fingerprints with evidence and confidence.
- Add bounded concurrency only with strict rate and resource limits.

### M3 — Crypto and integrity toolkit
- Complete manifests, HMAC, KDF, OS randomness, authenticated file encryption, signatures.
- Complete known-answer and tamper tests.
- Review key handling and threat model before declaring stable.

### M4 — Findings and vulnerability assessment
- Shared findings schema, safe checks, advisory matching, remediation reports.
- Start with local and passive checks, then explicitly authorized active checks.

### M5 — Web and API assessment
- Native HTTP engine, scoped site mapping, passive web checks, API specification analysis.
- Local vulnerable training fixtures for safe validation.

### M6 — Host, endpoint, and configuration auditing
- Windows/Linux inventory, hardening checks, local logs, baseline and drift reports.

### M7 — Forensics and traffic analysis
- Offline PCAP analysis, evidence manifests, timelines, case management, export.

### M8 — Reverse engineering and defensive malware triage
- Static file analysis, metadata, indicators, safe sample workflow, optional isolated sandbox.

### M9 — Cloud, containers, identity, and supply chain
- IaC, container, Kubernetes, identity, secrets, and SBOM auditing.

### M10 — Research lab and extensibility
- Fuzzing harnesses, crash triage, safe PoC templates, plugin API, automation workflows.

### M11 — Stable all-in-one release
- Complete cross-platform QA, threat model, security review, documentation, signed releases, SBOM, and compatibility policy.
- Publish a capability matrix that clearly distinguishes stable, experimental, and unsupported features.

## 5. Engineering layout target

The repository should move gradually toward a structure similar to this. Do not create empty modules just to match the diagram; introduce each module with working code and tests.

```text
src/
  main.rs                 # CLI entry point and command routing
  cli/                    # argument parsing, REPL, help, output
  core/                   # config, errors, scope, findings, events
  net/                    # DNS, TCP, UDP, TLS, HTTP, protocols, capture
  crypto/                 # hashes, KDF, AEAD, keys, signatures, manifests
  audit/                  # checks, advisory matching, remediation
  web/                    # HTTP assessment and API analysis
  host/                   # OS inventory and hardening
  forensics/              # evidence, timelines, PCAP/log analysis
  reverse/                # static file and binary analysis
  identity/               # accounts, permissions, key/secret auditing
  cloud/                  # IaC, containers, cloud configuration
  research/               # fuzzing harnesses and safe validation labs
  plugins/                # plugin contracts and optional adapters
tests/
  fixtures/
  integration/
docs/
  ARCHITECTURE.md
  COMMANDS.md
  SECURITY.md
  WORKSTREAMS.md
  ROADMAP.md
```

## 6. Shared command experience

The exact command syntax will be finalized as engines land. These are proposed namespaces, not promises that the commands already exist.

| Namespace | Planned responsibility |
|---|---|
| `nex net` | Discovery, DNS, TCP/UDP, TLS, HTTP, protocols, capture |
| `nex crypto` | Hashes, manifests, HMAC, KDF, encryption, keys, signatures |
| `nex audit` | Host, network, configuration, and vulnerability checks |
| `nex web` | Scoped web/API assessment |
| `nex host` | System inventory and hardening |
| `nex forensics` | Evidence, timelines, logs, PCAP |
| `nex reverse` | Static binary and file analysis |
| `nex identity` | Accounts, permissions, keys, secret exposure checks |
| `nex cloud` | IaC, containers, Kubernetes, cloud posture |
| `nex lab` | Safe local training and vulnerability validation |
| `nex report` | Findings, evidence, exports |
| `nex plugin` | Optional extensions and integrations |

## 7. Definition of done for every engine

An engine is not complete because a command prints output. Each feature must have:

- A documented purpose, supported platforms, limitations, and threat model.
- Explicit scope/authorization behavior for active operations.
- Bounded time, memory, concurrency, file size, and network activity.
- Structured errors and stable machine-readable output where appropriate.
- Unit tests, regression tests, and integration fixtures.
- Security review for parsing, filesystem access, secrets, and network behavior.
- Documentation updated in the same change.
- No hidden dependency on an optional third-party executable.
- Clear maturity label: Experimental, Beta, or Stable.

## 8. Contributor and AI-agent execution rules

All contributors and coding agents must:

1. Read this roadmap, `docs/ARCHITECTURE.md`, `docs/COMMANDS.md`, `docs/WORKSTREAMS.md`, and `CONTRIBUTING.md` before coding.
2. Check current `main`, open PRs, and existing module ownership before choosing a task.
3. Claim one task from `docs/WORKSTREAMS.md`; do not independently invent overlapping work.
4. Work on a branch and keep changes focused.
5. Respect file ownership. Coordinate before editing another contributor's owned files.
6. Never overwrite another contributor's work or reimplement an already merged feature.
7. Add tests and update docs with every behavior change.
8. Run formatting, tests, and available platform checks; report exactly what was and was not run.
9. Open a PR with scope, design, tests, limitations, and screenshots/logs where useful.
10. Never merge their own PR unless repository maintainers explicitly authorize it.

### Initial work queue

| Priority | Task | Primary area | Dependency |
|---|---|---|---|
| P0 | Extract DNS/TCP/UDP/service operations from the CLI into the native networking module | `src/main.rs`, `src/net.rs` | Preserve current CLI behavior, scope checks, timeouts and limits; add loopback tests |
| P1 | Close or mark duplicate crypto PRs #11 and #12 as superseded | PR review only | Manifest and byte-hash APIs already exist on `main` |
| P1 | Define shared error and findings types | `src/core/` | Architecture extraction |
| P1 | Add interface and route inventory | `src/net/` | Cross-platform API review |
| P1 | Expand DNS record queries | `src/net/` | Resolver design |
| P1 | Add TLS certificate inspection | `src/net/` | Networking module |
| P1 | Add native HTTP inspection | `src/net/`, `src/web/` | HTTP client design |
| P2 | Add HMAC and secure KDF | `src/crypto.rs` | Crypto threat model |
| P2 | Add structured findings and reports | `src/core/`, `src/audit/` | Shared data model |
| P2 | Build local host audit checks | `src/host/` | Findings model |
| P3 | Add offline PCAP analysis | `src/forensics/` | Protocol decoder foundation |
| P3 | Add safe fuzzing and crash triage | `src/research/` | Lab isolation design |

## 9. How progress is reported

For each roadmap task, record:

- Status: Planned / In Progress / Review / Implemented / Blocked.
- Owner and branch/PR.
- Files/modules changed.
- Tests run and exact result.
- Security and compatibility notes.
- Follow-up tasks.

Do not mark a whole engine complete when only one command exists. Keep this roadmap ambitious, but keep every status truthful.
