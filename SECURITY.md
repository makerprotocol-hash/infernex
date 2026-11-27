# Security policy

INFERNEX is intended for authorized security research, defensive assessment and lab work.

## Supported use

Use INFERNEX only on systems, accounts, applications and networks you own or have explicit permission to assess. Do not use this project to access, disrupt, persist in or extract data from systems without authorization.

Active network operations must use explicit targets, bounded behavior and the local authorization scope. Scope entries are a user-managed safeguard, not proof of legal permission. A scan result is an observation, not proof of permission, vulnerability or service identity.

## Reporting vulnerabilities

If you discover a vulnerability in INFERNEX, do not publish exploit details before coordinating a responsible fix. Until a private reporting channel is established, contact the repository owner through GitHub's private vulnerability reporting feature if enabled. Include affected commit/version, platform, impact and minimal reproduction steps; do not include real credentials, secrets or third-party target data.

## Sensitive information

Never include credentials, private keys, tokens, personal data, production secrets or real target information in issues, commits, test fixtures or pull requests. Avoid logging secret material or dumping environment variables.

## Network safety

- Every active network action must have an explicit target and enforce authorization scope before opening a socket.
- Keep connection counts, port ranges, payloads, reads and timeouts bounded.
- No stealth, evasion, persistence, unauthorized discovery or unbounded scans.
- Treat timeouts and missing responses as inconclusive where protocol semantics require it.
- DNS results do not automatically add targets to authorization scope.

## Cryptographic implementation

Use established, reviewed cryptographic algorithms and libraries. Do not implement custom ciphers or password KDFs. File encryption must use authenticated encryption, secure OS randomness, bounded KDF parameters and safe output handling. Authentication failure must not release plaintext. Do not claim encryption is available until implementation, tests and CLI integration are merged.

## Third-party components

Optional compatibility integrations must retain required licenses, notices and attribution. Do not bundle or redistribute external tools until their licensing and distribution requirements have been reviewed.
