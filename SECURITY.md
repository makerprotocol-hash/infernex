# Security policy

INFERNEX is intended for authorized security research, defensive assessment and lab work.

## Supported use

Use INFERNEX only on systems, accounts, applications and networks you own or have explicit permission to assess. Do not use this project to access, disrupt, persist in or extract data from systems without authorization.

Active network operations must have explicit targets, bounded behavior and authorization safeguards. A scan result is an observation, not proof of permission, vulnerability or service identity.

## Reporting vulnerabilities

If you discover a vulnerability in INFERNEX, do not publish exploit details before coordinating a responsible fix. Until a private reporting channel is established, contact the repository owner through GitHub's private vulnerability reporting feature if enabled.

## Sensitive information

Never include credentials, private keys, tokens, personal data, production secrets or real target information in issues, commits, test fixtures or pull requests.

## Cryptographic implementation

Use established, reviewed cryptographic algorithms and libraries. Do not implement custom ciphers or password KDFs. File encryption must use authenticated encryption, secure randomness, bounded KDF parameters and safe output handling. Authentication failure must not release plaintext.

## Third-party components

Optional compatibility integrations must retain required licenses, notices and attribution. Do not bundle or redistribute external tools until their licensing and distribution requirements have been reviewed.
