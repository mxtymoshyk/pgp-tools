# Security Policy

## Supported Versions

Security fixes ship in the latest minor release.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security reports.

Email `maksym.tymoshyk@gmail.com` with:

- Description of the issue
- Steps to reproduce
- Affected version(s)
- Suggested mitigation if any

Acknowledgment within 72 hours. Coordinated disclosure timeline agreed before any public mention.

## Scope

This project handles cryptographic key material and GnuPG keyrings. Particularly relevant concerns:

- Key disclosure or unintended export
- Path traversal when reading/writing keyrings
- Trust-flag manipulation
- Subprocess injection via key ID / fingerprint inputs
- Memory handling of passphrases
