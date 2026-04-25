# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-04-25

### Added

- Initial public release.
- `pgp-3des-cfb`: keygen / encrypt / decrypt / import / export with legacy 3DES-CFB for HL7 integration.
- `pgp-list-recipients`: trust + capability + expiry inspection per recipient.
- `pgp-manage-trust`: set ownertrust levels and key signatures (batch + interactive).
- `pgp-fix-key-usability`: multi-strategy diagnose & repair for "unusable public key" errors.
- `pgp-import-pubring` / `pgp-import-secring`: import keyrings with auto-trust.
- `pgp-import-pubring-from-gcp` / `pgp-import-secring-from-gcp`: pull keyrings from GCP Secret Manager.
- `pgp-cleanup-secring`: safe batch deletion of secret keys.
- Shared `pgp_common` module for trust constants, GPG init, ownertrust helpers, key resolver.
- pytest suite with throwaway GPG home fixture (no impact on user's `~/.gnupg`).
- GitHub Actions CI: tests on Linux/macOS/Windows × Python 3.9-3.12, ruff lint, PyPI release on tag.
