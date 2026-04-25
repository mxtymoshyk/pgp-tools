# Contributing

Thanks for considering a contribution!

## Dev setup

```bash
git clone https://github.com/maksymtymoshyk/pgp-tools.git
cd pgp-tools
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,gcp]"
pre-commit install
```

GnuPG must be installed and on `PATH`:

- Linux: `sudo apt-get install gnupg`
- macOS: `brew install gnupg`
- Windows: `choco install gnupg`

## Run tests

```bash
pytest                         # all tests
pytest --cov                   # with coverage
pytest tests/test_pgp_common.py
```

Tests use a throwaway GPG home directory so your real keyring is never touched.

## Lint & format

```bash
ruff check .
ruff format .
pre-commit run --all-files
```

## Branch / PR conventions

- Branch off `main`: `feat/<short>`, `fix/<short>`, `docs/<short>`.
- One logical change per PR. Add tests for new behavior.
- Update `CHANGELOG.md` under `[Unreleased]`.

## Architecture

```
src/pgp_tools/
  pgp_common.py             shared GPG init, trust helpers, key resolver
  pgp_3des_cfb.py           keygen / encrypt / decrypt with legacy 3DES-CFB cipher
  list_recipients.py        trust + capability + expiry check per recipient
  manage_trust.py           set ownertrust + key signatures
  fix_key_usability.py      diagnose & repair "unusable public key"
  import_pubring.py         import a public keyring
  import_secring.py         import a secret keyring
  import_pubring_from_gcp.py  pull pubring from GCP Secret Manager
  import_secring_from_gcp.py  pull secring from GCP Secret Manager
  cleanup_secring.py        safe batch delete of secret keys
```

## Release process

1. Bump `version` in `pyproject.toml` and `src/pgp_tools/__init__.py`.
2. Move `CHANGELOG.md` `[Unreleased]` items under `[X.Y.Z] - YYYY-MM-DD`.
3. Commit, tag: `git tag vX.Y.Z && git push --tags`.
4. The `release` workflow builds + publishes to PyPI.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
