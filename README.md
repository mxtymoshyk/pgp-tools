# pgp_tools

A small Python toolkit for everyday PGP/GnuPG work: keyring management, file encryption/decryption with the legacy 3DES-CFB cipher, ownertrust fixes, and optional GCP Secret Manager-backed keyring distribution.

Each script does one thing and is usable on its own from the command line.

## Why this exists

Plain `gpg` works, but a few rough edges come up over and over:

- **Trust never gets set automatically.** After `gpg --import`, peer keys remain with "unknown" ownertrust, and encryption fails with `Unusable public key` until you run an interactive `gpg --edit-key trust` per key.
- **3DES is rejected by default on modern gpg.** Some legacy systems still expect 3DES-CFB, which means every gpg invocation needs `--allow-old-cipher-algos` and the right cipher flags.
- **Batch deletion of keys is awkward.** `gpg --delete-secret-keys` prompts per key.
- **Keyring distribution by email is a security smell.** Storing pubrings (and even secrings) in a real secret store like GCP Secret Manager is much better, but there's no off-the-shelf script that pulls them down and imports them.
- **`gpg --list-keys` doesn't answer the question you usually have:** "Can I encrypt to this recipient right now or not?" That requires combining trust + capability + expiry into one view.

`pgp_tools` is a collection of small focused scripts that paper over each of these.

## Quick start

```bash
# 1. install gpg (see Install section for per-OS instructions)
gpg --version

# 2. set up venv + install python deps
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. for the GCP-backed scripts only
pip install -r requirements-gcp.txt

# 4. round-trip sanity check using the bundled fixture
python pgp_3des_cfb.py --generate --name "Test" --email "test@example.com"
python pgp_3des_cfb.py --encrypt examples/example.txt --recipient test@example.com --output /tmp/enc.pgp
python pgp_3des_cfb.py --decrypt /tmp/enc.pgp --output /tmp/dec.txt
diff examples/example.txt /tmp/dec.txt && echo "round-trip OK"
```

## Install

### System dependency: GnuPG

| OS | Command |
|----|---------|
| Ubuntu / Debian | `sudo apt-get install gnupg` |
| macOS (Homebrew) | `brew install gnupg` |
| Windows | install [Gpg4win](https://www.gpg4win.org/) |

GnuPG 2.2 or newer is recommended.

### Python dependencies

```bash
pip install -r requirements.txt          # python-gnupg only
pip install -r requirements-gcp.txt      # adds google-cloud-secret-manager
```

The GCP extras are only needed if you want to run `import_secring_from_gcp.py` or `import_pubring_from_gcp.py`. The other 7 scripts work with just the base `requirements.txt`.

Python 3.10+ is supported. The GCP extras pin `protobuf >= 6.30.0` so things work cleanly on Python 3.13 / 3.14 (older protobuf 4.x fails to import on 3.14 with `Metaclasses with custom tp_new are not supported`).

### GCP credentials (optional)

The two GCP scripts use Application Default Credentials. Either:

```bash
gcloud auth application-default login
# or
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
```

## Tools at a glance

| Script | One-liner | Use when |
|--------|-----------|----------|
| [`pgp_3des_cfb.py`](#pgp_3des_cfbpy) | All-in-one keygen + encrypt + decrypt + import + export with 3DES-CFB | Everyday encryption/decryption, especially against legacy systems |
| [`list_recipients.py`](#list_recipientspy) | Show who you can encrypt to right now, with diagnostics | Picking a recipient, debugging "unusable key" errors |
| [`manage_trust.py`](#manage_trustpy) | Set ownertrust levels and key signatures | Imported keys show as "untrusted" |
| [`fix_key_usability.py`](#fix_key_usabilitypy) | Multi-strategy diagnose + repair of unusable keys | "Unusable public key" persists after import |
| [`import_pubring.py`](#import_pubringpy) | Import a public keyring file and auto-trust the keys | You received a `.gpg`/`.asc` keyring from a peer |
| [`import_secring.py`](#import_secringpy) | Import a secret keyring file with visibility | Restoring your own keys from a backup |
| [`cleanup_secring.py`](#cleanup_secringpy) | Safe batch deletion of keys (with explicit guards) | Removing old / test keys |
| [`import_pubring_from_gcp.py`](#import_pubring_from_gcppy) | Pull a public keyring from GCP Secret Manager + auto-trust | Centralized keyring distribution in GCP |
| [`import_secring_from_gcp.py`](#import_secring_from_gcppy) | Pull a secret keyring from GCP Secret Manager | Bootstrap signing keys on a new machine |

Every script supports `--help` for the full flag reference, and every script except `pgp_common.py` (which is the shared helper module, not a script) takes an optional `--gpg-home DIR` so you can point it at an isolated keyring instead of `~/.gnupg`.

---

## `pgp_3des_cfb.py`

The everyday CLI. One entrypoint covers key generation, encryption, decryption, import, export, and listing keys, all with 3DES-CFB cipher support enabled by default.

```bash
# generate a 2-year RSA-2048 keypair
python pgp_3des_cfb.py --generate --name "Alice" --email "alice@example.com"

# list everything in the keyring
python pgp_3des_cfb.py --list-keys

# encrypt a file
python pgp_3des_cfb.py --encrypt examples/example.txt \
    --recipient alice@example.com --output msg.pgp

# encrypt and sign in one step
python pgp_3des_cfb.py --encrypt examples/example.txt \
    --recipient alice@example.com --sign sender@example.com \
    --passphrase "signing-key-pass" --output msg.pgp

# decrypt
python pgp_3des_cfb.py --decrypt msg.pgp --output decoded.txt

# import / export
python pgp_3des_cfb.py --import-key public_key.asc
python pgp_3des_cfb.py --export-key alice@example.com --output alice_pub.asc
python pgp_3des_cfb.py --export-key alice@example.com --output alice_sec.asc --secret
```

Selected flags:

| Flag | Meaning |
|------|---------|
| `--encrypt FILE` | encrypt a file |
| `--decrypt FILE` | decrypt a file |
| `--generate` | generate a new RSA-2048 keypair |
| `--list-keys` | list public + secret keys |
| `--import-key FILE` | import a key |
| `--export-key KEY` | export a key (use `--secret` for the secret half) |
| `--recipient EMAIL/ID` | recipient identifier |
| `--sign KEY` | sign with this key |
| `--passphrase` | passphrase for key operations |
| `--output FILE` | output path |
| `--gpg-home DIR` | custom keyring directory |

Pitfalls:

- 3DES-CFB is **not** the cipher to choose for new systems. Use AES (the default in modern gpg) when you don't have a legacy interop requirement.
- Passing `--always-trust` is built-in (it's how the script avoids "unusable public key" errors). If that's not what you want, edit `GPG_BASE_OPTIONS` near the top of the script.

## `list_recipients.py`

Combines trust, capability, and expiry into one verdict per key, plus search and one-shot encryption test.

```bash
python list_recipients.py                              # everyone, summary view
python list_recipients.py -v                           # include algo + expiry
python list_recipients.py --search alice               # filter by substring
python list_recipients.py --test alice@example.com     # try encrypting a test message
python list_recipients.py --diagnose                   # diagnose common issues
```

| Flag | Meaning |
|------|---------|
| `-v`, `--verbose` | extra detail per key (algorithm, length, expiry, capabilities) |
| `--search TERM` | filter recipients by substring (UID, key ID, fingerprint) |
| `--test RECIPIENT` | try a test encryption to that recipient |
| `--test-file FILE` | use FILE as the test payload instead of a fixed string |
| `--diagnose` | run a checklist of common encryption-blocking issues |
| `--gpg-home DIR` | custom keyring directory |

Pitfalls:

- "VALID but UNTRUSTED" recipients can still be used with `--always-trust`, but the recommended fix is `manage_trust.py --set-trust ... --level 5` so it persists.

## `manage_trust.py`

Sets ownertrust and key signatures. Run with no args for an interactive menu, or use the flags for scripted/batch invocations.

```bash
python manage_trust.py                                  # interactive menu
python manage_trust.py --list                           # show keys + trust
python manage_trust.py --set-trust alice@example.com --level 5
python manage_trust.py --trust-all --level 5
python manage_trust.py --sign-key alice@example.com
python manage_trust.py --check-sigs alice@example.com
python manage_trust.py --quick-fix                      # ultimately-trust everything
```

| Flag | Meaning |
|------|---------|
| `--list` | list keys with trust |
| `--set-trust KEY --level N` | set ownertrust on a single key |
| `--trust-all --level N` | set ownertrust on every key |
| `--sign-key KEY` | sign (certify) a key |
| `--check-sigs KEY` | print signatures on a key |
| `--quick-fix` | ultimately-trust every key (handy when bootstrapping) |
| `--gpg-home DIR` | custom keyring directory |

Pitfalls:

- "Trust" in PGP has two distinct meanings: **ownertrust** (how much you trust the key holder to certify others) and **calculated validity** (whether you trust the key itself, derived from the web-of-trust). This script sets ownertrust. For most personal/team keyrings, level 5 is the sane default.

## `fix_key_usability.py`

When `Unusable public key` won't go away, this script tries every remedy in sequence: set ownertrust, edit-key trust, lsign with your own key, refresh from keyserver, and finally fall back to `--always-trust`. Each step prints whether it ran and whether the key became usable.

```bash
python fix_key_usability.py                                  # show key status
python fix_key_usability.py --fix-key alice@example.com
python fix_key_usability.py --fix-all --trust-level 5
python fix_key_usability.py --show-workarounds
python fix_key_usability.py --test-encryption alice@example.com
```

| Flag | Meaning |
|------|---------|
| `--fix-all` | run the multi-strategy fix on every public key |
| `--fix-key KEY` | run it on a single key (email, key ID, or fingerprint) |
| `--trust-level N` | trust level to apply (default 5) |
| `--show-workarounds` | print the workaround commands without changing anything |
| `--test-encryption RECIPIENT` | try a real encryption against the recipient |
| `--gpg-home DIR` | custom keyring directory |

Pitfalls:

- This script is the heaviest hammer. If you only need ownertrust set, use `manage_trust.py`.

## `import_pubring.py`

Imports a public keyring file and immediately offers to set ownertrust on the imported keys, so they're usable as recipients without a separate step.

```bash
python import_pubring.py partners_pubring.asc
python import_pubring.py keys.gpg --trust-level 4 --yes
python import_pubring.py keys.gpg --gpg-home ./tmp_keyring
```

| Flag | Meaning |
|------|---------|
| `pubring_file` | path to the keyring file (positional, required) |
| `--trust-level N` | trust level to apply (default 5) |
| `--yes` | skip the trust-level confirmation prompt |
| `--gpg-home DIR` | custom keyring directory |

## `import_secring.py`

Imports a secret keyring file and lists what landed - useful when you don't trust `gpg --import` to be informative enough about restored backup contents.

```bash
python import_secring.py backup/secring.gpg
python import_secring.py keys.asc --gpg-home ./tmp_keyring
```

| Flag | Meaning |
|------|---------|
| `secring_file` | path to the keyring file (positional, required) |
| `--gpg-home DIR` | custom keyring directory |

## `cleanup_secring.py`

Batch deletion with built-in safety. Interactive by default; flag-driven for automation.

```bash
python cleanup_secring.py                                          # interactive menu
python cleanup_secring.py --key-id ABCD1234 --yes
python cleanup_secring.py --email old-test@example.com --yes
python cleanup_secring.py --key-id ABCD --key-id EFGH --yes
python cleanup_secring.py --all                                    # type "DELETE ALL" to confirm
```

| Flag | Meaning |
|------|---------|
| `--key-id KEY` | substring matched against key ID/fingerprint (repeatable) |
| `--email EMAIL` | substring matched against UIDs (repeatable) |
| `--all` | delete every key (still prompts for "DELETE ALL") |
| `--yes` | skip the per-batch confirmation |
| `--gpg-home DIR` | custom keyring directory |

Pitfalls:

- The script deletes both the secret and public copies of a matching key (when both exist). If you only want to drop the public half, use `gpg --delete-keys` directly.

## `import_pubring_from_gcp.py`

Pulls a named secret (containing a PGP public keyring) from GCP Secret Manager, imports it, and applies ownertrust automatically.

```bash
python import_pubring_from_gcp.py --project my-project --secret my-pubring
python import_pubring_from_gcp.py --project my-project --secret my-pubring --version 2 --trust-level 4
```

| Flag | Meaning |
|------|---------|
| `--project P` | GCP project ID (required) |
| `--secret S` | secret name (required) |
| `--version V` | secret version (default `latest`) |
| `--trust-level N` | trust level to apply (default 5) |
| `--gpg-home DIR` | custom keyring directory |

Pitfalls:

- The script auto-trusts every imported key with the chosen level. If you want manual review, use `import_pubring.py` instead and pass the downloaded file.

## `import_secring_from_gcp.py`

Same idea but for secret keyrings. The bytes are piped straight into `gpg --import` so the secret material never touches local disk.

```bash
python import_secring_from_gcp.py --project my-project --secret my-secring
python import_secring_from_gcp.py --project my-project --secret my-secring --version 3
```

| Flag | Meaning |
|------|---------|
| `--project P` | GCP project ID (required) |
| `--secret S` | secret name (required) |
| `--version V` | secret version (default `latest`) |
| `--gpg-home DIR` | custom keyring directory |

---

## Test fixtures (`examples/`)

| File | What |
|------|------|
| `examples/example.txt` | Plaintext test fixture (Unicode, special chars, multiple paragraphs) |
| `examples/example.txt.pgp` | A 3DES-CFB-encrypted version of `example.txt` (binary PGP message) |
| `examples/example_encrypted.pgp` | Duplicate fixture used as a second-source encrypted sample |
| `examples/example_decrypted.txt` | Reference plaintext, identical to `example.txt`, for diff-checking decrypts |

Use them for the round-trip walkthrough below.

## Trust levels

| Level | Short | Meaning |
|-------|-------|---------|
| 1 | undefined | I do not know or won't say |
| 2 | never | I do NOT trust this key holder |
| 3 | marginal | I trust this key holder marginally |
| 4 | full | I trust this key holder fully |
| 5 | ultimate | I trust ultimately (typically reserved for your own keys) |

For most personal or small-team setups, level 5 on your own keys and level 4 on peer keys is a reasonable default. Use `manage_trust.py` to set them.

## End-to-end walkthrough (Alice and Bob)

```bash
# 1. Alice and Bob each generate a keypair
python pgp_3des_cfb.py --generate --name "Alice" --email "alice@example.com"
python pgp_3des_cfb.py --generate --name "Bob"   --email "bob@example.com"

# 2. Verify the keyring
python list_recipients.py

# 3. Trust Bob's key fully (so encryption to Bob doesn't warn)
python manage_trust.py --set-trust bob@example.com --level 4

# 4. Alice encrypts a file for Bob
python pgp_3des_cfb.py --encrypt examples/example.txt \
    --recipient bob@example.com --output for_bob.pgp

# 5. Bob decrypts it
python pgp_3des_cfb.py --decrypt for_bob.pgp --output bob_received.txt
diff examples/example.txt bob_received.txt

# 6. Clean up
python cleanup_secring.py --email alice@example.com --yes
python cleanup_secring.py --email bob@example.com   --yes
```

## Troubleshooting

**`Unusable public key`**
The recipient's ownertrust is unset. Either trust the key (`manage_trust.py --set-trust ... --level 5`), or use the bundled `--always-trust` workaround already in `pgp_3des_cfb.py`. If trust is set and the key is still unusable, try `fix_key_usability.py --fix-key ...`.

**`No secret key`** (during decryption)
You don't have the matching private key. Verify with `python pgp_3des_cfb.py --list-keys` that the secret key is present.

**`gpg: command not found`**
Install GnuPG (see Install). On Windows, restart your terminal after installing Gpg4win so the `gpg` binary appears on `PATH`.

**`gpg: <key>: skipped: Unusable public key` after `--import-ownertrust`**
The trust DB needs the **fingerprint**, not the key ID. The scripts in this repo always use the fingerprint, but if you're running `gpg --import-ownertrust` by hand, double-check that.

**GCP scripts fail with `403 Permission denied`**
The Application Default Credentials in use don't have `roles/secretmanager.secretAccessor` on the secret. Grant the role or run `gcloud auth application-default login` with an account that does.

## Security notes

- 3DES-CFB is a legacy cipher. Use it only when an existing system requires it. For new work, prefer AES (gpg's default).
- Never commit `.gpg`, `.asc`, or `.kbx` files. The `.gitignore` in this repo allowlists only `examples/` so demonstration fixtures can ship.
- `pgp_3des_cfb.py` passes `--always-trust` by default for usability. If you need stricter behavior, edit `GPG_BASE_OPTIONS` at the top of the script and remove that flag.
- The GCP scripts pipe the secret payload straight into `gpg --import` and never write it to disk.
- Keep your secret keyring backed up in a real secret store (not a git repo).

## Project layout

```
pgp_tools/
├── README.md
├── LICENSE
├── .gitignore
├── requirements.txt              # base: python-gnupg
├── requirements-gcp.txt          # extras: google-cloud-secret-manager
├── pgp_common.py                 # shared constants + helpers
├── pgp_3des_cfb.py
├── manage_trust.py
├── fix_key_usability.py
├── import_pubring.py
├── import_secring.py
├── cleanup_secring.py
├── list_recipients.py
├── import_pubring_from_gcp.py
├── import_secring_from_gcp.py
└── examples/
    ├── example.txt
    ├── example.txt.pgp
    ├── example_encrypted.pgp
    └── example_decrypted.txt
```

## Contributing

PRs welcome. Before submitting:

1. Run all scripts manually with `--help` to confirm argparse still loads (`for f in *.py; do python "$f" --help > /dev/null || echo "FAIL: $f"; done`).
2. Run the round-trip walkthrough above against a temporary `$GNUPGHOME` (`export GNUPGHOME=$(mktemp -d)`).
3. Keep one script = one purpose. If you find yourself adding two unrelated subcommands to the same script, consider a new script instead.

## License

[MIT](LICENSE).
