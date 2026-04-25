#!/usr/bin/env python3
"""
import_secring - Import a secret keyring file with visibility into what landed.

Why this exists:
    Plain `gpg --import` of a secret keyring is silent about which keys
    actually entered the keyring. This script imports the file and then
    lists every public + secret key with its UIDs, fingerprints, and
    expiration so you can verify the import without a separate
    `gpg --list-secret-keys` round-trip.

Usage:
    python import_secring.py SECRING_FILE [--gpg-home DIR]

Examples:
    python import_secring.py backup/secring.gpg
    python import_secring.py keys.asc --gpg-home ./tmp_keyring

Requires:
    - python-gnupg
    - gpg binary on PATH
"""

import argparse
import subprocess
import sys

from .pgp_common import get_gpg


def import_secring(secring_data, gpg_home=None):
    """
    Pipe a secret-keyring blob into `gpg --import`.

    Args:
        secring_data: raw bytes of the secret keyring file.
        gpg_home: optional GPG home directory passed via --homedir.

    Returns:
        True on success, False otherwise.
    """
    cmd = ["gpg"]
    if gpg_home:
        cmd.extend(["--homedir", gpg_home])
    cmd.extend(["--batch", "--import"])

    try:
        result = subprocess.run(cmd, input=secring_data, capture_output=True, check=True)
        print("Secring imported successfully.")
        print("Import output:", result.stderr.decode())
        return True
    except subprocess.CalledProcessError as exc:
        print(f"Failed to import secring: {exc}")
        print(f"Error output: {exc.stderr.decode()}")
        return False


def list_imported_keys(gpg_home=None):
    """
    Display every public and secret key in the keyring.

    Args:
        gpg_home: optional GPG home directory.

    Returns:
        Tuple (public_keys, secret_keys) as lists of key dicts.
    """
    gpg = get_gpg(gpg_home)

    print("\n=== Public Keys After Import ===")
    public_keys = gpg.list_keys()
    for key in public_keys:
        print(f"Key ID: {key['keyid']}")
        print(f"Fingerprint: {key['fingerprint']}")
        print(f"UIDs (emails/names): {key['uids']}")
        print(f"Creation date: {key['date']}")
        print(f"Expires: {key.get('expires', 'Never')}")
        print(f"Trust: {key.get('trust', 'Unknown')}")
        print("-" * 50)

    print("\n=== Secret Keys After Import ===")
    secret_keys = gpg.list_keys(True)
    for key in secret_keys:
        print(f"Key ID: {key['keyid']}")
        print(f"Fingerprint: {key['fingerprint']}")
        print(f"UIDs (emails/names): {key['uids']}")
        print(f"Creation date: {key['date']}")
        print(f"Expires: {key.get('expires', 'Never')}")
        print("-" * 50)

    return public_keys, secret_keys


def main():
    parser = argparse.ArgumentParser(
        description="Import a secret keyring (secring) file and report what was imported.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s backup/secring.gpg
  %(prog)s keys.asc --gpg-home ./tmp_keyring
""",
    )
    parser.add_argument("secring_file", help="Path to the secring file to import")
    parser.add_argument("--gpg-home", help="GPG home directory (default: ~/.gnupg)")

    args = parser.parse_args()

    try:
        with open(args.secring_file, "rb") as f:
            secring_data = f.read()
        print(f"Read secring from: {args.secring_file}")
    except FileNotFoundError:
        print(f"Error: File not found: {args.secring_file}")
        sys.exit(1)
    except OSError as exc:
        print(f"Error reading file: {exc}")
        sys.exit(1)

    if not import_secring(secring_data, args.gpg_home):
        sys.exit(1)

    public_keys, secret_keys = list_imported_keys(args.gpg_home)

    print("\nSummary:")
    print(f"Total public keys: {len(public_keys)}")
    print(f"Total secret keys: {len(secret_keys)}")

    if secret_keys:
        print("\nYou can now use these email addresses/key IDs for encryption:")
        for key in secret_keys:
            for uid in key["uids"]:
                print(f"  - {uid}")
            print(f"  - Key ID: {key['keyid']}")


if __name__ == "__main__":
    main()
