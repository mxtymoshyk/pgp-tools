#!/usr/bin/env python3
"""
import_pubring - Import a public keyring file and immediately set ownertrust.

Why this exists:
    A bare `gpg --import` of a pubring leaves every imported key with
    "unknown" ownertrust, which causes "unusable public key" errors at
    encrypt time. This script combines the import and ownertrust step
    so peer keys are usable as encryption recipients right away.

Usage:
    python import_pubring.py PUBRING_FILE [--trust-level 1-5] [--gpg-home DIR] [--yes]

Examples:
    python import_pubring.py partners_pubring.asc
    python import_pubring.py keys.gpg --trust-level 4 --yes

Requires:
    - python-gnupg
    - gpg binary on PATH
"""

import argparse
import subprocess
import sys

from .pgp_common import TRUST_LEVELS, get_gpg, import_ownertrust, trust_level_help


def import_pubring(pubring_data, gpg_home=None):
    """
    Pipe a public-keyring blob into `gpg --import`.

    Args:
        pubring_data: raw bytes of the pubring file.
        gpg_home: optional GPG home directory passed via --homedir.

    Returns:
        True on success, False otherwise.
    """
    cmd = ["gpg"]
    if gpg_home:
        cmd.extend(["--homedir", gpg_home])
    cmd.extend(["--batch", "--import"])

    try:
        result = subprocess.run(cmd, input=pubring_data, capture_output=True, check=True)
        print("Pubring imported successfully.")
        print("Import output:", result.stderr.decode())
        return True
    except subprocess.CalledProcessError as exc:
        print(f"Failed to import pubring: {exc}")
        print(f"Error output: {exc.stderr.decode()}")
        return False


def list_imported_keys(gpg_home=None):
    """
    Print every public and secret key in the keyring after import.

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
        print(f"Length: {key.get('length', 'Unknown')}")
        print(f"Algorithm: {key.get('algo', 'Unknown')}")
        print("-" * 50)

    print("\n=== Secret Keys (for reference) ===")
    secret_keys = gpg.list_keys(True)
    for key in secret_keys:
        print(f"Key ID: {key['keyid']}")
        print(f"UIDs: {key['uids']}")
        print("-" * 50)

    return public_keys, secret_keys


def main():
    parser = argparse.ArgumentParser(
        description="Import a public keyring (pubring) and optionally set ownertrust.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
Examples:
  %(prog)s partners_pubring.asc
  %(prog)s keys.gpg --trust-level 4
  %(prog)s keys.gpg --trust-level 5 --yes --gpg-home ./tmp_keyring

{trust_level_help()}
""",
    )
    parser.add_argument("pubring_file", help="Path to the pubring file to import")
    parser.add_argument(
        "--trust-level",
        choices=list(TRUST_LEVELS),
        default="5",
        help="Ownertrust level to apply to imported keys (default: 5)",
    )
    parser.add_argument("--gpg-home", help="GPG home directory (default: ~/.gnupg)")
    parser.add_argument(
        "--yes", action="store_true", help="Skip the trust-level confirmation prompt"
    )

    args = parser.parse_args()

    try:
        with open(args.pubring_file, "rb") as f:
            pubring_data = f.read()
        print(f"Read pubring from: {args.pubring_file}")
        print(f"File size: {len(pubring_data)} bytes")
    except FileNotFoundError:
        print(f"Error: File not found: {args.pubring_file}")
        sys.exit(1)
    except OSError as exc:
        print(f"Error reading file: {exc}")
        sys.exit(1)

    if not import_pubring(pubring_data, args.gpg_home):
        sys.exit(1)

    public_keys, secret_keys = list_imported_keys(args.gpg_home)

    print("\nSummary:")
    print(f"Total public keys: {len(public_keys)}")
    print(f"Total secret keys: {len(secret_keys)}")

    if not public_keys:
        print("\nNo public keys were imported.")
        return

    print("\n=== Setting Trust Levels ===")
    fingerprints = [key["fingerprint"] for key in public_keys]

    if args.yes:
        proceed = True
    else:
        response = input(
            f"\nSet trust level '{args.trust_level}' for all {len(public_keys)} imported public keys? (yes/no): "
        )
        proceed = response.lower() == "yes"

    if proceed:
        for fingerprint in fingerprints:
            import_ownertrust(fingerprint, args.trust_level, args.gpg_home)
        print("\nTrust levels updated.")
    else:
        print("Skipping trust level setup.")

    print("\n=== Available Recipients for Encryption ===")
    print("You can now encrypt files for these recipients:")
    for key in public_keys:
        for uid in key["uids"]:
            print(f"  - {uid}")
        print(f"  - Key ID: {key['keyid']}")
        print()


if __name__ == "__main__":
    main()
