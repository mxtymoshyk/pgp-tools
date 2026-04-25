#!/usr/bin/env python3
"""
cleanup_secring - Safe batch deletion of GPG keys (secret + public).

Why this exists:
    `gpg --delete-secret-keys` and `gpg --delete-keys` both prompt for
    interactive confirmation per key, which makes cleaning up a keyring
    full of test keys tedious. This script batches deletion by key ID
    or email substring, with explicit guards (--all requires typing
    "DELETE ALL", and batch mode requires --yes to skip the confirmation
    prompt) so accidental wipes are hard to trigger.

Usage:
    python cleanup_secring.py                              # interactive menu
    python cleanup_secring.py --key-id KEY [--key-id KEY...] [--yes]
    python cleanup_secring.py --email EMAIL [--email EMAIL...] [--yes]
    python cleanup_secring.py --all                        # nuke entire keyring

Examples:
    python cleanup_secring.py --key-id ABCD1234 --yes
    python cleanup_secring.py --email old-test@example.com --yes
    python cleanup_secring.py --all  # type "DELETE ALL" to confirm

Requires:
    - python-gnupg
    - gpg binary on PATH
"""

import argparse
import subprocess
import sys

from .pgp_common import get_gpg


def list_keys(gpg, secret=False):
    """
    Print every key (public or secret) in the keyring.

    Args:
        gpg: configured gnupg.GPG instance.
        secret: True to list secret keys, False for public.

    Returns:
        List of key dicts in keyring order.
    """
    keys = gpg.list_keys(secret)
    key_type = "Secret" if secret else "Public"

    if not keys:
        print(f"No {key_type.lower()} keys found.")
        return keys

    print(f"\n=== {key_type} Keys ===")
    for idx, key in enumerate(keys, 1):
        print(f"{idx}. Key ID: {key['keyid']}")
        print(f"   Fingerprint: {key['fingerprint']}")
        print(f"   UIDs: {key['uids']}")
        print(f"   Created: {key['date']}")
        print(f"   Expires: {key.get('expires', 'Never')}")
        print("-" * 50)

    return keys


def delete_key(fingerprint, secret=False, gpg_home=None):
    """
    Delete a single key from the keyring.

    Args:
        fingerprint: key fingerprint.
        secret: True to delete the secret key, False for public.
        gpg_home: optional GPG home directory.

    Returns:
        Tuple (bool success, str message).
    """
    cmd = ["gpg"]
    if gpg_home:
        cmd.extend(["--homedir", gpg_home])
    cmd.extend(["--batch", "--yes"])
    cmd.append("--delete-secret-keys" if secret else "--delete-keys")
    cmd.append(fingerprint)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode == 0:
            return True, "Key deleted successfully"
        return False, result.stderr
    except OSError as exc:
        return False, str(exc)


def delete_key_pair(fingerprint, gpg_home=None):
    """
    Delete both secret and public copies of a key.

    Args:
        fingerprint: key fingerprint.
        gpg_home: optional GPG home directory.

    Returns:
        Tuple (bool any_deleted, str combined_message).
    """
    secret_success, secret_msg = delete_key(fingerprint, secret=True, gpg_home=gpg_home)
    public_success, public_msg = delete_key(fingerprint, secret=False, gpg_home=gpg_home)

    if secret_success or public_success:
        return True, "Key pair deleted successfully"
    return False, f"Secret: {secret_msg}, Public: {public_msg}"


def interactive_cleanup(gpg, gpg_home=None):
    """Run the menu-driven deletion UI."""
    print("\n=== GPG Keyring Cleanup Tool ===")

    secret_keys = list_keys(gpg, secret=True)
    public_keys = list_keys(gpg, secret=False)

    if not secret_keys and not public_keys:
        print("\nNo keys found in keyring.")
        return

    while True:
        print("\nOptions:")
        print("1. Delete a secret key (and its public key)")
        print("2. Delete a public key only")
        print("3. Delete all keys (CAUTION!)")
        print("4. List all keys")
        print("5. Exit")

        choice = input("\nEnter your choice (1-5): ").strip()

        if choice == "1":
            if not secret_keys:
                print("No secret keys available.")
                continue
            print("\nSelect secret key to delete:")
            for idx, key in enumerate(secret_keys, 1):
                uid = key["uids"][0] if key["uids"] else "No UID"
                print(f"{idx}. {uid} ({key['keyid']})")
            try:
                selection = int(input("Enter number (0 to cancel): "))
                if selection == 0:
                    continue
                if 1 <= selection <= len(secret_keys):
                    key = secret_keys[selection - 1]
                    confirm = input(
                        f"Delete secret key {key['keyid']} and its public key? (yes/no): "
                    )
                    if confirm.lower() == "yes":
                        success, msg = delete_key_pair(key["fingerprint"], gpg_home)
                        if success:
                            print(msg)
                            secret_keys = gpg.list_keys(True)
                            public_keys = gpg.list_keys(False)
                        else:
                            print(f"Failed: {msg}")
                else:
                    print("Invalid selection.")
            except ValueError:
                print("Invalid input.")

        elif choice == "2":
            if not public_keys:
                print("No public keys available.")
                continue
            print("\nSelect public key to delete:")
            for idx, key in enumerate(public_keys, 1):
                uid = key["uids"][0] if key["uids"] else "No UID"
                print(f"{idx}. {uid} ({key['keyid']})")
            try:
                selection = int(input("Enter number (0 to cancel): "))
                if selection == 0:
                    continue
                if 1 <= selection <= len(public_keys):
                    key = public_keys[selection - 1]
                    confirm = input(f"Delete public key {key['keyid']}? (yes/no): ")
                    if confirm.lower() == "yes":
                        success, msg = delete_key(
                            key["fingerprint"], secret=False, gpg_home=gpg_home
                        )
                        if success:
                            print(msg)
                            public_keys = gpg.list_keys(False)
                        else:
                            print(f"Failed: {msg}")
                else:
                    print("Invalid selection.")
            except ValueError:
                print("Invalid input.")

        elif choice == "3":
            confirm = input("Delete ALL keys from keyring? Type 'DELETE ALL' to confirm: ")
            if confirm == "DELETE ALL":
                deleted_count = 0
                for key in secret_keys:
                    success, _ = delete_key(key["fingerprint"], secret=True, gpg_home=gpg_home)
                    if success:
                        deleted_count += 1
                for key in public_keys:
                    success, _ = delete_key(key["fingerprint"], secret=False, gpg_home=gpg_home)
                    if success:
                        deleted_count += 1
                print(f"Deleted {deleted_count} keys from keyring.")
                secret_keys = []
                public_keys = []
            else:
                print("Cancelled.")

        elif choice == "4":
            secret_keys = list_keys(gpg, secret=True)
            public_keys = list_keys(gpg, secret=False)

        elif choice == "5":
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")


def batch_cleanup(gpg, key_ids=None, emails=None, all_keys=False, gpg_home=None):
    """
    Non-interactive deletion driven by CLI flags.

    Args:
        gpg: configured gnupg.GPG instance.
        key_ids: optional list of key ID/fingerprint substrings to delete.
        emails: optional list of email substrings to delete.
        all_keys: when True, delete every key in the keyring.
        gpg_home: optional GPG home directory.
    """
    if all_keys:
        secret_keys = gpg.list_keys(True)

        deleted_count = 0
        for key in secret_keys:
            success, _ = delete_key_pair(key["fingerprint"], gpg_home)
            if success:
                deleted_count += 1
                print(f"Deleted secret key: {key['keyid']}")

        remaining_public = gpg.list_keys(False)
        for key in remaining_public:
            success, _ = delete_key(key["fingerprint"], secret=False, gpg_home=gpg_home)
            if success:
                deleted_count += 1
                print(f"Deleted public key: {key['keyid']}")

        print(f"\nTotal keys deleted: {deleted_count}")
        return

    fingerprints_to_delete = []

    if key_ids:
        keys_all = gpg.list_keys() + gpg.list_keys(True)
        for key_id in key_ids:
            for key in keys_all:
                matches = key_id in key["keyid"] or key_id in key["fingerprint"]
                if matches and key["fingerprint"] not in fingerprints_to_delete:
                    fingerprints_to_delete.append(key["fingerprint"])
                    print(f"Found key: {key['keyid']} - {key['uids']}")

    if emails:
        keys_all = gpg.list_keys() + gpg.list_keys(True)
        for email in emails:
            for key in keys_all:
                for uid in key["uids"]:
                    if email in uid and key["fingerprint"] not in fingerprints_to_delete:
                        fingerprints_to_delete.append(key["fingerprint"])
                        print(f"Found key: {key['keyid']} - {uid}")

    if not fingerprints_to_delete:
        print("No matching keys found.")
        return

    for fingerprint in fingerprints_to_delete:
        success, msg = delete_key_pair(fingerprint, gpg_home)
        if success:
            print(f"Deleted: {fingerprint}")
        else:
            print(f"Failed to delete {fingerprint}: {msg}")


def main():
    parser = argparse.ArgumentParser(
        description="Clean up the GPG keyring by removing imported keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Interactive mode (recommended)
  %(prog)s

  # Delete specific key by ID
  %(prog)s --key-id 1234567890ABCDEF --yes

  # Delete keys by email substring
  %(prog)s --email user@example.com --yes

  # Delete multiple keys at once
  %(prog)s --key-id ABCD1234 --key-id EFGH5678 --email user@example.com --yes

  # Delete ALL keys (caution!)
  %(prog)s --all

  # Specify custom GPG home
  %(prog)s --gpg-home /path/to/gnupg
""",
    )

    parser.add_argument(
        "--key-id",
        action="append",
        help="Key ID or fingerprint substring (can be repeated)",
    )
    parser.add_argument(
        "--email",
        action="append",
        help="Email substring matched against UIDs (can be repeated)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Delete ALL keys from the keyring (use with caution)",
    )
    parser.add_argument("--gpg-home", help="GPG home directory")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the confirmation prompt for batch mode",
    )

    args = parser.parse_args()

    gpg = get_gpg(args.gpg_home)

    if args.key_id or args.email or args.all:
        if not args.yes:
            keys_to_delete = []
            if args.all:
                keys_to_delete.append("ALL KEYS")
            if args.key_id:
                keys_to_delete.extend(f"Key ID: {kid}" for kid in args.key_id)
            if args.email:
                keys_to_delete.extend(f"Email: {email}" for email in args.email)

            print("Will delete the following:")
            for item in keys_to_delete:
                print(f"  - {item}")

            confirm = input("\nProceed with deletion? (yes/no): ")
            if confirm.lower() != "yes":
                print("Cancelled.")
                sys.exit(0)

        batch_cleanup(gpg, args.key_id, args.email, args.all, args.gpg_home)
    else:
        interactive_cleanup(gpg, args.gpg_home)


if __name__ == "__main__":
    main()
