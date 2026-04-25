#!/usr/bin/env python3
"""
manage_trust - Set GPG ownertrust levels and key signatures (batch + interactive).

Why this exists:
    python-gnupg cannot set ownertrust at all, and `gpg --edit-key trust`
    is interactive-only. After importing peer keys you almost always need
    to set ownertrust before encrypting (otherwise gpg complains about
    "unusable public key"). This script wraps `gpg --import-ownertrust`
    and `gpg --sign-key` so trust can be set in batch from CLI flags or
    via a friendly interactive menu.

Usage:
    python manage_trust.py                              # interactive menu
    python manage_trust.py --list                       # show keys + trust
    python manage_trust.py --set-trust KEY --level 5
    python manage_trust.py --trust-all --level 5
    python manage_trust.py --sign-key KEY
    python manage_trust.py --check-sigs KEY
    python manage_trust.py --quick-fix                  # trust everything ultimately

Examples:
    python manage_trust.py --set-trust alice@example.com --level 4
    python manage_trust.py --trust-all --level 5 --gpg-home ./tmp_keyring

Requires:
    - python-gnupg
    - gpg binary on PATH
"""

import argparse
import subprocess
import sys

from .pgp_common import (
    TRUST_FLAG_LABELS,
    TRUST_LEVELS,
    get_gpg,
    import_ownertrust,
    trust_level_help,
)


def list_keys_with_trust(gpg):
    """
    Print every public key in the keyring with its current trust flag.

    Args:
        gpg: configured gnupg.GPG instance.

    Returns:
        List of key dicts (in keyring order). Empty list if no keys.
    """
    public_keys = gpg.list_keys()

    if not public_keys:
        print("No public keys found.")
        return []

    print("\n=== Public Keys and Trust Levels ===")
    print(
        "Trust legend: " + ", ".join(f"{flag}={label}" for flag, label in TRUST_FLAG_LABELS.items())
    )
    print("-" * 70)

    for idx, key in enumerate(public_keys, 1):
        trust = key.get("trust", "-")
        trust_desc = TRUST_FLAG_LABELS.get(trust, "Unknown")

        print(f"{idx}. [{trust}] {trust_desc}")
        print(f"   Key ID: {key['keyid']}")
        print(f"   Fingerprint: {key['fingerprint']}")
        print(f"   UIDs: {key['uids']}")
        print(f"   Created: {key['date']}")
        print(f"   Expires: {key.get('expires', 'Never')}")
        print("-" * 70)

    return public_keys


def sign_key(fingerprint, signing_key=None):
    """
    Sign a target key (certify it) so gpg accepts it as trusted.

    Args:
        fingerprint: full fingerprint of the key to sign.
        signing_key: optional key ID to sign as; otherwise gpg picks the default.

    Returns:
        True on success, False on failure.
    """
    cmd = ["gpg", "--batch", "--yes"]
    if signing_key:
        cmd.extend(["--local-user", signing_key])
    cmd.extend(["--sign-key", fingerprint])

    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"Signed key {fingerprint}")
        return True
    except subprocess.CalledProcessError as exc:
        print(f"Failed to sign key: {exc.stderr}")
        return False


def check_signatures(fingerprint):
    """
    Print the signatures that exist on the given key.

    Args:
        fingerprint: full fingerprint or key ID.

    Returns:
        True on success, False on failure.
    """
    try:
        result = subprocess.run(
            ["gpg", "--check-sigs", fingerprint],
            capture_output=True,
            text=True,
            check=True,
        )
        print(f"\nSignatures for {fingerprint}:")
        print(result.stdout)
        return True
    except subprocess.CalledProcessError as exc:
        print(f"Failed to check signatures: {exc.stderr}")
        return False


def trust_all_keys(gpg, trust_level="5", gpg_home=None):
    """
    Set the same ownertrust level on every public key in the keyring.

    Args:
        gpg: configured gnupg.GPG instance.
        trust_level: numeric level "1".."5".
        gpg_home: optional GPG home directory passed through to gpg.
    """
    public_keys = gpg.list_keys()

    if not public_keys:
        print("No keys to trust.")
        return

    print(f"\nSetting trust level '{trust_level}' for {len(public_keys)} keys...")

    success_count = 0
    for key in public_keys:
        if import_ownertrust(key["fingerprint"], trust_level, gpg_home):
            success_count += 1

    print(f"\nTrust set successfully for {success_count}/{len(public_keys)} keys")


def _resolve_fingerprint(gpg, identifier):
    """Match identifier (fingerprint, key ID, or UID substring) to a key fingerprint."""
    for key in gpg.list_keys():
        if identifier in key["fingerprint"] or identifier in key["keyid"]:
            return key["fingerprint"]
        for uid in key["uids"]:
            if identifier in uid:
                return key["fingerprint"]
    return None


def interactive_mode(gpg, gpg_home=None):
    """Run the menu-driven trust management UI."""
    while True:
        print("\n=== GPG Trust Management ===")
        print("1. List all keys with trust levels")
        print("2. Set trust for a specific key")
        print("3. Trust all keys")
        print("4. Sign a key")
        print("5. Check signatures on a key")
        print("6. Quick fix: trust all keys ultimately")
        print("7. Exit")

        choice = input("\nEnter your choice (1-7): ").strip()

        if choice == "1":
            list_keys_with_trust(gpg)

        elif choice == "2":
            keys = list_keys_with_trust(gpg)
            if not keys:
                continue

            try:
                idx = int(input("\nSelect key number: ")) - 1
                if 0 <= idx < len(keys):
                    print()
                    print(trust_level_help())
                    trust = input("Enter trust level (1-5): ").strip()
                    if trust in TRUST_LEVELS:
                        import_ownertrust(keys[idx]["fingerprint"], trust, gpg_home)
                    else:
                        print("Invalid trust level.")
                else:
                    print("Invalid selection.")
            except (ValueError, IndexError):
                print("Invalid input.")

        elif choice == "3":
            print()
            print(trust_level_help())
            trust = input("Enter trust level for all keys (1-5): ").strip()
            if trust in TRUST_LEVELS:
                trust_all_keys(gpg, trust, gpg_home)
            else:
                print("Invalid trust level.")

        elif choice == "4":
            keys = list_keys_with_trust(gpg)
            if not keys:
                continue
            try:
                idx = int(input("\nSelect key number to sign: ")) - 1
                if 0 <= idx < len(keys):
                    sign_key(keys[idx]["fingerprint"])
                else:
                    print("Invalid selection.")
            except (ValueError, IndexError):
                print("Invalid input.")

        elif choice == "5":
            keys = list_keys_with_trust(gpg)
            if not keys:
                continue
            try:
                idx = int(input("\nSelect key number to check signatures: ")) - 1
                if 0 <= idx < len(keys):
                    check_signatures(keys[idx]["fingerprint"])
                else:
                    print("Invalid selection.")
            except (ValueError, IndexError):
                print("Invalid input.")

        elif choice == "6":
            confirm = input("\nThis will trust ALL keys ultimately. Continue? (yes/no): ")
            if confirm.lower() == "yes":
                trust_all_keys(gpg, "5", gpg_home)
                print("\nAll keys are now ultimately trusted.")
                print("You should now be able to encrypt files without warnings.")
            else:
                print("Cancelled.")

        elif choice == "7":
            print("Exiting...")
            break

        else:
            print("Invalid choice.")


def main():
    parser = argparse.ArgumentParser(
        description="Manage GPG key trust levels and signatures.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
Examples:
  # Interactive mode
  %(prog)s

  # Set trust for a specific key
  %(prog)s --set-trust FINGERPRINT --level 5
  %(prog)s --set-trust user@example.com --level 4

  # Trust all keys
  %(prog)s --trust-all --level 5

  # Sign a key
  %(prog)s --sign-key FINGERPRINT

  # Check signatures
  %(prog)s --check-sigs FINGERPRINT

  # Quick fix for encryption issues
  %(prog)s --quick-fix

{trust_level_help()}
""",
    )

    parser.add_argument(
        "--set-trust", metavar="KEY", help="Set trust for specific key (fingerprint or email)"
    )
    parser.add_argument("--level", choices=list(TRUST_LEVELS), help="Trust level to set")
    parser.add_argument("--trust-all", action="store_true", help="Set trust for all keys")
    parser.add_argument("--sign-key", metavar="KEY", help="Sign a key")
    parser.add_argument("--check-sigs", metavar="KEY", help="Check signatures on a key")
    parser.add_argument(
        "--quick-fix", action="store_true", help="Quick fix: trust all keys ultimately"
    )
    parser.add_argument("--gpg-home", help="GPG home directory")
    parser.add_argument("--list", action="store_true", help="List all keys with trust levels")

    args = parser.parse_args()

    gpg = get_gpg(args.gpg_home)

    if args.list:
        list_keys_with_trust(gpg)

    elif args.set_trust:
        if not args.level:
            print("Error: --level is required with --set-trust")
            sys.exit(1)
        fingerprint = _resolve_fingerprint(gpg, args.set_trust)
        if fingerprint:
            import_ownertrust(fingerprint, args.level, args.gpg_home)
        else:
            print(f"Key not found: {args.set_trust}")
            sys.exit(1)

    elif args.trust_all:
        trust_all_keys(gpg, args.level or "5", args.gpg_home)

    elif args.sign_key:
        fingerprint = _resolve_fingerprint(gpg, args.sign_key)
        if fingerprint:
            sign_key(fingerprint)
        else:
            print(f"Key not found: {args.sign_key}")
            sys.exit(1)

    elif args.check_sigs:
        check_signatures(args.check_sigs)

    elif args.quick_fix:
        print("Quick fix: setting ultimate trust for all keys...")
        trust_all_keys(gpg, "5", args.gpg_home)
        print("\nAll keys are now ultimately trusted.")
        print("You should now be able to encrypt files without warnings.")

    else:
        interactive_mode(gpg, args.gpg_home)


if __name__ == "__main__":
    main()
