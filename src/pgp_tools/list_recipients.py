#!/usr/bin/env python3
"""
list_recipients - Show who you can encrypt to right now (with diagnostics).

Why this exists:
    `gpg --list-keys` shows raw key data but does not synthesize the
    actual question you usually have: "can I encrypt to this recipient
    or not?" That answer needs trust level + encryption capability +
    expiry checked together. This script does that synthesis, and also
    offers a search-by-substring mode and a one-shot encryption test
    against a chosen recipient.

Usage:
    python list_recipients.py [-v] [--gpg-home DIR]
    python list_recipients.py --search SUBSTR
    python list_recipients.py --test RECIPIENT [--test-file FILE]
    python list_recipients.py --diagnose

Examples:
    python list_recipients.py
    python list_recipients.py --search alice
    python list_recipients.py --test alice@example.com

Requires:
    - python-gnupg
    - gpg binary on PATH
"""

import argparse
import subprocess

from .pgp_common import TRUST_FLAG_LABELS, get_gpg


def get_key_details(key):
    """
    Extract a normalized dict of useful fields from a python-gnupg key.

    Args:
        key: key dict as returned by gnupg.GPG.list_keys().

    Returns:
        Dict with keyid, fingerprint, uids, trust, expires, created,
        length, algo, capabilities (list), and subkeys (list).
    """
    details = {
        "keyid": key["keyid"],
        "fingerprint": key["fingerprint"],
        "uids": key["uids"],
        "trust": key.get("trust", "-"),
        "expires": key.get("expires", "Never"),
        "created": key.get("date", "Unknown"),
        "length": key.get("length", "Unknown"),
        "algo": key.get("algo", "Unknown"),
        "capabilities": [],
        "subkeys": key.get("subkeys", []),
    }

    caps = key.get("cap", "")
    if "e" in caps or "E" in caps:
        details["capabilities"].append("Encrypt")
    if "s" in caps or "S" in caps:
        details["capabilities"].append("Sign")
    if "c" in caps or "C" in caps:
        details["capabilities"].append("Certify")
    if "a" in caps or "A" in caps:
        details["capabilities"].append("Authenticate")

    return details


def list_recipients(gpg, verbose=False):
    """
    Print every public key with usability assessment.

    Args:
        gpg: configured gnupg.GPG instance.
        verbose: include creation, expiry, algorithm details.

    Returns:
        List of detail dicts that pass the validity check.
    """
    public_keys = gpg.list_keys()

    if not public_keys:
        print("No public keys found. You need to import public keys before encrypting.")
        print("\nTo import keys, use:")
        print("  python import_pubring.py <keyfile>")
        print("  python import_pubring_from_gcp.py --project PROJECT --secret SECRET")
        return []

    print("\n=== Available Recipients for Encryption ===")
    print("=" * 70)

    valid_recipients = []
    invalid_recipients = []

    for key in public_keys:
        details = get_key_details(key)

        can_encrypt = "Encrypt" in details["capabilities"]
        for subkey in details["subkeys"]:
            if "e" in subkey[1] or "E" in subkey[1]:
                can_encrypt = True
                break

        trust_display = TRUST_FLAG_LABELS.get(details["trust"], "Unknown")

        is_expired = details["trust"] == "e"
        is_revoked = details["trust"] == "r"
        is_untrusted = details["trust"] in ("-", "n", "q")

        if can_encrypt and not is_expired and not is_revoked:
            valid_recipients.append(details)
            status = "VALID but UNTRUSTED" if is_untrusted else "VALID"
        else:
            invalid_recipients.append(details)
            if is_expired:
                status = "EXPIRED"
            elif is_revoked:
                status = "REVOKED"
            elif not can_encrypt:
                status = "NO ENCRYPTION CAPABILITY"
            else:
                status = "INVALID"

        print(f"\n[{status}] Key ID: {details['keyid']}")
        print(f"  Fingerprint: {details['fingerprint']}")
        print(f"  Trust Level: {trust_display}")
        print("  Recipients (use any of these):")

        for uid in details["uids"]:
            print(f"    - {uid}")
        print(f"    - {details['keyid']}")
        print(f"    - {details['fingerprint']}")

        if verbose:
            print(f"  Created: {details['created']}")
            print(f"  Expires: {details['expires']}")
            print(f"  Algorithm: {details['algo']} {details['length']}")
            caps = ", ".join(details["capabilities"]) if details["capabilities"] else "None"
            print(f"  Capabilities: {caps}")

    print("\n" + "=" * 70)
    print(f"Summary: {len(valid_recipients)} valid recipients, {len(invalid_recipients)} invalid")

    if valid_recipients:
        print("\nYou can encrypt files using these recipients:")
        for key in valid_recipients:
            for uid in key["uids"]:
                print(
                    f'  python pgp_3des_cfb.py --encrypt <file> --recipient "{uid}" --output <output>'
                )
                break

    untrusted = [k for k in valid_recipients if k["trust"] in ("-", "q")]
    if untrusted:
        print("\nWarning: some keys are not trusted. To fix this:")
        print("  python manage_trust.py --quick-fix")
        print("  OR")
        print("  python manage_trust.py --trust-all --level 5")

    return valid_recipients


def test_encryption(gpg, recipient, test_file=None, gpg_home=None):
    """
    Try a one-shot encryption to `recipient` and report success or failure.

    Args:
        gpg: configured gnupg.GPG instance (used for fallback options).
        recipient: recipient identifier (UID, key ID, or fingerprint).
        test_file: optional path; if omitted a fixed test message is used.
        gpg_home: optional GPG home directory.

    Returns:
        True on success, False on failure.
    """
    print(f"\n=== Testing Encryption for Recipient: {recipient} ===")

    if test_file:
        try:
            with open(test_file, "rb") as f:
                test_data = f.read()
            print(f"Using test file: {test_file}")
        except OSError as exc:
            print(f"Error reading test file: {exc}")
            return False
    else:
        test_data = b"This is a test message for encryption."
        print("Using test message: 'This is a test message for encryption.'")

    print(f"\nAttempting encryption to: {recipient}")
    print("Trying with --always-trust flag...")

    cmd = ["gpg"]
    if gpg_home:
        cmd.extend(["--homedir", gpg_home])
    cmd.extend(
        [
            "--armor",
            "--cipher-algo",
            "3DES",
            "--allow-old-cipher-algos",
            "--always-trust",
            "--encrypt",
            "--recipient",
            recipient,
        ]
    )

    result = subprocess.run(cmd, input=test_data, capture_output=True, check=False)

    if result.returncode == 0:
        print("Encryption successful with --always-trust.")
        print(f"Encrypted data length: {len(result.stdout)} bytes")
        print("\nUse this command for encryption:")
        print(
            f"  gpg --armor --cipher-algo 3DES --allow-old-cipher-algos --always-trust "
            f'--encrypt --recipient "{recipient}" --output output.pgp input.txt'
        )
        return True

    print("Encryption failed even with --always-trust.")
    print(f"Error: {result.stderr.decode()}")

    if b"INV_RECP" in result.stderr:
        print("\nProblem: Invalid recipient.")
        print("Solutions:")
        print("  1. Check if the email/ID exactly matches what's in the key")
        print("  2. Use 'python list_recipients.py' to see exact recipient strings")
        print("  3. Try using the key ID or fingerprint instead of email")

    if b"Unusable public key" in result.stderr:
        print("\nProblem: Public key is unusable (likely trust issue).")
        print("Solutions:")
        print("  1. Run: python manage_trust.py --quick-fix")
        print(f"  2. Or trust manually: python manage_trust.py --set-trust {recipient} --level 5")

    return False


def find_recipient_key(gpg, search_term):
    """
    Return all keys that match `search_term` in UID, key ID, or fingerprint.

    Args:
        gpg: configured gnupg.GPG instance.
        search_term: substring to match (case-insensitive).

    Returns:
        List of (key_dict, match_string) tuples.
    """
    public_keys = gpg.list_keys()
    matches = []
    search_lower = search_term.lower()

    for key in public_keys:
        for uid in key["uids"]:
            if search_lower in uid.lower():
                matches.append((key, uid))
                break
        if search_lower in key["keyid"].lower():
            matches.append((key, f"Key ID: {key['keyid']}"))
        if search_lower in key["fingerprint"].lower():
            matches.append((key, f"Fingerprint: {key['fingerprint']}"))

    return matches


def diagnose_issues(gpg):
    """Run a checklist of common encryption-blocking issues."""
    print("\n=== Diagnostics ===")
    print("=" * 70)

    public_keys = gpg.list_keys()
    secret_keys = gpg.list_keys(True)

    print(f"Public keys found: {len(public_keys)}")
    print(f"Secret keys found: {len(secret_keys)}")

    if not public_keys:
        print("\nIssue: No public keys found.")
        print("Solution: Import public keys using:")
        print("  python import_pubring.py <keyfile>")
        print("  python import_pubring_from_gcp.py --project PROJECT --secret SECRET")
        return

    untrusted = [k for k in public_keys if k.get("trust", "-") in ("-", "n", "q")]
    if untrusted:
        print(f"\nIssue: {len(untrusted)} untrusted keys found.")
        print("Solution: set trust levels using:")
        print("  python manage_trust.py --quick-fix  # trust all keys")
        for key in untrusted[:3]:
            uid = key["uids"][0] if key["uids"] else key["keyid"]
            print(f'  python manage_trust.py --set-trust "{uid}" --level 5')

    expired = [k for k in public_keys if k.get("trust") == "e"]
    if expired:
        print(f"\nIssue: {len(expired)} expired keys found.")
        print("Solution: remove expired keys and import updated ones:")
        for key in expired:
            print(f"  python cleanup_secring.py --key-id {key['keyid']} --yes")

    try:
        result = subprocess.run(["gpg", "--version"], capture_output=True, text=True, check=False)
        first_line = result.stdout.split("\n", 1)[0] if result.stdout else ""
        if first_line:
            print(f"\nGPG Version: {first_line}")
    except OSError:
        pass

    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="List available recipients and diagnose encryption issues.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # List all available recipients
  %(prog)s

  # List with verbose details
  %(prog)s -v

  # Search for a specific recipient
  %(prog)s --search alice

  # Test encryption with a recipient
  %(prog)s --test alice@example.com

  # Diagnose encryption issues
  %(prog)s --diagnose

  # Use custom GPG home
  %(prog)s --gpg-home /path/to/gnupg
""",
    )

    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose key details")
    parser.add_argument("--search", metavar="TERM", help="Search for recipients matching term")
    parser.add_argument("--test", metavar="RECIPIENT", help="Test encryption with a recipient")
    parser.add_argument("--test-file", help="File to use for encryption test")
    parser.add_argument("--diagnose", action="store_true", help="Diagnose common issues")
    parser.add_argument("--gpg-home", help="GPG home directory")

    args = parser.parse_args()

    gpg = get_gpg(args.gpg_home)

    if args.search:
        matches = find_recipient_key(gpg, args.search)
        if matches:
            print(f"\n=== Recipients matching '{args.search}' ===")
            for key, match_str in matches:
                print(f"\nFound: {match_str}")
                print(f"  Key ID: {key['keyid']}")
                print("  All UIDs:")
                for uid in key["uids"]:
                    print(f"    - {uid}")
                print("  Use any of these as recipient:")
                for uid in key["uids"]:
                    print(f'    --recipient "{uid}"')
                print(f"    --recipient {key['keyid']}")
                print(f"    --recipient {key['fingerprint']}")
        else:
            print(f"\nNo recipients found matching '{args.search}'.")
            print("\nAvailable recipients:")
            list_recipients(gpg)

    elif args.test:
        test_encryption(gpg, args.test, args.test_file, args.gpg_home)

    elif args.diagnose:
        diagnose_issues(gpg)

    else:
        list_recipients(gpg, verbose=args.verbose)


if __name__ == "__main__":
    main()
