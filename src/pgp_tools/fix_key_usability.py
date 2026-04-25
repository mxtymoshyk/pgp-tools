#!/usr/bin/env python3
"""
fix_key_usability - Diagnose and repair "unusable public key" errors.

Why this exists:
    "gpg: <key>: skipped: Unusable public key" can stem from at least
    four different root causes:
        1. no entry for the key in the trust DB,
        2. ownertrust was never set,
        3. the key has no signatures gpg accepts as a chain of trust,
        4. the key (or one of its subkeys) has expired.
    Each cause has a different fix. This script tries them in sequence
    (set ownertrust -> direct trust edit -> local-sign with own key ->
    refresh -> fall back to --always-trust) and reports which steps
    produced a usable key.

Usage:
    python fix_key_usability.py                            # show key status
    python fix_key_usability.py --fix-all [--trust-level N]
    python fix_key_usability.py --fix-key KEY [--trust-level N]
    python fix_key_usability.py --show-workarounds
    python fix_key_usability.py --test-encryption RECIPIENT

Examples:
    python fix_key_usability.py --fix-key alice@example.com --trust-level 5
    python fix_key_usability.py --fix-all

Requires:
    - python-gnupg
    - gpg binary on PATH
"""

import argparse
import subprocess

from .pgp_common import (
    TRUST_FLAG_LABELS,
    TRUST_LEVELS,
    get_gpg,
)
from .pgp_common import (
    import_ownertrust as set_ownertrust,
)


def run_gpg_command(cmd, input_data=None):
    """
    Run a GPG command and return (success, stdout, stderr).

    Args:
        cmd: list of args including the leading 'gpg'.
        input_data: optional stdin payload (bytes or str).

    Returns:
        Tuple (bool success, str stdout, str stderr).
    """
    try:
        text_mode = input_data is None or isinstance(input_data, str)
        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=text_mode,
            check=False,
        )
        return result.returncode == 0, result.stdout, result.stderr
    except OSError as exc:
        return False, "", str(exc)


def check_key_usability(fingerprint):
    """
    Test whether the given key can be used as an encryption recipient.

    Args:
        fingerprint: full fingerprint or key ID.

    Returns:
        Tuple (bool usable, str stderr).
    """
    test_message = b"test"
    success, _stdout, stderr = run_gpg_command(
        [
            "gpg",
            "--armor",
            "--trust-model",
            "always",
            "--encrypt",
            "--recipient",
            fingerprint,
        ],
        test_message,
    )
    return success, stderr


def get_own_keys(gpg):
    """Return secret keys eligible for use as a signing identity."""
    secret_keys = gpg.list_keys(True)
    return [key for key in secret_keys if key.get("trust") in ("u", "f", "-")]


def sign_key_locally(fingerprint, signing_key_id=None):
    """
    Locally-sign (lsign) a key so the local trust DB accepts it.

    Args:
        fingerprint: key to sign.
        signing_key_id: optional signing key.

    Returns:
        True on success, False on failure.
    """
    print(f"Signing key {fingerprint} locally...")

    cmd = ["gpg", "--batch", "--yes", "--lsign-key"]
    if signing_key_id:
        cmd.extend(["--local-user", signing_key_id])
    cmd.append(fingerprint)

    success, _stdout, stderr = run_gpg_command(cmd)

    if success:
        print(f"  signed key {fingerprint}")
        return True
    print(f"  failed to sign key {fingerprint}: {stderr}")
    return False


def set_key_trust_directly(fingerprint, trust_level="5"):
    """
    Set trust via interactive `gpg --edit-key trust` driven by --command-fd.

    Args:
        fingerprint: target key fingerprint.
        trust_level: numeric level "1".."5".

    Returns:
        True on success, False on failure.
    """
    print(f"Setting trust level {trust_level} for {fingerprint} via --edit-key...")

    commands = f"trust\n{trust_level}\ny\nquit\n"
    cmd = ["gpg", "--batch", "--command-fd", "0", "--edit-key", fingerprint]

    success, _stdout, stderr = run_gpg_command(cmd, commands)

    if success or "Good signature" in stderr:
        print(f"  trust level set for {fingerprint}")
        return True
    print(f"  failed to set trust: {stderr}")
    return False


def fix_key_comprehensive(gpg, fingerprint, trust_level="5", gpg_home=None):
    """
    Apply every available remedy to make `fingerprint` usable for encryption.

    Order of attempts:
        1. test current usability (if good, stop)
        2. set ownertrust via --import-ownertrust
        3. set trust via --edit-key trust
        4. lsign with our own key
        5. refresh from keyserver
        6. test with --always-trust as last-resort workaround

    Args:
        gpg: configured gnupg.GPG instance.
        fingerprint: target fingerprint.
        trust_level: numeric level "1".."5".
        gpg_home: optional GPG home directory.

    Returns:
        True if the key ended up usable, False otherwise.
    """
    print(f"\n=== Fixing Key: {fingerprint} ===")

    target_key = next(
        (k for k in gpg.list_keys() if fingerprint in k["fingerprint"]),
        None,
    )

    if not target_key:
        print(f"Key {fingerprint} not found!")
        return False

    print(f"Key UIDs: {target_key['uids']}")
    print(f"Current trust: {target_key.get('trust', 'unknown')}")

    print("\n1. Checking current usability...")
    usable, error = check_key_usability(fingerprint)
    if usable:
        print("  key is already usable")
        return True
    print(f"  not usable: {error}")

    print("\n2. Setting ownertrust...")
    set_ownertrust(fingerprint, trust_level, gpg_home)

    print("\n3. Setting trust via --edit-key...")
    set_key_trust_directly(fingerprint, trust_level)

    print("\n4. Looking for a signing key...")
    own_keys = get_own_keys(gpg)
    if own_keys:
        signing_key = own_keys[0]
        signing_uid = signing_key["uids"][0] if signing_key["uids"] else "No UID"
        print(f"  using signing key: {signing_key['keyid']} ({signing_uid})")
        print("\n5. Signing key locally...")
        sign_key_locally(fingerprint, signing_key["keyid"])
    else:
        print("  no signing keys available, skipping signing step")

    print("\n6. Testing usability...")
    usable, error = check_key_usability(fingerprint)

    if usable:
        print("  key is now usable")
        return True

    print(f"  still not usable: {error}")

    print("\n7. Trying alternative fixes...")
    print("  refreshing key from keyserver...")
    run_gpg_command(["gpg", "--refresh-keys", fingerprint])

    print("\n  testing with --always-trust...")
    success, _stdout, stderr = run_gpg_command(
        [
            "gpg",
            "--armor",
            "--always-trust",
            "--encrypt",
            "--recipient",
            fingerprint,
        ],
        b"test",
    )

    if success:
        print("  key works with --always-trust")
        print("  use --always-trust in your encryption commands as workaround")
        return True

    print(f"  still failed with --always-trust: {stderr}")
    return False


def fix_all_keys(gpg, trust_level="5", gpg_home=None):
    """Run fix_key_comprehensive for every public key in the keyring."""
    public_keys = gpg.list_keys()

    if not public_keys:
        print("No public keys found.")
        return

    print(f"Found {len(public_keys)} public keys to fix...")

    fixed_count = 0
    for key in public_keys:
        if fix_key_comprehensive(gpg, key["fingerprint"], trust_level, gpg_home):
            fixed_count += 1

    print("\n=== Summary ===")
    print(f"Fixed {fixed_count}/{len(public_keys)} keys")

    if fixed_count < len(public_keys):
        print("\nFor remaining problematic keys, you can:")
        print("  1. Use --always-trust at encryption time (pgp_3des_cfb.py already does this)")
        print("  2. Re-import the keys from a trusted source")
        print("  3. Generate new keys if these are test keys")


def show_encryption_workarounds(gpg):
    """Print known workarounds for encryption problems."""
    print("\n=== Encryption Workarounds ===")
    print("\nIf keys are still showing as 'untrusted', you can:")
    print("\n1. Use pgp_3des_cfb.py (already passes --always-trust by default).")
    print("\n2. Use the gpg CLI directly with --always-trust:")
    keys = gpg.list_keys()
    if keys:
        key = keys[0]
        uid = key["uids"][0] if key["uids"] else key["keyid"]
        print(
            "   gpg --armor --cipher-algo 3DES --always-trust --encrypt "
            f'--recipient "{uid}" --output output.pgp input.txt'
        )
    print("\n3. Run manage_trust.py --quick-fix to ultimately-trust every key in the keyring.")


def main():
    parser = argparse.ArgumentParser(
        description="Fix GPG key usability issues comprehensively.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Fix all keys
  %(prog)s --fix-all

  # Fix specific key
  %(prog)s --fix-key user@example.com
  %(prog)s --fix-key ABCD1234567890

  # Show workarounds
  %(prog)s --show-workarounds

  # Test encryption after fixes
  %(prog)s --test-encryption user@example.com
""",
    )

    parser.add_argument("--fix-all", action="store_true", help="Fix all keys")
    parser.add_argument(
        "--fix-key", metavar="KEY", help="Fix specific key (email, key ID, or fingerprint)"
    )
    parser.add_argument(
        "--trust-level",
        choices=list(TRUST_LEVELS),
        default="5",
        help="Trust level to set (default: 5)",
    )
    parser.add_argument(
        "--show-workarounds", action="store_true", help="Show encryption workarounds"
    )
    parser.add_argument(
        "--test-encryption", metavar="RECIPIENT", help="Test encryption with recipient"
    )
    parser.add_argument("--gpg-home", help="GPG home directory")

    args = parser.parse_args()

    gpg = get_gpg(args.gpg_home)

    if args.fix_all:
        fix_all_keys(gpg, args.trust_level, args.gpg_home)

    elif args.fix_key:
        keys = gpg.list_keys()
        target_fingerprint = None

        for key in keys:
            if (
                args.fix_key in key["keyid"]
                or args.fix_key in key["fingerprint"]
                or any(args.fix_key in uid for uid in key["uids"])
            ):
                target_fingerprint = key["fingerprint"]
                break

        if target_fingerprint:
            fix_key_comprehensive(gpg, target_fingerprint, args.trust_level, args.gpg_home)
        else:
            print(f"Key not found: {args.fix_key}")
            print("\nAvailable keys:")
            for key in keys:
                print(f"  {key['keyid']} - {key['uids']}")

    elif args.show_workarounds:
        show_encryption_workarounds(gpg)

    elif args.test_encryption:
        print(f"Testing encryption with {args.test_encryption}...")
        success, error = check_key_usability(args.test_encryption)
        if success:
            print("Encryption test successful")
        else:
            print(f"Encryption test failed: {error}")

    else:
        print("Please specify an action. Use --help for options.")
        keys = gpg.list_keys()
        if keys:
            print(f"\nFound {len(keys)} public keys:")
            for key in keys:
                trust = key.get("trust", "-")
                trust_desc = TRUST_FLAG_LABELS.get(trust, trust)
                uid = key["uids"][0] if key["uids"] else "No UID"
                print(f"  [{trust}] {trust_desc} - {uid}")


if __name__ == "__main__":
    main()
