#!/usr/bin/env python3
"""
import_pubring_from_gcp - Pull a public keyring from GCP Secret Manager + auto-trust.

Why this exists:
    Distributing peer public keys via email or shared drives is awkward
    and easy to get wrong. Storing them in GCP Secret Manager gives you
    a single source of truth with versioning and access control. This
    script fetches the named secret, imports it, and immediately sets
    ownertrust on every imported key so they are usable as encryption
    recipients without an extra manual step.

Usage:
    python import_pubring_from_gcp.py --project P --secret S [--version V]
                                      [--trust-level 1-5] [--gpg-home DIR]

Examples:
    python import_pubring_from_gcp.py --project my-project --secret my-pubring
    python import_pubring_from_gcp.py --project my-project --secret my-pubring --version 2 --trust-level 4

Requires:
    - python-gnupg
    - google-cloud-secret-manager (pip install -r requirements-gcp.txt)
    - gpg binary on PATH
    - Application Default Credentials configured
        (`gcloud auth application-default login`
         or GOOGLE_APPLICATION_CREDENTIALS pointing at a service-account key)
"""

import argparse
import os
import subprocess
import sys

from google.cloud import secretmanager

from .pgp_common import TRUST_LEVELS, get_gpg, import_ownertrust, trust_level_help


def fetch_secret_from_gcp(project_id, secret_id, version_id="latest"):
    """
    Fetch a secret payload from GCP Secret Manager.

    Args:
        project_id: GCP project ID.
        secret_id: secret name within the project.
        version_id: secret version. "latest" or a numeric version string.

    Returns:
        Secret payload as bytes, or None on error.
    """
    try:
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        response = client.access_secret_version(request={"name": name})
        secret_value = response.payload.data
        print(f"Fetched secret '{secret_id}' from project '{project_id}' (version {version_id}).")
        return secret_value
    except Exception as exc:
        print(f"Error fetching secret from GCP: {exc}")
        return None


def import_pubring(pubring_data, gpg_home=None):
    """
    Pipe a public-keyring blob into `gpg --import`.

    Args:
        pubring_data: raw bytes of the public keyring.
        gpg_home: optional GPG home directory.

    Returns:
        True on success, False otherwise.
    """
    cmd = ["gpg"]
    if gpg_home:
        cmd.extend(["--homedir", gpg_home])
    cmd.extend(["--batch", "--import"])

    try:
        result = subprocess.run(cmd, input=pubring_data, capture_output=True, check=True)
        print("\nPubring imported successfully.")
        print("Import details:", result.stderr.decode())
        return True
    except subprocess.CalledProcessError as exc:
        print(f"Failed to import pubring: {exc}")
        print(f"Error output: {exc.stderr.decode()}")
        return False


def list_imported_keys(gpg_home=None):
    """
    Print every public and secret key in the keyring.

    Args:
        gpg_home: optional GPG home directory.

    Returns:
        Tuple (public_keys, secret_keys).
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
        description="Fetch a public keyring from GCP Secret Manager, import it, and auto-trust the keys.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
Examples:
  %(prog)s --project my-project --secret my-pubring
  %(prog)s --project my-project --secret my-pubring --version 2 --trust-level 4
  %(prog)s --project my-project --secret my-pubring --gpg-home ./tmp_keyring

Authentication:
  Set GOOGLE_APPLICATION_CREDENTIALS to a service account key file, OR
  run: gcloud auth application-default login

{trust_level_help()}
""",
    )
    parser.add_argument("--project", required=True, help="GCP project ID")
    parser.add_argument("--secret", required=True, help="Secret name in Secret Manager")
    parser.add_argument("--version", default="latest", help="Secret version (default: latest)")
    parser.add_argument(
        "--trust-level",
        choices=list(TRUST_LEVELS),
        default="5",
        help="Ownertrust level applied to imported keys (default: 5)",
    )
    parser.add_argument("--gpg-home", help="GPG home directory (default: ~/.gnupg)")

    args = parser.parse_args()

    if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        print("Warning: GOOGLE_APPLICATION_CREDENTIALS not set.")
        print("Make sure you ran 'gcloud auth application-default login'")
        print("or that GOOGLE_APPLICATION_CREDENTIALS points at a service-account key.\n")

    print("Fetching public keyring from GCP Secret Manager...")
    print(f"Project: {args.project}")
    print(f"Secret: {args.secret}")
    print(f"Version: {args.version}")
    print(f"Trust Level: {args.trust_level}")

    pubring_data = fetch_secret_from_gcp(args.project, args.secret, args.version)
    if not pubring_data:
        print("Failed to fetch pubring from GCP")
        sys.exit(1)

    print(f"Fetched pubring data ({len(pubring_data)} bytes)")

    if not import_pubring(pubring_data, args.gpg_home):
        sys.exit(1)

    public_keys, secret_keys = list_imported_keys(args.gpg_home)

    print("\n=== Summary ===")
    print(f"Total public keys: {len(public_keys)}")
    print(f"Total secret keys: {len(secret_keys)}")

    if not public_keys:
        print(
            "\nNo public keys were imported. Check if the secret contains a valid GPG public keyring."
        )
        return

    print("\n=== Setting Trust Levels ===")
    print(f"Setting trust level '{args.trust_level}' for imported keys...")
    for key in public_keys:
        import_ownertrust(key["fingerprint"], args.trust_level, args.gpg_home)

    print("\n=== Available Recipients for Encryption ===")
    print("You can now encrypt files for these recipients:")
    for key in public_keys:
        print(f"\nKey ID: {key['keyid']}")
        for uid in key["uids"]:
            print(f"  - {uid}")


if __name__ == "__main__":
    main()
