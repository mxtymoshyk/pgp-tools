#!/usr/bin/env python3
"""
import_secring_from_gcp - Pull a secret keyring from GCP Secret Manager and import it.

Why this exists:
    Storing a secret keyring on disk or committing it to git is risky.
    GCP Secret Manager gives you encrypted, access-audited storage with
    versioning. This script fetches a named secret, pipes the bytes into
    `gpg --import` without ever writing the secring to disk, and shows
    what landed in the keyring afterward.

Usage:
    python import_secring_from_gcp.py --project PROJECT --secret SECRET [--version V] [--gpg-home DIR]

Examples:
    python import_secring_from_gcp.py --project my-project --secret my-secring
    python import_secring_from_gcp.py --project my-project --secret my-secring --version 3

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

from .pgp_common import get_gpg


def fetch_secret_from_gcp(project_id, secret_id, version_id="latest"):
    """
    Fetch a secret payload from GCP Secret Manager.

    Args:
        project_id: GCP project ID (e.g. "my-project").
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


def import_secring(secring_data, gpg_home=None):
    """
    Pipe a secret-keyring blob into `gpg --import`.

    Args:
        secring_data: raw bytes of the secret keyring.
        gpg_home: optional GPG home directory.

    Returns:
        True on success, False otherwise.
    """
    cmd = ["gpg"]
    if gpg_home:
        cmd.extend(["--homedir", gpg_home])
    cmd.extend(["--batch", "--import"])

    try:
        result = subprocess.run(cmd, input=secring_data, capture_output=True, check=True)
        print("\nSecring imported successfully.")
        print("Import details:", result.stderr.decode())
        return True
    except subprocess.CalledProcessError as exc:
        print(f"Failed to import secring: {exc}")
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
        description="Fetch a secret keyring from GCP Secret Manager and import it to GPG.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s --project my-project --secret my-secring
  %(prog)s --project my-project --secret my-secring --version 3
  %(prog)s --project my-project --secret my-secring --gpg-home ./tmp_keyring

Authentication:
  Set GOOGLE_APPLICATION_CREDENTIALS to a service account key file, OR
  run: gcloud auth application-default login
""",
    )
    parser.add_argument("--project", required=True, help="GCP project ID")
    parser.add_argument("--secret", required=True, help="Secret name in Secret Manager")
    parser.add_argument("--version", default="latest", help="Secret version (default: latest)")
    parser.add_argument("--gpg-home", help="GPG home directory (default: ~/.gnupg)")

    args = parser.parse_args()

    if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        print("Warning: GOOGLE_APPLICATION_CREDENTIALS not set.")
        print("Make sure you ran 'gcloud auth application-default login'")
        print("or that GOOGLE_APPLICATION_CREDENTIALS points at a service-account key.\n")

    print("Fetching secring from GCP Secret Manager...")
    print(f"Project: {args.project}")
    print(f"Secret: {args.secret}")
    print(f"Version: {args.version}")

    secring_data = fetch_secret_from_gcp(args.project, args.secret, args.version)
    if not secring_data:
        print("Failed to fetch secring from GCP")
        sys.exit(1)

    print(f"Fetched secring data ({len(secring_data)} bytes)")

    if not import_secring(secring_data, args.gpg_home):
        sys.exit(1)

    public_keys, secret_keys = list_imported_keys(args.gpg_home)

    print("\n=== Summary ===")
    print(f"Total public keys: {len(public_keys)}")
    print(f"Total secret keys: {len(secret_keys)}")

    if secret_keys:
        print("\n=== Available Recipients for Encryption ===")
        print("You can now use these email addresses/key IDs for encryption:")
        for key in secret_keys:
            print(f"\nKey ID: {key['keyid']}")
            for uid in key["uids"]:
                print(f"  - {uid}")
    else:
        print("\nNo secret keys were imported. Check if the secret contains a valid GPG keyring.")


if __name__ == "__main__":
    main()
