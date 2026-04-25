#!/usr/bin/env python3
"""
pgp_3des_cfb - All-in-one PGP CLI: keygen, encrypt, decrypt, import, export.

Why this exists:
    Some legacy systems (older HL7 integrations, archived clinical data
    feeds, certain B2B partners) still require the 3DES-CFB cipher for
    compatibility. Modern `gpg` rejects 3DES by default - it must be
    explicitly enabled via `--allow-old-cipher-algos`. This script wraps
    that workflow plus the day-to-day key operations behind a single CLI.

Usage:
    python pgp_3des_cfb.py --generate --name NAME --email EMAIL
    python pgp_3des_cfb.py --list-keys
    python pgp_3des_cfb.py --encrypt FILE --recipient EMAIL [--output OUT]
    python pgp_3des_cfb.py --decrypt FILE [--output OUT]
    python pgp_3des_cfb.py --import-key FILE
    python pgp_3des_cfb.py --export-key KEY [--secret] --output OUT

Examples:
    python pgp_3des_cfb.py --generate --name "Alice" --email "alice@example.com"
    python pgp_3des_cfb.py --encrypt examples/example.txt --recipient alice@example.com --output msg.pgp
    python pgp_3des_cfb.py --decrypt msg.pgp --output decoded.txt

Requires:
    - python-gnupg
    - gpg binary on PATH (GnuPG 2.x recommended)
"""

import argparse
import os
import sys

import gnupg

# extra options passed to every gpg invocation. --allow-old-cipher-algos
# is what makes 3DES usable on modern gpg; --always-trust skips the
# trust-DB warning at encryption time (use list_recipients.py first
# if you need a real trust review).
GPG_BASE_OPTIONS = [
    "--cipher-algo",
    "3DES",
    "--compress-algo",
    "ZIP",
    "--allow-old-cipher-algos",
    "--always-trust",
]


class PGP3DESHandler:
    """Handler for PGP encryption/decryption with 3DES-CFB cipher."""

    def __init__(self, gpg_home=None):
        """
        Initialize the GPG handler.

        Args:
            gpg_home: optional path to GPG home directory. Falls back to
                ~/.gnupg when None.
        """
        if gpg_home:
            self.gpg = gnupg.GPG(gnupghome=gpg_home)
        else:
            self.gpg = gnupg.GPG(gnupghome=os.path.expanduser("~/.gnupg"))
        self.gpg.encoding = "utf-8"

    def list_keys(self):
        """Print public and private keys in the current keyring."""
        public_keys = self.gpg.list_keys()
        private_keys = self.gpg.list_keys(True)

        print("\n=== Public Keys ===")
        for key in public_keys:
            print(f"ID: {key['keyid']}")
            print(f"UIDs: {key['uids']}")
            print(f"Fingerprint: {key['fingerprint']}")
            print("-" * 40)

        print("\n=== Private Keys ===")
        for key in private_keys:
            print(f"ID: {key['keyid']}")
            print(f"UIDs: {key['uids']}")
            print(f"Fingerprint: {key['fingerprint']}")
            print("-" * 40)

    def generate_key(self, name, email, passphrase=None):
        """
        Generate a new RSA-2048 PGP key pair valid for 2 years.

        Args:
            name: real name for the UID.
            email: email address for the UID.
            passphrase: optional passphrase to encrypt the secret key.

        Returns:
            The fingerprint string on success, None on failure.
        """
        key_params = self.gpg.gen_key_input(
            name_real=name,
            name_email=email,
            passphrase=passphrase,
            key_type="RSA",
            key_length=2048,
            key_usage="encrypt,sign",
            subkey_type="RSA",
            subkey_length=2048,
            subkey_usage="encrypt,sign",
            expire_date="2y",
        )

        print("Generating key pair... This may take a moment...")
        key = self.gpg.gen_key(key_params)

        if key:
            print(f"Successfully generated key: {key}")
            return str(key)
        print("Failed to generate key")
        return None

    def encrypt_file(self, input_file, output_file, recipient, sign_key=None, passphrase=None):
        """
        Encrypt a file with 3DES-CFB and write ASCII-armored output.

        Args:
            input_file: path to plaintext input.
            output_file: path to write encrypted output.
            recipient: recipient's key ID, fingerprint, or email.
            sign_key: optional key ID to sign with.
            passphrase: passphrase for the signing key (when sign_key is set).

        Returns:
            True on success, False on failure.
        """
        with open(input_file, "rb") as f:
            data = f.read()

        self.gpg.options = list(GPG_BASE_OPTIONS)

        encrypted = self.gpg.encrypt(
            data,
            recipient,
            sign=sign_key,
            passphrase=passphrase,
            armor=True,
            always_trust=True,
        )

        if encrypted.ok:
            with open(output_file, "wb") as f:
                f.write(str(encrypted).encode())
            print(f"Successfully encrypted: {input_file} -> {output_file}")
            return True

        print(f"Encryption failed: {encrypted.status}")
        if encrypted.stderr:
            print(f"Error details: {encrypted.stderr}")
        return False

    def decrypt_file(self, input_file, output_file, passphrase=None):
        """
        Decrypt a PGP-encrypted file.

        Args:
            input_file: path to encrypted input.
            output_file: path to write plaintext output.
            passphrase: passphrase for the secret key (if it is encrypted).

        Returns:
            True on success, False on failure.
        """
        with open(input_file, "rb") as f:
            encrypted_data = f.read()

        decrypted = self.gpg.decrypt(
            encrypted_data,
            passphrase=passphrase,
            always_trust=True,
        )

        if decrypted.ok:
            with open(output_file, "wb") as f:
                f.write(decrypted.data)
            print(f"Successfully decrypted: {input_file} -> {output_file}")

            if decrypted.signature_id:
                print(f"Signature ID: {decrypted.signature_id}")
                print(f"Signature timestamp: {decrypted.sig_timestamp}")
            return True

        print(f"Decryption failed: {decrypted.status}")
        if decrypted.stderr:
            print(f"Error details: {decrypted.stderr}")
        return False

    def import_key(self, key_file):
        """
        Import a PGP key from an ASCII-armored or binary file.

        Args:
            key_file: path to the key file.
        """
        with open(key_file) as f:
            key_data = f.read()

        result = self.gpg.import_keys(key_data)

        if result.count > 0:
            print(f"Successfully imported {result.count} key(s)")
            for fingerprint in result.fingerprints:
                print(f"Fingerprint: {fingerprint}")
        else:
            print("No keys imported")
            if result.stderr:
                print(f"Error: {result.stderr}")

    def export_key(self, key_id, output_file, secret=False):
        """
        Export a key in ASCII armor format.

        Args:
            key_id: key ID, fingerprint, or email of the key to export.
            output_file: path to write the exported key.
            secret: when True, export the secret key instead of public.
        """
        if secret:
            key_data = self.gpg.export_keys(key_id, True)
            key_type = "secret"
        else:
            key_data = self.gpg.export_keys(key_id)
            key_type = "public"

        if key_data:
            with open(output_file, "w") as f:
                f.write(key_data)
            print(f"Successfully exported {key_type} key to: {output_file}")
        else:
            print(f"Failed to export key: {key_id}")


def main():
    parser = argparse.ArgumentParser(
        description="PGP encryption/decryption with 3DES-CFB cipher.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Generate a new key pair
  %(prog)s --generate --name "John Doe" --email "john@example.com"

  # List all keys
  %(prog)s --list-keys

  # Encrypt a file
  %(prog)s --encrypt input.txt --output encrypted.pgp --recipient john@example.com

  # Decrypt a file
  %(prog)s --decrypt encrypted.pgp --output decrypted.txt

  # Import a key
  %(prog)s --import-key public_key.asc

  # Export a public key
  %(prog)s --export-key john@example.com --output john_public.asc

  # Export a secret key
  %(prog)s --export-key john@example.com --output john_secret.asc --secret
""",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--encrypt", metavar="FILE", help="Encrypt a file")
    group.add_argument("--decrypt", metavar="FILE", help="Decrypt a file")
    group.add_argument("--generate", action="store_true", help="Generate new key pair")
    group.add_argument("--list-keys", action="store_true", help="List all keys")
    group.add_argument("--import-key", metavar="FILE", help="Import key from file")
    group.add_argument("--export-key", metavar="KEY_ID", help="Export key to file")

    parser.add_argument("--output", "-o", help="Output file path")
    parser.add_argument("--gpg-home", help="GPG home directory")
    parser.add_argument("--passphrase", help="Passphrase for key operations")

    parser.add_argument("--recipient", "-r", help="Recipient for encryption")
    parser.add_argument("--sign", help="Sign with specified key ID")

    parser.add_argument("--name", help="Name for key generation")
    parser.add_argument("--email", help="Email for key generation")

    parser.add_argument("--secret", action="store_true", help="Export secret key")

    args = parser.parse_args()

    handler = PGP3DESHandler(args.gpg_home)

    if args.generate:
        if not args.name or not args.email:
            print("Error: --name and --email are required for key generation")
            sys.exit(1)
        handler.generate_key(args.name, args.email, args.passphrase)

    elif args.list_keys:
        handler.list_keys()

    elif args.encrypt:
        if not args.output:
            args.output = args.encrypt + ".pgp"
        if not args.recipient:
            print("Error: --recipient is required for encryption")
            sys.exit(1)

        success = handler.encrypt_file(
            args.encrypt,
            args.output,
            args.recipient,
            args.sign,
            args.passphrase,
        )
        sys.exit(0 if success else 1)

    elif args.decrypt:
        if not args.output:
            if args.decrypt.endswith(".pgp"):
                args.output = args.decrypt[:-4]
            else:
                args.output = args.decrypt + ".decrypted"

        success = handler.decrypt_file(args.decrypt, args.output, args.passphrase)
        sys.exit(0 if success else 1)

    elif args.import_key:
        handler.import_key(args.import_key)

    elif args.export_key:
        if not args.output:
            print("Error: --output is required for key export")
            sys.exit(1)
        handler.export_key(args.export_key, args.output, args.secret)


if __name__ == "__main__":
    main()
