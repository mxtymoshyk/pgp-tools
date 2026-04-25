"""
pgp_common - Shared constants and helpers for the pgp_tools suite.

Why this module exists:
    Multiple scripts in this folder need the same trust-level reference,
    the same GPG initialization with old-cipher-algos enabled, and the
    same ownertrust-import boilerplate. Centralizing them keeps trust
    semantics consistent and removes duplicated code blocks.

Public API:
    TRUST_LEVELS         - dict mapping numeric level (1-5) to (short, long) labels
    TRUST_FLAG_LABELS    - dict mapping GPG single-letter trust flags to human labels
    trust_level_help     - returns multi-line trust level reference text
    get_gpg              - construct a configured gnupg.GPG instance
    import_ownertrust    - set ownertrust for a fingerprint via `gpg --import-ownertrust`
    find_key             - resolve a key by fingerprint, key ID, or UID substring
"""

import subprocess
from typing import Optional

import gnupg

TRUST_LEVELS = {
    "1": ("undefined", "I do not know or won't say"),
    "2": ("never", "I do NOT trust"),
    "3": ("marginal", "I trust marginally"),
    "4": ("full", "I trust fully"),
    "5": ("ultimate", "I trust ultimately (own keys)"),
}

# single-letter trust flags returned by gpg in the `trust` field of a key dict
TRUST_FLAG_LABELS = {
    "-": "Unknown",
    "n": "Never",
    "m": "Marginal",
    "f": "Full",
    "u": "Ultimate",
    "e": "Expired",
    "q": "Undefined",
    "r": "Revoked",
}


def trust_level_help() -> str:
    """Return a formatted help block listing all numeric trust levels."""
    lines = ["Trust levels:"]
    for level, (short, desc) in TRUST_LEVELS.items():
        lines.append(f"  {level} = {short:<10} ({desc})")
    return "\n".join(lines)


def get_gpg(gpg_home: Optional[str] = None) -> gnupg.GPG:
    """
    Construct a python-gnupg GPG instance.

    Args:
        gpg_home: optional path to GPG home directory. If None, the default
            location (~/.gnupg or $GNUPGHOME) is used.

    Returns:
        Configured gnupg.GPG instance with utf-8 encoding.
    """
    if gpg_home:
        gpg = gnupg.GPG(gnupghome=gpg_home)
    else:
        gpg = gnupg.GPG()
    gpg.encoding = "utf-8"
    return gpg


def import_ownertrust(fingerprint: str, level: str, gpg_home: Optional[str] = None) -> bool:
    """
    Set ownertrust for a fingerprint by piping into `gpg --import-ownertrust`.

    python-gnupg cannot set ownertrust directly, so we shell out to the gpg
    binary. The trust DB is updated immediately and persisted to disk.

    Args:
        fingerprint: full 40-char fingerprint of the target key.
        level: numeric trust level "1".."5" (see TRUST_LEVELS).
        gpg_home: optional GPG home directory. If provided, passed via
            `--homedir` so we touch the right keyring.

    Returns:
        True on success, False otherwise. Errors are printed to stdout.
    """
    if level not in TRUST_LEVELS:
        print(f"Invalid trust level: {level!r}. Must be one of {list(TRUST_LEVELS)}.")
        return False

    cmd = ["gpg"]
    if gpg_home:
        cmd.extend(["--homedir", gpg_home])
    cmd.append("--import-ownertrust")

    trust_record = f"{fingerprint}:{level}:\n".encode()

    try:
        subprocess.run(cmd, input=trust_record, capture_output=True, check=True)
        short = TRUST_LEVELS[level][0]
        print(f"  set trust '{short}' for {fingerprint}")
        return True
    except subprocess.CalledProcessError as exc:
        print(f"  failed to set trust for {fingerprint}: {exc.stderr.decode().strip()}")
        return False


def find_key(gpg: gnupg.GPG, identifier: str, secret: bool = False) -> Optional[dict]:
    """
    Resolve a key by fingerprint substring, key ID substring, or UID substring.

    Args:
        gpg: configured gnupg.GPG instance.
        identifier: fingerprint, key ID, email, or UID substring to match.
        secret: search secret keys instead of public keys.

    Returns:
        The first matching key dict, or None if no match.
    """
    for key in gpg.list_keys(secret):
        if identifier in key["fingerprint"] or identifier in key["keyid"]:
            return key
        for uid in key["uids"]:
            if identifier in uid:
                return key
    return None
