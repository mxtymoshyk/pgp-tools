import os
import shutil
import subprocess
from pathlib import Path

import pytest


def _gpg_available() -> bool:
    return shutil.which("gpg") is not None


requires_gpg = pytest.mark.skipif(not _gpg_available(), reason="gpg binary not installed")


@pytest.fixture
def gpg_home(tmp_path, monkeypatch):
    """Throwaway GPG home so tests never touch ~/.gnupg."""
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("GNUPGHOME", str(home))
    return str(home)


@pytest.fixture
def gpg(gpg_home):
    """python-gnupg instance pointed at the throwaway home."""
    import gnupg

    g = gnupg.GPG(gnupghome=gpg_home)
    g.encoding = "utf-8"
    return g


@pytest.fixture
def test_key(gpg):
    """Generate a short-lived RSA key in the throwaway home and yield its fingerprint."""
    input_data = gpg.gen_key_input(
        name_real="Test User",
        name_email="test@example.invalid",
        passphrase="",
        key_type="RSA",
        key_length=2048,
        expire_date="1d",
        no_protection=True,
    )
    result = gpg.gen_key(input_data)
    fp = str(result)
    if not fp:
        pytest.skip(
            f"could not generate test key: {result.stderr if hasattr(result, 'stderr') else 'unknown'}"
        )
    return fp


@pytest.fixture
def examples_dir():
    """Path to bundled example fixtures."""
    return Path(__file__).resolve().parent.parent / "examples"
