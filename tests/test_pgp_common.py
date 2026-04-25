import subprocess
from unittest.mock import MagicMock, patch

import pytest

from pgp_tools.pgp_common import (
    TRUST_FLAG_LABELS,
    TRUST_LEVELS,
    find_key,
    get_gpg,
    import_ownertrust,
    trust_level_help,
)
from tests.conftest import requires_gpg


class TestTrustLevels:
    def test_levels_present(self):
        assert set(TRUST_LEVELS.keys()) == {"1", "2", "3", "4", "5"}

    def test_each_level_has_short_and_long(self):
        for _level, (short, desc) in TRUST_LEVELS.items():
            assert short
            assert desc

    def test_short_labels_are_unique(self):
        shorts = [s for s, _ in TRUST_LEVELS.values()]
        assert len(shorts) == len(set(shorts))


class TestTrustFlags:
    def test_known_flags(self):
        for flag in ("-", "n", "m", "f", "u", "e", "q", "r"):
            assert flag in TRUST_FLAG_LABELS

    def test_labels_are_strings(self):
        for v in TRUST_FLAG_LABELS.values():
            assert isinstance(v, str) and v


class TestTrustLevelHelp:
    def test_returns_string(self):
        s = trust_level_help()
        assert isinstance(s, str) and "Trust levels" in s

    def test_includes_all_levels(self):
        s = trust_level_help()
        for level in TRUST_LEVELS:
            assert level in s


@requires_gpg
class TestGetGpg:
    def test_default_home(self, gpg_home):
        g = get_gpg()
        assert g.encoding == "utf-8"

    def test_explicit_home(self, gpg_home):
        g = get_gpg(gpg_home)
        assert g.gnupghome == gpg_home


class TestImportOwnertrust:
    def test_invalid_level_returns_false(self, capsys):
        assert import_ownertrust("ABC123" * 7, "9") is False
        out = capsys.readouterr().out
        assert "Invalid trust level" in out

    def test_calls_gpg_with_correct_args(self):
        fp = "A" * 40
        with patch("pgp_tools.pgp_common.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            assert import_ownertrust(fp, "4") is True
            args, kwargs = mock_run.call_args
            cmd = args[0]
            assert cmd[0] == "gpg"
            assert "--import-ownertrust" in cmd
            assert kwargs["input"] == f"{fp}:4:\n".encode()

    def test_passes_gpg_home(self):
        fp = "B" * 40
        with patch("pgp_tools.pgp_common.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            import_ownertrust(fp, "4", gpg_home="/tmp/fake")
            cmd = mock_run.call_args[0][0]
            assert "--homedir" in cmd
            assert "/tmp/fake" in cmd

    def test_returns_false_on_failure(self):
        fp = "C" * 40
        with patch("pgp_tools.pgp_common.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, ["gpg"], stderr=b"boom")
            assert import_ownertrust(fp, "4") is False


class TestFindKey:
    def _fake_key(self, fingerprint="A" * 40, keyid="A" * 16, uids=None):
        return {
            "fingerprint": fingerprint,
            "keyid": keyid,
            "uids": uids or ["Alice <alice@example.com>"],
        }

    def test_match_by_fingerprint(self):
        gpg = MagicMock()
        gpg.list_keys.return_value = [self._fake_key()]
        result = find_key(gpg, "A" * 40)
        assert result is not None

    def test_match_by_keyid_substring(self):
        gpg = MagicMock()
        gpg.list_keys.return_value = [self._fake_key(keyid="DEADBEEF12345678")]
        result = find_key(gpg, "DEADBEEF")
        assert result is not None

    def test_match_by_uid_substring(self):
        gpg = MagicMock()
        gpg.list_keys.return_value = [self._fake_key(uids=["Bob <bob@example.com>"])]
        result = find_key(gpg, "bob@example.com")
        assert result is not None

    def test_no_match(self):
        gpg = MagicMock()
        gpg.list_keys.return_value = [self._fake_key()]
        assert find_key(gpg, "nonexistent") is None

    def test_secret_flag_propagates(self):
        gpg = MagicMock()
        gpg.list_keys.return_value = []
        find_key(gpg, "anything", secret=True)
        gpg.list_keys.assert_called_once_with(True)
