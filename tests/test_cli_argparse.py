"""Smoke tests: every CLI's --help works without error.

Each module is imported and main() invoked with `--help`; argparse calls
sys.exit(0) which we capture as a clean exit. This catches obvious wiring
bugs (missing imports, malformed argparse, etc.) without needing GnuPG.
"""

import importlib

import pytest

CLI_MODULES = [
    "pgp_tools.pgp_3des_cfb",
    "pgp_tools.list_recipients",
    "pgp_tools.manage_trust",
    "pgp_tools.fix_key_usability",
    "pgp_tools.import_pubring",
    "pgp_tools.import_secring",
    "pgp_tools.cleanup_secring",
]

GCP_CLI_MODULES = [
    "pgp_tools.import_pubring_from_gcp",
    "pgp_tools.import_secring_from_gcp",
]


@pytest.mark.parametrize("module_name", CLI_MODULES)
def test_help_runs_cleanly(module_name, monkeypatch, capsys):
    mod = importlib.import_module(module_name)
    monkeypatch.setattr("sys.argv", [module_name, "--help"])
    with pytest.raises(SystemExit) as exc_info:
        mod.main()
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out.lower()


@pytest.mark.parametrize("module_name", GCP_CLI_MODULES)
def test_gcp_help_runs_cleanly(module_name, monkeypatch, capsys):
    pytest.importorskip("google.cloud.secretmanager")
    mod = importlib.import_module(module_name)
    monkeypatch.setattr("sys.argv", [module_name, "--help"])
    with pytest.raises(SystemExit) as exc_info:
        mod.main()
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out.lower()
