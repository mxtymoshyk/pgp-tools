def test_package_imports():
    import pgp_tools

    assert pgp_tools.__version__


def test_pgp_common_exports():
    from pgp_tools import pgp_common

    for attr in (
        "TRUST_LEVELS",
        "TRUST_FLAG_LABELS",
        "trust_level_help",
        "get_gpg",
        "import_ownertrust",
        "find_key",
    ):
        assert hasattr(pgp_common, attr), f"missing: {attr}"
