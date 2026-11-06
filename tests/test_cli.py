"""CLI helpers that need no network: the ENR cache and output ownership."""
import json
import os

from wyzecrack import cli


def test_enr_cache_by_mac(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "STATE_DIR", tmp_path)
    (tmp_path / "enr.json").write_text(json.dumps(
        {"D03F27A1B2C3": {"enr": "old", "seen": 1}}))
    assert cli._cached_enr("d0:3f:27:a1:b2:c3") == "old"
    cli._cache_enr("d0:3f:27:a1:b2:c3", "new")
    assert cli._cached_enr("D0:3F:27:A1:B2:C3") == "new"
    assert oct(os.stat(tmp_path / "enr.json").st_mode & 0o777) == "0o600"
    assert cli._cached_enr("aa:bb:cc:dd:ee:ff") is None


def test_new_root_is_the_topmost_missing_directory(tmp_path):
    assert cli._new_root(tmp_path / "a" / "b" / "c") == tmp_path / "a"
    assert cli._new_root(tmp_path) == tmp_path

