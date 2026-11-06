"""CLI helpers that need no network."""
from wyzecrack import cli


def test_new_root_is_the_topmost_missing_directory(tmp_path):
    assert cli._new_root(tmp_path / "a" / "b" / "c") == tmp_path / "a"
    assert cli._new_root(tmp_path) == tmp_path
