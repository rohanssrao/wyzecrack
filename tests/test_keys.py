"""The key cache: by MAC in any spelling, private, and what forgetting keeps."""
import json
import os

from wyzecrack import keys


def test_saved_by_mac(tmp_path, monkeypatch):
    monkeypatch.setenv("WYZECRACK_STATE", str(tmp_path))
    (tmp_path / "enr.json").write_text(json.dumps({"D03F27A1B2C3": {"enr": "old"}}))
    assert keys.cached("d0:3f:27:a1:b2:c3")["enr"] == "old"
    keys.save("d0:3f:27:a1:b2:c3", enr="new", uid="U", model=None)
    assert keys.cached("D0:3F:27:A1:B2:C3") == {"enr": "new", "uid": "U"}
    assert oct(os.stat(tmp_path / "enr.json").st_mode & 0o777) == "0o600"
    assert keys.cached("02:00:00:00:00:01") == {}


def test_forgetting_the_key_keeps_the_uid(tmp_path, monkeypatch):
    monkeypatch.setenv("WYZECRACK_STATE", str(tmp_path))
    keys.save("D03F27A1B2C3", enr="e", uid="U", framing="cc51")
    keys.forget_enr("D03F27A1B2C3")
    assert keys.cached("D03F27A1B2C3") == {"uid": "U"}
