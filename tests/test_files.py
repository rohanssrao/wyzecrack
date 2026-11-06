"""files.py: the user's XDG directories and the saved recordings."""
import json

from wyzecrack import files


def _recording(lib_root, cam, stamp, mac):
    d = lib_root / cam / stamp
    d.mkdir(parents=True)
    (d / "video.mp4").write_bytes(b"mp4")
    (d / "meta.json").write_text(json.dumps({"mac": mac, "started": 1}))
    return d


def test_the_videos_dir_follows_user_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(files, "_user", lambda: (tmp_path, 1000, 1000))
    assert files.videos_dir() == tmp_path / "Videos" / "wyzecrack"
    (tmp_path / ".config").mkdir()
    (tmp_path / ".config/user-dirs.dirs").write_text(
        'XDG_DESKTOP_DIR="$HOME/Desktop"\nXDG_VIDEOS_DIR="$HOME/Films"\n')
    assert files.videos_dir() == tmp_path / "Films" / "wyzecrack"


def test_a_renamed_camera_keeps_its_directory(tmp_path):
    lib = files.Library(tmp_path)
    cam = {"mac": "d0:3f:27:a1:b2:c3", "name": "Driveway"}
    assert lib.camera_dir(cam) == tmp_path / "driveway-A1B2C3"
    (tmp_path / "driveway-A1B2C3").mkdir()
    assert lib.camera_dir({**cam, "name": "Front"}) == tmp_path / "driveway-A1B2C3"


def test_delete_takes_a_recording_or_clip_and_nothing_else(tmp_path):
    lib = files.Library(tmp_path)
    rec = _recording(tmp_path, "driveway-A1B2C3", "20260101-000000", "D03F27A1B2C3")
    ev = tmp_path / "driveway-A1B2C3" / "events" / "20260101-000500_1"
    ev.mkdir(parents=True)
    (ev / "clip.mp4").write_bytes(b"clip")
    (tmp_path / "secret.mp4").write_bytes(b"x")
    assert not lib.delete("/files/../secret.mp4")
    assert not lib.delete("/files/secret.mp4")
    assert not lib.delete("/files/driveway-A1B2C3/20260101-000000/meta.json")
    assert lib.delete(lib.recordings()[0]["video"]) and not rec.exists()
    assert lib.delete(lib.motion()[0]["clip"]) and not ev.exists()
    assert (tmp_path / "driveway-A1B2C3" / "events").exists()
