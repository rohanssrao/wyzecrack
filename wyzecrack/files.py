"""Where wyzecrack keeps things, in the XDG directories of the user who
started it (it runs as root under sudo):

- recordings and motion clips: $XDG_VIDEOS_DIR/wyzecrack (~/Videos/wyzecrack),
  one directory per camera;
- camera keys and the page's camera settings: $XDG_DATA_HOME/wyzecrack
  (~/.local/share/wyzecrack).

Everything created there belongs to that user.
"""
import json
import os
import pwd
import re
import shutil
import time
from pathlib import Path


def _user():
    """(home, uid, gid) of the user who started wyzecrack."""
    name = os.environ.get("SUDO_USER")
    try:
        pw = pwd.getpwnam(name) if name else pwd.getpwuid(os.getuid())
    except KeyError:
        pw = pwd.getpwuid(os.getuid())
    return Path(pw.pw_dir), pw.pw_uid, pw.pw_gid


def _user_dir(var, default):
    """An XDG directory of that user. sudo drops their environment, so
    XDG_VIDEOS_DIR comes from their user-dirs.dirs, as xdg-user-dir reads it."""
    home = _user()[0]
    if var == "XDG_VIDEOS_DIR":
        try:
            text = (home / ".config/user-dirs.dirs").read_text()
            m = re.search(r'^XDG_VIDEOS_DIR="([^"]+)"', text, re.M)
            if m and m.group(1).replace("$HOME", "").strip("/"):
                return Path(m.group(1).replace("$HOME", str(home)))
        except OSError:
            pass
    elif os.environ.get(var) and not os.environ.get("SUDO_USER"):
        return Path(os.environ[var])
    return home / default


def videos_dir():
    return _user_dir("XDG_VIDEOS_DIR", "Videos") / "wyzecrack"


def data_dir():
    if os.environ.get("WYZECRACK_STATE"):
        return Path(os.environ["WYZECRACK_STATE"])
    return _user_dir("XDG_DATA_HOME", ".local/share") / "wyzecrack"


def make_dir(path):
    """mkdir -p, giving every directory it creates to the user."""
    path = Path(path)
    missing = []
    p = path
    while not p.exists():
        missing.append(p)
        p = p.parent
    path.mkdir(parents=True, exist_ok=True)
    for p in missing:
        _chown(p)
    return path


def _chown(path):
    _, uid, gid = _user()
    if os.geteuid() == 0 and uid != 0:
        try:
            os.chown(path, uid, gid)
        except OSError:
            pass


def give_to_user(path, since):
    """Hand the user the files under path that this run created."""
    _, uid, gid = _user()
    if os.geteuid() != 0 or uid == 0 or not Path(path).exists():
        return
    for root, dirs, files in os.walk(path):
        for n in [root, *(os.path.join(root, f) for f in dirs + files)]:
            st = os.lstat(n)
            if st.st_uid == 0 and st.st_mtime >= since - 1:
                os.chown(n, uid, gid)


def write_json(path, data, mode=0o644):
    """Write JSON atomically, owned by the user."""
    path = Path(path)
    make_dir(path.parent)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(data, indent=1) + "\n")
    _chown(tmp)
    os.replace(tmp, path)


def mac_key(mac):
    return mac.replace(":", "").upper()


# -- the page's camera settings: name, last address, motion clips on ------
def camera_settings():
    try:
        return json.loads((data_dir() / "cameras.json").read_text())
    except (OSError, ValueError):
        return {}


def save_camera_settings(mac, **fields):
    d = camera_settings()
    d.setdefault(mac_key(mac), {}).update(fields)
    write_json(data_dir() / "cameras.json", d)


def _slug(text):
    keep = "".join(c if c.isalnum() else "-" for c in text.lower())
    return "-".join(p for p in keep.split("-") if p)[:40] or "camera"


class Library:
    """Recordings and motion clips under the videos root:
    <camera>-<MAC tail>/<time>/{video.mp4, frame.jpg, meta.json} for live
    views and <camera>-<MAC tail>/events/<time>_<id>/{clip.mp4,
    snapshot.jpg, meta.json} for motion clips."""

    def __init__(self, root=None):
        # resolved, like the paths resolve() checks against it: a symlink
        # anywhere above the root would otherwise refuse every file
        self.root = Path(root or videos_dir()).absolute().resolve()

    def camera_dir(self, cam):
        """The camera's directory: the one it already has (a rename keeps
        it), else one named after it."""
        tail = mac_key(cam["mac"])[-6:]
        for d in sorted(self.root.glob(f"*-{tail}")):
            if d.is_dir():
                return d
        name = cam.get("name") or cam.get("model") or "camera"
        return self.root / f"{_slug(name)}-{tail}"

    def recordings(self, mac=None):
        out = []
        for meta in self.root.glob("*/*/meta.json"):
            try:
                m = json.loads(meta.read_text())
            except (OSError, ValueError):
                continue
            if mac and mac_key(m.get("mac", "")) != mac_key(mac):
                continue
            d = meta.parent
            if not (d / "video.mp4").exists():
                continue
            out.append({"started": m.get("started", 0), "seconds": m.get("seconds"),
                        "video": self.url(d / "video.mp4"),
                        "thumb": self.url(d / "frame.jpg")
                        if (d / "frame.jpg").exists() else None})
        return sorted(out, key=lambda r: r["started"], reverse=True)

    def motion(self, mac=None):
        out = []
        for d in self.root.glob("*/events/*/"):
            cam = d.parent.parent.name
            if mac and not cam.endswith(mac_key(mac)[-6:]):
                continue
            clip, snap = d / "clip.mp4", d / "snapshot.jpg"
            if not clip.exists():
                continue
            try:
                seconds = json.loads((d / "meta.json").read_text()).get("seconds")
            except (OSError, ValueError):
                seconds = None
            out.append({"t": d.stat().st_mtime, "clip": self.url(clip),
                        "snapshot": self.url(snap) if snap.exists() else None,
                        "seconds": seconds})
        return sorted(out, key=lambda e: e["t"], reverse=True)

    def thumb(self, mac):
        for r in self.recordings(mac):
            if r["thumb"]:
                return r["thumb"]
        for e in self.motion(mac):
            if e["snapshot"]:
                return e["snapshot"]
        return None

    def url(self, path):
        return "/files/" + str(Path(path).absolute().relative_to(self.root))

    def resolve(self, rel):
        p = (self.root / rel).resolve()
        return p if p.is_relative_to(self.root) and p.is_file() else None

    def delete(self, url):
        """Delete the recording or motion clip whose video is at this URL
        (its whole directory). False if there is none."""
        p = self.resolve(url.removeprefix("/files/"))
        if p is None or p.name not in ("video.mp4", "clip.mp4"):
            return False
        d = p.parent
        depth = len(d.relative_to(self.root).parts)
        if not ((p.name == "video.mp4" and depth == 2)
                or (p.name == "clip.mp4" and depth == 3 and d.parent.name == "events")):
            return False
        shutil.rmtree(d)
        return True


def save_recording(av_bin, outdir, mac=None, started=None):
    """video.mp4 and frame.jpg from a live view's av.bin, plus meta.json
    (when it started, how long, which camera) for the page. av.bin then
    goes; it stays when writing the video failed, for `wyzecrack extract`.
    Returns media.export's result."""
    from .media import export
    av_bin, outdir = Path(av_bin), Path(outdir)
    now = time.time()
    try:
        r = export(str(av_bin), str(outdir))
    except Exception as e:  # noqa: BLE001
        r = {"mp4": None, "error": repr(e)}
    if r["error"]:
        return r
    av_bin.unlink(missing_ok=True)
    if r["mp4"]:
        meta = outdir / "meta.json"
        old = {}
        try:
            old = json.loads(meta.read_text())
        except (OSError, ValueError):
            pass
        meta.write_text(json.dumps({
            "mac": mac or old.get("mac"),
            "started": started or old.get("started") or outdir.stat().st_mtime,
            "seconds": round(r["seconds"], 1)}, indent=1) + "\n")
    give_to_user(outdir, now)
    return r
