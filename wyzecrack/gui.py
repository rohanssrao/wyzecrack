"""wyzecrack's graphical front end: a small local web app.

`wyzecrack` (no command) starts it: a server on 127.0.0.1 with a
one-time token in its URL, opened in the invoking user's browser. The page
lists the Wyze cameras on the LAN; picking one plays its live view in the
page (video decoded by the browser with WebCodecs, audio with WebAudio)
and records it.

The first time with a camera, the tool gets on its path to read its ENR
off its HTTPS (cutting its internet for a minute if it doesn't send it
soon), then asks Wyze for its UID with that ENR; both are cached. After
that a live view is a direct LAN session (direct.py): nothing on the
network is changed. If Wyze won't give the UID, the page falls back to
splicing the live views the Wyze app opens (splice.py).

The server runs in the main thread (asyncio); the session runs in a
worker thread and reports through `events`.
"""
import asyncio
import contextlib
import json
import os
import secrets
import shutil
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from . import events
from .live import LiveAssembler, codec_string

WEB = Path(__file__).parent / "web"
STATE_DIR = Path(os.environ.get("WYZECRACK_STATE", "/var/lib/wyzecrack"))
MSG_VIDEO, MSG_AUDIO, MSG_JPEG = 1, 2, 3


# -- camera directory -----------------------------------------------------
def _names():
    try:
        return json.loads((STATE_DIR / "cameras.json").read_text())
    except (OSError, ValueError):
        return {}


def _save_camera(mac, **fields):
    """Remember the page's settings for a camera (its name, whether its
    motion clips are saved), keyed by MAC."""
    d = _names()
    entry = d.get(_key(mac), {})
    entry.update(fields)
    d[_key(mac)] = entry
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = STATE_DIR / "cameras.json.tmp"
    tmp.write_text(json.dumps(d, indent=1) + "\n")
    os.replace(tmp, STATE_DIR / "cameras.json")


def _save_name(mac, name, ip=None):
    _save_camera(mac, name=name.strip()[:60], ip=ip)


def _key(mac):
    return mac.replace(":", "").upper()


def _slug(text):
    keep = "".join(c if c.isalnum() else "-" for c in text.lower())
    return "-".join(p for p in keep.split("-") if p)[:40] or "camera"


class Library:
    """Everything saved under the captures root: recordings (one directory
    per live view, with meta.json) and motion events, per camera."""

    def __init__(self, root):
        # resolved, like the paths resolve() checks against it: a symlink
        # anywhere above the captures root would otherwise refuse every file
        self.root = Path(root).resolve()

    def camera_dir(self, mac, name):
        return self.root / f"{_slug(name)}-{_key(mac)[-6:]}"

    def recordings(self, mac=None):
        out = []
        for meta in self.root.glob("*/*/meta.json"):
            try:
                m = json.loads(meta.read_text())
            except (OSError, ValueError):
                continue
            if mac and _key(m.get("mac", "")) != _key(mac):
                continue
            d = meta.parent
            if not (d / "video.mp4").exists():
                continue
            out.append({**m, "video": self.url(d / "video.mp4"),
                        "thumb": self.url(d / "frame.jpg")
                        if (d / "frame.jpg").exists() else None})
        return sorted(out, key=lambda r: r.get("started", 0), reverse=True)

    def motion(self, mac=None):
        out = []
        for d in self.root.glob("*/events/*/"):
            cam = d.parent.parent.name
            if mac and not cam.endswith(_key(mac)[-6:]):
                continue
            clip, snap = d / "clip.mp4", d / "snapshot.jpg"
            if not clip.exists() and not snap.exists():
                continue
            try:
                seconds = json.loads((d / "meta.json").read_text()).get("seconds")
            except (OSError, ValueError):
                seconds = None
            out.append({"id": d.name, "t": d.stat().st_mtime,
                        "clip": self.url(clip) if clip.exists() else None,
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


# -- the armed session, in a worker thread --------------------------------
class Controller:
    def __init__(self, hub, library, journal):
        self.hub, self.lib = hub, library
        self.journal = journal       # the page's Changes; parts take scopes
        self.captures = {}           # MAC -> motion.MotionCapture
        self._cap_lock = threading.RLock()
        self._paused = None          # MAC whose capture stepped aside
        self._view_since = None
        self.thread = None
        self.stop = threading.Event()
        self.state = {"phase": "idle"}
        self.camera = None
        self.live = None
        self.jpeg = None            # jpegfeed.JpegFeed while a page wants it
        self.live_stats = {}
        self.saving = []            # export threads still running
        self.uid = int(os.environ.get("SUDO_UID", os.getuid()))
        self.gid = int(os.environ.get("SUDO_GID", os.getgid()))

    # state shown to the page
    def set(self, **kw):
        self.state.update(kw)
        self.hub.send_json({"kind": "state", **self.state})

    def busy(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self, cam):
        if self.busy():
            return False
        self.camera = cam
        self.stop.clear()
        self.state = {"phase": "starting", "camera": cam, "steps": {},
                      "error": None, "error_kind": None, "mode": "direct"}
        self.set()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return True

    def request_stop(self):
        if self.busy():
            self.set(phase="stopping")
            self.stop.set()

    def _step(self, name, status, detail=None):
        steps = dict(self.state.get("steps") or {})
        steps[name] = {"status": status, "detail": detail}
        self.set(steps=steps)

    def _on_event(self, ev):
        k = ev["kind"]
        if k == "onpath":
            self._step("onpath", "active" if ev["state"] == "arming" else "done")
        elif k == "enr":
            st = ev.get("stats") or {}
            if ev["state"] in ("waiting", "nudging"):
                prev = (self.state.get("steps") or {}).get("enr") or {}
                detail = {"seen": st.get("intercepted", 0) if st else
                          (prev.get("detail") or {}).get("seen", 0),
                          "resets": st.get("resets", 0),
                          "nudging": ev["state"] == "nudging"}
                self._step("enr", "active", detail)
            elif ev["state"] == "refused":
                self._step("enr", "problem", {"refused": st.get("tls_failed")})
            else:
                self._step("enr", "done", {"how": "cached" if ev.get("cached")
                                           else "harvested"})
        elif k == "uid":
            status = {"active": "active", "done": "done"}.get(ev["state"],
                                                              "problem")
            self._step("uid", status, {"detail": ev.get("detail")})
        elif k == "learning":
            self._step("watch", "active", {"note": "learning"})
        elif k == "watching":
            self._step("watch", "active")
            self.set(phase="waiting", session=None)
        elif k == "bypass":
            if ev["missing"]:
                self._step("onpath", "problem")
                self.set(hint="unplug")
            else:
                self._step("onpath", "done")
                self.set(hint=None)
                self.hub.send_json({"kind": "toast", "text": "All set: the camera's connections now come through here"})
        elif k == "missed":
            self.set(hint="bypass")
            self.hub.send_json({"kind": "missed"})
        elif k == "session":
            s = ev["state"]
            if s == "armed":
                self.set(phase="connecting", session={"state": "armed"})
            elif s == "handshake":
                self.set(phase="connecting", session={"state": "handshake"})
            elif s == "live":
                # both handshakes are done; "live" waits for the first
                # picture (the camera may still drop the session first)
                self.set(phase="connecting", hint=None,
                         session={"state": "joined"})
            elif s == "failed":
                self.set(phase="connecting",
                         session={"state": "failed", "detail": ev.get("detail")})
            elif s == "ended":
                was_live = self.state.get("phase") == "live"
                self.hub.send_json({"kind": "viewer_left",
                                    "spliced": bool(ev.get("spliced")),
                                    "had_video": was_live})

    def _run(self):
        from .cli import _give_to_user
        unsub = events.subscribe(self._on_event)
        cam = self.camera
        cam_dir = self.lib.camera_dir(cam["mac"], cam.get("name") or cam["model"])
        started = time.time()
        try:
            enr, uid = self._key(cam, cam_dir)
            if self.stop.is_set() or not enr:
                return
            if uid:
                self._watch(cam, cam_dir, enr, uid)
            else:
                self._run_splice(cam, cam_dir)
        except SystemExit as e:
            self.set(phase="error", error=str(e.code or e))
        except Exception as e:  # noqa: BLE001
            self.set(phase="error", error=f"{type(e).__name__}: {e}")
        finally:
            unsub()
            if cam_dir.exists():
                _give_to_user(cam_dir.parent, started)
            if self.state.get("phase") != "error":
                self.set(phase="idle", session=None)
            self.hub.send_json({"kind": "library"})

    def _key(self, cam, cam_dir):
        """(enr, uid) for the camera: cached, or read once while on its
        path (motion clips it uploads meanwhile are saved too)."""
        from .cli import (Armed, _cached_enr, _cached_uid, obtain_key,
                          uid_from_wyze)
        from .cloud import CloudError
        mac = cam["mac"]
        enr, uid = _cached_enr(mac), _cached_uid(mac)
        self.set(mode="direct")
        if enr:
            self._step("enr", "done", {"how": "cached"})
        if enr and uid:
            self._step("uid", "done")
            return enr, uid
        if enr:
            self._step("uid", "active")
            try:
                uid = uid_from_wyze(cam["ip"], mac, enr)
                self._step("uid", "done")
                return enr, uid
            except CloudError as e:
                self._step("uid", "problem", {"detail": str(e)})
                return enr, None
        args = SimpleNamespace(target=cam["ip"], on_path=False, enr=None,
                               reharvest=False, pass_through=False,
                               journal=False, events_dir=cam_dir / "events",
                               harvest_timeout=0)
        armed = Armed(args, cam_dir, splice=False, harvest=True,
                      changes=self.journal.scope())
        armed.stop = self.stop
        armed.on_motion = self._motion
        self._step("enr", "active", {"seen": 0})
        with self._capture_paused(mac), armed:
            return obtain_key(armed, args)

    def _watch(self, cam, cam_dir, enr, uid):
        """The live view straight from the camera until Stop. When the
        camera hangs up it reconnects; everything from the click to Stop
        is one recording."""
        from .changes import signals_held
        from .cli import (_cached, _inhibit_sleep, _release_inhibitor,
                          _remember_framing)
        from .direct import CameraGone, Direct, open_firewall, open_first
        from .netutil import local_ip_for
        failures = 0                 # attempts in a row without a picture
        any_video = False
        out = cam_dir / time.strftime("%Y%m%d-%H%M%S")
        out.mkdir(parents=True, exist_ok=True)
        self._new_live(view_start=True)
        sleep_lock = _inhibit_sleep("showing a live view")
        try:
            while not self.stop.is_set():
                self.set(phase="connecting", hint=None,
                         session={"state": "direct"})
                scope = self.journal.scope()
                d, why = None, ""
                framing = _cached(cam["mac"]).get("framing")

                def make(stop, scope=scope, framing=framing):
                    s = Direct(cam["ip"], uid, enr, cam["mac"],
                               local_ip=local_ip_for(cam["ip"]), stop=stop,
                               framing=framing)
                    open_firewall(scope, cam["ip"], s.port)
                    return s

                try:
                    t0 = time.monotonic()
                    d = open_first(make, stop=self.stop, on_av=self._on_av,
                                   av_log=str(out / "av.bin"))
                    _remember_framing(cam["mac"], d)
                    print(f"[+] live from {cam['ip']} after "
                          f"{time.monotonic() - t0:.1f} s"
                          + (f" ({d.tries} sessions tried)" if d.tries > 1 else ""))
                    while not self.stop.is_set():
                        d.pump(0.3)
                except (CameraGone, ValueError, OSError) as e:
                    # ValueError: a DTLS handshake that went wrong; OSError:
                    # no route (the host's network is still coming up)
                    print(f"[*] {e}")
                    why = str(e)
                finally:
                    if d:
                        d.close()
                    with signals_held():
                        scope.undo_all()
                had_video = self.live_stats.get("frames", 0) > 0
                any_video = any_video or had_video
                if self.stop.is_set():
                    break
                failures = 0 if had_video else failures + 1
                # no answer at all to a first try: switched off, offline, or
                # a new key; trying again won't change that
                if failures >= 3 or ("(discovery)" in why and not any_video):
                    self.set(phase="error", error_kind="no_answer",
                             error="The camera doesn't answer. Is it switched "
                                   "on in the Wyze app? A camera that is "
                                   "turned off can't be watched. If it is on "
                                   "and was set up again in the Wyze app, its "
                                   "key has changed.")
                    break
                self.hub.send_json({"kind": "toast", "text":
                                    "The camera hung up · reconnecting"
                                    if had_video else "Trying again…"})
                self._new_live()     # the next stream starts afresh
                self.stop.wait(1.5)
        finally:
            _release_inhibitor(sleep_lock)
            self._session_end(out, any_video)

    def _run_splice(self, cam, cam_dir):
        """The fallback: splice the live views the Wyze app opens."""
        from .cli import Armed
        args = SimpleNamespace(target=cam["ip"], on_path=False, enr=None,
                               reharvest=False, pass_through=False,
                               journal=False, events_dir=cam_dir / "events")
        armed = Armed(args, cam_dir, splice=True, changes=self.journal.scope())
        armed.stop = self.stop
        armed.on_motion = self._motion
        self.set(mode="splice")
        self._step("onpath", "active")
        with self._capture_paused(cam["mac"]), armed:
            enr = armed.enr()
            if not enr or self.stop.is_set():
                return
            sp = armed.splicer
            sp.stop = sp.watcher.stop = self.stop
            sp.session_dir = lambda: cam_dir / time.strftime("%Y%m%d-%H%M%S")
            sp.on_av = self._on_av
            sp.on_session_end = self._session_end
            self._new_live()
            sp.run(enr)

    # live media -> the page
    def _new_live(self, view_start=False):
        if view_start:
            self._view_since = None
        if self.jpeg:
            self.jpeg.close()       # the next stream starts at its own key frame
            self.jpeg = None
        self.live = LiveAssembler(on_video=self._video, on_audio=self._audio)
        self.live_stats = {"frames": 0, "t0": None, "recent": [], "size": None,
                           "codec": None}

    def _on_av(self, direction, ts, plaintext):
        if self.live:
            self.live.feed(direction, ts, plaintext)

    def _video(self, f):
        if self.state.get("phase") != "live":
            # the page's recording timer runs from the view's first picture
            self._view_since = self._view_since or time.time()
            self.set(phase="live", session={"state": "live",
                                            "since": self._view_since})
        st = self.live_stats
        codec = codec_string(f.sps)
        size = self.live.size
        if f.key and (codec != st["codec"] or size != st["size"]):
            st["codec"], st["size"] = codec, size
            self.hub.send_json({"kind": "video_config", "codec": codec,
                                "width": size[0] if size else None,
                                "height": size[1] if size else None})
        st["frames"] += 1
        now = time.time()
        st["t0"] = st["t0"] or now
        st["recent"] = [t for t in st["recent"] if now - t < 2] + [now]
        self.hub.send_bytes(struct.pack(">BBd", MSG_VIDEO, f.key, f.t) + f.data,
                            audience="h264")
        if self.hub.jpeg:
            if self.jpeg is None:
                from .jpegfeed import JpegFeed
                self.jpeg = JpegFeed(lambda t, jpg: self.hub.send_bytes(
                    struct.pack(">Bd", MSG_JPEG, t) + jpg, audience="jpeg"))
            self.jpeg.feed(f)

    def _audio(self, ts, pcm):
        self.hub.send_bytes(struct.pack(">Bd", MSG_AUDIO, ts) + pcm)

    def stats(self):
        st = self.live_stats
        if not st or not st.get("t0") or self.state.get("phase") != "live":
            return None
        return {"fps": round(len(st["recent"]) / 2, 1), "frames": st["frames"],
                "width": st["size"][0] if st["size"] else None,
                "height": st["size"][1] if st["size"] else None,
                "seconds": round(time.time() - st["t0"], 1)}

    def _session_end(self, out, spliced):
        self._new_live()
        if not spliced:
            # keep what explains a miss, under .missed/, out of the library
            keep = self.lib.root / ".missed" / out.name
            keep.mkdir(parents=True, exist_ok=True)
            for f in ("splice.log",):
                if (out / f).exists():
                    shutil.move(str(out / f), keep / f)
            shutil.rmtree(out, ignore_errors=True)
            return
        t = threading.Thread(target=self._save, args=(out,), daemon=True)
        self.saving = [x for x in self.saving if x.is_alive()] + [t]
        t.start()

    def _save(self, out):
        from .cli import _give_to_user
        from .media import export
        self.hub.send_json({"kind": "saving"})
        started = time.time()
        try:
            r = export(str(out / "av.bin"), str(out), merge=True)
        except Exception as e:  # noqa: BLE001
            self.hub.send_json({"kind": "toast", "level": "error",
                                "text": f"Could not save the video: {e}"})
            return
        main = next((m for m in r["mp4s"] if m["path"].endswith("/video.mp4")),
                    None)
        if not main:
            # joined, but the camera sent no picture before it hung up
            keep = self.lib.root / ".missed" / out.name
            keep.mkdir(parents=True, exist_ok=True)
            if (out / "splice.log").exists():
                shutil.move(str(out / "splice.log"), keep / "splice.log")
            shutil.rmtree(out, ignore_errors=True)
            self.hub.send_json({"kind": "dropped"})
            return
        cam = self.camera or {}
        meta = {"mac": cam.get("mac"), "ip": cam.get("ip"),
                "camera": cam.get("name") or cam.get("model"),
                "started": out.stat().st_mtime,
                "seconds": round(main["seconds"], 1) if main else 0,
                "width": main["size"][0] if main and main["size"] else None,
                "height": main["size"][1] if main and main["size"] else None}
        (out / "meta.json").write_text(json.dumps(meta, indent=1) + "\n")
        _give_to_user(out.parent, started - 600)
        self.hub.send_json({"kind": "library", "new": self.lib.url(out / "video.mp4")
                            if main else None})

    # -- motion clips, in the background -------------------------------
    def set_motion(self, cam, on):
        """Turn saving a camera's motion clips on or off (remembered)."""
        _save_camera(cam["mac"], motion=bool(on), ip=cam.get("ip"))
        with self._cap_lock:
            if on and not self._in_use(cam["mac"]):
                self._start_capture(cam)
            elif not on:
                self._stop_capture(cam["mac"])
        self._send_captures()

    def _in_use(self, mac):
        """The camera is being keyed or spliced right now (its capture
        resumes by itself afterwards)."""
        return self._paused == _key(mac)

    def ensure_captures(self, cams):
        """Start the captures turned on for cameras found on the LAN (and
        follow a camera to a new address)."""
        with self._cap_lock:
            for cam in cams:
                if not cam.get("motion") or self._in_use(cam["mac"]):
                    continue
                c = self.captures.get(_key(cam["mac"]))
                if c and c.running and c.ip == cam["ip"]:
                    continue
                if c:
                    self._stop_capture(cam["mac"])
                self._start_capture(cam)
        self._send_captures()

    def _start_capture(self, cam):
        from .motion import MotionCapture
        key = _key(cam["mac"])
        if key in self.captures and self.captures[key].running:
            return
        cam_dir = self.lib.camera_dir(cam["mac"], cam.get("name") or cam.get("model") or "camera")
        c = MotionCapture(self.journal, cam["ip"], cam["mac"],
                          cam_dir / "events", self._motion)
        self.captures[key] = c
        try:
            c.start()
            c.error = None
            print(f"[+] saving {cam['ip']}'s motion clips")
        except SystemExit as e:
            c.error = str(e.code or e)
            print(f"[!] can't save {cam['ip']}'s motion clips: {c.error}")
        except Exception as e:  # noqa: BLE001
            c.error = f"{type(e).__name__}: {e}"
            print(f"[!] can't save {cam['ip']}'s motion clips: {c.error}")

    def _stop_capture(self, mac):
        c = self.captures.pop(_key(mac), None)
        if c:
            c.stop()

    def stop_captures(self):
        with self._cap_lock:
            for mac in list(self.captures):
                self._stop_capture(mac)

    def _capturing(self, key, c):
        # a capture paused for a key read or splice of the same camera is
        # still saving clips: those sessions read its uploads themselves
        return c.running or self._paused == key

    def capture_status(self, mac):
        c = self.captures.get(_key(mac))
        if not c:
            return None
        return "on" if self._capturing(_key(mac), c) else "error"

    def _send_captures(self):
        self.hub.send_json({"kind": "captures", "captures": {
            k: {"on": self._capturing(k, c), "error": c.error}
            for k, c in self.captures.items()}})

    @contextlib.contextmanager
    def _capture_paused(self, mac):
        """Getting a camera's key or splicing it routes it through this host
        on its own; a motion capture of the same camera steps aside."""
        with self._cap_lock:
            c = self.captures.get(_key(mac))
            paused = bool(c and c.running)
            if paused:
                c.stop()
                self._paused = _key(mac)
        try:
            yield
        finally:
            if paused:
                with self._cap_lock:
                    self._paused = None
                    if self.captures.get(_key(mac)) is c:
                        try:
                            c.start()
                        except (SystemExit, Exception) as e:  # noqa: BLE001
                            c.error = str(e)
                self._send_captures()

    def _motion(self, path):
        print(f"[+] motion event: {path}")
        if path.name == "clip.mp4":
            self.hub.send_json({"kind": "motion",
                                "clip": self.lib.url(path),
                                "snapshot": self.lib.url(path.with_name("snapshot.jpg"))
                                if path.with_name("snapshot.jpg").exists() else None})


# -- the web server ---------------------------------------------------------
class Hub:
    """The page's websocket connections; thread-safe sends."""

    def __init__(self):
        self.loop = None
        self.clients = set()
        self.jpeg = set()           # pages that can't decode H.264 themselves
        self.backlog = {}

    def _send(self, data, audience=None):
        for ws in list(self.clients):
            if ws.closed:
                self.clients.discard(ws)
                self.jpeg.discard(ws)
                continue
            if audience == "h264" and ws in self.jpeg:
                continue
            if audience == "jpeg" and ws not in self.jpeg:
                continue
            # a slow viewer drops media rather than queueing without bound;
            # status messages always go through
            n = self.backlog.get(ws, 0)
            if n > 120 and not isinstance(data, str):
                continue
            self.backlog[ws] = n + 1

            async def go(ws=ws):
                try:
                    if isinstance(data, str):
                        await ws.send_str(data)
                    else:
                        await ws.send_bytes(data)
                except Exception:  # noqa: BLE001
                    self.clients.discard(ws)
                finally:
                    self.backlog[ws] = self.backlog.get(ws, 1) - 1
            asyncio.ensure_future(go())

    def send_json(self, obj):
        self._post(json.dumps(obj))

    def send_bytes(self, data, audience=None):
        """Media to every page, or only to those that decode H.264
        themselves ("h264") or only to those that want JPEG ("jpeg")."""
        if self.clients:
            self._post(data, audience)

    def _post(self, data, audience=None):
        try:
            if self.loop and not self.loop.is_closed():
                self.loop.call_soon_threadsafe(self._send, data, audience)
        except RuntimeError:      # the loop closed meanwhile (shutdown)
            pass


def _cameras(lib):
    from .cli import _cached_enr, _cached_uid
    from .discover import describe, find_cameras
    from .netutil import default_gateway, iface_for
    iface = iface_for("8.8.8.8")
    gw = default_gateway(iface)
    names = _names()
    out = []
    known = [v.get("ip") for v in names.values()]
    for ip, mac in find_cameras(iface, known):
        d = describe(ip, mac, gw)
        out.append({"ip": ip, "mac": mac, **d,
                    "name": names.get(_key(mac), {}).get("name"),
                    "key_known": bool(_cached_enr(mac)),
                    "ready": bool(_cached_enr(mac) and _cached_uid(mac)),
                    "motion": bool(names.get(_key(mac), {}).get("motion")),
                    "online": None,
                    "thumb": lib.thumb(mac),
                    "recordings": len(lib.recordings(mac))})
    _check_online([c for c in out if c["ready"]], iface)
    return out


def _check_online(cams, iface):
    """Mark which ready cameras answer on the LAN (in parallel, ~1.5 s): a
    camera that is switched off in the Wyze app, or offline, can't be
    watched."""
    from .cli import _cached_enr, _cached_uid
    from .direct import answers

    def one(c):
        try:
            c["online"] = answers(c["ip"], _cached_uid(c["mac"]),
                                  _cached_enr(c["mac"]), c["mac"], iface)
        except OSError:
            c["online"] = None
    threads = [threading.Thread(target=one, args=(c,)) for c in cams]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)


def make_app(token, hub, ctl, lib):
    from aiohttp import web

    @web.middleware
    async def auth(request, handler):
        # the link carries a one-time token; it becomes a cookie, so the
        # address bar shows no secret and other pages can't drive the API
        if request.query.get("t") == token:
            resp = web.HTTPFound(request.path)
            resp.set_cookie("wyzecrack", token, httponly=True,
                            samesite="Strict")
            raise resp
        if request.cookies.get("wyzecrack") != token:
            return web.Response(status=403, text="Open the link wyzecrack "
                                "printed in its terminal.")
        return await handler(request)

    async def index(_):
        return web.FileResponse(WEB / "index.html")

    async def cameras(_):
        loop = asyncio.get_running_loop()
        cams = await loop.run_in_executor(None, _cameras, lib)
        await loop.run_in_executor(None, ctl.ensure_captures, cams)
        for c in cams:
            c["capturing"] = ctl.capture_status(c["mac"])
        return web.json_response(cams)

    async def motion(request):
        body = await request.json()
        await asyncio.get_running_loop().run_in_executor(
            None, ctl.set_motion, body, bool(body.get("on")))
        return web.json_response({"ok": True,
                                  "capturing": ctl.capture_status(body["mac"])})

    async def rekey(request):
        from .cli import _forget_key
        body = await request.json()
        if ctl.busy():
            return web.json_response({"error": "busy"}, status=409)
        _forget_key(body["mac"])
        return web.json_response({"ok": True})

    async def start(request):
        cam = await request.json()
        if not ctl.start(cam):
            return web.json_response({"error": "already running"}, status=409)
        return web.json_response({"ok": True})

    async def stop(_):
        ctl.request_stop()
        return web.json_response({"ok": True})

    async def name(request):
        body = await request.json()
        _save_name(body["mac"], body["name"], body.get("ip"))
        return web.json_response({"ok": True})

    async def library(request):
        mac = request.query.get("mac")
        return web.json_response({"recordings": lib.recordings(mac),
                                  "motion": lib.motion(mac)})

    async def files(request):
        p = lib.resolve(request.match_info["rel"])
        if not p:
            raise web.HTTPNotFound()
        return web.FileResponse(p)

    async def quit_(request):
        ctl.request_stop()
        request.app["quit"].set()
        return web.json_response({"ok": True})

    async def ws(request):
        sock = web.WebSocketResponse(heartbeat=20, max_msg_size=0)
        await sock.prepare(request)
        hub.clients.add(sock)
        await sock.send_str(json.dumps({"kind": "state", **ctl.state}))
        try:
            async for msg in sock:
                if msg.type != web.WSMsgType.TEXT:
                    continue
                try:
                    want = json.loads(msg.data)
                except ValueError:
                    continue
                # the page can't decode H.264: send it still frames instead
                if want.get("kind") == "want" and want.get("video") == "jpeg":
                    hub.jpeg.add(sock)
        finally:
            hub.clients.discard(sock)
            hub.jpeg.discard(sock)
        return sock

    async def ticker(app):
        async def tick():
            while True:
                await asyncio.sleep(1)
                st = ctl.stats()
                if st:
                    hub.send_json({"kind": "stats", **st})
        task = asyncio.ensure_future(tick())
        yield
        task.cancel()

    app = web.Application(middlewares=[auth])
    app["quit"] = asyncio.Event()
    app.cleanup_ctx.append(ticker)
    app.add_routes([
        web.get("/", index), web.get("/api/cameras", cameras),
        web.post("/api/start", start), web.post("/api/stop", stop),
        web.post("/api/name", name), web.get("/api/library", library),
        web.post("/api/motion", motion), web.post("/api/rekey", rekey),
        web.post("/api/quit", quit_), web.get("/ws", ws),
        web.get("/files/{rel:.+}", files),
        web.static("/assets", WEB),
    ])
    return app


class _Tee:
    def __init__(self, stream, f):
        self.stream, self.f = stream, f

    def write(self, data):
        try:
            self.f.write(time.strftime("%H:%M:%S ") + data if data.strip()
                         else data)
            self.f.flush()
        except OSError:
            pass
        return self.stream.write(data)

    def flush(self):
        self.stream.flush()

    def __getattr__(self, name):
        return getattr(self.stream, name)


def _tee(path):
    """Keep what the terminal shows in a log next to the recordings, for
    working out what happened later."""
    try:
        f = open(path, "a")
    except OSError:
        return
    f.write(f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} wyzecrack started\n")
    sys.stdout = _Tee(sys.stdout, f)


def open_browser(url):
    """Open url in the invoking user's desktop session, not as root."""
    user = os.environ.get("SUDO_USER")
    env = {k: os.environ[k] for k in ("DISPLAY", "WAYLAND_DISPLAY",
                                      "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS")
           if k in os.environ}
    if not env.get("DISPLAY") and not env.get("WAYLAND_DISPLAY"):
        return False
    opener = shutil.which("xdg-open")
    if not opener:
        return False
    cmd = [opener, url]
    if user and os.geteuid() == 0:
        cmd = ["sudo", "-u", user, "env", *(f"{k}={v}" for k, v in env.items())] + cmd
    try:
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
        return True
    except OSError:
        return False


def serve(listen="127.0.0.1", port=0, out="captures", browser=True):
    from aiohttp import web
    import socket as _socket
    token = secrets.token_urlsafe(18)
    hub = Hub()
    lib = Library(out)
    lib.root.mkdir(parents=True, exist_ok=True)
    _tee(lib.root / "wyzecrack.log")
    from .changes import Changes, signals_held
    journal = Changes()
    journal.acquire()            # one wyzecrack at a time; replays a crash's
    ctl = Controller(hub, lib, journal)
    app = make_app(token, hub, ctl, lib)
    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    sock.bind((listen, port or 0))
    host = listen if listen != "0.0.0.0" else _socket.gethostname()
    url = f"http://{host}:{sock.getsockname()[1]}/?t={token}"

    async def main():
        hub.loop = asyncio.get_running_loop()
        import signal as _signal
        for sig in (_signal.SIGINT, _signal.SIGTERM, _signal.SIGHUP):
            hub.loop.add_signal_handler(sig, app["quit"].set)
        runner = web.AppRunner(app, handle_signals=False)
        await runner.setup()
        site = web.SockSite(runner, sock)
        await site.start()
        print(f"\n  wyzecrack is running: {url}\n")
        if browser and open_browser(url):
            print("  (opened in your browser; Ctrl-C here quits)\n")
        else:
            print("  Open that link in a browser. Ctrl-C here quits.\n")
        try:
            await app["quit"].wait()
            print("[*] stopping, putting the camera's network back...")
            ctl.request_stop()
            for _ in range(300):          # let the session tear down
                if not ctl.busy():
                    break
                await asyncio.sleep(0.1)
        finally:
            await runner.cleanup()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    finally:
        if ctl.busy():
            ctl.request_stop()
            ctl.thread.join(30)
        ctl.stop_captures()
        with signals_held():
            journal.undo_all()               # whatever is left, if anything
        journal.release()
        for t in ctl.saving:                # finish saving the last video
            if t.is_alive():
                print("[*] saving the last recording...")
                t.join(120)
    print("[+] bye")
    return 0
