"""wyze-splice's graphical front end: a small local web app.

`wyze-splice` (no command) starts it: a server on 127.0.0.1 with a
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
STATE_DIR = Path(os.environ.get("WYZE_SPLICE_STATE", "/var/lib/wyze-splice"))
MSG_VIDEO, MSG_AUDIO = 1, 2


# -- camera directory -----------------------------------------------------
def _names():
    try:
        return json.loads((STATE_DIR / "cameras.json").read_text())
    except (OSError, ValueError):
        return {}


def _save_name(mac, name, ip=None):
    d = _names()
    d[_key(mac)] = {"name": name.strip()[:60], "ip": ip}
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = STATE_DIR / "cameras.json.tmp"
    tmp.write_text(json.dumps(d, indent=1) + "\n")
    os.replace(tmp, STATE_DIR / "cameras.json")


def _key(mac):
    return mac.replace(":", "").upper()


def _slug(text):
    keep = "".join(c if c.isalnum() else "-" for c in text.lower())
    return "-".join(p for p in keep.split("-") if p)[:40] or "camera"


class Library:
    """Everything saved under the captures root: recordings (one directory
    per live view, with meta.json) and motion events, per camera."""

    def __init__(self, root):
        self.root = Path(root).absolute()

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
            out.append({"id": d.name, "t": d.stat().st_mtime,
                        "clip": self.url(clip) if clip.exists() else None,
                        "snapshot": self.url(snap) if snap.exists() else None})
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
    def __init__(self, hub, library):
        self.hub, self.lib = hub, library
        self.thread = None
        self.stop = threading.Event()
        self.state = {"phase": "idle"}
        self.camera = None
        self.live = None
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
                      "error": None, "mode": "direct"}
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
        armed = Armed(args, cam_dir, splice=False, harvest=True)
        armed.stop = self.stop
        armed.on_motion = self._motion
        self._step("enr", "active", {"seen": 0})
        with armed:
            return obtain_key(armed, args)

    def _watch(self, cam, cam_dir, enr, uid):
        """Live views straight from the camera until Stop; reconnects when
        the camera hangs up, saving each stretch as its own recording."""
        from .changes import Changes, signals_held
        from .cli import _inhibit_sleep, _release_inhibitor
        from .direct import CameraGone, Direct, open_firewall
        from .netutil import local_ip_for
        failures = 0                 # attempts in a row without a picture
        sleep_lock = _inhibit_sleep("showing a live view")
        try:
            while not self.stop.is_set():
                self.set(phase="connecting", hint=None,
                         session={"state": "direct"})
                out = cam_dir / time.strftime("%Y%m%d-%H%M%S")
                out.mkdir(parents=True, exist_ok=True)
                self._new_live()
                changes = Changes()
                changes.acquire()
                d = None
                try:
                    d = Direct(cam["ip"], uid, enr, cam["mac"],
                               local_ip=local_ip_for(cam["ip"]),
                               on_av=self._on_av, av_log=str(out / "av.bin"),
                               stop=self.stop)
                    open_firewall(changes, cam["ip"], d.port)
                    d.open()
                    print(f"[+] live from {cam['ip']}")
                    while not self.stop.is_set():
                        d.pump(0.3)
                except (CameraGone, ValueError, OSError) as e:
                    # ValueError: a DTLS handshake that went wrong; OSError:
                    # no route (the host's network is still coming up)
                    print(f"[*] {e}")
                finally:
                    if d:
                        d.close()
                    with signals_held():
                        changes.undo_all()
                    changes.release()
                had_video = self.live_stats.get("frames", 0) > 0
                self._session_end(out, had_video)
                if self.stop.is_set():
                    break
                failures = 0 if had_video else failures + 1
                if failures >= 3:
                    self.set(phase="error",
                             error="The camera doesn't answer. Is it switched "
                                   "on in the Wyze app? (A camera that is "
                                   "turned off can't be watched.)")
                    return
                self.hub.send_json({"kind": "toast", "text":
                                    "The camera hung up · reconnecting"
                                    if had_video else "Trying again…"})
                self.stop.wait(1.5)
        finally:
            _release_inhibitor(sleep_lock)

    def _run_splice(self, cam, cam_dir):
        """The fallback: splice the live views the Wyze app opens."""
        from .cli import Armed
        args = SimpleNamespace(target=cam["ip"], on_path=False, enr=None,
                               reharvest=False, pass_through=False,
                               journal=False, events_dir=cam_dir / "events")
        armed = Armed(args, cam_dir, splice=True)
        armed.stop = self.stop
        armed.on_motion = self._motion
        self.set(mode="splice")
        self._step("onpath", "active")
        with armed:
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
    def _new_live(self):
        self.live = LiveAssembler(on_video=self._video, on_audio=self._audio)
        self.live_stats = {"frames": 0, "t0": None, "recent": [], "size": None,
                           "codec": None}

    def _on_av(self, direction, ts, plaintext):
        if self.live:
            self.live.feed(direction, ts, plaintext)

    def _video(self, f):
        if self.state.get("phase") != "live":
            self.set(phase="live", session={"state": "live",
                                            "since": time.time()})
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
        self.hub.send_bytes(struct.pack(">BBd", MSG_VIDEO, f.key, f.t) + f.data)

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
            r = export(str(out / "av.bin"), str(out))
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
        self.backlog = {}

    def _send(self, data):
        for ws in list(self.clients):
            if ws.closed:
                self.clients.discard(ws)
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

    def send_bytes(self, data):
        if self.clients:
            self._post(data)

    def _post(self, data):
        try:
            if self.loop and not self.loop.is_closed():
                self.loop.call_soon_threadsafe(self._send, data)
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
            resp.set_cookie("wyze_splice", token, httponly=True,
                            samesite="Strict")
            raise resp
        if request.cookies.get("wyze_splice") != token:
            return web.Response(status=403, text="Open the link wyze-splice "
                                "printed in its terminal.")
        return await handler(request)

    async def index(_):
        return web.FileResponse(WEB / "index.html")

    async def cameras(_):
        cams = await asyncio.get_running_loop().run_in_executor(None, _cameras, lib)
        return web.json_response(cams)

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
            async for _ in sock:
                pass
        finally:
            hub.clients.discard(sock)
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
    f.write(f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} wyze-splice started\n")
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
    _tee(lib.root / "wyze-splice.log")
    ctl = Controller(hub, lib)
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
        print(f"\n  wyze-splice is running: {url}\n")
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
        for t in ctl.saving:                # finish saving the last video
            if t.is_alive():
                print("[*] saving the last recording...")
                t.join(120)
    print("[+] bye")
    return 0
