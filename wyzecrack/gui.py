"""wyzecrack's graphical front end: a small local web app.

`wyzecrack` (no command) starts it: a server on 127.0.0.1 with a
one-time token in its URL, opened in the invoking user's browser. The page
lists the Wyze cameras on the LAN; picking one plays its live view in the
page (video decoded by the browser with WebCodecs, audio with WebAudio)
and records it.

The first time with a camera, the tool reads its key (keys.camera_key);
every live view is then a direct LAN session (view.py) that changes
nothing on the network. Motion clips, when turned on for a camera, are
copied for as long as the page is open (onpath.Reroute).

The server runs in the main thread (asyncio); a live view runs in a
worker thread.
"""
import asyncio
import contextlib
import json
import os
import secrets
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

from aiohttp import web

from . import keys
from .keys import STATE_DIR, mac_key

WEB = Path(__file__).parent / "web"
QUIT = web.AppKey("quit", asyncio.Event)
MSG_VIDEO, MSG_AUDIO, MSG_JPEG = 1, 2, 3
NO_ANSWER = ("Is it switched on in the Wyze app? A camera that is turned off "
             "can't be watched. If it is on and was set up again in the Wyze "
             "app, its key has changed.")


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
    d.setdefault(mac_key(mac), {}).update(fields)
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = STATE_DIR / "cameras.json.tmp"
    tmp.write_text(json.dumps(d, indent=1) + "\n")
    os.replace(tmp, STATE_DIR / "cameras.json")


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

    def camera_dir(self, cam):
        name = cam.get("name") or cam.get("model") or "camera"
        return self.root / f"{_slug(name)}-{mac_key(cam['mac'])[-6:]}"

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
            out.append({**m, "video": self.url(d / "video.mp4"),
                        "thumb": self.url(d / "frame.jpg")
                        if (d / "frame.jpg").exists() else None})
        return sorted(out, key=lambda r: r.get("started", 0), reverse=True)

    def motion(self, mac=None):
        out = []
        for d in self.root.glob("*/events/*/"):
            cam = d.parent.parent.name
            if mac and not cam.endswith(mac_key(mac)[-6:]):
                continue
            clip, snap = d / "clip.mp4", d / "snapshot.jpg"
            if not clip.exists() and not snap.exists():
                continue
            try:
                seconds = json.loads((d / "meta.json").read_text()).get("seconds")
            except (OSError, ValueError):
                seconds = None
            out.append({"t": d.stat().st_mtime,
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


# -- the live view, in a worker thread ------------------------------------
class Controller:
    def __init__(self, hub, library, journal):
        self.hub, self.lib = hub, library
        self.journal = journal       # the page's Changes; parts take scopes
        self.captures = {}           # MAC -> onpath.Reroute saving clips
        self._cap_lock = threading.RLock()
        self._paused = None          # MAC whose capture stepped aside
        self.thread = None
        self.stop = threading.Event()
        self.state = {"phase": "idle"}
        self.camera = None
        self.jpeg = None             # jpegfeed.JpegFeed while a page wants it
        self.codec = None            # of the stream the page decodes
        self.since = None            # when this view's first picture came
        self.saving = []             # export threads still running

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
                      "error": None, "error_kind": None}
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

    def _run(self):
        from .cli import give_to_user
        cam = self.camera
        cam_dir = self.lib.camera_dir(cam)
        started = time.time()
        try:
            # reading a key routes the camera through this host on its
            # own: a motion capture of the same camera steps aside
            paused = (self._capture_paused(cam["mac"])
                      if not keys.cached(cam["mac"]).get("enr")
                      else contextlib.nullcontext())
            with paused:
                got = keys.camera_key(self.journal, cam["ip"], cam["mac"],
                                      stop=self.stop, on_step=self._step,
                                      events_dir=cam_dir / "events",
                                      on_motion=self._motion)
            if got and not self.stop.is_set():
                self._watch(cam, cam_dir, *got)
        except SystemExit as e:
            self.set(phase="error", error=str(e.code or e))
        except Exception as e:  # noqa: BLE001
            self.set(phase="error", error=f"{type(e).__name__}: {e}")
        finally:
            if cam_dir.exists():
                give_to_user(cam_dir.parent, started)
            if self.state.get("phase") != "error":
                self.set(phase="idle", since=None)
            self.hub.send_json({"kind": "library"})

    def _watch(self, cam, cam_dir, enr, uid):
        """The live view until Stop: everything from the click to Stop is
        one recording, reconnects included."""
        from .view import watch
        out = cam_dir / time.strftime("%Y%m%d-%H%M%S")
        out.mkdir(parents=True, exist_ok=True)
        self.since = None

        def status(kind, **info):
            if kind == "connecting":
                self._new_stream()
                self.set(phase="connecting")
            elif kind == "retry":
                self.hub.send_json({"kind": "toast", "text":
                                    "The camera hung up · reconnecting"
                                    if info["hung_up"] else "Trying again…"})
            elif kind == "gave_up":
                self.set(phase="error", error_kind="no_answer", error=NO_ANSWER)

        try:
            watch(self.journal, cam["ip"], cam["mac"], enr, uid,
                  str(out / "av.bin"), self.stop, on_video=self._video,
                  on_audio=self._audio, on_status=status)
        finally:
            self._new_stream()
            self._session_end(out)

    # live media -> the page
    def _new_stream(self):
        """A new session: its stream starts at its own key frame."""
        if self.jpeg:
            self.jpeg.close()
            self.jpeg = None
        self.codec = None

    def _video(self, f):
        if self.state.get("phase") != "live":
            # the page's recording timer runs from the view's first picture
            self.since = self.since or time.time()
            self.set(phase="live", since=self.since)
        if f.key and f.codec != self.codec:
            self.codec = f.codec
            self.hub.send_json({"kind": "video_config", "codec": f.codec})
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

    def _session_end(self, out):
        if self.since is None:            # no picture: nothing to keep
            shutil.rmtree(out, ignore_errors=True)
            return
        t = threading.Thread(target=self._save, args=(out,), daemon=True)
        self.saving = [x for x in self.saving if x.is_alive()] + [t]
        t.start()

    def _save(self, out):
        from .cli import give_to_user
        from .media import export
        self.hub.send_json({"kind": "saving"})
        started = time.time()
        try:
            r = export(str(out / "av.bin"), str(out))
        except Exception as e:  # noqa: BLE001
            r = {"mp4": None, "error": repr(e)}
        if r["error"]:
            # av.bin stays, for `wyzecrack extract` to try again
            self.hub.send_json({"kind": "toast", "level": "error",
                                "text": f"Could not save the video: {r['error']}"})
            return
        if not r["mp4"]:
            # the camera hung up before a whole picture
            shutil.rmtree(out, ignore_errors=True)
            return
        (out / "av.bin").unlink()
        meta = {"mac": (self.camera or {}).get("mac"),
                "started": out.stat().st_mtime, "seconds": round(r["seconds"], 1)}
        (out / "meta.json").write_text(json.dumps(meta, indent=1) + "\n")
        give_to_user(out.parent, started - 600)
        self.hub.send_json({"kind": "library", "new": self.lib.url(out / "video.mp4")})

    # -- motion clips, in the background -------------------------------
    def set_motion(self, cam, on):
        """Turn saving a camera's motion clips on or off (remembered)."""
        _save_camera(cam["mac"], motion=bool(on), ip=cam.get("ip"))
        with self._cap_lock:
            if on and self._paused != mac_key(cam["mac"]):
                self._start_capture(cam)
            elif not on:
                self._stop_capture(cam["mac"])
        self._send_captures()

    def ensure_captures(self, cams):
        """Start the captures turned on for cameras found on the LAN (and
        follow a camera to a new address)."""
        with self._cap_lock:
            for cam in cams:
                if not cam.get("motion") or self._paused == mac_key(cam["mac"]):
                    continue
                c = self.captures.get(mac_key(cam["mac"]))
                if c and c.running and c.ip == cam["ip"]:
                    continue
                if c:
                    self._stop_capture(cam["mac"])
                self._start_capture(cam)
        self._send_captures()

    def _start_capture(self, cam):
        from .onpath import Reroute
        key = mac_key(cam["mac"])
        if key in self.captures and self.captures[key].running:
            return
        c = Reroute(self.journal.scope(), cam["ip"], cam["mac"],
                    events_dir=self.lib.camera_dir(cam) / "events",
                    on_motion=self._motion)
        self.captures[key] = c
        try:
            c.start()
            print(f"[+] saving {cam['ip']}'s motion clips")
        except (SystemExit, Exception) as e:  # noqa: BLE001
            c.error = str(e.code or e) if isinstance(e, SystemExit) \
                else f"{type(e).__name__}: {e}"
            print(f"[!] can't save {cam['ip']}'s motion clips: {c.error}")

    def _stop_capture(self, mac):
        c = self.captures.pop(mac_key(mac), None)
        if c:
            c.stop()

    def stop_captures(self):
        with self._cap_lock:
            for mac in list(self.captures):
                self._stop_capture(mac)

    def _capturing(self, key, c):
        # a capture paused for a key read of the same camera is still
        # saving clips: the key read reads its uploads itself
        return c.running or self._paused == key

    def capture_status(self, mac):
        c = self.captures.get(mac_key(mac))
        if not c:
            return None
        return "on" if self._capturing(mac_key(mac), c) else "error"

    def _send_captures(self):
        self.hub.send_json({"kind": "captures", "captures": {
            k: {"on": self._capturing(k, c), "error": c.error}
            for k, c in self.captures.items()}})

    @contextlib.contextmanager
    def _capture_paused(self, mac):
        """Stop the camera's motion capture for the duration (a key read
        routes the camera itself), then start it again."""
        with self._cap_lock:
            c = self.captures.get(mac_key(mac))
            paused = bool(c and c.running)
            if paused:
                c.stop()
                self._paused = mac_key(mac)
        try:
            yield
        finally:
            if paused:
                with self._cap_lock:
                    self._paused = None
                    if self.captures.get(mac_key(mac)) is c:
                        try:
                            c.start()
                        except (SystemExit, Exception) as e:  # noqa: BLE001
                            c.error = str(e)
                self._send_captures()

    def _motion(self, path):
        print(f"[+] motion event: {path}")
        if path.name == "clip.mp4":
            snap = path.with_name("snapshot.jpg")
            self.hub.send_json({"kind": "motion", "clip": self.lib.url(path),
                                "snapshot": self.lib.url(snap)
                                if snap.exists() else None})


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
    from .discover import describe, find_cameras
    from .netutil import default_gateway, internet_iface
    iface = internet_iface()
    gw = default_gateway(iface)
    names = _names()
    out = []
    for ip, mac in find_cameras(iface, [v.get("ip") for v in names.values()]):
        known, saved = keys.cached(mac), names.get(mac_key(mac), {})
        out.append({"ip": ip, "mac": mac, **describe(ip, mac, gw),
                    "name": saved.get("name"), "motion": bool(saved.get("motion")),
                    "key_known": bool(known.get("enr")),
                    "ready": bool(known.get("enr") and known.get("uid")),
                    "online": None, "thumb": lib.thumb(mac)})
    _check_online([c for c in out if c["ready"]], iface)
    return out


def _check_online(cams, iface):
    """Mark which ready cameras answer on the LAN (in parallel, ~1.5 s): a
    camera that is switched off in the Wyze app, or offline, can't be
    watched."""
    from .direct import answers

    def one(c):
        known = keys.cached(c["mac"])
        try:
            c["online"] = answers(c["ip"], known["uid"], known["enr"], c["mac"],
                                  iface)
        except OSError:
            c["online"] = None
    threads = [threading.Thread(target=one, args=(c,)) for c in cams]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)


def make_app(token, hub, ctl, lib):
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
        body = await request.json()
        if ctl.busy():
            return web.json_response({"error": "busy"}, status=409)
        keys.forget_enr(body["mac"])
        return web.json_response({"ok": True})

    async def start(request):
        if not ctl.start(await request.json()):
            return web.json_response({"error": "already running"}, status=409)
        return web.json_response({"ok": True})

    async def stop(_):
        ctl.request_stop()
        return web.json_response({"ok": True})

    async def name(request):
        body = await request.json()
        _save_camera(body["mac"], name=body["name"].strip()[:60],
                     ip=body.get("ip"))
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
        request.app[QUIT].set()
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

    app = web.Application(middlewares=[auth])
    app[QUIT] = asyncio.Event()
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
    from .changes import Changes, signals_held
    token = secrets.token_urlsafe(18)
    hub = Hub()
    lib = Library(out)
    lib.root.mkdir(parents=True, exist_ok=True)
    journal = Changes()
    journal.acquire()            # one wyzecrack at a time; replays a crash's
    ctl = Controller(hub, lib, journal)
    app = make_app(token, hub, ctl, lib)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((listen, port))
    host = listen if listen != "0.0.0.0" else socket.gethostname()
    url = f"http://{host}:{sock.getsockname()[1]}/?t={token}"

    async def main():
        hub.loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            hub.loop.add_signal_handler(sig, app[QUIT].set)
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
            await app[QUIT].wait()
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
