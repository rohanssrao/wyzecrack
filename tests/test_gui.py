"""The GUI server: token login, the library, and the live assembler feed."""
import asyncio
import json
import os

import pytest

aiohttp = pytest.importorskip("aiohttp")
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402

from wyze_splice import gui  # noqa: E402


class FakeController:
    def __init__(self):
        self.state = {"phase": "idle"}
        self.started = None

    def start(self, cam):
        self.started = cam
        return True

    def request_stop(self):
        pass

    def busy(self):
        return False

    def stats(self):
        return None


def _library(tmp_path):
    lib = gui.Library(tmp_path)
    d = tmp_path / "my-camera-A1B2C3" / "20260101-001000"
    d.mkdir(parents=True)
    (d / "video.mp4").write_bytes(b"mp4")
    (d / "frame.jpg").write_bytes(b"jpg")
    (d / "meta.json").write_text(json.dumps({"mac": "d0:3f:27:a1:b2:c3",
                                             "started": 1, "seconds": 33.2}))
    ev = tmp_path / "my-camera-A1B2C3" / "events" / "20260101-000500_1767225900"
    ev.mkdir(parents=True)
    (ev / "clip.mp4").write_bytes(b"clip")
    return lib


def run(coro):
    return asyncio.run(coro)


def test_token_login_api_and_files(tmp_path):
    lib = _library(tmp_path)
    ctl = FakeController()

    async def go():
        app = gui.make_app("tok", gui.Hub(), ctl, lib)
        async with TestClient(TestServer(app)) as c:
            assert (await c.get("/api/library")).status == 403
            r = await c.get("/?t=tok", allow_redirects=False)
            assert r.status == 302 and "wyze_splice=tok" in r.headers["Set-Cookie"]
            c.session.cookie_jar.update_cookies({"wyze_splice": "tok"})
            lib_ = await (await c.get("/api/library?mac=d0:3f:27:a1:b2:c3")).json()
            assert [r["seconds"] for r in lib_["recordings"]] == [33.2]
            assert len(lib_["motion"]) == 1
            assert (await c.get(lib_["recordings"][0]["video"])).status == 200
            # nothing outside the captures root is served
            assert (await c.get("/files/../../etc/passwd")).status == 404
            r = await c.post("/api/start", json={"ip": "192.168.1.20", "mac": "x"})
            assert r.status == 200 and ctl.started["ip"] == "192.168.1.20"
    run(go())


def test_library_thumb_prefers_recordings(tmp_path):
    lib = _library(tmp_path)
    assert lib.thumb("D0:3F:27:A1:B2:C3").endswith("frame.jpg")
    assert lib.thumb("aa:bb:cc:dd:ee:ff") is None
