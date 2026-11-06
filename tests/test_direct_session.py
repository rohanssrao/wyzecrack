"""direct.py against a fake camera (tests/fakecam.py): the whole LAN
session in both framings, and the ways it can go wrong."""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from fakecam import CC51, ENR, IOTC, MAC, UID, FakeCamera  # noqa: E402

from wyzecrack import direct  # noqa: E402
from wyzecrack.live import LiveAssembler  # noqa: E402


@pytest.fixture(scope="module")
def h264():
    from test_jpegfeed import _h264_frames
    return _h264_frames(n=20)


def _session(cam, enr=ENR, on_av=None, **kw):
    d = direct.Direct("127.0.0.1", UID, enr, MAC, local_ip="127.0.0.1",
                      disco_port=cam.disco_port, **kw)
    d.record(on_av=on_av)
    return d


@pytest.mark.parametrize("framing", [CC51, IOTC])
def test_live_view_and_hang_up(framing, h264):
    cam = FakeCamera(UID, ENR, MAC, framing=framing, frames=h264)
    pictures = []
    live = LiveAssembler(on_video=pictures.append)
    d = _session(cam, on_av=live.feed)
    try:
        d.open(timeout=10)
        assert d.framing == framing
        end = time.monotonic() + 3
        while time.monotonic() < end and len(pictures) < 5:
            d.pump(0.2)
        assert len(pictures) >= 5 and pictures[0].key
        ev = cam.events
        assert ev.index("discovery") < ev.index("handshake") < ev.index("login")
        assert "keepalive" in ev
    finally:
        d.close()
    time.sleep(0.2)
    # hanging up switched the camera's video and audio off, and (0xCC51
    # framing) ended the session rather than leaving it to time out
    assert "K10010 0102" in cam.events and "K10010 0202" in cam.events
    assert not cam.media_on[1] and not cam.media_on[2]
    if framing == CC51:
        assert cam.events[-1] == "close"
    cam.close()


def test_known_framing_sends_only_its_own_discovery(h264):
    cam = FakeCamera(UID, ENR, MAC, framing=CC51, frames=h264)
    d = _session(cam, framing=CC51)
    sent = []
    orig = d._send_iotc
    d._send_iotc = lambda pkt, to=None: (sent.append(pkt), orig(pkt, to))
    try:
        d.open(timeout=10)
        assert not sent                       # no older-framing packets at all
    finally:
        d.close()
        cam.close()


def test_slow_camera_is_waited_for(h264):
    cam = FakeCamera(UID, ENR, MAC, frames=h264, login_delay=3.0)
    d = _session(cam)
    try:
        t0 = time.monotonic()
        d.open(timeout=10)
        assert time.monotonic() - t0 >= 3.0
    finally:
        d.close()
        cam.close()


@pytest.mark.parametrize("framing", [CC51, IOTC])
def test_wrong_key_is_ignored_by_the_camera(framing):
    cam = FakeCamera(UID, ENR, MAC, framing=framing)
    d = _session(cam, enr="AAAAAAAAAAAAAAAA")
    try:
        with pytest.raises(direct.CameraGone, match="discovery"):
            d.open(timeout=1.5)
        assert d.framing is None and "handshake" not in cam.events
    finally:
        d.close()
        cam.close()


def test_camera_that_goes_quiet_ends_the_session(h264, monkeypatch):
    monkeypatch.setattr(direct, "SILENT_AFTER", 1.0)
    cam = FakeCamera(UID, ENR, MAC, frames=h264)
    d = _session(cam)
    try:
        d.open(timeout=10)
        cam.quiet = True
        with pytest.raises(direct.CameraGone, match="quiet"):
            end = time.monotonic() + 5
            while time.monotonic() < end:
                d.pump(0.2)
    finally:
        d.close()
        cam.close()


@pytest.mark.parametrize("framing", [CC51, IOTC])
def test_a_second_session_after_hanging_up(framing, h264):
    """The page reconnects when a camera hangs up: a new session to the
    same camera must work."""
    cam = FakeCamera(UID, ENR, MAC, framing=framing, frames=h264)
    try:
        for _ in range(2):
            pictures = []
            live = LiveAssembler(on_video=pictures.append)
            d = _session(cam, on_av=live.feed)
            try:
                d.open(timeout=10)
                end = time.monotonic() + 3
                while time.monotonic() < end and len(pictures) < 5:
                    d.pump(0.2)
                assert len(pictures) >= 5
            finally:
                d.close()
        assert cam.sessions == 2 and cam.events.count("login") == 2
    finally:
        cam.close()


def test_a_slow_session_is_hedged_with_a_second_one(h264, monkeypatch):
    """The camera leaves the first session's AV login unanswered; a second
    session started beside it gets through, and the first hangs up."""
    monkeypatch.setattr(direct, "HEDGE_AFTER", 0.5)
    cam = FakeCamera(UID, ENR, MAC, frames=h264, ignore_logins={1})
    made = []

    def make(stop):
        made.append(_session(cam, stop=stop))
        return made[-1]

    pictures = []
    live = LiveAssembler(on_video=pictures.append)
    try:
        t0 = time.monotonic()
        d = direct.open_first(make, timeout=10, on_av=live.feed)
        assert d is made[1] and d.tries == 2 and time.monotonic() - t0 < 5
        assert made[0].sock.fileno() == -1          # the slow one hung up
        end = time.monotonic() + 3
        while time.monotonic() < end and len(pictures) < 5:
            d.pump(0.2)
        assert len(pictures) >= 5
        d.close()
    finally:
        cam.close()


@pytest.mark.parametrize("framing", [CC51, IOTC])
def test_no_hedging_for_a_camera_that_does_not_answer(framing, h264, monkeypatch):
    """A wrong key: the v3 doesn't answer discovery, the v2 doesn't set up
    the session. One session, and an answer that says so."""
    monkeypatch.setattr(direct, "HEDGE_AFTER", 0.3)
    monkeypatch.setattr(direct, "DISCO_GIVE_UP", 1.5)
    cam = FakeCamera(UID, ENR, MAC, framing=framing, frames=h264)
    made = []

    def make(stop):
        made.append(_session(cam, enr="XXXXXXXXXXXXXXXX", stop=stop))
        return made[-1]

    try:
        t0 = time.monotonic()
        with pytest.raises(direct.CameraGone, match="discovery"):
            direct.open_first(make, timeout=10)
        assert len(made) == 1 and time.monotonic() - t0 < 3
    finally:
        cam.close()


def test_a_camera_that_comes_back_takes_a_new_session(h264, monkeypatch):
    """What `watch` and the page do when the camera drops off and returns."""
    monkeypatch.setattr(direct, "SILENT_AFTER", 1.0)
    cam = FakeCamera(UID, ENR, MAC, frames=h264, quiet_after=1.0, quiet_for=2.0)
    try:
        d = _session(cam)
        d.open(timeout=10)
        with pytest.raises(direct.CameraGone, match="quiet"):
            while True:
                d.pump(0.2)
        d.close()
        time.sleep(1.5)                       # back by now
        d = _session(cam)
        d.open(timeout=10)
        d.close()
        assert cam.events.count("login") == 2 and "back" in cam.events
    finally:
        cam.close()
