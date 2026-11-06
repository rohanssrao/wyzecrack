"""jpegfeed.py: H.264 access units in, JPEG pictures out."""
import threading
import time
from fractions import Fraction

import pytest

av = pytest.importorskip("av")


def _h264_frames(n=10, w=320, h=240):
    """Encode n test pictures; returns their Annex-B access units."""
    try:
        enc = av.CodecContext.create("libx264", "w")
    except Exception:  # noqa: BLE001
        pytest.skip("no H.264 encoder in this PyAV build")
    enc.width, enc.height, enc.pix_fmt = w, h, "yuv420p"
    enc.time_base = Fraction(1, 20)
    enc.options = {"tune": "zerolatency", "bframes": "0"}
    out = []
    for i in range(n):
        frame = av.VideoFrame(w, h, "yuv420p")
        for plane in frame.planes:
            plane.update(bytes([(i * 20) % 255]) * plane.buffer_size)
        frame.pts = i
        out += [bytes(p) for p in enc.encode(frame)]
    out += [bytes(p) for p in enc.encode(None)]
    return out


class _F:
    def __init__(self, data, key):
        self.data, self.key, self.t = data, key, time.time()


def test_frames_become_jpegs():
    from wyzecrack.jpegfeed import JpegFeed
    units = _h264_frames()
    got, done = [], threading.Event()

    def on_jpeg(t, jpg):
        got.append(jpg)
        done.set()

    feed = JpegFeed(on_jpeg)
    try:
        for i, u in enumerate(units):
            feed.feed(_F(u, key=(i == 0)))
        assert done.wait(5)
        assert got[0][:3] == b"\xff\xd8\xff"            # a JPEG
    finally:
        feed.close()


def test_waits_for_a_key_frame():
    from wyzecrack.jpegfeed import JpegFeed
    feed = JpegFeed(lambda t, jpg: None)
    try:
        feed.feed(_F(b"\x00\x00\x00\x01\x41", key=False))
        assert feed.q.empty()
    finally:
        feed.close()
