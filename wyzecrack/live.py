"""Turn the decrypted media stream into playable frames as it arrives.

Feed it every plaintext record from the camera (direct.Direct's on_av);
it calls on_video(frame) for each complete, decodable H.264 access unit
and on_audio(ts, pcm) for each audio frame (signed 16-bit little-endian
PCM, 8 kHz mono).
"""
from .media import AUDIO_CHANNEL, VIDEO_CHANNELS, nal_units, parse_media

KEEP_PARTIAL = 64           # partial frames kept while waiting for chunks
REORDER_WAIT = 0.5          # s to wait for a missing frame before giving up


class Frame:
    """One access unit: its arrival time, Annex-B bytes, whether it is a
    key frame, and the WebCodecs codec string of its stream."""
    __slots__ = ("t", "data", "key", "codec")

    def __init__(self, t, data, key, codec):
        self.t, self.data, self.key, self.codec = t, data, key, codec


class LiveAssembler:
    """Reassembles chunked TUTK media frames as they arrive and releases
    video frames in frame-number order (numbers run on across the video
    channels). A frame that does not complete within REORDER_WAIT breaks
    its GOP: nothing more is released until the next complete IDR, since
    every P-frame references the one before it."""

    def __init__(self, on_video=None, on_audio=None):
        self.on_video, self.on_audio = on_video, on_audio
        self.partial = {}            # (ch, frame_no) -> state
        self.done = set()            # recently completed keys (duplicates)
        self.ready = {}              # frame_no -> (t, blob) awaiting order
        self.next_no = None
        self.wait_since = None
        self.gop_ok = False
        self.codec = None

    def feed(self, ts, plaintext):
        m = parse_media(plaintext)
        if m is None:
            return
        ch, frame_no, cidx, payload, end, count = m
        key = (ch, frame_no)
        if key in self.done:
            return
        if ch == AUDIO_CHANNEL:
            if end and self.on_audio:
                self._done_add(key)
                self.on_audio(ts, payload)
            return
        if ch not in VIDEO_CHANNELS:
            return
        f = self.partial.get(key)
        if f is None:
            f = self.partial[key] = {"t": ts, "chunks": {}, "count": 0,
                                     "end": False}
            if len(self.partial) > KEEP_PARTIAL:
                oldest = min(self.partial, key=lambda k: self.partial[k]["t"])
                del self.partial[oldest]
        f["chunks"].setdefault(cidx, payload)
        f["count"] = max(f["count"], count)
        f["end"] |= end
        need = set(range(max(0, f["count"] - 1))) | {0xFFFF}
        if f["end"] and need <= set(f["chunks"]):
            del self.partial[key]
            self._done_add(key)
            blob = b"".join(pl for _, pl in sorted(f["chunks"].items()))
            self.ready[frame_no] = (f["t"], blob)
        self._release(ts)

    def _done_add(self, key):
        self.done.add(key)
        if len(self.done) > 4096:
            self.done = set(sorted(self.done, key=lambda k: k[1])[-2048:])

    def _release(self, now):
        while self.ready:
            if self.next_no is None or self.next_no in self.ready:
                n = self.next_no if self.next_no in self.ready else min(self.ready)
                t, blob = self.ready.pop(n)
                self.next_no = n + 1
                self.wait_since = None
                self._emit(t, blob)
                continue
            # a gap: wait a little for the missing frame, then give up on
            # it and resume at the next IDR
            if self.wait_since is None:
                self.wait_since = now
            if now - self.wait_since < REORDER_WAIT:
                return
            self.gop_ok = False
            self.next_no = min(self.ready)
            self.wait_since = None
        if len(self.ready) > 256:
            self.ready.clear()

    def _emit(self, t, blob):
        units = nal_units(blob)
        key = any(typ == 5 for typ, _ in units)
        if key:
            self.gop_ok = True
            for typ, nal in units:
                if typ == 7 and len(nal) >= 4:
                    # avc1.PPCCLL: profile, constraints, level
                    self.codec = "avc1." + nal[1:4].hex().upper()
        if self.gop_ok and self.codec and self.on_video:
            self.on_video(Frame(t, blob, key, self.codec))
