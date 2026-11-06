"""Turn the decrypted media stream into playable frames as it arrives.

Feed it every plaintext record from the camera (direct.Direct's on_av);
it calls on_video(frame) for each complete, decodable H.264 access unit
and on_audio(ts, pcm) for each audio frame (signed 16-bit little-endian
PCM, 8 kHz mono, the camera's live audio format: codec 0x8C).
"""
import struct

from .media import parse_media

VIDEO_CHANNELS = (5, 6, 7)
AUDIO_CHANNEL = 3
KEEP_PARTIAL = 64           # partial frames kept while waiting for chunks


def nal_types(blob):
    out, i = [], blob.find(b"\x00\x00\x01")
    while i != -1 and i + 3 < len(blob):
        out.append(blob[i + 3] & 0x1F)
        i = blob.find(b"\x00\x00\x01", i + 3)
    return out


def sps_of(blob):
    i = blob.find(b"\x00\x00\x01")
    while i != -1 and i + 3 < len(blob):
        if blob[i + 3] & 0x1F == 7:
            return blob[i + 3:i + 7]
        i = blob.find(b"\x00\x00\x01", i + 3)
    return None


def codec_string(sps):
    """avc1.PPCCLL for a WebCodecs decoder, from the SPS NAL's first bytes."""
    return "avc1." + sps[1:4].hex().upper()


def sps_size(sps_nal):
    """(width, height) from an SPS NAL (for the common 4:2:0 profiles), or
    None. Only for display; decoders read the SPS themselves."""
    try:
        bits = _Bits(_unescape(sps_nal[1:]))
        profile = bits.u(8)
        bits.u(16)
        bits.ue()
        if profile in (100, 110, 122, 244, 44, 83, 86, 118, 128):
            if bits.ue() == 3:
                bits.u(1)
            bits.ue(), bits.ue()
            bits.u(1)
            if bits.u(1):
                for i in range(8):
                    if bits.u(1):
                        _skip_scaling(bits, 16 if i < 6 else 64)
        bits.ue()
        poc = bits.ue()
        if poc == 0:
            bits.ue()
        elif poc == 1:
            bits.u(1), bits.se(), bits.se()
            for _ in range(bits.ue()):
                bits.se()
        bits.ue(), bits.u(1)
        w = (bits.ue() + 1) * 16
        mbs_only = None
        h_units = bits.ue() + 1
        mbs_only = bits.u(1)
        h = h_units * 16 * (2 - mbs_only)
        if not mbs_only:
            bits.u(1)
        bits.u(1)
        if bits.u(1):
            l, r, t, b = bits.ue(), bits.ue(), bits.ue(), bits.ue()
            w -= 2 * (l + r)
            h -= 2 * (t + b) * (2 - mbs_only)
        return w, h
    except (IndexError, ValueError):
        return None


def _unescape(b):
    return b.replace(b"\x00\x00\x03", b"\x00\x00")


def _skip_scaling(bits, n):
    last = nxt = 8
    for _ in range(n):
        if nxt:
            nxt = (last + bits.se()) % 256
        last = nxt or last


class _Bits:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def u(self, n):
        v = 0
        for _ in range(n):
            byte = self.data[self.pos >> 3]
            v = (v << 1) | ((byte >> (7 - (self.pos & 7))) & 1)
            self.pos += 1
        return v

    def ue(self):
        z = 0
        while self.u(1) == 0:
            z += 1
            if z > 31:
                raise ValueError("bad exp-golomb")
        return (1 << z) - 1 + self.u(z)

    def se(self):
        v = self.ue()
        return (v + 1) // 2 if v & 1 else -(v // 2)


class Frame:
    __slots__ = ("t", "data", "key", "sps")

    def __init__(self, t, data, key, sps):
        self.t, self.data, self.key, self.sps = t, data, key, sps


REORDER_WAIT = 0.5          # s to wait for a missing frame before giving up


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
        self.last_sps = None
        self.size = None

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
        key = 5 in nal_types(blob)
        if key:
            self.gop_ok = True
            sps = sps_of(blob)
            if sps:
                if sps != self.last_sps:
                    self.size = sps_size(blob[blob.find(sps):]) or self.size
                self.last_sps = sps
        if not self.gop_ok or self.last_sps is None:
            return
        if self.on_video:
            self.on_video(Frame(t, blob, key, self.last_sps))
