"""Reassemble the decrypted TUTK/Wyze AV media of a session's av.bin.

av.bin entry format (written by direct.Direct): "<BdI" = direction byte
(1 = from the camera, 255 = a new session starts), capture timestamp
(double), payload length (u32 LE), then the decrypted DTLS application
record.

Media records from the camera carry a 28-byte header:

  [0]     channel: 0x03 audio, 0x05/0x06 video (I), 0x07 video (P)
  [1]     frame type: 0x08/0x09 start, 0x00/0x04 cont, 0x01/0x05 end
  [2]     protocol version: 0x0c (v3), 0x0b (v2)
  [8]     channel again
  [12:14] last chunk index of the frame
  [14:16] chunk index within the frame (0x0028 on end packets marks a
          40-byte FrameInfo trailer inside the payload, cf. go2rtc
          pkg/tutk frame.go ParsePacketHeader)
  [16:18] payload size
  [20:24] previous frame number
  [24:28] frame number
  [28:]   payload

Frame types with bit 0x08 set (0x08 start, 0x09 single-packet frame,
0x0d) carry 8 extra header bytes: every field above from [8] on sits 8
bytes later and the payload starts at [36]. Every I-frame's first chunk
and most single-packet P-frames use it, so parsing them with the short
layout corrupts exactly the frames that start a new picture. Bit 0x01
marks a frame's last packet.
"""

import os
import struct

AUDIO_CHANNEL = 3
VIDEO_CHANNELS = (5, 6, 7)
MEDIA_CHANNELS = (AUDIO_CHANNEL, *VIDEO_CHANNELS)
AUDIO_RATE = 8000           # the camera's live audio: 8 kHz mono
HEADER = 8                  # bytes before the [8] fields above
# audio codecs in the FrameInfo: the v3 sends 16-bit PCM (0x8C), the v2
# G.711 mu-law (0x89); both 8 kHz mono. G.711 is decoded to 16-bit PCM
# here, so everything downstream sees one format.
CODEC_PCMU, CODEC_PCMA = 0x89, 0x8A


def _g711_tables():
    """256-entry little-endian s16 lookup tables (the classic g711.c)."""
    mu, al = [], []
    for b in range(256):
        u = ~b & 0xFF
        t = (((u & 0x0F) << 3) + 0x84) << ((u & 0x70) >> 4)
        mu.append(0x84 - t if u & 0x80 else t - 0x84)
        a = b ^ 0x55
        t, seg = (a & 0x0F) << 4, (a & 0x70) >> 4
        t = t + 8 if seg == 0 else (t + 0x108) << max(seg - 1, 0)
        al.append(t if a & 0x80 else -t)
    return ([struct.pack("<h", v) for v in mu], [struct.pack("<h", v) for v in al])


_ULAW, _ALAW = _g711_tables()


def g711_to_pcm(data, codec):
    table = _ULAW if codec == CODEC_PCMU else _ALAW
    return b"".join(table[x] for x in data)


def parse_media(p):
    """Media record from the camera -> (ch, frame_no, cidx, payload, end,
    count), or None for anything else. `count` is the frame's packet
    count (chunks 0..count-2 plus the end packet). The end packet's chunk
    index comes back as 0xFFFF so it sorts last; a 0x0028 marker there
    means the payload ends with the 40-byte FrameInfo, which is stripped."""
    if len(p) < 28 or p[0] not in MEDIA_CHANNELS or p[2] not in (0x0B, 0x0C):
        return None
    ft = p[1]
    o = HEADER + (8 if ft & 0x08 else 0)
    if len(p) < o + 20:
        return None
    ch = p[o]
    count = struct.unpack_from("<H", p, o + 4)[0]
    cidx = struct.unpack_from("<H", p, o + 6)[0]
    paysize = struct.unpack_from("<H", p, o + 8)[0]
    frame_no = struct.unpack_from("<I", p, o + 16)[0]
    payload = p[o + 20 : o + 20 + paysize]
    end = bool(ft & 0x01)
    if end:
        if cidx == 0x0028 and len(payload) >= 40:
            codec = payload[-40]
            payload = payload[:-40]
            if ch == AUDIO_CHANNEL and codec in (CODEC_PCMU, CODEC_PCMA):
                payload = g711_to_pcm(payload, codec)
        cidx = 0xFFFF
    return ch, frame_no, cidx, payload, end, count


def read_entries(path):
    data = open(path, "rb").read()
    off = 0
    while off + 13 <= len(data):
        d, ts, ln = struct.unpack_from("<BdI", data, off)
        if off + 13 + ln > len(data):
            break
        yield d, ts, data[off + 13 : off + 13 + ln]
        off += 13 + ln


# an av.bin entry with this "direction" (and no payload) marks the start
# of a session (direct.py writes one per session): frame numbers restart
SESSION_MARK = 255


def sessions(path):
    """Camera media records of av.bin, split per AV session:
    [[(ts, parsed), ...], ...]. Frame numbers are only unique within one."""
    out, cur = [], []
    for d, ts, p in read_entries(path):
        if d == SESSION_MARK:
            if cur:
                out.append(cur)
            cur = []
            continue
        m = parse_media(p) if d == 1 else None
        if m is not None:
            cur.append((ts, m))
    if cur:
        out.append(cur)
    return out


def assemble(records):
    """One session's records -> [(t, ch, frame_no, blob, complete)] in
    arrival order of each frame's first packet. complete means the end
    packet and every chunk before it arrived; duplicate chunks (the
    camera sends each datagram twice) are merged."""
    frames, order = {}, []
    for ts, (ch, frame_no, cidx, payload, end, count) in records:
        key = (ch, frame_no)
        f = frames.get(key)
        if f is None:
            f = frames[key] = {"t": ts, "pkts": {}, "end": False, "count": 0}
            order.append(key)
        f["end"] |= end
        f["count"] = max(f["count"], count)
        f["pkts"].setdefault(cidx, payload)
    out = []
    for key in order:
        f = frames[key]
        chunks = set(f["pkts"]) - {0xFFFF}
        complete = f["end"] and chunks >= set(range(max(0, f["count"] - 1)))
        blob = b"".join(pl for _, pl in sorted(f["pkts"].items()))
        out.append((f["t"], key[0], key[1], blob, complete))
    return out


def nal_units(blob):
    """[(type, NAL unit)] of an Annex-B access unit, start codes left out."""
    out, i = [], blob.find(b"\x00\x00\x01")
    while i != -1 and i + 3 < len(blob):
        j = blob.find(b"\x00\x00\x01", i + 3)
        nal = blob[i + 3:j if j != -1 else len(blob)]
        out.append((nal[0] & 0x1F, nal))
        i = j
    return out


def is_idr(blob):
    return any(t == 5 for t, _ in nal_units(blob))


def sps(blob):
    """The access unit's SPS NAL unit, or None."""
    for t, nal in nal_units(blob):
        if t == 7:
            # a 4-byte start code after it leaves a zero byte at its end
            return nal.rstrip(b"\x00")
    return None


def decodable(tagged):
    """Frames a decoder can show cleanly: complete frames, minus every
    frame that follows an incomplete IDR until the next complete one,
    and every frame after an incomplete P-frame until the next IDR (a
    P-frame references the one before it, and the frames after a broken
    one decode as smears in whatever moves)."""
    out, gop_ok = [], False      # nothing decodes before the first IDR
    for t in tagged:
        blob, complete = t[3], t[4]
        if is_idr(blob):
            gop_ok = complete
        elif not complete:
            gop_ok = False
        if gop_ok:
            out.append(t)
    return out


def audio_frames(records):
    """[(t, s16le PCM)] of a session's audio, each frame once."""
    seen, out = set(), []
    for ts, (ch, frame_no, cidx, payload, end, count) in records:
        if ch == AUDIO_CHANNEL and end and frame_no not in seen:
            seen.add(frame_no)
            out.append((ts, payload))
    return out


def _add_audio_stream(out):
    from fractions import Fraction
    stream = out.add_stream("aac", rate=AUDIO_RATE, layout="mono")
    stream.time_base = Fraction(1, AUDIO_RATE)
    return stream


def _mux_audio(out, stream, audio, t0):
    """Encode the PCM frames to AAC on `stream`. The audio is laid end to
    end from its first frame's arrival (it arrives in bursts like the
    video, but is captured at a steady rate)."""
    import av
    from fractions import Fraction
    resampler = av.AudioResampler(format="fltp", layout="mono", rate=AUDIO_RATE)
    fifo = av.AudioFifo()
    pts = max(0, round((audio[0][0] - t0) * AUDIO_RATE))
    tb = Fraction(1, AUDIO_RATE)

    def encode(frame):
        nonlocal pts
        if frame is not None:
            frame.pts, frame.time_base = pts, tb
            pts += frame.samples
        for pkt in stream.encode(frame):
            out.mux(pkt)
    for _t, pcm in audio:
        n = len(pcm) // 2
        if not n:
            continue
        f = av.AudioFrame(format="s16", layout="mono", samples=n)
        f.planes[0].update(pcm[:n * 2])
        f.sample_rate = AUDIO_RATE
        for r in resampler.resample(f):
            r.pts = None              # the fifo keeps its own sample count
            fifo.write(r)
        size = stream.codec_context.frame_size or 1024
        while fifo.samples >= size:
            encode(fifo.read(size))
    if fifo.samples:
        encode(fifo.read())
    encode(None)


def make_mp4(h264_path, mp4_path, frames, audio=None):
    """Remux the Annex-B stream into an MP4 without re-encoding, giving
    each frame its arrival time as its timestamp, so playback runs at
    true speed (delivery is bursty, so a fixed frame rate would
    stretch quiet gaps and compress bursts).

    frames: the [(t, ch, frame_no, blob, ended)] list that produced
    h264_path, in order. Each demuxed packet is mapped back to its frame
    by byte offset. audio: [(t, pcm)] to add as an AAC track."""
    import av
    from bisect import bisect_right
    from fractions import Fraction
    starts, off = [], 0
    for f in frames:
        starts.append(off)
        off += len(f[3])
    tb = 90000
    last = -1
    with av.open(h264_path, format="h264") as inp, \
            av.open(mp4_path, "w", format="mp4") as out:
        vin = inp.streams.video[0]
        vout = out.add_stream_from_template(vin)
        vout.time_base = Fraction(1, tb)
        # every stream must exist before the first packet is written
        aout = _add_audio_stream(out) if audio else None
        t0 = frames[0][0]
        for i, pkt in enumerate(inp.demux(vin)):
            if pkt.size == 0:
                continue
            idx = (bisect_right(starts, pkt.pos) - 1 if pkt.pos is not None
                   and pkt.pos >= 0 else i)
            ts = round((frames[min(max(idx, 0), len(frames) - 1)][0] - t0) * tb)
            # bursts deliver frames microseconds apart; give each at
            # least 10 ms on screen (the burst catches up at the next gap)
            ts = max(ts, last + tb // 100)
            last = ts
            # the camera's stream has no B-frames, so pts == dts
            pkt.pts = pkt.dts = ts
            pkt.time_base = vout.time_base
            pkt.stream = vout
            out.mux(pkt)
        if aout is not None:
            try:
                _mux_audio(out, aout, audio, t0)
            except Exception:  # noqa: BLE001  (video without sound beats none)
                pass


def clip_facts(mp4_path, jpg_path=None, at=1.0):
    """{"seconds": length} of a motion clip; with jpg_path, also save the
    picture `at` s in (or the last one, if shorter) as a still. The v2
    uploads no snapshot of its own."""
    import av
    img, seconds = None, None
    with av.open(mp4_path) as inp:
        if inp.duration:
            seconds = round(inp.duration / 1e6, 1)
        if jpg_path:
            for frame in inp.decode(video=0):
                img = frame.to_image()
                if frame.time is not None and frame.time >= at:
                    break
    if img is not None:
        img.save(jpg_path, quality=90)
    return {"seconds": seconds}


def last_frame_jpeg(h264_path, jpg_path):
    """Decode the stream and save its last picture; returns its (width,
    height), or None without one."""
    import av
    img = None
    with av.open(h264_path, format="h264") as inp:
        for frame in inp.decode(video=0):
            img = frame.to_image()
    if img is None:
        return None
    img.save(jpg_path, quality=92)
    return img.size


def segments(tagged):
    """Split frames where the SPS changes. The camera starts each live
    view in SD and switches to HD a few seconds in (640x360 -> 1920x1080
    at an IDR), and an MP4 track holds one resolution."""
    segs, cur = [], None
    for t in tagged:
        s = sps(t[3])
        if s is not None and s != cur:
            segs.append([])
            cur = s
        if not segs:
            segs.append([])
        segs[-1].append(t)
    return segs


def export(av_bin, outdir):
    """av.bin -> outdir/video.mp4 (true speed, with the audio as AAC) and
    outdir/frame.jpg (its last picture). A capture that holds several AV
    sessions (the page's view, reconnecting when the camera hung up) makes
    one recording; the picture holds still across each gap. Only the main
    resolution is kept: the camera starts each session in SD for a few
    seconds before it switches to HD.

    Returns {"mp4", "size", "seconds", "error"}; "mp4" is None when
    nothing decodable was found or the remux failed ("error")."""
    res = {"mp4": None, "size": None, "seconds": 0.0, "error": None}
    tagged, audio = [], []
    # frame numbers restart with each session, and a session's pictures
    # only reference each other: assemble, dedupe and check them per
    # session, then lay them end to end
    for recs in sessions(av_bin):
        tagged += decodable([t for t in assemble(recs) if t[1] in VIDEO_CHANNELS])
        audio += audio_frames(recs)
    if not tagged:
        return res
    segs = segments(tagged)
    span = {}
    for seg in segs:
        s = sps(seg[0][3])
        span[s] = span.get(s, 0) + seg[-1][0] - seg[0][0] + 0.05
    main = max(span, key=span.get)
    frames = [t for seg in segs if sps(seg[0][3]) == main for t in seg]
    os.makedirs(outdir, exist_ok=True)
    part = os.path.join(outdir, ".video.h264")
    mp4 = os.path.join(outdir, "video.mp4")
    try:
        with open(part, "wb") as f:
            f.write(b"".join(t[3] for t in frames))
        t0, t1 = frames[0][0], frames[-1][0]
        make_mp4(part, mp4, frames,
                 [a for a in audio if t0 - 0.5 <= a[0] <= t1 + 0.5])
        res.update(mp4=mp4, seconds=t1 - t0,
                   size=last_frame_jpeg(part, os.path.join(outdir, "frame.jpg")))
    except Exception as e:  # noqa: BLE001
        res["error"] = repr(e)
    finally:
        if os.path.exists(part):
            os.remove(part)
    return res
