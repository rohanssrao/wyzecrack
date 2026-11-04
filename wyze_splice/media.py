"""Reassemble decrypted TUTK/Wyze AV media from a splice av.bin capture.

av.bin entry format (written by dtls.SpliceEngine): "<BdI" = direction byte
(0 = phone->camera, 1 = camera->phone), capture timestamp (double),
payload length (u32 LE), then the decrypted DTLS application-data record.

Camera->phone media records (first byte 0x0c) carry a 36-byte header:

  [0]     0x0c magic
  [1]     frame type: 0x08/0x09 start, 0x00/0x04 cont, 0x01/0x05 end
  [2:4]   0x000c protocol version
  [4:6]   packet sequence
  [6:8]   stream session constant
  [10:12] unix-ms low 16 bits
  [16]    channel: 0x03 audio, 0x05/0x06 video (I), 0x07 video (P)
  [17]    flags (0x01 on end packets)
  [18:20] global chunk sequence
  [20:22] last chunk index of the frame
  [22:24] chunk index within the frame (0x0028 on end packets marks a
          40-byte FrameInfo trailer inside the payload, cf. go2rtc
          pkg/tutk frame.go ParsePacketHeader)
  [24:26] payload size
  [28:32] previous frame number
  [32:36] frame number
  [36:]   payload

Frame types with bit 0x08 set (0x08 start, 0x09 single-packet frame,
0x0d) carry 8 extra header bytes at [8:16]: every field above from [8]
on sits 8 bytes later and the payload starts at [44]. Every I-frame's
first chunk and most single-packet P-frames use it (run14: 40 of ~560
frames), so parsing them with the 36-byte layout corrupts exactly the
frames that start a new picture. Bit 0x01 marks a frame's last packet.

Output: one Annex-B .h264 per channel, ordered by first appearance.
Verified against live captures (fw 4.36.17.21): H.264 640x360.
"""

import os
import struct

VIDEO_CHANNELS = (5, 6, 7)


def parse_media(p):
    """Camera->phone media record -> (ch, frame_no, cidx, payload, end,
    count), or None for anything else. `count` is the frame's packet
    count (chunks 0..count-2 plus the end packet). The end packet's chunk
    index comes back as 0xFFFF so it sorts last; a 0x0028 marker there
    means the payload ends with the 40-byte FrameInfo, which is stripped."""
    if len(p) < 40 or p[0] != 0x0C:
        return None
    ft = p[1]
    o = 8 if ft & 0x08 else 0
    if len(p) < 36 + o:
        return None
    ch = p[16 + o]
    count = struct.unpack_from("<H", p, 20 + o)[0]
    cidx = struct.unpack_from("<H", p, 22 + o)[0]
    paysize = struct.unpack_from("<H", p, 24 + o)[0]
    frame_no = struct.unpack_from("<I", p, 32 + o)[0]
    payload = p[36 + o : 36 + o + paysize]
    end = bool(ft & 0x01)
    if end:
        if cidx == 0x0028 and len(payload) >= 40:
            payload = payload[:-40]
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


# a new camera AV session (another live view, or a rebuilt engine)
# restarts frame numbers; a gap this long also starts a new session
SESSION_GAP = 5.0


def sessions(path, direction=1):
    """Camera media records of av.bin, split per AV session:
    [[(ts, parsed), ...], ...]. Frame numbers are only unique within one."""
    out, cur, last_ts, top = [], [], None, {}
    for d, ts, p in read_entries(path):
        if d != direction:
            continue
        m = parse_media(p)
        if m is None:
            continue
        ch, frame_no = m[0], m[1]
        if cur and ((last_ts is not None and ts - last_ts > SESSION_GAP)
                    or frame_no + 50 < top.get(ch, 0)):
            out.append(cur)
            cur, top = [], {}
        cur.append((ts, m))
        top[ch] = max(top.get(ch, 0), frame_no)
        last_ts = ts
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


def extract_combined(path, direction=1):
    """All video frames (channels 5/6/7) of the first AV session, merged
    in arrival order. The P-frames on one channel reference SPS/PPS
    delivered on another, so this interleaving is what decodes."""
    s = sessions(path, direction)
    return [t for t in assemble(s[0]) if t[1] in VIDEO_CHANNELS] if s else []


def _has_idr(blob):
    i = blob.find(b"\x00\x00\x01")
    while i != -1 and i + 3 < len(blob):
        if blob[i + 3] & 0x1F == 5:
            return True
        i = blob.find(b"\x00\x00\x01", i + 3)
    return False


def decodable(tagged):
    """Frames a decoder can show cleanly: complete frames, minus every
    frame that follows an incomplete IDR until the next complete one,
    and every frame after an incomplete P-frame until the next IDR (a
    P-frame references the one before it).
    Once the viewer leaves, the camera keeps streaming to the dead
    session but stops completing I-frames (run14: the last chunk of every
    IDR from ~8 s after the phone left), and the P-frames after a broken
    IDR decode as smears in whatever moves."""
    out, gop_ok = [], False      # nothing decodes before the first IDR
    for t in tagged:
        blob, complete = t[3], t[4]
        if _has_idr(blob):
            gop_ok = complete
        elif not complete:
            gop_ok = False
        if gop_ok:
            out.append(t)
    return out


AUDIO_CHANNEL = 3
AUDIO_RATE = 8000          # the camera's live audio: s16le PCM, 8 kHz mono


def audio_frames(records, t_from, t_to):
    """[(t, pcm)] of a session's audio (codec 0x8C, PCM) between two times,
    each frame once."""
    seen, out = set(), []
    for ts, (ch, frame_no, cidx, payload, end, count) in records:
        if (ch == AUDIO_CHANNEL and end and frame_no not in seen
                and t_from - 0.5 <= ts <= t_to + 0.5):
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
    true speed (relay delivery is bursty, so a fixed frame rate would
    stretch quiet gaps and compress bursts).

    frames: the [(t, ch, frame_no, blob, ended)] list that produced
    h264_path, in order. Each demuxed packet is mapped back to its frame
    by byte offset. audio: [(t, pcm)] to add as an AAC track. Returns the
    number of frames written."""
    import av
    from bisect import bisect_right
    from fractions import Fraction
    starts, off = [], 0
    for f in frames:
        starts.append(off)
        off += len(f[3])
    tb = 90000
    n, last = 0, -1
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
            # relay bursts deliver frames microseconds apart; give each at
            # least 10 ms on screen (the burst catches up at the next gap)
            ts = max(ts, last + tb // 100)
            last = ts
            # the camera's stream has no B-frames, so pts == dts
            pkt.pts = pkt.dts = ts
            pkt.time_base = vout.time_base
            pkt.stream = vout
            out.mux(pkt)
            n += 1
        if aout is not None:
            try:
                _mux_audio(out, aout, audio, t0)
            except Exception:  # noqa: BLE001  (video without sound beats none)
                pass
    return n


def last_frame_jpeg(h264_path, jpg_path):
    """Decode the stream and save its last picture (needs Pillow)."""
    import av
    img = None
    with av.open(h264_path, format="h264") as inp:
        for frame in inp.decode(video=0):
            img = frame.to_image()
    if img is None:
        return False
    img.save(jpg_path, quality=92)
    return True


def _sps(blob):
    """The SPS NAL (bytes) of an access unit, or None."""
    i = blob.find(b"\x00\x00\x01")
    while i != -1 and i + 3 < len(blob):
        if blob[i + 3] & 0x1F == 7:
            j = blob.find(b"\x00\x00\x01", i + 3)
            return blob[i + 3: j if j != -1 else len(blob)].rstrip(b"\x00")
        i = blob.find(b"\x00\x00\x01", i + 3)
    return None


def segments(tagged):
    """Split frames where the SPS changes. The app starts the live view
    in SD and switches the camera to HD a few seconds in (640x360 ->
    1920x1080 at an IDR), and an MP4 track holds one resolution."""
    segs, cur = [], None
    for t in tagged:
        sps = _sps(t[3])
        if sps is not None and sps != cur:
            segs.append([])
            cur = sps
        if not segs:
            segs.append([])
        segs[-1].append(t)
    return segs


def _size(h264_path):
    import av
    with av.open(h264_path, format="h264") as inp:
        for frame in inp.decode(video=0):
            return frame.width, frame.height
    return None


def export(av_bin, outdir):
    """av.bin -> per AV session (one per live view; a single session is
    written to outdir itself, several to outdir/session-N): video.h264
    (all clean GOPs), one true-speed MP4 per resolution (video.mp4 is the
    longest; others video-WxH.mp4) and frame.jpg, the last picture of
    video.mp4. Returns totals plus every MP4 written."""
    res = {"frames": 0, "dropped": 0, "mp4s": [], "sessions": 0}
    parts = [([t for t in assemble(recs) if t[1] in VIDEO_CHANNELS], recs)
             for recs in sessions(av_bin)]
    parts = [p for p in parts if p[0]]
    for n, (every, recs) in enumerate(parts, 1):
        d = outdir if len(parts) == 1 else os.path.join(outdir, f"session-{n}")
        try:
            r = _export_session(every, d, recs)
        except Exception as e:  # noqa: BLE001  (one bad session must not
            res.setdefault("errors", []).append(f"{d}: {e!r}")  # cost the rest)
            continue
        res["sessions"] += 1
        res["frames"] += r["frames"]
        res["dropped"] += r["dropped"]
        res["mp4s"] += r["mp4s"]
        res.setdefault("errors", []).extend(r.get("errors", []))
        if "frame" in r and "frame" not in res:
            res["frame"] = r["frame"]
    return res


def _export_session(every, outdir, records=()):
    os.makedirs(outdir, exist_ok=True)
    tagged = decodable(every)
    res = {"frames": len(tagged), "dropped": len(every) - len(tagged),
           "mp4s": []}
    if not tagged:
        return res
    h264 = os.path.join(outdir, "video.h264")
    with open(h264, "wb") as f:
        f.write(b"".join(t[3] for t in tagged))
    segs = segments(tagged)
    main = max(range(len(segs)), key=lambda i: len(segs[i]))
    used = set()
    for i, seg in enumerate(segs):
        part = os.path.join(outdir, f".seg{i}.h264")
        with open(part, "wb") as f:
            f.write(b"".join(t[3] for t in seg))
        try:
            size = _size(part)
        except Exception:  # noqa: BLE001
            size = None
        stem = ("video" if i == main else
                f"video-{size[0]}x{size[1]}" if size else f"video-part{i + 1}")
        name, k = f"{stem}.mp4", 2
        while name in used:
            name, k = f"{stem}-{k}.mp4", k + 1
        used.add(name)
        mp4 = os.path.join(outdir, name)
        try:
            make_mp4(part, mp4, seg,
                     audio_frames(records, seg[0][0], seg[-1][0]))
        except Exception as e:  # noqa: BLE001
            res.setdefault("errors", []).append(f"{mp4}: {e!r}")
            os.remove(part)
            continue
        res["mp4s"].append({"path": mp4, "size": size, "frames": len(seg),
                            "seconds": seg[-1][0] - seg[0][0]})
        if i == main:
            jpg = os.path.join(outdir, "frame.jpg")
            try:
                if last_frame_jpeg(part, jpg):
                    res["frame"] = jpg
            except Exception:  # noqa: BLE001
                pass
        os.remove(part)
    return res
