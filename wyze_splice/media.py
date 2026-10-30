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
    """Camera->phone media record -> (ch, frame_no, cidx, payload, end),
    or None for anything else. The end packet's chunk index comes back
    as 0xFFFF so it sorts last; a 0x0028 marker there means the payload
    ends with the 40-byte FrameInfo, which is stripped."""
    if len(p) < 40 or p[0] != 0x0C:
        return None
    ft = p[1]
    o = 8 if ft & 0x08 else 0
    if len(p) < 36 + o:
        return None
    ch = p[16 + o]
    cidx = struct.unpack_from("<H", p, 22 + o)[0]
    paysize = struct.unpack_from("<H", p, 24 + o)[0]
    frame_no = struct.unpack_from("<I", p, 32 + o)[0]
    payload = p[36 + o : 36 + o + paysize]
    end = bool(ft & 0x01)
    if end:
        if cidx == 0x0028 and len(payload) >= 40:
            payload = payload[:-40]
        cidx = 0xFFFF
    return ch, frame_no, cidx, payload, end


def read_entries(path):
    data = open(path, "rb").read()
    off = 0
    while off + 13 <= len(data):
        d, ts, ln = struct.unpack_from("<BdI", data, off)
        if off + 13 + ln > len(data):
            break
        yield d, ts, data[off + 13 : off + 13 + ln]
        off += 13 + ln


def extract(path, direction=1):
    """-> {channel: [(frame_no, blob, ended), ...]} in capture order."""
    frames, order = {}, []
    for d, ts, p in direction_reader(path, direction):
        m = parse_media(p)
        if m is None:
            continue
        ch, frame_no, cidx, payload, end = m
        key = (ch, frame_no)
        if key not in frames:
            frames[key] = {"pos": len(order), "pkts": [], "end": False}
            order.append(key)
        f = frames[key]
        f["end"] |= end
        f["pkts"].append((cidx, payload))
    out = {}
    for key in order:
        ch, frame_no = key
        f = frames[key]
        seen, merged = set(), []
        for c, pl in sorted(f["pkts"]):
            if c in seen:
                continue
            seen.add(c)
            merged.append(pl)
        out.setdefault(ch, []).append((frame_no, b"".join(merged), f["end"]))
    return out


def frame_times(path, direction=1):
    """-> {(ch, frame_no): first-packet wall time} for media packets."""
    times = {}
    for d, ts, p in direction_reader(path, direction):
        m = parse_media(p)
        if m is not None:
            times.setdefault((m[0], m[1]), ts)
    return times


def extract_combined(path, direction=1):
    """All video frames (channels 5/6/7) merged in capture order — the
    P-frames on one channel reference SPS/PPS delivered on another, so
    this interleaving is what actually decodes."""
    per_ch = extract(path, direction)
    tagged = []
    times = frame_times(path, direction)
    for ch, frs in per_ch.items():
        if ch not in VIDEO_CHANNELS:
            continue
        for frame_no, blob, ended in frs:
            t = times.get((ch, frame_no))
            if t is None:
                continue
            tagged.append((t, ch, frame_no, blob, ended))
    tagged.sort(key=lambda x: x[0])
    return tagged


def _has_idr(blob):
    i = blob.find(b"\x00\x00\x01")
    while i != -1 and i + 3 < len(blob):
        if blob[i + 3] & 0x1F == 5:
            return True
        i = blob.find(b"\x00\x00\x01", i + 3)
    return False


def decodable(tagged):
    """Frames a decoder can show cleanly: complete frames, minus every
    frame that follows an incomplete IDR until the next complete one.
    Once the viewer leaves, the camera keeps streaming to the dead
    session but stops completing I-frames (run14: the last chunk of every
    IDR from ~8 s after the phone left), and the P-frames after a broken
    IDR decode as smears in whatever moves."""
    out, gop_ok = [], True
    for t in tagged:
        blob, ended = t[3], t[4]
        if _has_idr(blob):
            gop_ok = ended
        if ended and gop_ok:
            out.append(t)
    return out


def direction_reader(path, direction):
    for d, ts, p in read_entries(path):
        if d == direction:
            yield d, ts, p


def make_mp4(h264_path, mp4_path, frames):
    """Remux the Annex-B stream into an MP4 without re-encoding, giving
    each frame its arrival time as its timestamp, so playback runs at
    true speed (relay delivery is bursty, so a fixed frame rate would
    stretch quiet gaps and compress bursts).

    frames: the [(t, ch, frame_no, blob, ended)] list that produced
    h264_path, in order. Each demuxed packet is mapped back to its frame
    by byte offset. Returns the number of frames written."""
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
    """av.bin -> outdir/video.h264 (all clean GOPs), one true-speed MP4
    per resolution (video.mp4 is the longest; others are named
    video-WxH.mp4) and frame.jpg, the last picture of video.mp4.
    Returns what was written."""
    os.makedirs(outdir, exist_ok=True)
    every = extract_combined(av_bin)
    tagged = decodable(every)
    res = {"frames": len(tagged), "dropped": len(every) - len(tagged),
           "mp4s": []}
    if not tagged:
        return res
    h264 = os.path.join(outdir, "video.h264")
    with open(h264, "wb") as f:
        f.write(b"".join(t[3] for t in tagged))
    res["h264"] = h264
    res["seconds"] = tagged[-1][0] - tagged[0][0]
    segs = segments(tagged)
    main = max(range(len(segs)), key=lambda i: len(segs[i]))
    for i, seg in enumerate(segs):
        part = os.path.join(outdir, f".seg{i}.h264")
        with open(part, "wb") as f:
            f.write(b"".join(t[3] for t in seg))
        size = _size(part)
        name = ("video.mp4" if i == main or size is None
                else f"video-{size[0]}x{size[1]}.mp4")
        mp4 = os.path.join(outdir, name)
        make_mp4(part, mp4, seg)
        res["mp4s"].append({"path": mp4, "size": size, "frames": len(seg),
                            "seconds": seg[-1][0] - seg[0][0]})
        if i == main:
            res["mp4"] = mp4
            jpg = os.path.join(outdir, "frame.jpg")
            if last_frame_jpeg(part, jpg):
                res["frame"] = jpg
        os.remove(part)
    return res
