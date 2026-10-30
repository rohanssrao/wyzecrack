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
Verified against capture splice3 (fw 4.36.17.21): H.264 640x360 decodable
by ffmpeg.
"""

import struct
import sys
import time

START = time.time()

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


def write_timed(outdir, extract, times, channels=VIDEO_CHANNELS):
    """Per-channel frame fragments + ffconcat manifests with wall-clock
    durations, for true-speed VFR MP4s (ffmpeg -f concat -safe 0)."""
    import os
    manifests = []
    for ch in channels:
        if ch not in extract:
            continue
        chdir = os.path.join(outdir, f"ch{ch}")
        os.makedirs(chdir, exist_ok=True)
        lines = ["ffconcat version 1.0"]
        n = 0
        t_prev = None
        for frame_no, blob, ended in extract[ch]:
            t = times.get((ch, frame_no))
            if t is None or not ended or b"\x00\x00\x01" not in blob[:4096]:
                continue
            frag = os.path.join(chdir, f"f{n:05d}.h264")
            with open(frag, "wb") as f:
                f.write(blob)
            dur = max(0.01, t - t_prev) if t_prev is not None else 0.04
            lines.append(f"file '{os.path.basename(frag)}'")
            lines.append(f"duration {dur:.3f}")
            t_prev = t
            n += 1
        if n:
            manifest = os.path.join(chdir, "frames.ffconcat")
            with open(manifest, "w") as f:
                f.write("\n".join(lines) + "\n")
            manifests.append(manifest)
    return manifests


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


def live(path, outdir, poll=0.25, channels=VIDEO_CHANNELS):
    """Tail av.bin as it grows; reassemble frames incrementally; emit
    each completed frame to outdir/frames/ as f%05d.h264 the moment its
    end packet lands. Yields (ch, frame_no, blob, t) per frame."""
    import os
    import time
    os.makedirs(os.path.join(outdir, "frames"), exist_ok=True)
    state = {}   # (ch, frame_no) -> {"pkts": [...], "end": bool}
    n = 0
    seen_off = 0
    while True:
        data = open(path, "rb").read()
        off = seen_off
        new = 0
        while off + 13 <= len(data):
            d, ts, ln = struct.unpack_from("<BdI", data, off)
            if off + 13 + ln > len(data):
                break            # partial write; retry next poll
            p = data[off + 13 : off + 13 + ln]
            off += 13 + ln
            m = parse_media(p) if d == 1 else None
            if m is None or m[0] not in channels:
                continue
            ch, frame_no, cidx, payload, end = m
            key = (ch, frame_no)
            if key not in state:
                state[key] = {"pkts": [], "end": False}
            f = state[key]
            f["end"] |= end
            f["pkts"].append((cidx, payload))
            if f["end"]:
                seen, merged = set(), []
                for c, pl in sorted(f["pkts"]):
                    if c in seen:
                        continue
                    seen.add(c)
                    merged.append(pl)
                blob = b"".join(merged)
                frag = os.path.join(outdir, "frames", f"f{n:05d}.h264")
                open(frag, "wb").write(blob)
                n += 1
                yield ch, frame_no, blob, ts
                del state[key]
        seen_off = off
        if not new:
            time.sleep(poll)


def make_mp4(h264_path, mp4_path, frames, ffmpeg=None):
    """True-speed MP4 with per-frame PTS.

    frames: [(t, ch, frame_no, blob, ended)] in stream order — the same
    list that produced h264_path — supplies each frame's arrival time.

    A uniform setpts stretch is wrong because delivery is bursty (relay
    batching): quiet gaps would stretch and bursts compress. Instead:
    pyav demuxes the stream, each packet is mapped back to its owning
    frame blob by byte offset (corrupt blobs with no access unit never
    demux, so they never display — same as live), each decoded frame is
    written to a JPEG, and an ffconcat manifest with duration =
    t[next] - t[this] drives the final encode: frame i is shown from
    its arrival until the next frame arrives, exactly what a live
    viewer would have seen. Falls back to a uniform stretch (approximate
    pacing) when pyav/Pillow are unavailable."""
    import os
    import subprocess
    import tempfile
    if ffmpeg is None:
        ffmpeg = os.environ.get("FFMPEG", "ffmpeg")
    try:
        import av
        from bisect import bisect_right
        starts, off = [], 0
        for f in frames:
            starts.append(off)
            off += len(f[3])
        work = tempfile.mkdtemp(prefix="avmp4_")
        inp = av.open(h264_path)
        vin = inp.streams.video[0]
        order = []
        for packet in inp.demux(vin):
            pos = packet.pos if packet.pos is not None else 0
            idx = max(0, bisect_right(starts, pos) - 1)
            for frame in packet.decode():
                frame.to_image().save(
                    os.path.join(work, f"{len(order):06d}.jpg"),
                    quality=92)
                order.append(idx)
        inp.close()
        if not order:
            raise RuntimeError("nothing decoded")
        lines = ["ffconcat version 1.0"]
        for i, idx in enumerate(order):
            t = frames[idx][0]
            t_next = (frames[order[i + 1]][0] if i + 1 < len(order)
                      else t + 0.13)
            lines.append(f"file '{i:06d}.jpg'")
            lines.append(f"duration {max(0.01, t_next - t):.3f}")
        lines.append(f"file '{len(order) - 1:06d}.jpg'")
        manifest = os.path.join(work, "frames.ffconcat")
        with open(manifest, "w") as f:
            f.write("\n".join(lines) + "\n")
        r = subprocess.run([ffmpeg, "-v", "error", "-f", "concat",
                            "-safe", "0", "-i", manifest,
                            "-c:v", "libx264", "-pix_fmt", "yuv420p",
                            "-crf", "20", mp4_path, "-y"],
                           capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError(f"ffmpeg concat failed: {r.stderr[-400:]}")
        return len(order)
    except ImportError:
        return _make_mp4_uniform(h264_path, mp4_path, frames, ffmpeg)


def _make_mp4_uniform(h264_path, mp4_path, frames, ffmpeg=None):
    """Fallback (no pyav): uniform setpts stretch — approximate pacing
    only; per-frame arrival gaps are bursty, so this compresses bursts
    and stretches quiet gaps."""
    import os
    import subprocess
    if ffmpeg is None:
        ffmpeg = os.environ.get("FFMPEG", "ffmpeg")
    if not frames:
        raise RuntimeError("no frames")
    span = frames[-1][0] - frames[0][0]
    native_dur = len(frames) / 20.0
    factor = max(0.01, span / native_dur) if native_dur > 0 else 1.0
    subprocess.run([ffmpeg, "-v", "error", "-f", "h264", "-i", h264_path,
                    "-vf", f"setpts=PTS*{factor:.4f}",
                    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-crf", "20",
                    mp4_path, "-y"], check=True)
    return len(frames)


def export(av_bin, outdir, mp4=True, frame=True):
    """av.bin -> outdir/video.h264 (clean GOPs only), and with mp4=True a
    true-speed outdir/video.mp4 plus outdir/frame.jpg (needs pyav,
    Pillow and ffmpeg). Returns a dict of what was written."""
    import os
    os.makedirs(outdir, exist_ok=True)
    every = extract_combined(av_bin)
    tagged = decodable(every)
    res = {"frames": len(tagged), "dropped": len(every) - len(tagged)}
    if not tagged:
        return res
    h264 = os.path.join(outdir, "video.h264")
    with open(h264, "wb") as f:
        f.write(b"".join(t[3] for t in tagged))
    res["h264"] = h264
    res["seconds"] = tagged[-1][0] - tagged[0][0]
    if mp4:
        path = os.path.join(outdir, "video.mp4")
        make_mp4(h264, path, tagged)
        res["mp4"] = path
        if frame:
            import subprocess
            jpg = os.path.join(outdir, "frame.jpg")
            r = subprocess.run([os.environ.get("FFMPEG", "ffmpeg"), "-v",
                                "error", "-y", "-sseof", "-1", "-i", path,
                                "-frames:v", "1", jpg], capture_output=True)
            if r.returncode == 0:
                res["frame"] = jpg
    return res


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} av.bin [outdir] [--timed|--live]",
              file=sys.stderr)
        return 2
    outdir = (sys.argv[2] if len(sys.argv) > 2
              and not sys.argv[2].startswith("-") else ".")
    import os

    if "--live" in sys.argv:
        try:
            for ch, frame_no, blob, t in live(sys.argv[1], outdir):
                print(f"[live] ch{ch} frame {frame_no}: {len(blob)}B")
        except KeyboardInterrupt:
            return 0
    os.makedirs(outdir, exist_ok=True)
    if "--combined" in sys.argv:
        every = extract_combined(sys.argv[1])
        tagged = decodable(every)
        blob = b"".join(t[3] for t in tagged)
        path_out = os.path.join(outdir, "combined.h264")
        open(path_out, "wb").write(blob)
        n = len(tagged)
        if n < len(every):
            print(f"dropped {len(every) - n} of {len(every)} frames "
                  f"(incomplete, or after an incomplete I-frame)")
        span = (tagged[-1][0] - tagged[0][0]) if len(tagged) > 1 else 1.0
        fps = (n - 1) / span if span > 0 else 25.0
        print(f"{path_out}: {len(blob)} bytes, {n} frames over "
              f"{span:.2f}s ({fps:.2f} fps)")
        if "--mp4" in sys.argv:
            mp4 = os.path.join(outdir, "realtime.mp4")
            n = make_mp4(path_out, mp4, tagged)
            print(f"{mp4}: true-speed MP4, {n} frames, per-frame PTS")
        if "--live-fifo" in sys.argv:
            fifo = os.path.join(outdir, "live.h264")
            if not os.path.exists(fifo):
                os.mkfifo(fifo)
            print(f"live pipe: {fifo}")
            print(f"view with: ffplay -probesize 32 -fflags nobuffer "
                  f"-f h264 -vf setpts=PTS*{20/max(fps,0.01):.2f} -i {fifo}")
            with open(fifo, "wb") as f:
                t0 = None
                for t, ch, frame_no, b_, ended in tagged:
                    if t0 is None:
                        t0 = t
                    time.sleep(max(0, t - t0 - (time.time() - START)))
                    f.write(b_)
        return 0
    if "--timed" in sys.argv:
        for m in write_timed(os.path.join(outdir, "timed"),
                             extract(sys.argv[1]),
                             frame_times(sys.argv[1])):
            print(f"timed manifest: {m}")
        return 0
    for ch, frs in sorted(extract(sys.argv[1]).items()):
        blob = b"".join(b for _, b, _ in frs)
        path = os.path.join(outdir, f"video_ch{ch}.h264" if ch in VIDEO_CHANNELS
                            else f"media_ch{ch}.bin")
        open(path, "wb").write(blob)
        kind = "video" if ch in VIDEO_CHANNELS else "audio"
        print(f"{path}: {len(blob)} bytes, {len(frs)} frames "
              f"({sum(1 for f in frs if f[2])} ended) [{kind}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())

