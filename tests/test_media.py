import os
import struct
import tempfile

from wyzecrack import media as av_extract


def _rec(direction, payload, ts=0.0):
    return struct.pack("<BdI", direction, ts, len(payload)) + payload


def _media(ft, ch, frame_no, cidx, paysize, payload, last=0):
    # frame types with bit 0x08 carry 8 extra header bytes at [8:16]
    o = 8 if ft & 0x08 else 0
    hdr = bytearray(36 + o)
    hdr[0] = 0x0C
    hdr[1] = ft
    struct.pack_into("<H", hdr, 2, 0x000C)
    struct.pack_into("<H", hdr, 16 + o, ch)
    struct.pack_into("<H", hdr, 20 + o, last)
    struct.pack_into("<H", hdr, 22 + o, cidx)
    struct.pack_into("<H", hdr, 24 + o, paysize)
    struct.pack_into("<I", hdr, 28 + o, frame_no - 1)
    struct.pack_into("<I", hdr, 32 + o, frame_no)
    return bytes(hdr) + payload


def _write(blob):
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(blob)
    f.close()
    return f.name


def test_reassembly_dedupe_frameinfo_strip():
    sps = b"\x00\x00\x00\x01\x27\x4d\x00\x32"
    p1 = b"\xAA" * 16
    p2 = b"\xBB" * 8
    frameinfo = b"\x4e\x00\x01\x00" + b"\x00" * 36  # H264 keyframe info
    endpayload = b"\xCC" * 12 + frameinfo
    path = _write(b"".join([
        _rec(0, b"\x0a\x08-command-not-media"),
        # 3 packets: chunks 0 and 1, then the end packet
        _rec(1, _media(0x08, 5, 7, 0, len(sps + p1), sps + p1, last=3)),
        _rec(1, _media(0x00, 5, 7, 1, len(p2), p2, last=3)),
        _rec(1, _media(0x01, 5, 7, 0x0028, len(endpayload), endpayload,
                       last=3)),
        # duplicate chunk must be dropped
        _rec(1, _media(0x00, 5, 7, 1, len(p2), p2, last=3)),
        # audio is not video
        _rec(1, _media(0x01, 3, 1, 0x0028, 4, b"\x11\x22\x33\x44", last=1)),
        _rec(1, b"\x0c\x00-truncated"),
    ]))
    try:
        frames = av_extract.extract_combined(path)
        assert [(f[1], f[2], f[4]) for f in frames] == [(5, 7, True)]
        assert frames[0][3] == sps + p1 + p2 + b"\xCC" * 12
    finally:
        os.unlink(path)


def test_missing_middle_chunk_is_incomplete():
    path = _write(b"".join([
        _rec(1, _media(0x08, 5, 7, 0, 4, b"\x00\x00\x01\x65", last=3)),
        # chunk 1 lost
        _rec(1, _media(0x01, 5, 7, 0x0028, 8, b"\xCC" * 8, last=3)),
    ]))
    try:
        (f,) = av_extract.extract_combined(path)
        assert f[4] is False
    finally:
        os.unlink(path)


def test_sessions_split_on_frame_reset_and_gap():
    one = lambda fno, ts: _rec(1, _media(0x01, 7, fno, 0x0028, 8, b"\x41" * 8, last=1), ts)
    path = _write(b"".join([one(n, n * 0.05) for n in range(1, 120)]
                           + [one(n, 10 + n * 0.05) for n in range(1, 5)]     # reset
                           + [one(n, 30 + n * 0.05) for n in range(5, 9)]))   # gap
    try:
        assert [len(s) for s in av_extract.sessions(path)] == [119, 4, 4]
    finally:
        os.unlink(path)


def test_single_packet_extended_frame():
    # 0x09: whole frame in one packet, 44-byte header, FrameInfo trailer
    pslice = b"\x00\x00\x00\x01\x21\xfe" + b"\xDD" * 10
    frameinfo = b"\x4e\x00\x00\x00" + b"\x00" * 36
    body = pslice + frameinfo
    m = av_extract.parse_media(_media(0x09, 7, 20, 0x0028, len(body), body,
                                      last=1))
    assert m == (7, 20, 0xFFFF, pslice, True, 1)


def test_decodable_drops_gop_after_incomplete_idr():
    idr = b"\x00\x00\x00\x01\x67\x4d" + b"\x00\x00\x00\x01\x65\x88"
    p = b"\x00\x00\x00\x01\x41\x9a"
    frames = [(-1, 7, 0, p, True),            # before any IDR: undecodable
              (0, 5, 1, idr, True), (1, 7, 2, p, True),
              (2, 5, 3, idr, False),          # IDR missing its last chunk
              (3, 7, 4, p, True), (4, 7, 5, p, True),
              (5, 5, 6, idr, True), (6, 7, 7, p, True)]
    kept = [f[2] for f in av_extract.decodable(frames)]
    assert kept == [1, 2, 6, 7]
    # an incomplete P-frame breaks the rest of its GOP too
    frames[4] = (3, 7, 4, p, False)
    frames[3] = (2, 5, 3, idr, True)
    assert [f[2] for f in av_extract.decodable(frames)] == [1, 2, 3, 6, 7]


def test_segments_split_where_the_sps_changes():
    sd = b"\x00\x00\x00\x01\x67\x4d\x00\x1e" + b"\x00\x00\x00\x01\x65\x88"
    hd = b"\x00\x00\x00\x01\x67\x4d\x00\x29" + b"\x00\x00\x00\x01\x65\x88"
    p = b"\x00\x00\x00\x01\x41\x9a"
    frames = [(0, 5, 1, sd, True), (1, 7, 2, p, True),
              (2, 5, 3, sd, True), (3, 7, 4, p, True),     # same SPS: same segment
              (4, 5, 5, hd, True), (5, 7, 6, p, True)]
    segs = av_extract.segments(frames)
    assert [[f[2] for f in s] for s in segs] == [[1, 2, 3, 4], [5, 6]]


def test_g711_decodes_to_pcm():
    import struct
    from wyzecrack.media import CODEC_PCMA, CODEC_PCMU, g711_to_pcm
    mu = struct.unpack("<4h", g711_to_pcm(bytes((0xFF, 0x7F, 0x00, 0x80)), CODEC_PCMU))
    assert mu == (0, 0, -32124, 32124)
    al = struct.unpack("<4h", g711_to_pcm(bytes((0xD5, 0x55, 0xAA, 0x2A)), CODEC_PCMA))
    assert al == (8, -8, 32256, -32256)


def test_parse_media_decodes_v2_audio():
    """A v2 audio packet: plain format (version 0x0B), G.711 mu-law, with
    the 40-byte FrameInfo (codec 0x89) after the samples."""
    import struct
    from wyzecrack.media import parse_media
    samples = bytes((0xFF, 0x00)) * 4
    info = bytes((0x89, 0x00, 0x02)) + bytes(37)
    payload = samples + info
    rec = (bytes((3, 0x01)) + struct.pack("<HHH", 0x000B, 7, 0x65)
           + bytes((3, 1)) + struct.pack("<HHHHH", 9, 1, 0x28, len(payload), 0)
           + struct.pack("<II", 4, 5) + payload)
    ch, frame_no, cidx, pcm, end, count = parse_media(rec)
    assert (ch, frame_no, end) == (3, 5, True)
    assert struct.unpack("<8h", pcm) == (0, -32124) * 4


def _write_av_bin(path, stretches):
    """av.bin with one camera session per (start time, access units)."""
    import os
    import struct
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    from fakecam import media_record
    with open(path, "wb") as f:
        for t0, units in stretches:
            f.write(struct.pack("<BdI", 255, t0, 0))        # a new session
            for i, au in enumerate(units):
                rec = media_record(i + 1, au, key=(i == 0))
                f.write(struct.pack("<BdI", 1, t0 + i / 20, len(rec)) + rec)


def test_one_recording_across_a_reconnect(tmp_path):
    import av
    import pytest
    from wyzecrack.media import export
    try:
        from test_jpegfeed import _h264_frames
        units = _h264_frames(n=20)
    except pytest.skip.Exception:
        raise
    av_bin = tmp_path / "av.bin"
    _write_av_bin(av_bin, [(1000.0, units), (1004.0, units)])  # 3 s gap
    merged = tmp_path / "merged"
    r = export(str(av_bin), str(merged), merge=True)
    assert [m["path"] for m in r["mp4s"]] == [str(merged / "video.mp4")]
    with av.open(str(merged / "video.mp4")) as c:
        v = c.streams.video[0]
        assert v.frames == 40
        assert float(v.duration * v.time_base) > 4.5      # the gap is kept
    split = tmp_path / "split"
    r = export(str(av_bin), str(split))
    assert sorted(p.name for p in split.iterdir() if p.is_dir()) == ["session-1", "session-2"]
