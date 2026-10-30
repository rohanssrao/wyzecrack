import os
import struct
import tempfile

from wyze_splice import media as av_extract


def _rec(direction, payload):
    return struct.pack("<BdI", direction, 0.0, len(payload)) + payload


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


def test_av_extract():
    sps = b"\x00\x00\x00\x01\x27\x4d\x00\x32"
    p1 = b"\xAA" * 16
    p2 = b"\xBB" * 8
    frameinfo = b"\x4e\x00\x01\x00" + b"\x00" * 36  # H264 keyframe info
    endpayload = b"\xCC" * 12 + frameinfo
    blob = b"".join([
        _rec(0, b"\x0a\x08-command-not-media"),
        _rec(1, _media(0x08, 5, 7, 0, len(sps + p1), sps + p1, last=2)),
        _rec(1, _media(0x00, 5, 7, 1, len(p2), p2, last=2)),
        _rec(1, _media(0x01, 5, 7, 0x0028, len(endpayload), endpayload,
                       last=2)),
        # duplicate chunk must be dropped
        _rec(1, _media(0x00, 5, 7, 1, len(p2), p2, last=2)),
        # different channel goes to its own stream
        _rec(1, _media(0x01, 3, 1, 0x0028, 4, b"\x11\x22\x33\x44")),
        _rec(1, b"\x0c\x00-truncated"),
    ])
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(blob)
        path = f.name
    try:
        out = av_extract.extract(path)
        assert sorted(out) == [3, 5], sorted(out)
        frames = out[5]
        assert len(frames) == 1
        frame_no, data, ended = frames[0]
        assert frame_no == 7 and ended
        assert data == sps + p1 + p2 + b"\xCC" * 12, data.hex()
        assert out[3][0][1] == b"\x11\x22\x33\x44"
    finally:
        os.unlink(path)
    print("ok av_extract reassembly, dedupe, FrameInfo strip")


if __name__ == "__main__":
    test_av_extract()
    print("ALL TESTS PASSED")


def test_single_packet_extended_frame():
    # 0x09: whole frame in one packet, 44-byte header, FrameInfo trailer
    pslice = b"\x00\x00\x00\x01\x21\xfe" + b"\xDD" * 10
    frameinfo = b"\x4e\x00\x00\x00" + b"\x00" * 36
    body = pslice + frameinfo
    m = av_extract.parse_media(_media(0x09, 7, 20, 0x0028, len(body), body,
                                      last=1))
    assert m == (7, 20, 0xFFFF, pslice, True)


def test_decodable_drops_gop_after_incomplete_idr():
    idr = b"\x00\x00\x00\x01\x67\x4d" + b"\x00\x00\x00\x01\x65\x88"
    p = b"\x00\x00\x00\x01\x41\x9a"
    frames = [(0, 5, 1, idr, True), (1, 7, 2, p, True),
              (2, 5, 3, idr, False),          # IDR missing its last chunk
              (3, 7, 4, p, True), (4, 7, 5, p, True),
              (5, 5, 6, idr, True), (6, 7, 7, p, True)]
    kept = [f[2] for f in av_extract.decodable(frames)]
    assert kept == [1, 2, 6, 7]


def test_segments_split_where_the_sps_changes():
    sd = b"\x00\x00\x00\x01\x67\x4d\x00\x1e" + b"\x00\x00\x00\x01\x65\x88"
    hd = b"\x00\x00\x00\x01\x67\x4d\x00\x29" + b"\x00\x00\x00\x01\x65\x88"
    p = b"\x00\x00\x00\x01\x41\x9a"
    frames = [(0, 5, 1, sd, True), (1, 7, 2, p, True),
              (2, 5, 3, sd, True), (3, 7, 4, p, True),     # same SPS: same segment
              (4, 5, 5, hd, True), (5, 7, 6, p, True)]
    segs = av_extract.segments(frames)
    assert [[f[2] for f in s] for s in segs] == [[1, 2, 3, 4], [5, 6]]
