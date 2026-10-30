#!/usr/bin/env python3
"""Post-mortem for a splice session directory.

Reads interpose.log (tagged wrappers: C = from camera, R = from relay,
E = emitted toward the relay/phone, e = emitted toward the camera),
journal.jsonl, and av.bin, then answers the questions that matter after
a live run:

  1. Did the splice terminate both DTLS legs?
  2. Did every emitted packet reuse a valid pooled wrapper, or did the
     engine fall back to synthesized headers (stale trailer HMAC)?
  3. Did the phone's AV-layer ACKs ever report a completed video frame
     (rx_frame != 0xffff)? splice3's phone acknowledged camera commands
     but never completed a frame.
  4. Which wrapper channel markers ([12:14], main vs back) were seen in
     each direction? Backchannel traffic multiplexed into the flow is a
     candidate cause for app-side failures.
"""

import json
import struct
import sys

WRAPPER_HDR = 28
WRAPPER_TRL = 20

MAGIC = b"\x51\xcc"


def read_interpose(path, timestamped=True):
    """Records are tag(1) + [u64be ms timestamp] + u32be len + wrapper.
    Logs written before 2026-10-26 have no timestamp (timestamped=False);
    yields (tag, ms_or_None, wrapper)."""
    data = open(path, "rb").read()
    off = 0
    hdr = 13 if timestamped else 5
    while off + hdr <= len(data):
        tag = data[off : off + 1]
        ms = struct.unpack_from(">Q", data, off + 1)[0] if timestamped else None
        (ln,) = struct.unpack_from(">I", data, off + hdr - 4)
        if off + hdr + ln > len(data):
            break
        yield tag, ms, data[off + hdr : off + hdr + ln]
        off += hdr + ln


def wrapper_fields(w):
    if len(w) < WRAPPER_HDR + WRAPPER_TRL or w[:2] != MAGIC:
        return None
    cmd, plen = struct.unpack_from("<HH", w, 4)
    dirn, = struct.unpack_from("<H", w, 8)
    ch, ticket = struct.unpack_from("<HH", w, 12)
    return {"cmd": cmd, "plen": plen, "dir": dirn, "ch": ch,
            "ticket": ticket, "size": len(w)}


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <session-dir>", file=sys.stderr)
        return 2
    import os
    d = sys.argv[1]

    # 1. journal summary
    jp = os.path.join(d, "journal.jsonl")
    acks, events = [], {}
    if os.path.exists(jp):
        for line in open(jp):
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            events[ev.get("ev")] = events.get(ev.get("ev"), 0) + 1
            if ev.get("ev") == "phone_ack":
                acks.append((ev.get("cmd_seq"), ev.get("rx_frame"),
                             ev.get("rx_cmd")))
    print("== journal events ==", events or "(none)")
    for name in ("handshake_done", "fin_verify_failed",
                 "decrypt_exhausted"):
        if events.get(name):
            print(f"  {name}: {events[name]}")

    # 2. wrapper flow summary
    ip = os.path.join(d, "interpose.log")
    counts, ch_fields, plen_mismatch = {}, {}, 0
    emit_sizes, recv_sizes = {"E": 0, "e": 0}, {"R": 0, "C": 0}
    if os.path.exists(ip):
        for tag, _ms, w in read_interpose(
                ip, timestamped="--old-log" not in sys.argv):
            t = tag.decode()
            counts[t] = counts.get(t, 0) + 1
            f = wrapper_fields(w)
            if f is None:
                continue
            if f["plen"] != len(w) - 12:
                plen_mismatch += 1
            key = (t, f["ch"])
            ch_fields[key] = ch_fields.get(key, 0) + 1
            if t in emit_sizes:
                emit_sizes[t] += f["size"]
            if t in recv_sizes:
                recv_sizes[t] += f["size"]
    print("== interpose packets ==", counts or "(none)")
    print(f"  plen-field mismatches: {plen_mismatch}")
    print("  wrapper channel markers per tag:",
          {f"{t}/ch{c:#06x}": n for (t, c), n in sorted(ch_fields.items())})
    if counts.get("C") and counts.get("E"):
        print(f"  camera->phone: received {counts['C']} from camera, "
              f"emitted {counts['E']} toward relay")
    if counts.get("R") and counts.get("e"):
        print(f"  phone->camera: received {counts['R']} from relay, "
              f"emitted {counts['e']} toward camera")

    # 3. phone ACK health
    print("== phone AV ACKs ==")
    if not acks:
        print("  (none captured)")
    else:
        frames = [a for a in acks if a[1] not in (None, 0xFFFF)]
        print(f"  {len(acks)} acks; {len(frames)} report a completed video "
              f"frame")
        print(f"  first: cmd_seq={acks[0][0]} rx_frame={acks[0][1]:#06x} "
              f"rx_cmd={acks[0][2]:#06x}  last: cmd_seq={acks[-1][0]} "
              f"rx_frame={acks[-1][1]:#06x} rx_cmd={acks[-1][2]:#06x}")
        if not frames and counts.get("C", 0) > 50:
            print("  !! the phone never completed a video frame while the "
                  "camera streamed (splice3's failure signature)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
