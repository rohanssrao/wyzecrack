# wyze-splice

Decrypt a Wyze Cam v3's live video from the local network while the owner's
phone app keeps playing it.

```
sudo .venv/bin/wyze-splice run --target 192.168.1.20
```

Run it on any Linux host on the camera's LAN, then open the camera's live
view in the app (from anywhere: the app reaches the camera through
ThroughTek relays). When the viewer leaves, the tool tears everything down
and writes the decrypted stream to `captures/<time>/video.mp4` and a still
to `frame.jpg`. The app plays the feed normally.

It also saves the camera's motion events (the 12 s clip and snapshot it
uploads to Wyze's cloud) while it runs, and `wyze-splice events` does only
that, until Ctrl-C:

```
sudo .venv/bin/wyze-splice events --target 192.168.1.20
```

Only use this against cameras you own or are authorized to test.

## What it needs

- Root on a Linux host with a wired or WiFi link on the camera's LAN. No
  access to the camera, the phone or the Wyze account.
- The camera's ENR. The tool harvests it the first time (see below) and
  caches it in `/var/lib/wyze-splice/enr.json`; `--enr` skips that.
- `iptables` with the TPROXY target and `ip` (iproute2). Everything else
  comes from the Python dependencies: packet capture and ARP use
  `AF_PACKET` sockets with kernel BPF filters (no libpcap), conntrack is
  handled over netlink with pyroute2, and the MP4 and JPEG are written
  in-process with PyAV and Pillow.

Tested against a Wyze Cam v3 (WYZE_CAKP2JFUS) on firmware 4.36.17.21, with
the phone app on cellular.

## Install

```
uv sync
sudo .venv/bin/wyze-splice run --target <camera ip>
```

Options: `--enr` to supply the ENR, `--no-events` to leave event uploads alone, `--keep-going` to splice every session
until Ctrl-C (default: stop after the first), `--on-path` when the host
already routes the camera (its gateway, or the lab), `--journal` to also log
all key material, `--pass-through` to divert without decrypting (an A/B
control). `wyze-splice extract <av.bin>` rebuilds the video from a capture.

## How it works

1. **Get on-path** (`onpath.py`). ARP-poison only the camera so this host
   becomes its gateway, and MASQUERADE its traffic out under this host's
   address. The real router is never poisoned: two-way poisoning makes a
   typical home router route the camera's spoofed packets back to the MITM
   (same 5-tuple, TTL dropping by one per bounce), which black-holes the
   stream. The camera's existing flows survive the switch; the relays pick
   up the new NAT mapping from its next keepalive.

2. **Read the camera's HTTPS** (`cloud.py`). The camera's TLS client still trusts the
   eMudhra "EM OV TLS CA - G3C" intermediate, whose private key became
   public in October 2026 (a P-384 key with d=4). The tool redirects the
   camera's tcp/443 to a local TLS relay that presents a leaf for the
   requested name signed under that intermediate, forwards everything to
   the real server, and reads `"enr"` out of the camera's POSTs to
   api.wyzecam.com. The camera sends these at boot, on motion alarms, and
   every few hours, so the first harvest can take a while; walking past
   the camera triggers a motion alarm. The same relay saves motion events:
   for each alarm the camera PUTs a snapshot and a 12 s 1080p clip (H.264
   with A-law audio) to cpl-t-sightsafe.wyzecam.com through pre-signed
   URLs, encrypted by nothing but the TLS we terminate.

3. **Catch the session** (`splice.py`). Nothing is diverted while waiting.
   When the app opens the feed, the camera sends a 0x1102 channel-open to a
   fresh relay; at that moment the tool pins TPROXY rules to the camera's
   exact 5-tuples toward that data relay and toward each STUN relay
   (:3478). Both matter: the phone's ClientHello can arrive as cmd 0x1402
   through a STUN relay while the camera answers as 0x1502 on the data
   relay.

4. **Splice the DTLS** (`dtls.py`). The session is DTLS 1.2 with
   TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256, and the PSK is derived from
   the ENR alone. The engine terminates both legs (server toward the phone,
   client toward the camera) with flights byte-size-matched to the
   originals, so each 0xCC51 wrapper and its header-keyed trailer can be
   reused verbatim; no UID or relay credentials are needed. It decrypts the
   media to `av.bin` and re-encrypts it for the phone. Re-sent packets keep
   the TTL a forwarded packet would have had: re-originated packets
   leaving with TTL 64 made the camera stop routing through the MITM.

5. **Tear down and export** (`media.py`). When the camera goes quiet the
   rules are removed and the flows handed back to the kernel. The H.264 is
   reassembled from TUTK media frames and paced to arrival time. Frames
   after an incomplete I-frame are dropped: once the viewer leaves, the
   camera keeps streaming to the dead session for a while but stops
   completing I-frames.

## Output

`captures/<time>/` (owned by the invoking user under sudo):

| file | contents |
|---|---|
| `video.mp4`, `frame.jpg` | the decrypted live view at true speed (HD part), and its last frame |
| `video-640x360.mp4` | the SD start of the live view, before the app switches to HD |
| `events/<time>_<id>/` | `clip.mp4` and `snapshot.jpg` of each motion event uploaded meanwhile |
| `video.h264` | the raw Annex-B stream |
| `av.bin` | every decrypted DTLS application record, both directions |
| `splice.log` | engine milestones (handshakes, phone frame ACKs) |
| `interpose.log` | every wrapper seen and sent, timestamped |
| `journal.jsonl` | with `--journal`: key material and crypto decisions |

`scripts/postmortem.py <capture dir>` summarizes a run from these.

## Tests

```
uv run pytest            # unit tests; socket tests need root
sudo bash lab/labsuite.sh   # end-to-end in network namespaces, see lab/README.md
```
