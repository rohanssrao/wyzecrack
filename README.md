# wyze-splice

Decrypt a Wyze Cam v3's live video from the local network while the owner's
phone app keeps playing it, and save the motion clips the camera uploads.

```
uv sync
sudo .venv/bin/wyze-splice run
```

Run it on a Linux host on the camera's LAN. It finds the camera, gets on its
network path, and waits. Open the camera's live view in the Wyze app, from
anywhere: the app reaches the camera through ThroughTek relays. The app
plays normally. When the viewer leaves, the tool puts the network back and
writes the decrypted stream to `captures/<time>/video.mp4`, with a still in
`frame.jpg`.

Only use this against cameras you own or are authorized to test.

## Commands

| command | does |
|---|---|
| `sudo wyze-splice run` | splice the next live view; also saves motion events meanwhile |
| `sudo wyze-splice events` | only save motion events (`clip.mp4` + `snapshot.jpg`), until Ctrl-C or `--count N` |
| `sudo wyze-splice find` | list Wyze devices on the LAN (by their IEEE MAC prefixes) |
| `sudo wyze-splice cleanup` | undo the network changes of a run that was killed |
| `wyze-splice extract <capture>` | rebuild the video from a capture's `av.bin` |

`run` and `events` pick the camera themselves when the LAN has exactly one
Wyze device; otherwise pass `--target <camera ip>` (see `find`).

Useful `run` options:

- `--keep-going` splices every live view until Ctrl-C (default: stop after
  the first).
- `--enr <ENR>` supplies the camera's ENR instead of harvesting it, and
  `--reharvest` ignores the cached one.
- `--no-events` leaves motion-event uploads alone.
- `--on-path` is for a host that already routes the camera (its gateway, or
  the lab); it skips the ARP step.
- `--journal` also logs all key material; `--pass-through` diverts the
  session without decrypting it (an A/B control).

## What it needs

- Root on a Linux host with a wired or Wi-Fi link on the camera's LAN,
  using the same interface for its internet route. No access to the
  camera, the phone or the Wyze account.
- `iptables` with the TPROXY target, and `ip` (iproute2). Everything else
  comes from the Python dependencies: packet capture and ARP use
  `AF_PACKET` sockets with kernel BPF filters (no libpcap), conntrack is
  handled over netlink with pyroute2, and the MP4 and JPEG are written
  in-process with PyAV and Pillow.

The first run waits for the camera's ENR (see below), which it sends at
boot, on motion alarms and every few hours: walk past the camera to trigger
one. The ENR is then cached per camera in `/var/lib/wyze-splice/enr.json`.

Tested against a Wyze Cam v3 (WYZE_CAKP2JFUS) on firmware 4.36.17.21, with
the phone app on cellular.

## How it works

1. **Get on-path** (`onpath.py`). ARP-poison only the camera so this host
   becomes its gateway, and MASQUERADE its traffic out under this host's
   address. The real router is never poisoned: two-way poisoning makes a
   typical home router route the camera's spoofed packets back to the MITM
   (same 5-tuple, TTL dropping by one per bounce), which black-holes the
   stream. The camera's existing flows survive the switch; the relays pick
   up the new NAT mapping from its next keepalive.

2. **Read the camera's HTTPS** (`cloud.py`). The camera's TLS client still
   trusts the eMudhra "EM OV TLS CA - G3C" intermediate, whose private key
   became public in October 2026 (a P-384 key with d=4). The camera's
   tcp/443 is redirected to a local relay. Connections to `*.wyzecam.com`
   get a leaf for the requested name signed under that intermediate and are
   forwarded to the real server under the same name; everything else
   (firmware and model downloads from S3, for example) passes through as
   raw TCP. Two things are read off the camera's requests:
   - the ENR, the per-camera secret in the JSON of its POSTs to
     api.wyzecam.com;
   - motion events: for each alarm the camera PUTs a snapshot and a 12 s
     1080p clip (H.264 with A-law audio) to cpl-t-sightsafe.wyzecam.com
     through pre-signed URLs, encrypted by nothing but the TLS we terminate.

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
   reassembled from TUTK media frames and remuxed (not re-encoded) into an
   MP4 paced to arrival time. The app starts each live view in SD and
   switches the camera to 1080p a few seconds in; each resolution gets its
   own MP4. Frames that could not decode cleanly are left out: incomplete
   frames, and the rest of their group of pictures. Once the viewer leaves,
   the camera keeps streaming to the dead session for a while but stops
   completing I-frames, so that tail is dropped.

## Safety

Every change to the host (iptables rules, the policy route, sysctls, the
camera's ARP entry) is written to a journal in `/run/wyze-splice/` before
it is made. Leaving the tool any way, including Ctrl-C (once or repeatedly),
SIGTERM or a closed terminal, undoes the changes in reverse order. If the
process is killed outright or the host loses power, `wyze-splice cleanup`
or the next run replays the journal. Only one instance runs at a time.

The tool also adds FORWARD accept rules for the camera, for firewalls that
drop forwarded traffic (ufw, Docker, firewalld); a firewall that drops it
in nftables directly can't be overridden this way, and the tool warns when
the camera's traffic stops coming back. While it runs, it holds a
`systemd-inhibit` sleep lock: a suspended host black-holes the camera.

## Output

`captures/<time>/` (owned by the invoking user under sudo):

| file | contents |
|---|---|
| `video.mp4`, `frame.jpg` | the decrypted live view at true speed (its HD part), and its last frame |
| `video-640x360.mp4` | the SD start of the live view, before the app switches to HD |
| `events/<time>_<id>/` | `clip.mp4` and `snapshot.jpg` of each motion event uploaded meanwhile |
| `video.h264` | the raw Annex-B stream |
| `av.bin` | every decrypted DTLS application record, both directions |
| `splice.log` | engine milestones (handshakes, phone frame ACKs) |
| `interpose.log` | every wrapper seen and sent, timestamped |
| `journal.jsonl` | with `--journal`: key material and crypto decisions |

When a capture holds several live views (`--keep-going`), each one's video goes to `session-N/`.
`scripts/postmortem.py <capture dir>` summarizes a run from these files.

## Troubleshooting

- **"waiting for the camera's ENR" for a long time:** trigger a motion
  alarm. If the tool reports that the camera refuses the certificate, this
  firmware no longer trusts the eMudhra CA; supply the ENR with `--enr`.
- **"no replies come back":** something on the host drops forwarded
  traffic; check its firewall.
- **`engine failed` mentioning decryption:** the cached ENR is stale (the
  camera was re-paired); rerun with `--reharvest`.
- **A run was killed and the camera is offline:** `sudo wyze-splice
  cleanup`. The camera also recovers by itself within a few minutes, once
  its ARP entry expires.

## Tests

```
uv run pytest               # unit tests; the socket tests need root
sudo bash lab/labsuite.sh   # end to end in network namespaces, see lab/README.md
```
