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

Run them as `sudo .venv/bin/wyze-splice <command>` from the repo (shortened
to `wyze-splice` below).

| command | does |
|---|---|
| `wyze-splice run` | splice the next live view; also saves motion events meanwhile |
| `wyze-splice events` | only save motion events (`clip.mp4` + `snapshot.jpg`), until Ctrl-C or `--count N` |
| `wyze-splice find` | list Wyze devices on the LAN (by their IEEE MAC prefixes) |
| `wyze-splice check` | run every pre-flight check of `run` without touching the camera |
| `wyze-splice cleanup` | undo the network changes of a run that was killed |
| `wyze-splice extract <capture>` | rebuild the video from a capture's `av.bin` |

`run` and `events` find the camera by themselves: with one Wyze device on
the LAN they use it, and with several (Wyze plugs and bulbs share the vendor
prefix) they ask which one. `--target <camera ip>` skips the search.

Options for each command: `--help`, or [docs/guide.md](docs/guide.md#options).

## What it needs

- Root on a Linux host with a wired or Wi-Fi link on the camera's LAN,
  using the same interface for its internet route. No access to the
  camera, the phone or the Wyze account.
- `iptables` with the TPROXY target, and `ip` (iproute2). Everything else
  comes from the Python dependencies: packet capture and ARP use
  `AF_PACKET` sockets with kernel BPF filters (no libpcap), conntrack is
  handled over netlink with pyroute2, and the MP4 and JPEG are written
  in-process with PyAV and Pillow.

The first run waits for the camera's ENR, the per-camera secret the stream
key is derived from. The camera sends it at
boot, on motion alarms and every few hours: walk past the camera to trigger
one. The ENR is then cached per camera in `/var/lib/wyze-splice/enr.json`.

Tested against a Wyze Cam v3 (WYZE_CAKP2JFUS) on firmware 4.36.17.21, with
the phone app on cellular, from a NixOS host. The lab suite also passes on
Debian 12 (iptables 1.8.9, nf_tables backend); `lab/debian-check.sh` runs
it in a throwaway container.

## Output

`captures/<time>/` holds `video.mp4` (the live view, at true speed),
`frame.jpg`, and `events/<time>_<id>/clip.mp4` + `snapshot.jpg` for each
motion event, plus the raw capture files described in
[docs/guide.md](docs/guide.md).

More: [how it works](docs/how-it-works.md) (including how it keeps the
network safe if it is interrupted) and [troubleshooting](docs/guide.md#troubleshooting).

## Tests

```
uv run pytest               # unit tests; the socket tests need root
sudo bash lab/labsuite.sh   # end to end in network namespaces, see lab/README.md
```
