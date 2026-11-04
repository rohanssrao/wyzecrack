# wyze-splice

Decrypt a Wyze Cam v3's live view from the local network while the owner's
phone app keeps playing it, and save the motion clips the camera uploads.

Only use this against cameras you own or are authorized to test.

## Requirements

- Root on a Linux host with a wired or Wi-Fi link on the camera's LAN,
  using the same interface for its internet route. No access to the
  camera, the phone or the Wyze account is needed.
- `iptables` with the TPROXY target, and `ip` (iproute2). Everything else
  comes from the Python dependencies: packet capture and ARP use
  `AF_PACKET` sockets with kernel BPF filters (no libpcap), conntrack is
  handled over netlink with pyroute2, PyAV and Pillow write the MP4 and
  JPEG in-process, and aiohttp serves the page.
- For the page: a browser with WebCodecs (current Chrome, Edge, Firefox
  or Safari) to play the live view.

Tested against a Wyze Cam v3 (WYZE_CAKP2JFUS) on firmware 4.36.17.21, with
the phone app on cellular, from a NixOS host. The lab suite also passes on
Debian 12 (iptables 1.8.9, nf_tables backend); `lab/debian-check.sh` runs
it in a throwaway container.

## First run

```
uv sync
.venv/bin/wyze-splice
```

It asks for your password (it needs root to reroute the camera's traffic)
and opens a page in your browser:

1. **Pick a camera.** It lists the Wyze cameras on the network, with their
   model.
2. **The first time,** it waits for the camera's key (its ENR, which the
   stream key is derived from). The camera sends it to Wyze at boot, on
   motion alarms and every few hours; walk past the camera to trigger one.
   It's then remembered.
3. **Open the camera's live view in the Wyze app** from a phone that isn't
   on the camera's network (on cellular, for example). On the same Wi-Fi
   the app talks to the camera directly over the LAN, which never passes
   through this computer.
4. **Watch along.** The live view plays in the page, with sound if you
   turn it on, while the app keeps playing normally. When the viewer
   leaves, the video is saved with its audio, and the page waits for the
   next one. Motion clips the camera uploads meanwhile are saved too.

Stop or Quit in the page (or Ctrl-C in the terminal) puts the camera's
network back.

## Commands

The page is the default. For scripts and headless hosts there are
commands too; they also ask for the password themselves.

| command | does |
|---|---|
| `wyze-splice` | the page: pick a camera, watch along, everything saved |
| `wyze-splice run` | splice the next live view from the terminal; also saves motion events meanwhile |
| `wyze-splice events` | only save motion events (`clip.mp4` + `snapshot.jpg`), until Ctrl-C or `--count N` |
| `wyze-splice find` | list Wyze devices on the LAN (by their IEEE MAC prefixes) |
| `wyze-splice check` | run all of `run`'s pre-flight checks without touching the camera |
| `wyze-splice cleanup` | undo the network changes of a run that was killed |
| `wyze-splice extract <capture>` | rebuild the video from a capture's `av.bin` |

`wyze-splice gui --listen <address>` serves the page on another address
(a tailnet address, say) to watch from another device; `--no-browser`
just prints the link. For each command's options, use `--help` or see
[docs/guide.md](docs/guide.md#options).

## Output

The page saves under `captures/<camera>/`: one folder per live view
(`video.mp4` with sound, `frame.jpg`, `meta.json`) and `events/` for
motion clips. `run` writes to `captures/<time>/` instead. The raw capture
files are described in [docs/guide.md](docs/guide.md#output-files).

## More

- [How it works](docs/how-it-works.md), including how it keeps the network
  safe if it is interrupted
- [Troubleshooting](docs/guide.md#troubleshooting)

## Tests

```
uv run pytest               # unit tests; the socket tests need root
sudo bash lab/labsuite.sh   # end to end in network namespaces, see lab/README.md
```
