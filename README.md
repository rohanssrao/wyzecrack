# wyze-splice

Watch and record a Wyze Cam v3 from its local network, with no phone and no
Wyze account. It can also decrypt the live views the owner's Wyze app
opens, and save the motion clips the camera uploads.

Only use this against cameras you own or are authorized to test.

## Requirements

- Root on a Linux host with a wired or Wi-Fi link on the camera's LAN,
  using the same interface for its internet route, and internet access the
  first time with each camera. No access to the camera, the phone or the
  Wyze account is needed.
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

It asks for your password (it needs root) and opens a page in your
browser:

1. **Pick a camera.** It lists the Wyze cameras on the network, with their
   model.
2. **The first time with a camera** takes about two minutes. The tool
   reroutes the camera's traffic through this computer and reads the
   camera's key (its ENR) off the camera's own HTTPS. If the camera doesn't
   send it within 30 seconds, the tool cuts the camera's internet until the
   camera notices, about a minute; the camera reports in with its key when
   it's back online. The tool then asks Wyze for the camera's ID, presenting that key
   as the camera does. Both are saved, and the camera's network goes back
   to normal.
3. **Watch.** The live view plays in the page in 1080p, with sound if you
   turn it on, straight from the camera over the LAN. Stop saves it.

After the first time, a camera's live view starts within seconds and
nothing on the network is rerouted. If Wyze won't return a camera's ID,
the page instead waits for someone to open the camera in the Wyze app and
plays that live view ([how](docs/how-it-works.md)).

## Commands

The page is the default. For scripts and headless hosts there are
commands too; they also ask for the password themselves.

| command | does |
|---|---|
| `wyze-splice` | the page: pick a camera, watch it, everything saved |
| `wyze-splice watch` | record the live view straight from the camera, until Ctrl-C or `--seconds N` |
| `wyze-splice key` | get and save a camera's ENR and ID (the page and `watch` do this themselves) |
| `wyze-splice run` | splice the next live view the Wyze app opens; also saves motion events meanwhile |
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
motion clips. `watch` and `run` write to `captures/<time>/` instead. The raw capture
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
