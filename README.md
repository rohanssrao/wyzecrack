# wyzecrack

Watch and record a Wyze Cam v3 or v2 from its local network, with no phone
and no Wyze account. It can also decrypt the live views the owner's Wyze
app opens, and save the motion clips the camera uploads.

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
- For the page: a current browser. Chrome, Brave and Edge decode the
  1080p stream themselves. Browsers that can't decode H.264 (Playwright's
  Firefox, for example) get 720p still frames from the tool instead, about
  10 a second. WebKit, Safari's engine, decodes the H.264 itself (tried in
  Playwright's macOS build, not in Safari itself).

Tested from a NixOS host against three Wyze Cam v3s (WYZE_CAKP2JFUS,
firmware 4.36.17.21 and 4.36.16.7064) and a Wyze Cam v2 (WYZEC1-JZ,
4.9.9.3006). The lab suite also passes on Debian 12 (iptables 1.8.9,
nf_tables backend); `lab/debian-check.sh` runs it in a throwaway
container.

## First run

```
uv sync
.venv/bin/wyzecrack
```

It asks for your password (it needs root) and opens a page in your
browser:

1. **Pick a camera.** It lists the Wyze cameras on the network, with their
   model.
2. **The first time with a camera** takes two to four minutes. The tool
   reroutes the camera's traffic through this computer and reads the
   camera's key (its ENR) off the camera's own HTTPS. To make the camera
   send it now, it resets the camera's connection to Wyze a few times; the
   camera reconnects within seconds each time. The tool then asks Wyze for
   the camera's ID, presenting that key as the camera does. Both are
   saved, and the camera's network goes back to normal.
3. **Watch.** The live view plays in the page in 1080p, with sound if you
   turn it on, straight from the camera over the LAN. Stop saves it as
   one recording, even if the camera hung up and the page reconnected.

After the first time, a camera's live view usually starts within seconds
and nothing on the network is rerouted. To also keep the camera's motion
clips, turn on **Save this camera's motion clips** under its live view:
while the page is open, that camera's traffic goes through this computer
and every clip it uploads to Wyze is saved too. If Wyze won't return a
camera's ID, the page instead waits for someone to open the camera in the
Wyze app and plays that live view ([how](docs/how-it-works.md)).

## Commands

The page is the default. For scripts and headless hosts there are
commands too; they also ask for the password themselves.

| command | does |
|---|---|
| `wyzecrack` | the page: pick a camera, watch it, everything saved |
| `wyzecrack watch` | record the live view straight from the camera, until Ctrl-C or `--seconds N` |
| `wyzecrack key` | get and save a camera's ENR and ID (the page and `watch` do this themselves) |
| `wyzecrack run` | splice the next live view the Wyze app opens; also saves motion events meanwhile |
| `wyzecrack events` | only save motion events (`clip.mp4` + `snapshot.jpg`), until Ctrl-C or `--count N` |
| `wyzecrack find` | list Wyze devices on the LAN (by their IEEE MAC prefixes) |
| `wyzecrack check` | run all of `run`'s pre-flight checks without touching the camera |
| `wyzecrack cleanup` | undo the network changes of a run that was killed |
| `wyzecrack extract <capture>` | rebuild the video from a capture's `av.bin` |

`wyzecrack gui --listen <address>` serves the page on another address
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
