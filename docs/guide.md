# wyze-splice guide

## Options

`watch`:

- `--target <ip>` names the camera (default: find it).
- `--seconds <n>` stops after that long (default: until Ctrl-C).
- `--out <dir>` sets the capture directory (default:
  `captures/watch-<time>`).
- `--no-video` skips the MP4 export.
- `--enr <ENR>` supplies the camera's ENR instead of harvesting it.
- `--reharvest` ignores the saved ENR and ID and gets them again.
- `--no-nudge` never cuts the camera's internet to make it send its ENR;
  it waits for a motion alarm instead.
- `--harvest-timeout <seconds>` stops waiting for the ENR after that many
  seconds.

`key` takes the same options as `watch`, apart from `--seconds`, `--out`
and `--no-video`. The ENR and ID are saved in
`/var/lib/wyze-splice/enr.json`.

`run`:

- `--target <ip>` names the camera (default: find it).
- `--out <dir>` sets the capture directory (default: `captures/<time>`).
- `--keep-going` splices every live view until Ctrl-C (default: stop after
  the first).
- `--enr <ENR>` supplies the camera's ENR instead of harvesting it.
- `--reharvest` ignores the cached ENR.
- `--harvest-timeout <seconds>` stops waiting for the ENR after that many
  seconds.
- `--no-nudge` never cuts the camera's internet to make it send its ENR.
- `--no-events` leaves motion-event uploads alone.
- `--no-video` skips the MP4 export.
- `--on-path` skips the ARP step. Use it on a host that already carries the
  camera's traffic on the camera's LAN interface (the lab does this).
- `--journal` also logs all key material.
- `--pass-through` diverts the session without decrypting it, as an A/B
  control.

`events` takes `--target`, `--on-path`, `--out` and `--count N` (stop after
N clips).

`find` takes `--iface`.

`check` takes `--target`.

## Output files

`captures/<time>/` is owned by the user who invoked sudo.

| file | contents |
|---|---|
| `video.mp4`, `frame.jpg` | the decrypted live view at true speed (its HD part), and its last frame |
| `video-640x360.mp4` | the SD start of the live view, before the app switches to HD |
| `events/<time>_<id>/` | `clip.mp4` and `snapshot.jpg` for each motion event uploaded during the run |
| `video.h264` | the raw Annex-B stream |
| `av.bin` | every decrypted DTLS application record, both directions |
| `splice.log` | engine milestones (handshakes, phone frame ACKs) |
| `interpose.log` | every wrapper seen and sent, timestamped |
| `journal.jsonl` | with `--journal`: key material and crypto decisions |

With `--keep-going`, a capture can hold several live views. Each one's
video goes to `session-N/`.

`scripts/postmortem.py <capture dir>` summarizes a run from these files.

## Troubleshooting

- **"the camera did not answer (discovery)":** the camera is off (switched
  off in the Wyze app, or on a schedule) or unplugged. A camera that is
  turned off stops all its P2P traffic, so it can't be watched.
- **"Wyze did not return a UID":** the Wyze cloud refused the camera's
  key, or changed this call. `wyze-splice run` still works: it catches a
  live view that the Wyze app opens.
- **The first time takes long:** the camera only sends its ENR at certain
  moments. The tool cuts its internet up to three times, 2.5 minutes
  apart, to make it report in; a motion alarm also does it. Each cut takes
  the camera offline for about a minute.
- **The live view plays in the app but nothing shows up here:** the phone
  is probably on the camera's Wi-Fi. There the app reaches the camera
  directly over the LAN, which doesn't pass through this computer; use a
  phone on cellular or another network.

- **"that live view did not pass through this host":** the camera opened
  channels for a live view, but the stream never came through here. Some
  of the camera's connections go straight through the router, probably
  ones it opened before wyze-splice started. (Seen behind a home router
  router: the camera's traffic to two of its relays never reached this
  host while its other traffic did.) Unplugging the camera for 5 seconds
  while wyze-splice runs fixes it: the connections it opens then pass
  through here. (Before an unplug, 3 of 5 test views were missed; after
  it, 3 of 3 were caught.)
- **"waiting for the camera's ENR" for a long time:** trigger a motion
  alarm. If the tool reports that the camera refuses the certificate, this
  firmware no longer trusts the eMudhra CA. Supply the ENR with `--enr`.
- **"no replies come back":** something on the host drops forwarded
  traffic. Check its firewall.
- **`engine failed` mentioning decryption:** the cached ENR is stale
  because the camera was re-paired. Rerun with `--reharvest`.
- **A run was killed and the camera is offline:** run `wyze-splice
  cleanup`. The camera also recovers on its own within a few minutes, once
  its ARP entry expires.
