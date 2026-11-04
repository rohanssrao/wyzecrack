# wyze-splice guide

## Options

`run`:

- `--target <ip>` names the camera (default: find it).
- `--out <dir>` sets the capture directory (default: `captures/<time>`).
- `--keep-going` splices every live view until Ctrl-C (default: stop after
  the first).
- `--enr <ENR>` supplies the camera's ENR instead of harvesting it.
- `--reharvest` ignores the cached ENR.
- `--harvest-timeout <seconds>` stops waiting for the ENR after that many
  seconds.
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
