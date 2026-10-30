# wyze-splice guide

## Options

`run`:

- `--target <ip>` names the camera (default: find it); `--out <dir>` sets
  the capture directory (default `captures/<time>`).
- `--keep-going` splices every live view until Ctrl-C (default: stop after
  the first).
- `--enr <ENR>` supplies the camera's ENR instead of harvesting it, and
  `--reharvest` ignores the cached one.
- `--harvest-timeout <seconds>` gives up waiting for the ENR.
- `--no-events` leaves motion-event uploads alone; `--no-video` skips the
  MP4 export.
- `--on-path` skips the ARP step, for a host that already carries the
  camera's traffic on the camera's LAN interface (the lab does this).
- `--journal` also logs all key material; `--pass-through` diverts the
  session without decrypting it (an A/B control).

`events` takes `--target`, `--on-path`, `--out` and `--count N` (stop after
N clips). `find` takes `--iface`. `check` takes `--target`.

## Output files

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
