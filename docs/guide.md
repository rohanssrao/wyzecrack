# wyzecrack guide

## The page

`wyzecrack` opens it in your browser. Chrome, Edge and Brave play the
full 1080p stream; a browser that can't decode H.264 itself gets still
frames instead (720p, about 10 a second). Options:

- `--listen <address>` serves it on another address (a tailnet address,
  say) so you can watch from another device.
- `--no-browser` prints the link instead of opening it.
- `--out <dir>` sets where recordings go (default `./captures`).
- `--port <n>` picks the port (default: any free one).

## Commands

For scripts and headless hosts. Each one finds the camera by itself when
the network has one Wyze device, and asks which one when it has several;
`--target <camera ip>` skips the search.

- `wyzecrack watch` records the live view until Ctrl-C.
  - `--seconds <n>` stops after that long.
  - `--out <dir>` sets the capture directory (default
    `captures/watch-<time>`).
  - `--no-video` keeps only `av.bin` (no MP4 export).
- `wyzecrack key` reads and saves a camera's key and ID. The page and
  `watch` do this by themselves the first time.
  - `--reharvest` reads them again, for a camera that was set up again in
    the Wyze app.
  - `--enr <ENR>` uses this key instead of reading it.
  - `--no-nudge` waits for the camera to report its key on its own instead
    of resetting its connection to Wyze.
  - `--harvest-timeout <seconds>` gives up waiting for the key.

  `watch` takes these options too.
- `wyzecrack events` saves motion clips until Ctrl-C; `--count <n>` stops
  after that many, `--out <dir>` sets where.
- `wyzecrack find` lists the Wyze devices on the network (`--iface` picks
  the interface).
- `wyzecrack check` checks that this computer can reroute the camera,
  without touching it.
- `wyzecrack cleanup` undoes the network changes of a wyzecrack that was
  killed.
- `wyzecrack extract <capture>` rebuilds the video from a capture's
  `av.bin`.

Keys and camera IDs are saved in `/var/lib/wyzecrack/enr.json`.

## Files

A live view's directory:

| file | contents |
|---|---|
| `video.mp4` | the live view in HD at true speed, with sound |
| `video-640x360.mp4` | the first seconds, before the camera switches to HD (when they last 2 s or more) |
| `frame.jpg` | the last picture |
| `video.h264` | the raw H.264 stream |
| `av.bin` | everything the camera sent, decrypted; `extract` rebuilds the video from it |

A motion event's directory (`events/<time>_<id>/`) holds `clip.mp4`,
`snapshot.jpg` and `meta.json` (the clip's length). The v2 uploads no
snapshot, so its still is taken from the clip.

Files are owned by the user who started wyzecrack.

## Troubleshooting

- **A camera takes a while to start:** Wyze Cam v3s leave some new
  sessions waiting for up to 30 s, at random. After 2 s the tool opens a
  second session beside a slow one and keeps whichever gets in first, so
  most views start within a few seconds ([why](how-it-works.md)).
- **"The camera doesn't answer":** it's switched off in the Wyze app (or
  by a schedule), unplugged, or offline. If it was set up again in the
  Wyze app, its key changed: **Get its key again** on the page, or
  `wyzecrack key --reharvest`, reads the new one.
- **The first time takes long:** the camera only sends its key at certain
  moments. The tool resets its connection to Wyze until it does, usually
  within two to four minutes. On models it hasn't been tried on, it waits
  for the camera to report in on its own: usually within 20 minutes, or
  right away when the camera sees motion.
- **"The camera refused our certificate":** this firmware no longer
  trusts the eMudhra CA, so the tool can't read its key. If you have the
  key from elsewhere, pass it with `--enr`.
- **"Wyze didn't hand out this camera's ID":** the Wyze cloud refused the
  key or changed this call. Try again later.
- **The camera lost its connection while it was rerouted:** something on
  this computer drops forwarded traffic, such as an nftables firewall.
  `wyzecrack check` reports it.
- **wyzecrack was killed while it was rerouting a camera:** run
  `wyzecrack cleanup`. The camera also recovers on its own within a few
  minutes, once its ARP entry expires.
