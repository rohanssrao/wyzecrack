# wyzecrack guide

## The page

`wyzecrack` opens it in your browser. Chrome, Edge and Brave play the
full 1080p stream; a browser that can't decode H.264 itself gets still
frames instead (720p, about 10 a second). Options:

- `--listen <address>` serves it on another address (a tailnet address,
  say) so you can watch from another device.
- `--no-browser` prints the link instead of opening it.
- `--out <dir>` sets where recordings go (default `~/Videos/wyzecrack`).
- `--port <n>` picks the port (default: any free one).

## Commands

For scripts and headless hosts. Each one finds the camera by itself when
the network has one Wyze device, and asks which one when it has several;
`--target <camera ip>` skips the search.

- `wyzecrack watch` records the live view until Ctrl-C. The first time
  with a camera, it reads the camera's key and ID first. When the camera
  hangs up, it reconnects, as the page does, and gives up after three
  tries in a row without a picture; it's all one recording.
  - `--seconds <n>` stops after that many seconds of live view.
  - `--out <dir>` sets where the recording goes (default: a new folder in
    the camera's folder, where the page lists it).
  - `--reharvest` reads the camera's key again, for a camera that was set
    up again in the Wyze app.
  - `--enr <ENR>` uses this key, and saves it, instead of reading it.
- `wyzecrack events` saves motion clips until Ctrl-C, in the camera's
  `events` folder; `--count <n>` stops after that many, `--out <dir>` sets
  where.
- `wyzecrack cleanup` undoes the network changes of a wyzecrack that was
  killed.
- `wyzecrack extract <recording>` tries again to write a recording's video,
  if that failed.

Keys and camera IDs are saved in `~/.local/share/wyzecrack/enr.json`, and the
page's camera names and settings in `cameras.json` next to it.

## Files

Recordings and motion clips go in `~/Videos/wyzecrack` (your
`XDG_VIDEOS_DIR` if you've set one), a folder per camera. The page lists
each camera's files and can play, download and delete them.

A recording is a folder named after the time it started, holding
`video.mp4` (the live view in HD at true speed, with sound), `frame.jpg`
(its last picture) and `meta.json` (which camera, when, how long). If
writing the video failed, the folder keeps `av.bin`, everything the camera
sent, decrypted, for `extract` to try again.

Motion clips are in the camera's `events` folder, one folder per alarm
(`<time>_<id>/`) with `clip.mp4`, `snapshot.jpg` and `meta.json` (the
clip's length). The v2 uploads no snapshot, so its still is taken from the
clip.

Files are owned by the user who started wyzecrack.

## Troubleshooting

- **A camera takes a while to start:** Wyze Cam v3s leave some new
  sessions waiting for up to 30 s, at random. After 2 s the tool opens a
  second session beside a slow one and keeps whichever gets in first, so
  most views start within a few seconds ([why](how-it-works.md)).
- **"The camera doesn't answer":** it's switched off in the Wyze app (or
  by a schedule), unplugged, or offline. If it was set up again in the
  Wyze app, its key changed: **Get its key again** on the page, or
  `wyzecrack watch --reharvest`, reads the new one.
- **The first time takes long:** the camera only sends its key at certain
  moments. The tool resets its connection to Wyze until it does, usually
  within one or two minutes, sometimes four. On models it hasn't been tried on, it waits
  for the camera to report in on its own: usually within 20 minutes, or
  right away when the camera sees motion.
- **"The camera refused our certificate":** this firmware no longer
  trusts the eMudhra CA, so the tool can't read its key. If you have the
  key from elsewhere, pass it with `--enr`.
- **"Wyze didn't hand out this camera's ID":** the Wyze cloud refused the
  key or changed this call. Try again later.
- **The camera lost its connection while it was rerouted:** something on
  this computer drops forwarded traffic, such as an nftables firewall.
  wyzecrack warns about one when it starts rerouting.
- **wyzecrack was killed while it was rerouting a camera:** run
  `wyzecrack cleanup`. The camera also recovers on its own within a few
  minutes, once its ARP entry expires.
