# Lab

A network-namespace copy of a home LAN, for testing wyzecrack end to end
without a camera:

    cam 10.99.0.20 --(L2)-- mid 10.99.0.10 (wyzecrack) --(L2)-- gw 10.99.0.1 (NAT) -- internet 203.0.113.x

The camera's default route points at `mid`, as it does on a real LAN once
the tool has made itself the camera's router, and `mid` NATs its traffic.

- `lab_watch.sh` runs `tests/fakecam.py` as the camera and `wyzecrack watch`
  in `mid`, with the camera's key saved beforehand. It passes when the view
  went live and was recorded, hanging up switched the camera's video and
  audio off (K10010), and no firewall rule or journal is left in `mid`.
- `lab_onpath.sh` runs `wyzecrack events` in `mid` while `lab_api.py` plays
  the camera's HTTPS calls and the Wyze cloud (203.0.113.3). It passes when
  the ENR and both motion clips (one uploaded the way a v3 does, one the
  way a v2 does) were read, a name the tool must not read passed through
  untouched, and nothing is left in `mid` however the tool exited.
- `arp_check.sh` checks the ARP step: the camera's gateway entry points at
  `mid` while armed and back at the real gateway afterwards.

Run as root on Linux, from the repo, after `uv sync`:

    sudo bash lab/labsuite.sh            # everything; one PASS/FAIL line each in /tmp/wslab-suite.txt
    sudo bash lab/lab_watch.sh           # one view; FRAMING=iotc for the v2's framing,
                                         # LOGIN_DELAY=4 for a slow camera, QUIET_AFTER=3 SECS=30
                                         # for a camera that drops off mid-view
    sudo bash lab/lab_onpath.sh          # the key and clips; KILL_AT=2 KILL_SIG=TERM|HUP|INT2|KILL
                                         # signals the tool instead (INT2 = Ctrl-C twice,
                                         # KILL = then `wyzecrack cleanup`)
    sudo bash lab/debian-check.sh        # unit tests + suite on stock Debian 12 (podman/docker)

Logs land in `/tmp/wslab-out`.
