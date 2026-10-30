# Lab

The lab is a network-namespace replica of a home LAN as it looks once
`wyze-splice run` has made itself the camera's router. It tests the splice
end to end without a camera or phone:

    cam 10.99.0.20 --(L2)-- mid 10.99.0.10 (wyze-splice --on-path) --(L2)-- gw 10.99.0.1 (NAT) -- relays 203.0.113.x

The camera's default route points at `mid`, and `mid` NATs its traffic. On
a real LAN, the camera-only ARP poison plus MASQUERADE produce the same
result.

- `lab_peers.py` plays the camera and the phone behind the relay, with real
  DTLS and format-exact 0xCC51 wrappers modeled on live relay captures.
- `lab_api.py` plays the Wyze cloud, plus the camera's ENR-bearing POST and
  motion-clip upload.

Run as root on Linux, from the repo, after `uv sync`:

    sudo bash lab/lab_run.sh direct      # control: no splice, peers talk through the kernel
    sudo bash lab/lab_run.sh splice      # the same session through wyze-splice
    sudo MULTIPATH=1 bash lab/lab_run.sh splice
                                         # phone's ClientHello arrives via the STUN relay as 0x1402
    sudo FAIL_FIRST=1 CAM_IGNORE_FIRST_CH=1 DUR=30 bash lab/lab_run.sh splice
                                         # first attempt fails at the camera; the app retries on a new relay port
    sudo DIE_FIRST=1 DUR=30 bash lab/lab_run.sh splice
                                         # camera closes the spliced channel early; the app retries elsewhere
    sudo MEDIA_PPS=250 bash lab/lab_run.sh splice   # throughput
    sudo HARVEST=1 bash lab/lab_run.sh splice       # no --enr: harvest it from the camera's HTTPS
                                                    # first, and save its motion-clip upload
    sudo KILL_AT=6 KILL_SIG=TERM bash lab/lab_run.sh splice
                                         # signal the tool mid-session (TERM, HUP, INT2 =
                                         # Ctrl-C twice, KILL = then `cleanup`)
    sudo bash lab/arp_check.sh           # the ARP step: camera-only poison, then restore
    sudo bash lab/labsuite.sh            # all of the above; one PASS/FAIL line each in
                                         # /tmp/wslab-suite.txt
    sudo bash lab/debian-check.sh        # unit tests + suite on stock Debian 12 (podman/docker)

After every splice run, the lab checks that the tool left nothing behind in
the `mid` namespace: no TPROXY/REDIRECT/FORWARD rules, policy route,
`accept_local` or journal.

A run passes when:

- both peers report `handshake_done`;
- the phone's `media_ok` equals `expected_media`, with `media_bad` 0;
- each side sees only the other's real address in `srcs`.

A run that was signalled mid-session only has to leave nothing behind.
Captures and logs land in `/tmp/wslab-out`. `lab_run.sh` captures the
`mid` box with `tcpdump` (override with `TCPDUMP=`).
