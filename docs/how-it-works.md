# How wyze-splice works

1. **Get on-path** (`onpath.py`). The tool ARP-poisons only the camera so
   this host becomes the camera's gateway, and MASQUERADEs the camera's
   traffic out under this host's address. The real router is never
   poisoned. Two-way poisoning makes a typical home router route the
   camera's spoofed packets back to the MITM (same 5-tuple, TTL dropping by
   one per bounce), which black-holes the stream. The camera's existing
   flows survive the switch, and the relays pick up the new NAT mapping
   from the camera's next keepalive.

2. **Read the camera's HTTPS** (`cloud.py`). The camera's TLS client still
   trusts the eMudhra "EM OV TLS CA - G3C" intermediate, whose private key
   became public in October 2026 (a P-384 key with d=4). The camera's
   tcp/443 is redirected to a local relay. For connections to
   `*.wyzecam.com`, the relay presents a leaf for the requested name signed
   under that intermediate and forwards the connection to the real server
   under the same name. Everything else (firmware and model downloads from
   S3, for example) passes through as raw TCP. The tool reads two things
   from the camera's requests:
   - the ENR, the per-camera secret in the JSON of its POSTs to
     api.wyzecam.com;
   - motion events: for each alarm, the camera PUTs a snapshot and a 12 s
     1080p clip (H.264 with A-law audio) to cpl-t-sightsafe.wyzecam.com
     through pre-signed URLs. The only encryption on these uploads is the
     TLS the tool terminates.

3. **Catch the session** (`splice.py`). Nothing is diverted while the tool
   waits. When the app opens a live view, the camera sends a 0x1102
   channel-open to a fresh relay. At that moment the tool pins TPROXY rules
   to the camera's exact 5-tuples toward that data relay and toward each
   STUN relay (:3478). Both are needed: the phone's ClientHello can arrive
   as cmd 0x1402 through a STUN relay while the camera answers as 0x1502 on
   the data relay.

4. **Splice the DTLS** (`dtls.py`). The session is DTLS 1.2 with
   TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256, and the PSK is derived from
   the ENR alone. The engine terminates both legs (server toward the phone,
   client toward the camera) with flights byte-size-matched to the
   originals. This lets it reuse each 0xCC51 wrapper and its header-keyed
   trailer verbatim, so no UID or relay credentials are needed. It decrypts
   the media to `av.bin` and re-encrypts it for the phone. Re-sent packets
   keep the TTL a forwarded packet would have had. When re-originated
   packets left with TTL 64, the camera stopped routing through the MITM.

5. **Tear down and export** (`media.py`). When the camera goes quiet, the
   tool removes its rules and hands the flows back to the kernel. It
   reassembles the H.264 from TUTK media frames and remuxes it (without
   re-encoding) into an MP4 paced to arrival time. The app starts each live
   view in SD and switches the camera to 1080p a few seconds in, and each
   resolution gets its own MP4. Frames that could not decode cleanly are
   left out: any incomplete frame, plus the rest of its group of pictures.
   Once the viewer leaves, the camera keeps streaming to the dead session
   for a while but stops completing I-frames, so that tail is dropped.

## Safety

Every change to the host (iptables rules, the policy route, sysctls, the
camera's ARP entry) is written to a journal in `/run/wyze-splice/` before
it is made. However the tool exits, including Ctrl-C (once or repeatedly),
SIGTERM or a closed terminal, it undoes the changes in reverse order. If
the process is killed outright, `wyze-splice cleanup` or the next run
replays the journal. (A reboot clears these changes on its own: none of
them are persistent.) Only one instance runs at a time.

The tool also adds FORWARD accept rules for the camera, for firewalls that
drop forwarded traffic (ufw, Docker, firewalld). These rules can't override
a firewall that drops the traffic directly in nftables. In that case the
tool warns when the camera's traffic stops coming back. While the tool
runs, it holds a `systemd-inhibit` sleep lock, because a suspended host
black-holes the camera.
