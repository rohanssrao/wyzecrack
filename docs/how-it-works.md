# How wyzecrack works

A live view needs three things per camera: its MAC, its ENR and its TUTK
UID. The MAC comes from ARP. The ENR is read once off the camera's own
HTTPS (steps 1 and 2 below). The UID never crosses the LAN, but Wyze's
cloud returns it for the camera's MAC and ENR (step 3). With all three
cached, the tool talks to the camera directly over the LAN, the way the
Wyze app does on the camera's Wi-Fi (step 4), and nothing on the network
is rerouted. Steps 5 and 6 are the fallback when Wyze won't return the
UID: splicing the live views the Wyze app opens. Step 7 covers both.

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
   `*.wyzecam.com`, and to the S3 bucket the v2 uploads its alarms to
   (`c-t-usw2.s3.us-west-2.amazonaws.com`), the relay presents a leaf for
   the requested name signed under that intermediate and forwards the
   connection to the real server under the same name. Everything else
   (firmware and model downloads from S3, log uploads, for example) passes
   through as raw TCP, and so does a bucket host whose leaf the camera
   refused once, so that its retry still reaches Wyze. The tool reads two
   things from the camera's requests:
   - the ENR, the per-camera secret in the JSON of its POSTs to
     api.wyzecam.com (`enr`) and device-api.wyzecam.com (`device_enr`);
   - motion events: for each alarm, the camera PUTs a snapshot and a 12 s
     1080p clip (H.264 with A-law audio) through pre-signed URLs: the v3
     to cpl-t-sightsafe.wyzecam.com, the v2 to that S3 bucket. The only
     encryption on these uploads is the TLS the tool terminates.

   The camera sends its ENR in every device-API request, but it makes
   few: at boot, on motion alarms, and in its metrics report. In firmware
   4.36.17.21 (libwyzeUtils.so, `ms_upload_handler`) the report goes out
   at a random time 0 to 20 minutes after the previous one, or as soon as
   the 5120-byte metrics buffer is full. Each time the camera's MQTT
   connection to aws-iot.wyzecam.com drops, it logs about 1 KB of
   metrics while it reconnects. So `nudge.py` resets that connection, and
   only that one: a TCP RST spoofed from the broker plus an iptables
   REJECT for the connection, both journaled. It repeats the reset each
   time the camera has reconnected, until the report arrives, at most 8
   times. On v3 A that took 4 to 6 resets and 90 to 115 s; on the
   v2 (4.9.9.3006) one reset, after which the camera
   posted `set_device_info` with its ENR. The camera stays online apart
   from a few seconds per reconnect, and live views are unaffected. The
   nudge runs on the models it was tried on (`NUDGE_MODELS`: the v3 and
   the v2); `--no-nudge` turns it off.

   An earlier version cut all of the camera's traffic until it noticed.
   That produced the report only when the burst of connection events
   happened to overflow the buffer, and it left v3 C (4.36.16)
   offline in the Wyze app for about half an hour and the v2 for over an
   hour. The firmware also has a path for a network that stays
   unavailable past a retry limit (`exceed_network_connection_retry_limit`
   in `netChange_callback`): it plays a voice prompt
   (`notify/CN/user_need_check.wav`) and resets the network.

3. **Ask Wyze for the UID** (`cloud.fetch_uid`). Wyze's device API
   authenticates a camera only by the `mac` and `enr` in the JSON body.
   The firmware (4.36.17.21) calls `POST /device/system/get_p2pid` when it
   has no UID stored, with fixed `sc`/`sv` values and `"p2p_id_type": 3`;
   Wyze answers with the camera's TUTK UID. The tool makes the same call
   from this host, as the camera. The UID never appears on the LAN: every
   P2P packet only carries an HMAC keyed by it, the camera's link to
   ThroughTek's servers is encrypted, and the legacy LAN search that used
   to return it gets no answer on this firmware.

4. **Watch directly** (`direct.py`). This is the session the Wyze app
   opens when it is on the camera's Wi-Fi, after go2rtc's implementation
   (`pkg/tutk/dtls`, `pkg/wyze`):
   - discovery: cmd 0x1002 to udp/32761. The camera answers from its P2P
     port with a ticket, and four packets (seq 0 to 3) set up the session;
   - every packet ends in a 20-byte HMAC-SHA1 trailer keyed by the UID and
     the AuthKey (base64 of SHA256(ENR + MAC)[:6]), over the 28-byte
     header (32 bytes for discovery). The camera ignores packets whose
     trailer is wrong;
   - DTLS records ride in cmd 0x1502 (the same client leg as step 6);
   - inside: an AV login whose password is the ENR, the K10000/K10002
     challenge (XXTEA with the ENR), and K10056 for 1080p. The camera then
     streams H.264 and 8 kHz PCM, acknowledged every 100 ms.

   The camera answers from a different port than the one it was sent to,
   which a stateful host firewall drops, so the tool opens udp from the
   camera to its socket for the session (journaled).

   A camera answers some sessions' DTLS handshake or AV login at once and
   others only after 5 to 25 s, or never: it drops those after 30 s with
   cmd 0x1302. Sessions are slow independently of each other. Of two
   opened at the same moment, one logged in after 0.2 s and the other
   after 21 s; in another pair, one never got an answer and the other
   logged in after 1.2 s. Recent sessions, other viewers, the host's
   network and the session close below didn't explain it; the delay is
   inside the camera (both v3s, 4.36.17.21). So when a session hasn't
   logged in after 2 s, the tool opens a second one beside it and keeps
   whichever logs in first (`open_first`). Every 6 s after that it
   replaces the older of the two. It never holds more than two, because
   the camera takes five sessions in all (`IOTC_Set_Max_Session_Number(5)`
   in the v2 firmware) and other viewers need theirs. A camera that
   doesn't answer discovery within 10 s is switched off, offline, or has a
   new key, and gets no second session. Before this, a quarter of single
   sessions to the v3s got no answer within 30 s and the median was about
   8 s; with it, six views of v3 A started after 0.5 to 15 s
   (median 4 s), none failing. The v2 wasn't affected (0.5 to 2.2 s).

   When the tool hangs up, it first switches the camera's video and audio
   off (K10010); otherwise the camera keeps streaming to the dead session
   for about 30 s. It then sends cmd 0x1302 (laid out like a keepalive,
   with the session id at [20:28]), the message the camera itself sends
   when it drops a session. The camera ends the session at once instead of
   keeping it for its 30 s alive timeout
   (`IOTC_Setup_Session_Alive_Timeout(30)`). The older (v2) framing has no
   such message that the tool knows of.

5. **Catch the session** (`splice.py`, the fallback). Nothing is
   diverted while the tool waits. When the app opens a live view, the
   camera sends a 0x1102 channel-open to a fresh relay. At that moment the
   tool pins TPROXY rules to the camera's exact 5-tuples toward that data
   relay and toward each STUN relay (:3478). Both are needed: the phone's
   ClientHello can arrive as cmd 0x1402 through a STUN relay while the
   camera answers as 0x1502 on the data relay.

6. **Splice the DTLS** (`dtls.py`). The session is DTLS 1.2 with
   TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256, and the PSK is derived from
   the ENR alone. The engine terminates both legs (server toward the phone,
   client toward the camera) with flights byte-size-matched to the
   originals. This lets it reuse each 0xCC51 wrapper and its header-keyed
   trailer verbatim, so no UID or relay credentials are needed. It decrypts
   the media to `av.bin` and re-encrypts it for the phone. Re-sent packets
   keep the TTL a forwarded packet would have had. When re-originated
   packets left with TTL 64, the camera stopped routing through the MITM.

7. **Tear down and export** (`media.py`). When the camera goes quiet, the
   tool removes its rules and hands the flows back to the kernel. It
   reassembles the H.264 from TUTK media frames and remuxes it (without
   re-encoding) into an MP4 paced to arrival time. The app starts each live
   view in SD and switches the camera to 1080p a few seconds in, and each
   resolution that lasted at least 2 s gets its own MP4. A spliced session
   carries the media in the app's resend format; a direct one in the plain
   format, the same records with an 8-byte shorter header. Frames that could not decode cleanly are
   left out: any incomplete frame, plus the rest of its group of pictures.
   Once the viewer leaves, the camera keeps streaming to the dead session
   for a while but stops completing I-frames, so that tail is dropped.

## The page

The page (`gui.py`) runs one live view at a time. Everything from the
click to Stop is one recording: when the camera hangs up, the page opens a
new session and records into the same capture, and the export joins the
stretches (the picture holds still across the gap).

**Motion clips** (`motion.py`), when turned on for a camera, are copied
in the background for as long as the page is open: the camera is routed
through this host (step 1) and its uploads are read (step 2), as with the
`events` command. Several cameras can be captured at once, each with its
own interceptor port, and a capture steps aside while the same camera's
key is read or its live view is spliced. If a camera without a saved key
uploads a clip, its key is saved from that upload.

The page holds the single-instance lock and one journal (below) for its
whole life. Each live view, capture and key read takes a scope of it and
undoes only its own changes. A sysctl that two of them need (ip_forward,
for two cameras on the path) is put back when the last one is done.

## Safety

Every change to the host (iptables rules, the policy route, sysctls, the
camera's ARP entry) is written to a journal in `/run/wyzecrack/` before
it is made. However the tool exits, including Ctrl-C (once or repeatedly),
SIGTERM or a closed terminal, it undoes the changes in reverse order. If
the process is killed outright, `wyzecrack cleanup` or the next run
replays the journal. (A reboot clears these changes on its own: none of
them are persistent.) Only one instance runs at a time.

The tool also adds FORWARD accept rules for the camera, for firewalls that
drop forwarded traffic (ufw, Docker, firewalld). These rules can't override
a firewall that drops the traffic directly in nftables. In that case the
tool warns when the camera's traffic stops coming back. While the tool
runs, it holds a `systemd-inhibit` sleep lock, because a suspended host
black-holes the camera.
