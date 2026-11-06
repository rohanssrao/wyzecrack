# Live tests without a phone

These scripts run the real Wyze Android app in an emulator on the test host
and open the camera's live view through ThroughTek's relays while
`wyzecrack` runs, so the whole chain can be tested without anyone
holding a phone.

The emulator's direct paths to the camera are blocked for the test, as a
phone on cellular has them blocked by its carrier's NAT: the LAN, the home
public IP (hairpin P2P) and IPv6, plus the camera's own hairpin toward the
home public IP. The app then falls back to the relays, the path the tool
intercepts. The rules match the emulator's cgroup (`wyze-emu.scope`) and
are removed when the test ends.

One-time setup (on the test host):

1. `nix-build live/android.nix -o ~/wyze-emu/sdk` (Android 14 Google APIs
   x86_64 image; it translates the app's ARM code).
2. Get the Wyze app bundle (`.apkm`, e.g. from APKMirror), unzip it, and
   check the signer with `apksigner verify --print-certs base.apk`.
3. `bash live/emu-start.sh`, then
   `bash live/emu.sh install-multiple base.apk split_config.arm64_v8a.apk split_config.en.apk split_config.xxhdpi.apk`.
4. Log in once: `bash live/emu-screen.sh start` serves the emulator's screen
   as a password-protected noVNC page on the host's tailnet address; log in
   there, then `bash live/emu-screen.sh stop` and `bash live/emu-start.sh`
   to go back to headless.

Each test:

    bash live/emu-start.sh                        # if the emulator is not running
    sudo CAM=192.168.1.20 bash live/livetest.sh splice 25

It writes screenshots of the app, the tool's output and a camera pcap to
`~/wyze-emu/runs/<run>/`, and the capture to `captures/<run>/`. `pass`
instead of `splice` runs the tool with `--pass-through` (an observe-only
baseline). Don't run it while `lab/labsuite.sh` runs: a new network
namespace copies the host's IPv4 sysctls, so the lab would see the live
run's `accept_local`.
