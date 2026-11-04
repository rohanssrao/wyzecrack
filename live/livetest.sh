#!/usr/bin/env bash
# Autonomous live test: the real Wyze app in the emulator opens the
# camera's live view through the TUTK relays while wyze-splice runs.
# usage: sudo CAM=<camera ip> bash live/livetest.sh [splice|pass|drive] [watch seconds]
#   drive: only open the live view in the app (isolated); something else,
#          such as the GUI, runs wyze-splice
#   TILE_XY  where the camera's tile sits on the app's home screen
#            (default "543 1700": the second tile on a Pixel 6 AVD)
#   EMU_HOME emulator state (default ~/wyze-emu of the sudo user)
#
# The emulator's direct paths to the camera are blocked, as a cellular
# phone's are by carrier NAT: LAN (192.168.1.0/24), the home public IP
# (hairpin P2P) and all IPv6. The camera's own hairpin toward the home
# public IP is blocked too. All rules are removed on exit.
set -u
MODE=${1:-splice}; WATCH=${2:-20}
: "${CAM:?set CAM=<camera ip>}"
U=${SUDO_USER:?run with sudo}; H=$(getent passwd $U | cut -d: -f6)
W=${EMU_HOME:-$H/wyze-emu}; R=$(dirname "$(dirname "$(readlink -f "$0")")")
ADB=$W/sdk/libexec/android-sdk/platform-tools/adb
CG="user.slice/user-$(id -u $U).slice/user@$(id -u $U).service/app.slice/wyze-emu.scope"
PUB=$(curl -s -4 --max-time 5 https://ifconfig.me)
RUN=emu-$(date +%Y%m%d-%H%M%S)-$MODE; OUT=$R/captures/$RUN; LOG=$W/runs/$RUN; mkdir -p $LOG
adb() { $ADB -e "$@" < /dev/null; }
say() { echo "[$(date +%T)] $*" | tee -a $LOG/harness.log; }

RULES=(
  "iptables -w -I OUTPUT 1 -m cgroup --path $CG -d 192.168.1.0/24 -j DROP"
  "iptables -w -I OUTPUT 1 -m cgroup --path $CG -d $PUB -j DROP"
  "ip6tables -w -I OUTPUT 1 -m cgroup --path $CG ! -o lo -j DROP"
  "iptables -w -t raw -I PREROUTING 1 -s $CAM -d $PUB -j DROP"
)
TOOL=
cleanup() {
  [ -n "${TDP:-}" ] && kill $TDP 2>/dev/null
  [ -n "$TOOL" ] && kill -INT $TOOL 2>/dev/null && for i in $(seq 1 30); do kill -0 $TOOL 2>/dev/null || break; sleep 1; done
  adb shell am force-stop com.hualai
  for r in "${RULES[@]}"; do $(echo "$r" | sed 's/ -I \([A-Z]*\) 1 / -D \1 /') 2>/dev/null; done
  say "isolation rules removed"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

[ -n "$PUB" ] || { say "no public IP"; exit 1; }
[ "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1 ] || { say "emulator not booted"; exit 1; }
adb shell am force-stop com.hualai
for r in "${RULES[@]}"; do $r || { say "rule failed: $r"; exit 1; }; done
say "isolation on (public IP $PUB); mode $MODE"

TD=$(nix build --no-link --print-out-paths nixpkgs#tcpdump 2>/dev/null)/bin/tcpdump
$TD -ni enp10s0 -s0 -U -w $LOG/cam.pcap "host $CAM" > /dev/null 2>&1 &
TDP=$!
# the app's own traffic (all of it leaves as this host's address)
$TD -ni any -s 200 -U -w $LOG/app.pcap "not host $CAM and not port 22 and not port 41641 and not port 443 and (udp or tcp)" > /dev/null 2>&1 &
TDP="$TDP $!"
ARGS="--target $CAM --out $OUT --journal"
[ "$MODE" = pass ] && ARGS="$ARGS --pass-through"
cd $R
if [ "$MODE" != drive ]; then
  PYTHONUNBUFFERED=1 PYTHONPYCACHEPREFIX=/tmp/pyc .venv/bin/wyze-splice run $ARGS > $LOG/tool.out 2>&1 &
  TOOL=$!
  for i in $(seq 1 40); do grep -q "watching" $LOG/tool.out && break; sleep 1; done
  grep -q "watching" $LOG/tool.out || { say "tool did not start:"; cat $LOG/tool.out; exit 1; }
  say "tool watching; opening the app"
fi

adb shell monkey -p com.hualai -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 12
adb exec-out screencap -p > $LOG/home.png
# uiautomator cannot dump a screen with live video tiles (it never goes
# idle); the tile sits at a fixed spot on this AVD's home screen
XY=${TILE_XY:-"543 1700"}
say "tapping the camera tile at $XY"
adb shell input tap $XY
T0=$(date +%s)
for t in 3 6 10 15 20 25 30 40 50 60; do
  [ $t -gt $WATCH ] && break
  sleep $((T0 + t - $(date +%s)))
  adb exec-out screencap -p > $LOG/t$(printf %02d $t).png
done
say "leaving the live view"
adb shell input keyevent 4; sleep 1; adb shell am force-stop com.hualai
[ "$MODE" = drive ] && { chown -R $U $LOG; echo "logs: $LOG"; exit 0; }
for i in $(seq 1 60); do kill -0 $TOOL 2>/dev/null || break; grep -q "session(s) spliced" $LOG/tool.out && break; sleep 1; done
sleep 2
cp -r $OUT/splice.log $LOG/ 2>/dev/null
say "tool output:"; grep -v "new public flow" $LOG/tool.out | tee -a $LOG/harness.log
$R/.venv/bin/python - $LOG <<'PY' | tee -a $LOG/harness.log
# does the screen show moving video? compare consecutive screenshots
import glob, sys
from PIL import Image, ImageChops, ImageStat
shots = sorted(glob.glob(sys.argv[1] + "/t*.png"))
prev = None
for p in shots:
    im = Image.open(p).convert("L")
    top = im.crop((0, 0, im.width, im.height // 2))
    bright = ImageStat.Stat(top).mean[0]
    diff = ImageStat.Stat(ImageChops.difference(top, prev)).mean[0] if prev else 0
    print(f"{p.rsplit('/', 1)[1]}: brightness {bright:5.1f}, change {diff:5.2f}")
    prev = top
PY
chown -R $U $LOG
echo "logs: $LOG"
