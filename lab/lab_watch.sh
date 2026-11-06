#!/usr/bin/env bash
# Direct mode end to end: a fake camera (tests/fakecam.py) in the cam
# namespace, `wyzecrack watch` in mid with the camera's key already saved.
# usage: [FRAMING=cc51|iotc] [LOGIN_DELAY=s] [QUIET_AFTER=s [QUIET_FOR=s]]
#        [KILL_AT=s KILL_SIG=TERM|INT|KILL] [SECS=8] sudo bash lab_watch.sh
# Result: $OUT/watch.json (what the camera saw and what was recorded) and
# $OUT/leftovers.txt (firewall rules the tool left in mid; empty = clean).
set -u
LAB=$(dirname "$(readlink -f "$0")")
REPO=$(dirname "$LAB")
PY=${PY:-$REPO/.venv/bin/python}
SECS=${SECS:-8}
OUT=/tmp/wslab-out; rm -rf $OUT; mkdir -p $OUT/state
TOOLENV="WYZECRACK_DEBUG=1 PYTHONUNBUFFERED=1 PYTHONPYCACHEPREFIX=/tmp/pyc WYZECRACK_STATE=$OUT/state WYZECRACK_RUN=$OUT/run"
bash $LAB/lab_setup.sh up
cd $REPO
MAC=$(ip -n tfl-cam -o link show eth0 | sed -E 's/.*link\/ether ([0-9a-f:]+).*/\1/')
KEY=$(echo $MAC | tr -d : | tr a-f A-F)
cat > $OUT/state/enr.json <<EOF
{"$KEY": {"enr": "gekMdn0XjZoWF/mD", "uid": "ABCDEFGHJKLMNPQR111A", "model": "WYZE_CAKP2JFUS"}}
EOF
ip netns exec tfl-cam env PYTHONPYCACHEPREFIX=/tmp/pyc $PY tests/fakecam.py \
   --host 10.99.0.20 --mac $MAC --framing ${FRAMING:-cc51} --seconds $((SECS + 12)) \
   --login-delay ${LOGIN_DELAY:-0} ${QUIET_AFTER:+--quiet-after $QUIET_AFTER} \
   ${QUIET_FOR:+--quiet-for $QUIET_FOR} \
   > $OUT/cam.json 2> $OUT/cam.err &
CAM=$!
sleep 1.5
ip netns exec tfl-mid env $TOOLENV $PY -m wyzecrack watch --target 10.99.0.20 \
   --seconds $SECS --out $OUT/watch > $OUT/watch.out 2>&1 &
TOOL=$!
if [ -n "${KILL_AT:-}" ]; then
  sleep $KILL_AT
  case ${KILL_SIG:-TERM} in
    INT) kill -INT $TOOL ;;
    KILL) kill -KILL $TOOL; sleep 0.5
          ip netns exec tfl-mid env $TOOLENV $PY -m wyzecrack cleanup >> $OUT/watch.out 2>&1 ;;
    *) kill -$KILL_SIG $TOOL ;;
  esac
  echo killed > $OUT/killed.txt
fi
wait $TOOL; echo $? > $OUT/watch.rc
wait $CAM
# leftovers: any filter rule naming the camera (the setup's own MASQUERADE
# is in the nat table), and the journal
ip netns exec tfl-mid iptables -S | grep 10.99.0.20 > $OUT/leftovers.txt
[ -s $OUT/run/changes.json ] && echo "journal not empty" >> $OUT/leftovers.txt
$PY - $OUT <<'PY' > $OUT/watch.json
import json, os, sys
o = sys.argv[1]
cam = json.load(open(f"{o}/cam.json")) if os.path.getsize(f"{o}/cam.json") else {}
frames = None
mp4 = f"{o}/watch/video.mp4"
if os.path.exists(mp4):
    import av
    with av.open(mp4) as c:
        frames = c.streams.video[0].frames
print(json.dumps({"camera": cam, "mp4_frames": frames,
                  "rc": int(open(f"{o}/watch.rc").read())}))
PY
bash $LAB/lab_setup.sh down
cat $OUT/watch.json
