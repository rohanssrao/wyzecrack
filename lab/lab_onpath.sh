#!/usr/bin/env bash
# On-path mode end to end: `wyzecrack events` in mid while the camera
# namespace makes the camera's HTTPS calls (lab_api.py client) to a fake
# Wyze cloud. The ENR and both clips must be read, and the tool must leave
# nothing behind in mid however it exits.
# usage: [KILL_AT=s KILL_SIG=TERM|HUP|INT2|KILL] sudo bash lab_onpath.sh
# Result: $OUT/onpath.json and $OUT/leftovers.txt (empty = clean).
set -u
LAB=$(dirname "$(readlink -f "$0")")
REPO=$(dirname "$LAB")
PY=${PY:-$REPO/.venv/bin/python}
OUT=/tmp/wslab-out; rm -rf $OUT; mkdir -p $OUT/state
# the lab's journal and lock must never meet a real run's
TOOLENV="WYZECRACK_DEBUG=1 PYTHONUNBUFFERED=1 PYTHONPYCACHEPREFIX=/tmp/pyc WYZECRACK_STATE=$OUT/state WYZECRACK_RUN=$OUT/run"
bash $LAB/lab_setup.sh up
cd $REPO
tool_pids() { for p in $(ip netns pids tfl-mid); do grep -qa wyzecrack /proc/$p/cmdline 2>/dev/null && echo $p; done; }
ip netns exec tfl-relay env OUT=$OUT $PY $LAB/lab_api.py server 40 > $OUT/api-server.log 2>&1 &
API=$!
ip netns exec tfl-mid env $TOOLENV $PY -m wyzecrack events --target 10.99.0.20 \
   --on-path --out $OUT/events --count 2 > $OUT/tool.out 2>&1 &
sleep 4
if [ -n "${KILL_AT:-}" ]; then
  sleep $KILL_AT
  case ${KILL_SIG:-TERM} in
    INT2) kill -INT $(tool_pids); sleep 0.3; kill -INT $(tool_pids) 2>/dev/null ;;
    *) kill -$KILL_SIG $(tool_pids) ;;
  esac
  echo killed > $OUT/killed.txt
else
  ip netns exec tfl-cam env OUT=$OUT $PY $LAB/lab_api.py client > $OUT/api.json 2>&1
fi
for i in $(seq 1 30); do [ -z "$(tool_pids)" ] && break; sleep 0.5; done
if [ -n "$(tool_pids)" ]; then echo "tool still running" >> $OUT/leftovers.txt; kill -9 $(tool_pids); fi
if [ "${KILL_SIG:-}" = KILL ]; then
  ip netns exec tfl-mid env $TOOLENV $PY -m wyzecrack cleanup > $OUT/cleanup.out 2>&1
fi
kill $API 2>/dev/null
# anything the tool installed must be gone (lab_setup's own MASQUERADE stays)
ip netns exec tfl-mid sh -c '
  iptables-save | grep -E "REDIRECT|10\.99\.0\.20" | grep -v -- "-A POSTROUTING -s 10.99.0.20/32 -o eth0 -j MASQUERADE"
  [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || echo "ip_forward changed"' >> $OUT/leftovers.txt
[ -s $OUT/run/changes.json ] && echo "journal not empty" >> $OUT/leftovers.txt
$PY - $OUT <<'PY' > $OUT/onpath.json
import glob, hashlib, json, os, sys
o = sys.argv[1]
def load(p):
    try:
        return json.load(open(p))
    except Exception:
        return {}
api = load(f"{o}/api.json")
sent = open(f"{o}/sent-clip.mp4", "rb").read() if os.path.exists(f"{o}/sent-clip.mp4") else None
clips = sorted(glob.glob(f"{o}/events/*/clip.mp4"))
same = bool(sent) and all(open(c, "rb").read() == sent for c in clips)
sni = open(f"{o}/api-sni.txt").read().split() if os.path.exists(f"{o}/api-sni.txt") else []
# saved under the camera namespace's (random) MAC
enr = any(v.get("enr") == "gekMdn0XjZoWF/mD" for v in load(f"{o}/state/enr.json").values())
print(json.dumps({"api": api, "clips": len(clips), "clips_match": same,
                  "upstream_sni": sni, "enr_saved": enr}))
PY
bash $LAB/lab_setup.sh down
cat $OUT/onpath.json
echo "== leftovers"; cat $OUT/leftovers.txt
