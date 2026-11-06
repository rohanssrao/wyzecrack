#!/usr/bin/env bash
# Run every lab scenario as root; one PASS/FAIL line each in /tmp/wslab-suite.txt
L=$(dirname "$(readlink -f "$0")"); R=/tmp/wslab-suite.txt; : > $R

# direct mode (`watch`) against the fake camera
summ_watch() {  # $1 name, $2 expectation: live|gone|killed
  python3 - "$1" "$2" >> $R <<'PY'
import json, os, sys
name, want, o = sys.argv[1], sys.argv[2], "/tmp/wslab-out"
try:
    r = json.load(open(f"{o}/watch.json"))
except Exception as e:
    print(f"{name}: NO RESULT ({e})"); sys.exit()
ev = r["camera"].get("events", [])
out = open(f"{o}/watch.out").read()
left = open(f"{o}/leftovers.txt").read().strip()
live = "[+] live from" in out
media_off = "K10010 0102" in ev and "K10010 0202" in ev
if want == "live":
    good = live and media_off and (r["mp4_frames"] or 0) > 20 and r["rc"] == 0
elif want == "gone":
    good = live and "went quiet" in ev and "camera went quiet" in out
else:
    good = live
good = good and not left
print(f"{name}: {'PASS' if good else 'FAIL'} live={live} media_off={media_off} "
      f"frames={r['mp4_frames']} rc={r['rc']} events={ev[:12]}"
      + (f" left={left!r}" if left else ""))
PY
}
for spec in "watch-cc51:FRAMING=cc51:live" "watch-iotc:FRAMING=iotc:live" \
            "watch-slow-login:LOGIN_DELAY=4:live" \
            "watch-camera-gone:QUIET_AFTER=3 SECS=30:gone" \
            "watch-sigterm:KILL_AT=5 KILL_SIG=TERM:killed" \
            "watch-ctrl-c:KILL_AT=5 KILL_SIG=INT:killed" \
            "watch-sigkill-then-cleanup:KILL_AT=5 KILL_SIG=KILL:killed"; do
  name=${spec%%:*}; rest=${spec#*:}; envs=${rest%%:*}; want=${rest##*:}
  env $envs bash $L/lab_watch.sh > /tmp/wslab-$name.log 2>&1
  cp /tmp/wslab-out/watch.out /tmp/wslab-$name.watch.out 2>/dev/null
  summ_watch $name $want
done

# on-path mode (`events`: the key read's and motion clips' routing) against
# the fake Wyze cloud, and its teardown however the tool exits
summ_onpath() {  # $1 name, $2 expectation: read|killed
  python3 - "$1" "$2" >> $R <<'PY'
import json, sys
name, want, o = sys.argv[1], sys.argv[2], "/tmp/wslab-out"
try:
    r = json.load(open(f"{o}/onpath.json"))
except Exception as e:
    print(f"{name}: NO RESULT ({e})"); sys.exit()
left = open(f"{o}/leftovers.txt").read().strip()
sni_ok = r["upstream_sni"] == ["api.wyzecam.com", "cpl-t-sightsafe.wyzecam.com",
                               "c-t-usw2.s3.us-west-2.amazonaws.com",
                               "wyze-iot.s3.us-west-2.amazonaws.com"]
if want == "read":
    good = (r["api"].get("ok") and r["enr_saved"] and r["clips"] == 2
            and r["clips_match"] and sni_ok)
else:
    good = True
good = good and not left
print(f"{name}: {'PASS' if good else 'FAIL'} enr_saved={r['enr_saved']} clips={r['clips']} "
      f"match={r['clips_match']} upstream_sni={r['upstream_sni']}"
      + (f" api={r['api']}" if not r["api"].get("ok") and want == "read" else "")
      + (f" left={left!r}" if left else ""))
PY
}
for spec in "onpath-key-and-clips::read" \
            "onpath-sigterm:KILL_AT=2 KILL_SIG=TERM:killed" \
            "onpath-sighup:KILL_AT=2 KILL_SIG=HUP:killed" \
            "onpath-double-ctrl-c:KILL_AT=2 KILL_SIG=INT2:killed" \
            "onpath-sigkill-then-cleanup:KILL_AT=2 KILL_SIG=KILL:killed"; do
  name=${spec%%:*}; rest=${spec#*:}; envs=${rest%%:*}; want=${rest##*:}
  env $envs bash $L/lab_onpath.sh > /tmp/wslab-$name.log 2>&1
  cp /tmp/wslab-out/tool.out /tmp/wslab-$name.tool.out 2>/dev/null
  summ_onpath $name $want
done

echo "arp-poison: $(bash $L/arp_check.sh | tail -1)" >> $R
echo "leftover processes: $(pgrep -fc 'target 10.99.0.20')" >> $R
echo DONE >> $R
