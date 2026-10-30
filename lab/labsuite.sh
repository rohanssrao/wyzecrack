#!/usr/bin/env bash
# Run every lab scenario as root; one PASS/FAIL line each in /tmp/wslab-suite.txt
L=$(dirname "$(readlink -f "$0")"); R=/tmp/wslab-suite.txt; : > $R
summ() {  # $1 name
  python3 - "$1" >> $R <<'PY'
import json, os, sys
name, o = sys.argv[1], "/tmp/wslab-out"
try:
    ph = json.load(open(f"{o}/phone.json")); cam = json.load(open(f"{o}/cam.json"))
except Exception as e:
    print(f"{name}: NO RESULT ({e})"); sys.exit()
out = open(f"{o}/splice.out").read() if os.path.exists(f"{o}/splice.out") else ""
exp = ph["expected_media"]
sess = {p: (s["handshake_done"], s["media_ok"], s["media_bad"]) for p, s in ph["sessions"].items()}
srcs = sorted({a for s in ph["sessions"].values() for a in s["srcs"]}) + sorted(cam["srcs"])
good = any(m == exp and b == 0 and h for h, m, b in sess.values())
if os.path.exists(f"{o}/api.json"):
    api = json.load(open(f"{o}/api.json"))
    good = good and api.get("ok") and "ENR harvested" in out
    if "ENR harvested" not in out: print(f"  ({name}: no harvest)")
spliced = "spliced: both DTLS legs up" in out
ends = [l.split("session over: ")[1] for l in out.splitlines() if "session over:" in l]
latches = [l.split("relay flow ")[1] for l in out.splitlines() if "relay flow (" in l]
print(f"{name}: {'PASS' if good else 'FAIL'} phone={sess} expected={exp} spliced={spliced} "
      f"srcs={srcs} latches={latches} ends={ends}")
PY
}
for spec in "direct-plain::direct" "splice-plain::splice" \
            "splice-failfirst:FAIL_FIRST=1 CAM_IGNORE_FIRST_CH=1 DUR=30:splice" \
            "direct-diefirst:DIE_FIRST=1 DUR=30:direct" \
            "splice-diefirst:DIE_FIRST=1 DUR=30:splice" \
            "splice-500pps:MEDIA_PPS=250:splice" \
            "direct-multipath:MULTIPATH=1:direct" \
            "splice-multipath:MULTIPATH=1:splice" \
            "splice-multipath-diefirst:MULTIPATH=1 DIE_FIRST=1 DUR=30:splice" \
            "splice-harvest:HARVEST=1:splice"; do
  name=${spec%%:*}; rest=${spec#*:}; envs=${rest%%:*}; mode=${rest##*:}
  env $envs bash $L/lab_run.sh $mode > /tmp/wslab-$name.log 2>&1
  cp /tmp/wslab-out/splice.out /tmp/wslab-$name.splice.out 2>/dev/null
  summ $name
done
echo DONE >> $R
