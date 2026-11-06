#!/usr/bin/env bash
# ARP step of on-path mode: the camera's gateway entry must point at mid
# while armed and back at the real gateway after close(). Prints PASS/FAIL.
set -u
LAB=$(dirname "$(readlink -f "$0")"); REPO=$(dirname "$LAB")
PY=${PY:-$REPO/.venv/bin/python}
bash $LAB/lab_setup.sh up >/dev/null
# undo the lab's static "poisoned" route: the camera uses the real gateway
ip -n tfl-cam route replace default via 10.99.0.1
ip netns exec tfl-cam ping -c1 -W1 10.99.0.1 >/dev/null
MID=$(ip netns exec tfl-mid cat /sys/class/net/eth0/address)
GW=$(ip netns exec tfl-gw cat /sys/class/net/eth0/address)
gwmac() { ip -n tfl-cam neigh show 10.99.0.1 | awk '{print $5}'; }
before=$(gwmac)
ip netns exec tfl-mid env PYTHONPATH=$REPO $PY - <<'PY' &
import tempfile, time
from wyzecrack.changes import Changes
from wyzecrack.onpath import OnPath
c = Changes(tempfile.mkdtemp())
o = OnPath(c, "10.99.0.20", "eth0", poison=True, gateway="10.99.0.1")
o.start(); time.sleep(4); o.close()
assert not c.items, c.items
PY
sleep 3; during=$(gwmac)
# keep the camera talking so its entry stays live
ip netns exec tfl-cam ping -c1 -W1 10.99.0.1 >/dev/null
wait; sleep 1; after=$(gwmac)
bash $LAB/lab_setup.sh down
echo "gw=$GW mid=$MID before=$before during=$during after=$after"
[ "$before" = "$GW" ] && [ "$during" = "$MID" ] && [ "$after" = "$GW" ] && echo PASS || echo FAIL
