#!/usr/bin/env bash
# usage: [MULTIPATH=1] [FAIL_FIRST=1] [CAM_IGNORE_FIRST_CH=1] [DIE_FIRST=1]
#        [HARVEST=1] [PASS=1] [DUR=14] [KILL_AT=seconds KILL_SIG=TERM|HUP|INT2|KILL]
#        sudo bash lab_run.sh splice|direct
# KILL_AT signals the tool mid-session (INT2 = Ctrl-C twice; KILL is
# followed by `wyze-splice cleanup`). Whatever the tool leaves behind in
# the mid namespace is written to $OUT/leftovers.txt (empty = clean).
set -u
LAB=$(dirname "$(readlink -f "$0")")
REPO=$(dirname "$LAB")
PY=${PY:-$REPO/.venv/bin/python}
TCPDUMP=${TCPDUMP:-$(command -v tcpdump || true)}
MODE=${1:-splice}
DUR=${DUR:-14}
PEERENV="MULTIPATH=${MULTIPATH:-0} FAIL_FIRST=${FAIL_FIRST:-0} DIE_FIRST=${DIE_FIRST:-0} CAM_IGNORE_FIRST_CH=${CAM_IGNORE_FIRST_CH:-0} MEDIA_SECS=${MEDIA_SECS:-8} MEDIA_PPS=${MEDIA_PPS:-60} PYTHONPYCACHEPREFIX=/tmp/pyc"
OUT=/tmp/wslab-out; rm -rf $OUT; mkdir -p $OUT
# the lab's journal and lock must never meet a real run's
TOOLENV="WYZE_SPLICE_DEBUG=1 PYTHONUNBUFFERED=1 PYTHONPYCACHEPREFIX=/tmp/pyc WYZE_SPLICE_STATE=$OUT/state WYZE_SPLICE_RUN=$OUT/run"
bash $LAB/lab_setup.sh up
cd $REPO
tool_pids() { for p in $(ip netns pids tfl-mid); do grep -qa wyze_splice /proc/$p/cmdline 2>/dev/null && echo $p; done; }
if [ "${HARVEST:-0}" = 1 ]; then
  ENRARG="--reharvest --harvest-timeout 20"
  ip netns exec tfl-relay env OUT=$OUT $PY $LAB/lab_api.py server $((DUR+15)) > $OUT/api-server.log 2>&1 &
else
  ENRARG="--enr gekMdn0XjZoWF/mD"
fi
if [ "$MODE" = splice ]; then
  ip netns exec tfl-mid env $TOOLENV \
     $PY -m wyze_splice run --target 10.99.0.20 $ENRARG --on-path --keep-going \
     --out $OUT --journal --no-video ${PASS:+--pass-through} > $OUT/splice.out 2>&1 &
  sleep 4
fi
if [ "${HARVEST:-0}" = 1 ]; then
  ip netns exec tfl-cam env OUT=$OUT $PY $LAB/lab_api.py client > $OUT/api.json 2>&1
  sleep 1
fi
TD=
if [ -n "$TCPDUMP" ]; then
  ip netns exec tfl-mid $TCPDUMP -ni eth0 -s0 -U -w $OUT/mid.pcap udp >/dev/null 2>&1 &
  TD=$!
fi
sleep 0.5
ip netns exec tfl-relay env $PEERENV $PY $LAB/lab_peers.py phone $((DUR+1)) > $OUT/phone.json 2>$OUT/phone.err &
PH=$!
sleep 0.3
if [ -n "${KILL_AT:-}" ]; then
  ( sleep $KILL_AT
    case ${KILL_SIG:-TERM} in
      INT2) kill -INT $(tool_pids); sleep 0.3; kill -INT $(tool_pids) 2>/dev/null ;;
      *)    kill -${KILL_SIG:-TERM} $(tool_pids) ;;
    esac
    echo "sent ${KILL_SIG:-TERM} at ${KILL_AT}s" > $OUT/killed.txt ) &
fi
ip netns exec tfl-cam env $PEERENV $PY $LAB/lab_peers.py cam $DUR > $OUT/cam.json 2>$OUT/cam.err
wait $PH
sleep 1
[ -n "$TD" ] && kill $TD 2>/dev/null
if [ "$MODE" = splice ]; then
  [ -n "$(tool_pids)" ] && kill -INT $(tool_pids) 2>/dev/null
  for i in 1 2 3 4 5 6 7 8 9 10; do [ -z "$(tool_pids)" ] && break; sleep 0.5; done
  if [ -n "$(tool_pids)" ]; then echo "tool still running after SIGINT" >> $OUT/leftovers.txt; kill -9 $(tool_pids); fi
  if [ "${KILL_SIG:-}" = KILL ] && [ -z "${NO_CLEANUP:-}" ]; then
    ip netns exec tfl-mid env $TOOLENV $PY -m wyze_splice cleanup > $OUT/cleanup.out 2>&1
  fi
  # anything the tool installed must be gone (lab_setup's own MASQUERADE stays)
  ip netns exec tfl-mid sh -c '
    iptables-save | grep -E "TPROXY|REDIRECT|10\.99\.0\.20/32 -j ACCEPT|ACCEPT.*--dport (443|18443)"
    ip rule | grep -E "5917|fwmark"
    [ "$(cat /proc/sys/net/ipv4/conf/all/accept_local)" = 0 ] || echo "accept_local=1"
    [ "$(cat /proc/sys/net/ipv4/ip_forward)" = 1 ] || echo "ip_forward changed"' >> $OUT/leftovers.txt
  [ -s $OUT/run/changes.json ] && echo "journal not empty" >> $OUT/leftovers.txt
fi
echo "== cam";   python3 -m json.tool $OUT/cam.json 2>/dev/null || cat $OUT/cam.json;   tail -3 $OUT/cam.err
echo "== phone"; python3 -m json.tool $OUT/phone.json 2>/dev/null || cat $OUT/phone.json; tail -3 $OUT/phone.err
[ -f $OUT/api.json ] && { echo "== api"; cat $OUT/api.json; }
if [ "$MODE" = splice ]; then
  echo "== splice.out"; grep -v "new public flow" $OUT/splice.out | tail -40
  echo "== leftovers"; cat $OUT/leftovers.txt
fi
bash $LAB/lab_setup.sh down
