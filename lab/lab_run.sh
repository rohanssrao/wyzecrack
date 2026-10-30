#!/usr/bin/env bash
# usage: [MULTIPATH=1] [FAIL_FIRST=1] [CAM_IGNORE_FIRST_CH=1] [DIE_FIRST=1]
#        [HARVEST=1] [PASS=1] [DUR=14] sudo bash lab_run.sh splice|direct
set -u
LAB=$(dirname "$(readlink -f "$0")")
REPO=$(dirname "$LAB")
PY=${PY:-$REPO/.venv/bin/python}
TCPDUMP=${TCPDUMP:-$(command -v tcpdump || echo /tmp/tdbin/bin/tcpdump)}
MODE=${1:-splice}
DUR=${DUR:-14}
PEERENV="MULTIPATH=${MULTIPATH:-0} FAIL_FIRST=${FAIL_FIRST:-0} DIE_FIRST=${DIE_FIRST:-0} CAM_IGNORE_FIRST_CH=${CAM_IGNORE_FIRST_CH:-0} MEDIA_SECS=${MEDIA_SECS:-8} MEDIA_PPS=${MEDIA_PPS:-60} PYTHONPYCACHEPREFIX=/tmp/pyc"
OUT=/tmp/wslab-out; rm -rf $OUT; mkdir -p $OUT
bash $LAB/lab_setup.sh up
cd $REPO
if [ "${HARVEST:-0}" = 1 ]; then
  ENRARG="--reharvest --harvest-timeout 20"
  ip netns exec tfl-relay $PY $LAB/lab_api.py server $((DUR+15)) &
else
  ENRARG="--enr gekMdn0XjZoWF/mD"
fi
if [ "$MODE" = splice ]; then
  ip netns exec tfl-mid env PYTHONUNBUFFERED=1 PYTHONPYCACHEPREFIX=/tmp/pyc WYZE_SPLICE_STATE=$OUT/state \
     $PY -m wyze_splice run --target 10.99.0.20 $ENRARG --on-path --keep-going \
     --out $OUT --journal --no-video ${PASS:+--pass-through} > $OUT/splice.out 2>&1 &
  SP=$!
  sleep 4
fi
if [ "${HARVEST:-0}" = 1 ]; then
  ip netns exec tfl-cam $PY $LAB/lab_api.py client > $OUT/api.json 2>&1
  sleep 1
fi
ip netns exec tfl-mid $TCPDUMP -ni eth0 -s0 -U -w $OUT/mid.pcap udp >/dev/null 2>&1 &
TD=$!
sleep 0.5
ip netns exec tfl-relay env $PEERENV $PY $LAB/lab_peers.py phone $((DUR+1)) > $OUT/phone.json 2>$OUT/phone.err &
PH=$!
sleep 0.3
ip netns exec tfl-cam env $PEERENV $PY $LAB/lab_peers.py cam $DUR > $OUT/cam.json 2>$OUT/cam.err
wait $PH
sleep 1
kill $TD 2>/dev/null
[ "$MODE" = splice ] && { kill -INT $SP 2>/dev/null; sleep 3; kill $SP 2>/dev/null; }
echo "== cam";   python3 -m json.tool $OUT/cam.json 2>/dev/null || cat $OUT/cam.json;   tail -3 $OUT/cam.err
echo "== phone"; python3 -m json.tool $OUT/phone.json 2>/dev/null || cat $OUT/phone.json; tail -3 $OUT/phone.err
[ -f $OUT/api.json ] && { echo "== api"; cat $OUT/api.json; }
if [ "$MODE" = splice ]; then echo "== splice.out"; grep -v "new public flow" $OUT/splice.out | tail -40; fi
bash $LAB/lab_setup.sh down
