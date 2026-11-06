#!/usr/bin/env bash
# Netns lab mirroring the real topology after on-path mode is up:
#   cam (10.99.0.20) --L2-- mid (10.99.0.10, runs wyzecrack) --L2-- gw (10.99.0.1, NAT) -- internet (203.0.113.x)
# cam's default route points at mid (what the camera-only ARP poison does)
# and mid NATs the camera's traffic out, so wyzecrack runs with --on-path.
set -eu
down() {
  for n in tfl-cam tfl-mid tfl-gw tfl-inet tfl-lan; do ip netns del $n 2>/dev/null || true; done
  # veths an aborted setup left in the root namespace
  for l in v-cam v-mid v-gw v-gwo v-in p-cam p-mid p-gw; do ip link del $l 2>/dev/null || true; done
}
if [ "${1:-up}" = down ]; then down; exit 0; fi
down
for n in tfl-lan tfl-cam tfl-mid tfl-gw tfl-inet; do ip netns add $n; ip -n $n link set lo up; done
ip -n tfl-lan link add br0 type bridge; ip -n tfl-lan link set br0 up
for n in cam mid gw; do
  ip link add v-$n type veth peer name p-$n
  ip link set v-$n netns tfl-$n; ip link set p-$n netns tfl-lan
  ip -n tfl-lan link set p-$n master br0; ip -n tfl-lan link set p-$n up
done
ip -n tfl-cam link set v-cam name eth0; ip -n tfl-cam addr add 10.99.0.20/24 dev eth0; ip -n tfl-cam link set eth0 up
ip -n tfl-mid link set v-mid name eth0; ip -n tfl-mid addr add 10.99.0.10/24 dev eth0; ip -n tfl-mid link set eth0 up
ip -n tfl-gw  link set v-gw  name eth0; ip -n tfl-gw  addr add 10.99.0.1/24   dev eth0; ip -n tfl-gw  link set eth0 up
ip link add v-gwo type veth peer name v-in
ip link set v-gwo netns tfl-gw; ip link set v-in netns tfl-inet
ip -n tfl-gw addr add 203.0.113.254/24 dev v-gwo; ip -n tfl-gw link set v-gwo up
ip -n tfl-inet addr add 203.0.113.1/24 dev v-in; ip -n tfl-inet link set v-in up
ip -n tfl-inet addr add 203.0.113.3/24 dev v-in      # fake api.wyzecam.com (:443)
ip -n tfl-inet route add default via 203.0.113.254
ip -n tfl-cam route add default via 10.99.0.10          # "poisoned" gateway
ip -n tfl-mid route add default via 10.99.0.1
for n in tfl-mid tfl-gw; do ip netns exec $n sysctl -qw net.ipv4.ip_forward=1; done
ip netns exec tfl-mid sysctl -qw net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.eth0.send_redirects=0
ip netns exec tfl-gw sysctl -qw net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.eth0.send_redirects=0
ip netns exec tfl-gw iptables -t nat -A POSTROUTING -o v-gwo -j MASQUERADE
# mid NATs the camera, as on-path mode does
ip netns exec tfl-mid iptables -t nat -A POSTROUTING -s 10.99.0.20 -o eth0 -j MASQUERADE
echo "lab up"
