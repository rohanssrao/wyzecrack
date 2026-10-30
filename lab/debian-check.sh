#!/usr/bin/env bash
# Run the unit tests and the lab suite on a stock Debian 12 in a throwaway
# privileged container (podman or docker), to check nothing depends on the
# development host. usage: sudo bash lab/debian-check.sh
set -eu
REPO=$(dirname "$(dirname "$(readlink -f "$0")")")
ENGINE=$(command -v podman || command -v docker)
exec $ENGINE run --rm --privileged -v "$REPO":/src:ro docker.io/library/debian:bookworm bash -c '
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq iptables iproute2 python3 curl ca-certificates tcpdump procps iputils-ping >/dev/null
curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1
export PATH=$HOME/.local/bin:$PATH
cp -r /src /w && cd /w && rm -rf .venv captures
uv sync -q
iptables --version
echo "== unit tests"; .venv/bin/python -m pytest -q tests 2>&1 | tail -2
echo "== lab"; bash lab/labsuite.sh >/dev/null 2>&1; cut -c1-100 /tmp/wslab-suite.txt'
