#!/usr/bin/env bash
# Start or stop Pebble and challtestsrv for `make e2e-pebble` and
# `make compat`.
#
#   test/pebble.sh start    # exit 3: a port is busy (callers skip)
#   test/pebble.sh stop
#
# Both containers run on their own docker network (tlsbroker-e2e): Pebble
# asks challtestsrv for DNS inside that network, so challtestsrv's DNS port
# (8053) is never bound on the host, where a development broker's mockdoh
# usually listens. Only Pebble's defaults are published on 127.0.0.1:
# 14000 (ACME API), 15000 (management: roots, intermediates) and 8055
# (challtestsrv management: /set-txt, /clear-txt).
#
# After start, .claude/tmp/e2e/ holds pebble.minica.pem (Pebble's API TLS
# root) and pebble-root.pem (the root of the certificates this Pebble
# instance issues; it changes with every start).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
net=tlsbroker-e2e
pebble=tlsbroker-e2e-pebble
chall=tlsbroker-e2e-challtestsrv
pebble_image="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:latest}"
chall_image="${CHALLTESTSRV_IMAGE:-ghcr.io/letsencrypt/pebble-challtestsrv:latest}"
out="$root/.claude/tmp/e2e"

port_busy() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

stop() {
  docker rm -f "$pebble" "$chall" >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
}

start() {
  stop
  for p in 14000 15000 8055; do
    if port_busy "$p"; then
      echo "pebble.sh: 127.0.0.1:$p is already in use; Pebble cannot start (SKIPPED)" >&2
      exit 3
    fi
  done
  mkdir -p "$out"
  docker network create "$net" >/dev/null
  docker run -d --rm --network "$net" --name "$chall" -p 127.0.0.1:8055:8055 \
    "$chall_image" -defaultIPv6 "" -defaultIPv4 127.0.0.1 >/dev/null
  docker run -d --rm --network "$net" --name "$pebble" \
    -p 127.0.0.1:14000:14000 -p 127.0.0.1:15000:15000 \
    -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
    "$pebble_image" -config test/config/pebble-config.json -dnsserver "$chall:8053" >/dev/null

  docker cp "$pebble:/test/certs/pebble.minica.pem" "$out/pebble.minica.pem" >/dev/null
  for _ in $(seq 1 100); do
    chall_code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8055/ 2>/dev/null || true)
    if [ "${chall_code:-000}" != 000 ] &&
      curl -sf --cacert "$out/pebble.minica.pem" https://127.0.0.1:14000/dir >/dev/null 2>&1 &&
      curl -sf --cacert "$out/pebble.minica.pem" https://127.0.0.1:15000/roots/0 -o "$out/pebble-root.pem"; then
      echo "pebble.sh: Pebble https://127.0.0.1:14000/dir and challtestsrv http://127.0.0.1:8055 are up"
      return 0
    fi
    sleep 0.2
  done
  echo "pebble.sh: Pebble did not come up" >&2
  docker logs "$pebble" >&2 || true
  docker logs "$chall" >&2 || true
  stop
  exit 1
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
