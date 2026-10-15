#!/usr/bin/env bash
# Time to the first response from a new connection over a slow link: webfast with TLS on :8443
# and the client (examples/rtt.rs) in two containers, each adding DELAY_MS (25) with `tc netem` on
# its way out, so the round trip is 2 × DELAY_MS. Compares HTTP/2 over TCP+TLS, HTTP/3 with a full
# handshake and HTTP/3 with 0-RTT.
#
#   WEBFAST_BIN=… RTT_BIN=…/examples/rtt bench/rtt.sh
#
# Builds a small image with iproute2 (`webfast-netem`) on first use; the containers need NET_ADMIN.
set -euo pipefail

bin=${WEBFAST_BIN:?set WEBFAST_BIN to a Linux webfast binary}
rtt_bin=${RTT_BIN:?set RTT_BIN to the examples/rtt binary}
delay=${DELAY_MS:-25}
connections=${CONNECTIONS:-20}
net=webfast-rtt
work=$(mktemp -d) && chmod 755 "$work"

cleanup() {
  docker rm -f rtt-web >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
cleanup

if ! docker image inspect webfast-netem:latest >/dev/null 2>&1; then
  printf 'FROM debian:bookworm-slim\nRUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/*\n' |
    docker build --network host -q -t webfast-netem:latest - >/dev/null
fi
docker network create "$net" >/dev/null
mkdir -p "$work/certs" && chmod 777 "$work/certs"
docker run --rm -v "$work/certs:/certs" -v "$rtt_bin:/rtt:ro" debian:bookworm-slim /rtt cert /certs
printf ':8443 {\n\ttls /certs/cert.pem /certs/key.pem\n\trespond "ok"\n}\n' >"$work/Caddyfile"

docker run -d --name rtt-web --network "$net" --cap-add NET_ADMIN -v "$work:/cfg:ro" -v "$work/certs:/certs:ro" \
  -v "$bin:/webfast:ro" webfast-netem:latest \
  sh -c "tc qdisc add dev eth0 root netem delay ${delay}ms && exec /webfast run --config /cfg/Caddyfile" >/dev/null
sleep 2
echo "round trip: $((2 * delay)) ms (netem on both sides)"
docker run --rm --network "$net" --cap-add NET_ADMIN -v "$work/certs:/certs:ro" -v "$rtt_bin:/rtt:ro" webfast-netem:latest \
  sh -c "tc qdisc add dev eth0 root netem delay ${delay}ms && /rtt run rtt-web 8443 /certs/cert.pem $connections"
