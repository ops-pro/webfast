#!/usr/bin/env bash
# Differential check of web-server against Caddy: both serve docker/Caddyfile with the built site
# (dist/), stub upstreams play `app` and `stream`, and compare.mjs sends the same requests to both.
#
#   WEB_SERVER_BIN=/path/to/web-server services/web-server/compat/run.sh
#
# Needs a built site (npm run build) and a Linux web-server binary. Images can be overridden:
# CADDY_IMAGE (caddy:2-alpine), NODE_IMAGE (node:24-bookworm-slim), RUN_IMAGE (debian:bookworm-slim).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
bin=${WEB_SERVER_BIN:?set WEB_SERVER_BIN to a Linux web-server binary}
caddy_image=${CADDY_IMAGE:-caddy:2-alpine}
node_image=${NODE_IMAGE:-node:24-bookworm-slim}
run_image=${RUN_IMAGE:-debian:bookworm-slim}
net=web-compat

cleanup() {
  docker rm -f compat-app compat-stream compat-caddy compat-ours >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  docker volume rm -f web-compat-srv web-compat-conf >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create "$net" >/dev/null

# The site goes into volumes (a Linux file system: case-sensitive like production, unlike a
# bind mount from a Windows drive). Stock Caddy has no Brotli encoder, so both servers get the
# Caddyfile without `br` in `encode` (web-server's own tests cover it).
docker volume create web-compat-srv >/dev/null
docker volume create web-compat-conf >/dev/null
docker run --rm -v "$repo/dist:/from:ro" -v "$repo/docker/Caddyfile:/Caddyfile:ro" -v web-compat-srv:/srv \
  -v web-compat-conf:/conf --entrypoint sh "$caddy_image" -c '
    cp -a /from/client/. /srv/ && mkdir -p /conf/generated && cp -a /from/caddy/. /conf/generated/ &&
    sed -E "s/^([[:space:]]*encode[^#]*) br([[:space:]]|$)/\1\2/" /Caddyfile > /conf/Caddyfile'
site=(
  -v web-compat-conf:/etc/caddy:ro
  -v web-compat-srv:/srv:ro
)
for svc in app:8787 stream:8800; do
  name=${svc%%:*}
  docker run -d --name "compat-$name" --network "$net" --network-alias "$name" -e NAME="$name" -e PORT="${svc##*:}" \
    -v "$here:/compat:ro" --entrypoint node "$node_image" /compat/upstream.mjs >/dev/null
done
docker run -d --name compat-caddy --network "$net" "${site[@]}" "$caddy_image" >/dev/null
docker run -d --name compat-ours --network "$net" "${site[@]}" -v "$bin:/usr/local/bin/web-server:ro" \
  --entrypoint /usr/local/bin/web-server "$run_image" run --config /etc/caddy/Caddyfile >/dev/null

for _ in $(seq 1 50); do
  if docker run --rm --network "$net" --entrypoint node "$node_image" -e \
    "Promise.all(['compat-caddy','compat-ours'].map(h=>fetch('http://'+h+':8080/healthz'))).then(r=>process.exit(r.every(x=>x.ok)?0:1)).catch(()=>process.exit(1))" \
    >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

docker run --rm --network "$net" -v "$here:/compat:ro" --entrypoint node "$node_image" /compat/compare.mjs \
  http://compat-caddy:8080 http://compat-ours:8080 || status=$?
if [ "${status:-0}" != 0 ]; then
  echo "--- web-server log (last 20 lines)"
  docker logs --tail 20 compat-ours 2>&1 || true
fi
exit "${status:-0}"
