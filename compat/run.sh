#!/usr/bin/env bash
# Differential check of webfast against Caddy: both serve the same Caddyfile and site (by default
# sample/Caddyfile and the sample site), stub upstreams play `app` and `stream`, and compare.mjs sends
# the same ~80 requests to both and reports every difference that is not an expected one.
#
#   WEBFAST_BIN=…/webfast TRAIN_BIN=…/examples/train compat/run.sh
#   SCENARIO=errors … compat/run.sh      # handle_errors and error: compat/errors.Caddyfile
#   SCENARIO=ratelimit … compat/run.sh   # rate_limit, against Caddy with caddy-ratelimit (built
#                                        # from compat/caddy-plugins.Dockerfile)
#
# The site and configuration: scripts/volumes.sh (SITE_DIR, CADDYFILE, HEADERS); compare.mjs's
# requests are written for the sample site. Images can be overridden: CADDY_IMAGE (caddy:2-alpine),
# NODE_IMAGE (node:24-bookworm-slim), RUN_IMAGE (debian:bookworm-slim).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
scenario=${SCENARIO:-sample}
case $scenario in
  sample) ;;
  errors) export CADDYFILE=${CADDYFILE:-$here/errors.Caddyfile} ;;
  ratelimit)
    export CADDYFILE=${CADDYFILE:-$here/ratelimit.Caddyfile}
    if [ -z "${CADDY_IMAGE:-}" ]; then
      docker build -q -t webfast-compat-caddy-plugins -f "$here/caddy-plugins.Dockerfile" "$here" >/dev/null
      CADDY_IMAGE=webfast-compat-caddy-plugins
    fi
    ;;
  *)
    echo "SCENARIO: sample, errors or ratelimit" >&2
    exit 2
    ;;
esac
# shellcheck source=../scripts/volumes.sh
. "$here/../scripts/volumes.sh"
bin=${WEBFAST_BIN:?set WEBFAST_BIN to a Linux webfast binary}
caddy_image=${CADDY_IMAGE:-caddy:2-alpine}
node_image=${NODE_IMAGE:-node:24-bookworm-slim}
run_image=${RUN_IMAGE:-debian:bookworm-slim}
net=webfast-compat

cleanup() {
  docker rm -f compat-app compat-stream compat-caddy compat-ours >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  docker volume rm -f webfast-compat-srv webfast-compat-conf >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
docker network create "$net" >/dev/null

# Stock Caddy has no Brotli encoder, so both servers get the Caddyfile without `br` in `encode`
# (webfast's own tests cover it).
fill_volumes webfast-compat-srv webfast-compat-conf 's/^([[:space:]]*encode[^#]*) br([[:space:]]|$)/\1\2/'
site=(
  -v webfast-compat-conf:/etc/webfast:ro
  -v webfast-compat-srv:/srv:ro
)
for svc in app:8787 stream:8800; do
  name=${svc%%:*}
  docker run -d --name "compat-$name" --network "$net" --network-alias "$name" -e NAME="$name" -e PORT="${svc##*:}" \
    -v "$here:/compat:ro" --entrypoint node "$node_image" /compat/upstream.mjs >/dev/null
done
docker run -d --name compat-caddy --network "$net" "${site[@]}" "$caddy_image" \
  caddy run --config /etc/webfast/Caddyfile --adapter caddyfile >/dev/null
docker run -d --name compat-ours --network "$net" "${site[@]}" -v "$bin:/usr/local/bin/webfast:ro" \
  --entrypoint /usr/local/bin/webfast "$run_image" run --config /etc/webfast/Caddyfile >/dev/null

for _ in $(seq 1 50); do
  if docker run --rm --network "$net" --entrypoint node "$node_image" -e \
    "Promise.all(['compat-caddy','compat-ours'].map(h=>fetch('http://'+h+':8080/healthz'))).then(r=>process.exit(r.every(x=>x.ok)?0:1)).catch(()=>process.exit(1))" \
    >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

docker run --rm --network "$net" -v "$here:/compat:ro" --entrypoint node "$node_image" /compat/compare.mjs \
  http://compat-caddy:8080 http://compat-ours:8080 "$scenario" || status=$?
if [ "${status:-0}" != 0 ]; then
  echo "--- webfast log (last 20 lines)"
  docker logs --tail 20 compat-ours 2>&1 || true
  echo "--- caddy log (last 20 lines)"
  docker logs --tail 20 compat-caddy 2>&1 || true
fi
exit "${status:-0}"
