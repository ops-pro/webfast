#!/usr/bin/env bash
# Load benchmark of webfast with a Caddyfile and a site: oha sends requests at a fixed rate, several
# runs per scenario; the server's CPU time comes from its cgroup. Then the in-process benchmark of
# the handler chain (examples/bench.rs) on the same site.
#
#   WEBFAST_BIN=… TRAIN_BIN=…/examples/train [BENCH_BIN=…/examples/bench] bench/run.sh <label>
#
# The site and its configuration: scripts/volumes.sh (SITE_DIR, or the sample site; CADDYFILE,
# HEADERS). Scenarios: PAGE (/en/contact), ASSET (the site's first /assets/main-*.js), REDIRECT
# (/en/contact.html). RATE (1000 requests/s; 0: as fast as it goes), RUNS (10), REQUESTS (5000 per
# run), CONNECTIONS (20); WEB_LOG_FLUSH_MS (passed to the server), SERVER_ENV (more variables for
# the server, e.g. "WEB_RELOAD=lazy WEB_WORKERS=4"), OHA_ARGS (more oha options, e.g.
# --disable-keepalive for a new connection per request). Results go to $OUT_DIR/<label> (default
# /tmp/webfast-bench); summarize.mjs prints the table.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../scripts/volumes.sh
. "$here/../scripts/volumes.sh"
label=${1:?usage: run.sh <label>}
bin=${WEBFAST_BIN:?set WEBFAST_BIN to a Linux webfast binary}
bench_bin=${BENCH_BIN:-}
rate=${RATE:-1000}
runs=${RUNS:-10}
requests=${REQUESTS:-5000}
connections=${CONNECTIONS:-20}
read -ra oha_args <<<"${OHA_ARGS:-}"
rate_args=()
[ "$rate" = 0 ] || rate_args=(-q "$rate" --latency-correction)
server_env=()
for pair in ${SERVER_ENV:-}; do
  server_env+=(-e "$pair")
done
out=${OUT_DIR:-/tmp/webfast-bench}/$label
run_image=${RUN_IMAGE:-debian:bookworm-slim}
oha_image=${OHA_IMAGE:-ghcr.io/hatoo/oha:latest}
node_image=${NODE_IMAGE:-node:24-bookworm-slim}
net=webfast-bench

cleanup() {
  docker rm -f bench-web >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  docker volume rm -f webfast-bench-srv webfast-bench-conf >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
rm -rf "$out" && mkdir -p "$out"
docker network create "$net" >/dev/null
fill_volumes webfast-bench-srv webfast-bench-conf
site=(-v webfast-bench-conf:/etc/webfast:ro -v webfast-bench-srv:/srv:ro)

docker run -d --name bench-web --network "$net" "${site[@]}" -e "WEB_LOG_FLUSH_MS=${WEB_LOG_FLUSH_MS:-10}" "${server_env[@]}" \
  -v "$bin:/usr/local/bin/webfast:ro" --entrypoint /usr/local/bin/webfast "$run_image" \
  run --config /etc/webfast/Caddyfile >/dev/null
for _ in $(seq 1 50); do
  docker exec bench-web /usr/local/bin/webfast healthcheck http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break
  sleep 0.2
done

page=${PAGE:-/en/contact}
asset=${ASSET:-/assets/$(docker exec bench-web sh -c 'ls /srv/assets | grep -E "^main-.*\.js$" | head -1')}
redirect=${REDIRECT:-$page.html}
scenarios=("page $page" "asset $asset" "redirect $redirect")
printf '%s\n' "${scenarios[@]}" >"$out/scenarios.txt"

cpu() { docker exec bench-web sh -c 'grep usage_usec /sys/fs/cgroup/cpu.stat' | awk '{print $2}'; }

for scenario in "${scenarios[@]}"; do
  name=${scenario%% *}
  path=${scenario#* }
  for i in $(seq 1 "$runs"); do
    before=$(cpu)
    docker run --rm --network "$net" "$oha_image" "${rate_args[@]}" -n "$requests" -c "$connections" \
      --no-tui --output-format json "${oha_args[@]}" -H 'Accept-Encoding: gzip, deflate, br, zstd' \
      "http://bench-web:8080$path" >"$out/$name-$i.json"
    after=$(cpu)
    echo "$name $i $((after - before)) $requests" >>"$out/cpu.txt"
  done
done

if [ -n "$bench_bin" ]; then
  docker run --rm --network none "${site[@]}" -v "$bench_bin:/usr/local/bin/bench:ro" --entrypoint /usr/local/bin/bench \
    "$run_image" /etc/webfast/Caddyfile 200000 10 "$page" "304:$page" "$asset" "$redirect" \
    >"$out/inprocess.txt"
fi

docker run --rm -v "$here:/bench:ro" -v "$out:/out:ro" --entrypoint node "$node_image" /bench/summarize.mjs /out | tee "$out/summary.txt"
