#!/usr/bin/env bash
# Load benchmark of web-server with docker/Caddyfile and the built site (npm run build): oha sends
# requests at a fixed rate, several runs per scenario; the server's CPU time comes from its cgroup.
# Then the in-process benchmark of the handler chain (examples/bench.rs) on the same site.
#
#   WEB_SERVER_BIN=… BENCH_BIN=… services/web-server/bench/run.sh <label>
#
# RATE (1000 requests/s), RUNS (10), REQUESTS (5000 per run), CONNECTIONS (20); CADDYFILE (the
# configuration, docker/Caddyfile), WEB_LOG_FLUSH_MS (passed to the server), OHA_ARGS (more oha
# options, e.g. --disable-keepalive for a new connection per request). Results go to
# $OUT_DIR/<label> (default /tmp/web-bench); summarize.mjs prints the table.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
label=${1:?usage: run.sh <label>}
bin=${WEB_SERVER_BIN:?set WEB_SERVER_BIN to a Linux web-server binary}
bench_bin=${BENCH_BIN:-}
rate=${RATE:-1000}
runs=${RUNS:-10}
requests=${REQUESTS:-5000}
connections=${CONNECTIONS:-20}
read -ra oha_args <<<"${OHA_ARGS:-}"
out=${OUT_DIR:-/tmp/web-bench}/$label
run_image=${RUN_IMAGE:-debian:bookworm-slim}
oha_image=${OHA_IMAGE:-ghcr.io/hatoo/oha:latest}
node_image=${NODE_IMAGE:-node:24-bookworm-slim}
net=web-bench

cleanup() {
  docker rm -f bench-web >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  docker volume rm -f web-bench-srv web-bench-conf >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
rm -rf "$out" && mkdir -p "$out"
docker network create "$net" >/dev/null
docker volume create web-bench-srv >/dev/null
docker volume create web-bench-conf >/dev/null
docker run --rm -v "$repo/dist:/from:ro" -v "${CADDYFILE:-$repo/docker/Caddyfile}:/Caddyfile:ro" -v web-bench-srv:/srv \
  -v web-bench-conf:/conf --entrypoint sh "$run_image" -c '
    cp -a /from/client/. /srv/ && mkdir -p /conf/generated && cp -a /from/caddy/. /conf/generated/ &&
    cp /Caddyfile /conf/Caddyfile'
site=(-v web-bench-conf:/etc/caddy:ro -v web-bench-srv:/srv:ro)

docker run -d --name bench-web --network "$net" "${site[@]}" -e "WEB_LOG_FLUSH_MS=${WEB_LOG_FLUSH_MS:-10}" \
  -v "$bin:/usr/local/bin/web-server:ro" --entrypoint /usr/local/bin/web-server "$run_image" \
  run --config /etc/caddy/Caddyfile >/dev/null
for _ in $(seq 1 50); do
  docker exec bench-web /usr/local/bin/web-server healthcheck http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break
  sleep 0.2
done

asset=$(docker exec bench-web sh -c 'ls /srv/assets | grep -E "^main-.*\.js$" | head -1')
scenarios=("page /en/contact" "asset /assets/$asset" "redirect /en/contact.html")
printf '%s\n' "${scenarios[@]}" >"$out/scenarios.txt"

cpu() { docker exec bench-web sh -c 'grep usage_usec /sys/fs/cgroup/cpu.stat' | awk '{print $2}'; }

for scenario in "${scenarios[@]}"; do
  name=${scenario%% *}
  path=${scenario#* }
  for i in $(seq 1 "$runs"); do
    before=$(cpu)
    docker run --rm --network "$net" "$oha_image" -q "$rate" -n "$requests" -c "$connections" \
      --latency-correction --no-tui --output-format json "${oha_args[@]}" -H 'Accept-Encoding: gzip, deflate, br, zstd' \
      "http://bench-web:8080$path" >"$out/$name-$i.json"
    after=$(cpu)
    echo "$name $i $((after - before)) $requests" >>"$out/cpu.txt"
  done
done

if [ -n "$bench_bin" ]; then
  docker run --rm --network none "${site[@]}" -v "$bench_bin:/usr/local/bin/bench:ro" --entrypoint /usr/local/bin/bench \
    "$run_image" /etc/caddy/Caddyfile 200000 10 /en/contact 304:/en/contact "/assets/$asset" /en/contact.html \
    >"$out/inprocess.txt"
fi

docker run --rm -v "$here:/bench:ro" -v "$out:/out:ro" --entrypoint node "$node_image" /bench/summarize.mjs /out | tee "$out/summary.txt"
