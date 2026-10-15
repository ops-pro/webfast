#!/bin/sh
# Profile-guided optimisation, the training run (pgo/build.sh): an instrumented webfast serves the
# sample site (`train site`, examples/train.rs) with the given Caddyfile — on :8080, and over TLS on
# :8443 for HTTP/2 and HTTP/3 — while `train run` sends every kind of request and plays the app and
# the event-streaming service behind it. On SIGTERM the servers stop and write their profiles.
#
#   pgo/train.sh <instrumented webfast> <train example> [<Caddyfile>]
#
# The Caddyfile (sample/Caddyfile) needs a `:8080` site with `root * /srv`, may import
# /etc/webfast/headers.caddy (sample/headers.caddy is used) and proxy to app:8787 and stream:8800.
# PGO_DIR (/tmp/pgo): the profiles (webfast-*.profraw) and the scratch files; PGO_SECONDS (15).
# Nothing leaves the loopback: the upstreams become the training's own.
set -eu
usage='usage: train.sh <instrumented webfast> <train example> [<Caddyfile>]'
server=${1:?$usage}
train=${2:?$usage}
here=$(cd "$(dirname "$0")" && pwd)
sample=$(cd "$here/../sample" && pwd)
caddyfile=${3:-$sample/Caddyfile}
dir=${PGO_DIR:-/tmp/pgo}
seconds=${PGO_SECONDS:-15}
grep -q '^:8080 {$' "$caddyfile" || { echo "train.sh: no ':8080 {' site in $caddyfile" >&2; exit 1; }
rm -rf "$dir/srv" "$dir/client" "$dir"/webfast-*.profraw
mkdir -p "$dir/certs" "$dir/client"

# The client's own profile is kept apart: it must not count as the server's.
export LLVM_PROFILE_FILE="$dir/client/train-%p.profraw"
"$train" cert "$dir/certs"
paths=$("$train" site "$dir/srv")

# The Caddyfile with the sample site and headers, and the upstreams on the loopback; the same site
# once more over TLS.
sed -e "s|^import /etc/webfast/headers.caddy\$|import $sample/headers.caddy|" \
  -e "s|root \* /srv\$|root * $dir/srv|" \
  -e 's|app:8787|127.0.0.1:8787|g' -e 's|stream:8800|127.0.0.1:8787|g' "$caddyfile" >"$dir/plain.Caddyfile"
sed -e "s|^:8080 {\$|localhost:8443 {\n\ttls $dir/certs/cert.pem $dir/certs/key.pem|" \
  "$dir/plain.Caddyfile" >"$dir/tls.Caddyfile"

LLVM_PROFILE_FILE="$dir/webfast-%p-%m.profraw" "$server" run --config "$dir/plain.Caddyfile" >/dev/null 2>"$dir/plain.log" &
plain=$!
LLVM_PROFILE_FILE="$dir/webfast-%p-%m.profraw" "$server" run --config "$dir/tls.Caddyfile" >/dev/null 2>"$dir/tls.log" &
tls=$!

# shellcheck disable=SC2086
"$train" run 127.0.0.1:8080 127.0.0.1:8443 "$dir/certs/cert.pem" 127.0.0.1:8787 "$seconds" $paths || {
  tail -n 20 "$dir/plain.log" "$dir/tls.log" >&2
  exit 1
}

kill -TERM "$plain" "$tls"
wait "$plain" "$tls" || true
ls "$dir"/webfast-*.profraw >/dev/null
