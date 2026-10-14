#!/bin/sh
# Profile-guided optimisation, the training run (pgo/build.sh): an instrumented web-server serves a
# stand-in for the built site (`train site`, examples/train.rs) with docker/Caddyfile — on :8080, and
# over TLS on :8443 for HTTP/2 and HTTP/3 — while `train run` sends every kind of request and plays
# the app and the streaming service behind it. On SIGTERM the servers stop and write their profiles.
#
#   pgo/train.sh <instrumented web-server> <train example> <docker/Caddyfile>
#
# PGO_DIR (/tmp/pgo): the profiles (web-*.profraw) and the scratch files; PGO_SECONDS (15). Nothing
# leaves the loopback: the upstreams app:8787 and stream:8800 become the training's own.
set -eu
usage='usage: train.sh <instrumented web-server> <train example> <docker/Caddyfile>'
server=${1:?$usage}
train=${2:?$usage}
caddyfile=${3:?$usage}
here=$(cd "$(dirname "$0")" && pwd)
dir=${PGO_DIR:-/tmp/pgo}
seconds=${PGO_SECONDS:-15}
grep -q '^:8080 {$' "$caddyfile" || { echo "train.sh: no ':8080 {' site in $caddyfile" >&2; exit 1; }
rm -rf "$dir/srv" "$dir/client" "$dir"/web-*.profraw
mkdir -p "$dir/certs" "$dir/client"

# The client's own profile is kept apart: it must not count as the server's.
export LLVM_PROFILE_FILE="$dir/client/train-%p.profraw"
"$train" cert "$dir/certs"
paths=$("$train" site "$dir/srv")

# docker/Caddyfile with the stand-in site and headers, and the upstreams on the loopback; the same
# site once more over TLS.
sed -e "s|^import /etc/caddy/generated/site.caddy\$|import $here/site.caddy|" \
  -e "s|root \* /srv\$|root * $dir/srv|" \
  -e 's|app:8787|127.0.0.1:8787|g' -e 's|stream:8800|127.0.0.1:8787|g' "$caddyfile" >"$dir/plain.Caddyfile"
sed -e "s|^:8080 {\$|localhost:8443 {\n\ttls $dir/certs/cert.pem $dir/certs/key.pem|" \
  "$dir/plain.Caddyfile" >"$dir/tls.Caddyfile"

LLVM_PROFILE_FILE="$dir/web-%p-%m.profraw" "$server" run --config "$dir/plain.Caddyfile" >/dev/null 2>"$dir/plain.log" &
plain=$!
LLVM_PROFILE_FILE="$dir/web-%p-%m.profraw" "$server" run --config "$dir/tls.Caddyfile" >/dev/null 2>"$dir/tls.log" &
tls=$!

# shellcheck disable=SC2086
"$train" run 127.0.0.1:8080 127.0.0.1:8443 "$dir/certs/cert.pem" 127.0.0.1:8787 "$seconds" $paths || {
  tail -n 20 "$dir/plain.log" "$dir/tls.log" >&2
  exit 1
}

kill -TERM "$plain" "$tls"
wait "$plain" "$tls" || true
ls "$dir"/web-*.profraw >/dev/null
