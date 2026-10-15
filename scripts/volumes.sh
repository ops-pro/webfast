# Sourced by bench/run.sh and compat/run.sh: a site and its configuration in two Docker volumes (a
# Linux filesystem: case-sensitive like production, unlike a bind mount from a Windows drive).
#
#   fill_volumes <site volume> <configuration volume> [<sed -E script for the Caddyfile>]
#
# The site: SITE_DIR, or else the sample site that TRAIN_BIN (examples/train) makes. The
# configuration volume (mounted at /etc/webfast): CADDYFILE (sample/Caddyfile) as Caddyfile and
# HEADERS (sample/headers.caddy) as headers.caddy. RUN_IMAGE (debian:bookworm-slim).

fill_volumes() {
  local srv=$1 conf=$2 edit=${3:-}
  local root
  root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
  local caddyfile=${CADDYFILE:-$root/sample/Caddyfile}
  local headers=${HEADERS:-$root/sample/headers.caddy}
  local image=${RUN_IMAGE:-debian:bookworm-slim}
  docker volume create "$srv" >/dev/null
  docker volume create "$conf" >/dev/null
  if [ -n "${SITE_DIR:-}" ]; then
    docker run --rm -v "$SITE_DIR:/from:ro" -v "$srv:/srv" --entrypoint sh "$image" -c 'rm -rf /srv/* && cp -a /from/. /srv/'
  else
    local train=${TRAIN_BIN:?set SITE_DIR to a site, or TRAIN_BIN to the examples/train binary for the sample site}
    docker run --rm -v "$train:/train:ro" -v "$srv:/srv" --entrypoint sh "$image" -c 'rm -rf /srv/* && /train site /srv >/dev/null'
  fi
  docker run --rm -v "$caddyfile:/Caddyfile:ro" -v "$headers:/headers.caddy:ro" -v "$conf:/conf" -e EDIT="$edit" \
    --entrypoint sh "$image" -c 'sed -E -e "$EDIT" /Caddyfile >/conf/Caddyfile && cp /headers.caddy /conf/headers.caddy && chmod -R a+rX /conf'
  docker run --rm -v "$srv:/srv" --entrypoint chmod "$image" -R a+rX /srv
}
