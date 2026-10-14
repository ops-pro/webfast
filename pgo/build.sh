#!/bin/sh
# web-server's release build with profile-guided optimisation (the web image, Dockerfile): an
# instrumented build serves a training load (pgo/train.sh, loopback only) and writes a profile, and
# the release build is optimised by it — about twice the build time. WEB_PGO=0: a plain release build.
#
#   pgo/build.sh <docker/Caddyfile> <out dir>        → <out dir>/web-server
#
# Run in services/web-server with llvm-tools (rustup component add llvm-tools); RUSTFLAGS are kept
# (e.g. -Ctarget-cpu=…). CARGO_TARGET_DIR (target), PGO_DIR (/tmp/pgo), PGO_SECONDS (15).
set -eu
usage='usage: build.sh <docker/Caddyfile> <out dir>'
caddyfile=${1:?$usage}
out=${2:?$usage}
here=$(cd "$(dirname "$0")" && pwd)
target=${CARGO_TARGET_DIR:-target}
flags=${RUSTFLAGS:-}

if [ "${WEB_PGO:-1}" = 0 ]; then
  cargo build --release --locked --bin web-server
  install -D -m 0755 "$target/release/web-server" "$out/web-server"
  exit
fi

dir=${PGO_DIR:-/tmp/pgo}
host=$(rustc -vV | sed -n 's/^host: //p')
profdata="$(rustc --print sysroot)/lib/rustlib/$host/bin/llvm-profdata"
[ -x "$profdata" ] || { echo "build.sh: no $profdata (rustup component add llvm-tools)" >&2; exit 1; }

echo "PGO: instrumented build"
CARGO_TARGET_DIR="$target/pgo-instrumented" RUSTFLAGS="$flags -Cprofile-generate=$dir" \
  cargo build --release --locked --bin web-server --example train
instrumented="$target/pgo-instrumented/release"
echo "PGO: training"
PGO_DIR=$dir sh "$here/train.sh" "$instrumented/web-server" "$instrumented/examples/train" "$caddyfile"
"$profdata" merge -o "$dir/web-server.profdata" "$dir"/web-*.profraw
echo "PGO: optimised build"
CARGO_TARGET_DIR="$target/pgo-optimised" RUSTFLAGS="$flags -Cprofile-use=$dir/web-server.profdata" \
  cargo build --release --locked --bin web-server
install -D -m 0755 "$target/pgo-optimised/release/web-server" "$out/web-server"
