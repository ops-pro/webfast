#!/bin/sh
# webfast's release build with profile-guided optimisation (the Docker image builds it this way):
# an instrumented build serves a training load (pgo/train.sh, loopback only) and writes a profile,
# and the release build is optimised by it — about twice the build time, 10–20 % less CPU per
# request (docs/performance.md). WEBFAST_PGO=0: a plain release build.
#
#   pgo/build.sh <out dir>        → <out dir>/webfast
#
# Run in the project's root with llvm-tools (rustup component add llvm-tools); RUSTFLAGS are kept
# (e.g. -Ctarget-cpu=…). CADDYFILE (sample/Caddyfile: the configuration trained on, see train.sh),
# CARGO_TARGET_DIR (target), PGO_DIR (/tmp/pgo), PGO_SECONDS (15).
set -eu
out=${1:?usage: build.sh <out dir>}
here=$(cd "$(dirname "$0")" && pwd)
caddyfile=${CADDYFILE:-$here/../sample/Caddyfile}
target=${CARGO_TARGET_DIR:-target}
flags=${RUSTFLAGS:-}

if [ "${WEBFAST_PGO:-1}" = 0 ]; then
  cargo build --release --locked --bin webfast
  install -D -m 0755 "$target/release/webfast" "$out/webfast"
  exit
fi

dir=${PGO_DIR:-/tmp/pgo}
host=$(rustc -vV | sed -n 's/^host: //p')
profdata="$(rustc --print sysroot)/lib/rustlib/$host/bin/llvm-profdata"
[ -x "$profdata" ] || { echo "build.sh: no $profdata (rustup component add llvm-tools)" >&2; exit 1; }

echo "PGO: instrumented build"
CARGO_TARGET_DIR="$target/pgo-instrumented" RUSTFLAGS="$flags -Cprofile-generate=$dir" \
  cargo build --release --locked --bin webfast --example train
instrumented="$target/pgo-instrumented/release"
echo "PGO: training"
PGO_DIR=$dir sh "$here/train.sh" "$instrumented/webfast" "$instrumented/examples/train" "$caddyfile"
"$profdata" merge -o "$dir/webfast.profdata" "$dir"/webfast-*.profraw
echo "PGO: optimised build"
CARGO_TARGET_DIR="$target/pgo-optimised" RUSTFLAGS="$flags -Cprofile-use=$dir/webfast.profdata" \
  cargo build --release --locked --bin webfast
install -D -m 0755 "$target/pgo-optimised/release/webfast" "$out/webfast"
