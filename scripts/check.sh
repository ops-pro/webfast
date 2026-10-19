#!/usr/bin/env bash
# The checks CI runs (.github/workflows/ci.yml), here in Docker — the host needs nothing else:
#
#   scripts/check.sh [fmt] [clippy] [test] [msrv] [deny]     (none named: all)
#
# fmt: rustfmt; clippy: lints, warnings are errors (also without the optional modules,
# --no-default-features); test: unit and end-to-end tests on stable
# Rust; msrv: the tests on Cargo.toml's rust-version; deny: cargo-deny (advisories, licenses,
# bans, sources). The crate cache, build directories and tools stay in Docker volumes
# (webfast-cargo, webfast-target, webfast-tools). RUST_IMAGE (rust:1-slim-bookworm),
# CARGO_DENY_VERSION (the one CI installs).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
image=${RUST_IMAGE:-rust:1-slim-bookworm}
msrv=$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' "$root/Cargo.toml")
deny_version=${CARGO_DENY_VERSION:-0.20.2}
checks=("$@")
[ ${#checks[@]} -gt 0 ] || checks=(fmt clippy test msrv deny)

# run <image> <build directory> <command>: in /src, the project read-only.
run() {
  docker run --rm --network host \
    -v webfast-cargo:/usr/local/cargo/registry -v webfast-target:/target -v webfast-tools:/tools \
    -e CARGO_TARGET_DIR="/target/$2" -e CARGO_INSTALL_ROOT=/tools -e CARGO_TERM_COLOR=always \
    -v "$root:/src:ro" -w /src "$1" sh -c "export PATH=/tools/bin:\$PATH; $3"
}

failed=()
for check in "${checks[@]}"; do
  echo "== $check"
  case $check in
    fmt) command="rustup component add rustfmt >/dev/null 2>&1 && cargo fmt --check" ;;
    clippy) command="rustup component add clippy >/dev/null 2>&1 && cargo clippy --locked --all-targets -- -D warnings && cargo clippy --locked --all-targets --no-default-features -- -D warnings" ;;
    test) command="cargo test --locked" ;;
    msrv) command="cargo test --locked" ;;
    deny) command="command -v cargo-deny >/dev/null || cargo install --locked cargo-deny --version $deny_version; cargo deny check" ;;
    *)
      echo "unknown check $check (fmt, clippy, test, msrv, deny)" >&2
      exit 2
      ;;
  esac
  if [ "$check" = msrv ]; then
    run "rust:$msrv-slim-bookworm" msrv "$command" || failed+=("$check")
  elif [ "$check" = deny ]; then
    # The full image: cargo-deny fetches the advisory database with git.
    run "${image/-slim/}" stable "$command" || failed+=("$check")
  else
    run "$image" stable "$command" || failed+=("$check")
  fi
done

if [ ${#failed[@]} -gt 0 ]; then
  echo "failed: ${failed[*]}"
  exit 1
fi
echo "all passed: ${checks[*]}"
