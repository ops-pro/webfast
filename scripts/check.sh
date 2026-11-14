#!/usr/bin/env bash
# The checks CI runs (.github/workflows/ci.yml), here in Docker — the host needs nothing else:
#
#   scripts/check.sh [fmt] [clippy] [test] [msrv] [deny]     (none named: all)
#
# fmt: rustfmt; clippy: lints on both crates of the workspace, warnings are errors (also without
# the optional extensions and modules, --no-default-features per crate, and with each of them
# alone: the lists are CI's own, read from its workflow); test: unit and end-to-end
# tests on stable Rust; msrv: the tests on the workspace's rust-version (Cargo.toml); deny: cargo-deny (advisories, licenses,
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

# The features CI lints alone, as its workflow lists them (the core's, then the binary's): read
# from there, so that what passes here passes there. A feature that is fine with all the others
# and not without them — a field only another feature reads — shows only this way.
alone() {
  sed -n 's/^ *for feature in \(.*\); do$/\1/p' "$root/.github/workflows/ci.yml" | sed -n "$1p"
}
core_alone=$(alone 1)
binary_alone=$(alone 2)
[ -n "$core_alone" ] && [ -n "$binary_alone" ] || {
  echo "the features CI lints alone were not found in .github/workflows/ci.yml" >&2
  exit 2
}
lint="cargo clippy --locked --all-targets"

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
    fmt) command="rustup component add rustfmt >/dev/null 2>&1 && cargo fmt --all --check" ;;
    clippy) command="rustup component add clippy >/dev/null 2>&1 && $lint --workspace -- -D warnings && $lint -p webfast-core --no-default-features -- -D warnings && $lint -p webfast --no-default-features -- -D warnings && for feature in $core_alone; do echo \"-- webfast-core: \$feature alone\"; $lint -p webfast-core --no-default-features --features \$feature -- -D warnings || exit 1; done && for feature in $binary_alone; do echo \"-- webfast: \$feature alone\"; $lint -p webfast --no-default-features --features \$feature -- -D warnings || exit 1; done" ;;
    test) command="cargo test --locked --workspace" ;;
    msrv) command="cargo test --locked --workspace" ;;
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
