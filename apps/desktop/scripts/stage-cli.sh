#!/usr/bin/env bash
# Build the `9rai` CLI and stage it as the desktop app's sidecar.
#
# The GUI never does privileged work itself — it shells out to the `9rai` binary sitting next to
# its own executable (`locate_cli`, src-tauri/src/daemon.rs). But `cargo tauri dev|build` only
# builds the *desktop* crate, so without this step that neighbouring CLI can silently be an old
# build: a trust-store fix lands in crates/core and the app keeps running the binary from days
# ago. Staging on every dev/build run is what keeps the two halves in lockstep.
set -euo pipefail

profile="${1:-debug}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

triple="$(rustc -vV | sed -n 's/^host: //p')"
if [ -z "$triple" ]; then
  echo "stage-cli: cannot determine the host target triple from rustc" >&2
  exit 1
fi

# Windows builds both produce and expect `9rai.exe`: tauri-utils::resources::external_binaries
# appends `.exe` to `binaries/9rai-<triple>` on Windows targets, and a missing suffix is a hard
# bundle error rather than a rename.
exe=""
case "$triple" in *windows*) exe=".exe" ;; esac

case "$profile" in
  debug)
    cargo build --manifest-path "$root/Cargo.toml" --bin 9rai
    built="$root/target/debug/9rai$exe"
    ;;
  release)
    cargo build --manifest-path "$root/Cargo.toml" --bin 9rai --release
    built="$root/target/release/9rai$exe"
    ;;
  *)
    echo "usage: stage-cli.sh [debug|release]" >&2
    exit 1
    ;;
esac

# Tauri resolves an externalBin by appending the host triple; bundling strips the triple again so
# the binary lands beside the GUI as `9rai` (`9rai.exe` on Windows) — exactly the name locate_cli
# looks for.
dest="$root/apps/desktop/src-tauri/binaries"
mkdir -p "$dest"
cp -f "$built" "$dest/9rai-$triple$exe"
echo "stage-cli: staged $profile 9rai -> src-tauri/binaries/9rai-$triple$exe"
