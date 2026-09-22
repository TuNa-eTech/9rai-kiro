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

case "$profile" in
  debug)
    cargo build --manifest-path "$root/Cargo.toml" --bin 9rai
    built="$root/target/debug/9rai"
    ;;
  release)
    cargo build --manifest-path "$root/Cargo.toml" --bin 9rai --release
    built="$root/target/release/9rai"
    ;;
  *)
    echo "usage: stage-cli.sh [debug|release]" >&2
    exit 1
    ;;
esac

# Tauri resolves an externalBin by appending the host triple; bundling strips it again so the
# binary lands beside the GUI as plain `9rai` — exactly the name locate_cli looks for.
dest="$root/apps/desktop/src-tauri/binaries"
mkdir -p "$dest"
cp -f "$built" "$dest/9rai-$triple"
echo "stage-cli: staged $profile 9rai -> src-tauri/binaries/9rai-$triple"
