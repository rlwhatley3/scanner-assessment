#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
SERVER_DIR="$ROOT_DIR/server"
UI_DIR="$ROOT_DIR/ui"
NODE_MIN=24
CARGO_WATCH_VERSION=8.5.3
fail() {
  printf 'Error: %s\n' "$1" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "$2"
}

if [ "${SKIP_PRELOAD:-0}" != "1" ]; then
  printf '\n== Check tools ==\n'
  need node "Install Node.js $NODE_MIN+ with nvm: https://github.com/nvm-sh/nvm#installing-and-updating"
  need npm "Install Node.js $NODE_MIN+ (npm is included): https://nodejs.org/en/download"
  need rustup "Install Rustup: https://rustup.rs"
  need cargo "Cargo is missing. Install Rustup: https://rustup.rs"
  need rustc "rustc is missing. Install Rustup: https://rustup.rs"

  NODE_VERSION=$(node -p 'process.versions.node')
  NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]')
  [ "$NODE_MAJOR" -ge "$NODE_MIN" ] ||
    fail "Node.js $NODE_VERSION found; version $NODE_MIN or newer is required."

  RUST_PIN=$(awk -F '"' '/^[[:space:]]*channel[[:space:]]*=/ { print $2; exit }' "$SERVER_DIR/rust-toolchain.toml")
  [ -n "$RUST_PIN" ] || fail "Cannot read the pinned Rust version from server/rust-toolchain.toml."

  if ! RUST_INFO=$(cd "$SERVER_DIR" && rustc --version 2>&1); then
    fail "Cannot run the pinned Rust toolchain ($RUST_PIN). Install it with: rustup toolchain install $RUST_PIN"
  fi
  RUST_VERSION=$(printf '%s\n' "$RUST_INFO" | awk '$1 == "rustc" { print $2; exit }')
  [ "$RUST_VERSION" = "$RUST_PIN" ] ||
    fail "Rust $RUST_VERSION active; this project requires $RUST_PIN."

  if ! CARGO_INFO=$(cd "$SERVER_DIR" && cargo --version 2>&1); then
    fail "Cannot run Cargo with the pinned Rust toolchain ($RUST_PIN)."
  fi
  CARGO_VERSION=$(printf '%s\n' "$CARGO_INFO" | awk '$1 == "cargo" { print $2; exit }')
  [ "$CARGO_VERSION" = "$RUST_PIN" ] ||
    fail "Cargo $CARGO_VERSION active; this project requires $RUST_PIN."

  printf 'Node.js %s - Rust %s - Cargo %s\n' "$NODE_VERSION" "$RUST_VERSION" "$CARGO_VERSION"

  printf '\n== Install dependencies ==\n'
  npm ci --prefix "$UI_DIR"
  (
    cd "$SERVER_DIR"
    cargo fetch --locked
    if ! cargo watch --version >/dev/null 2>&1; then
      cargo install cargo-watch --version "$CARGO_WATCH_VERSION" --locked
    fi
  )
fi

if [ "${SKIP_PRELOAD:-0}" = "1" ] &&
  ! (cd "$UI_DIR" && node --input-type=module -e 'await import("rolldown")' >/dev/null 2>&1); then
  printf '\n== Repair UI dependencies for this container platform ==\n'
  npm ci --prefix "$UI_DIR"
fi

printf '\n== Start UI and API ==\n'
exec npm --prefix "$UI_DIR" run dev:stack
