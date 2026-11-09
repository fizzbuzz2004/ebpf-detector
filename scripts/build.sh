#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BPF_LINKER_VERSION="${BPF_LINKER_VERSION:-0.12.0}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Build nur auf Linux (oder WSL2 mit Linux-Kernel) ausführen." >&2
  exit 1
fi

for tool in rustup cargo clang llvm-ar pkg-config; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "Fehlendes Build-Werkzeug: $tool" >&2
    exit 1
  }
done

if ! pkg-config --exists libelf; then
  echo "libelf-Entwicklungsdateien fehlen. Unter Ubuntu: sudo apt install libelf-dev" >&2
  exit 1
fi

rustup toolchain install stable --profile minimal --component rustfmt --component clippy
rustup toolchain install nightly --profile minimal --component rust-src

if ! command -v bpf-linker >/dev/null 2>&1 \
  || ! bpf-linker --version 2>&1 | grep -q "${BPF_LINKER_VERSION}"; then
  cargo +stable install bpf-linker --version "$BPF_LINKER_VERSION" --locked --force
fi

if [[ ! -f Cargo.lock ]]; then
  echo "Hinweis: Cargo.lock wird beim ersten Cargo-Aufruf erzeugt." >&2
  echo "Für reproduzierbare Builds Cargo.lock in Git committen." >&2
fi

cargo +stable build --release -p detector-userspace

printf '\nBuild erfolgreich: %s/target/release/detector-userspace\n' "$ROOT_DIR"
printf 'BPF-Linker: %s\n' "$(bpf-linker --version 2>&1 | head -n 1)"
