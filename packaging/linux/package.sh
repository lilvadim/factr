#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."

if [[ "$(uname -s)" != Linux ]]; then
    echo "Build Linux packages on Linux." >&2
    exit 1
fi

for tool in cargo python3 nfpm; do
    if ! command -v "$tool" >/dev/null; then
        echo "Required tool not found: $tool" >&2
        exit 1
    fi
done

case "$(uname -m)" in
    x86_64) export PACKAGE_ARCH=amd64 ;;
    aarch64 | arm64) export PACKAGE_ARCH=arm64 ;;
    *) echo "Unsupported Linux architecture: $(uname -m)" >&2; exit 1 ;;
esac

read -r PACKAGE_VERSION target_dir < <(
    cargo metadata --no-deps --format-version 1 --locked |
        python3 -c 'import json, sys; metadata = json.load(sys.stdin); package = next(p for p in metadata["packages"] if p["name"] == "factr-auth"); print(package["version"], metadata["target_directory"])'
)
export PACKAGE_VERSION

cargo build --release --locked

export PACKAGE_BINARY="$target_dir/${CARGO_BUILD_TARGET:+$CARGO_BUILD_TARGET/}release/factr-auth"
mkdir -p "$target_dir/packages"
for format in deb rpm archlinux; do
    nfpm package --config packaging/linux/nfpm.yaml --packager "$format" --target "$target_dir/packages/"
done
