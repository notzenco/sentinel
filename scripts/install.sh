#!/usr/bin/env sh
set -eu

REPO="${SENTINEL_REPO:-notzenco/sentinel}"
VERSION="${SENTINEL_VERSION:-latest}"
INSTALL_DIR="${SENTINEL_INSTALL_DIR:-$HOME/.local/bin}"

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Linux) os_target="unknown-linux-gnu" ;;
  Darwin) os_target="apple-darwin" ;;
  *) echo "unsupported operating system: $os" >&2; exit 1 ;;
esac

case "$arch" in
  x86_64|amd64) arch_target="x86_64" ;;
  arm64|aarch64)
    if [ "$os" = "Darwin" ]; then
      arch_target="aarch64"
    else
      echo "linux arm64 release assets are not published yet" >&2
      exit 1
    fi
    ;;
  *) echo "unsupported architecture: $arch" >&2; exit 1 ;;
esac

target="$arch_target-$os_target"

if [ "$VERSION" = "latest" ]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
fi

if [ -z "$VERSION" ]; then
  echo "could not determine Sentinel release version" >&2
  exit 1
fi

asset="sentinel-$VERSION-$target.tar.gz"
base_url="https://github.com/$REPO/releases/download/$VERSION"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

curl -fsSL "$base_url/$asset" -o "$tmp_dir/$asset"
curl -fsSL "$base_url/$asset.sha256" -o "$tmp_dir/$asset.sha256"

(
  cd "$tmp_dir"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$asset.sha256"
  else
    expected="$(cut -d ' ' -f 1 "$asset.sha256")"
    actual="$(shasum -a 256 "$asset" | cut -d ' ' -f 1)"
    [ "$expected" = "$actual" ] || { echo "checksum mismatch" >&2; exit 1; }
  fi
)

mkdir -p "$INSTALL_DIR"
tar -C "$tmp_dir" -xzf "$tmp_dir/$asset"
cp "$tmp_dir/sentinel-$VERSION-$target/sentinel" "$INSTALL_DIR/sentinel"
chmod +x "$INSTALL_DIR/sentinel"

echo "sentinel installed to $INSTALL_DIR/sentinel"
