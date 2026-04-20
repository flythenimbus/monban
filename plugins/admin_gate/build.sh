#!/usr/bin/env bash
# Build admin-gate for all supported platforms, package the installer
# sub-pkg, and tar + sign every artefact. Run from the admin_gate dir.
#
#   VERSION=0.1.0 SIGN_KEY=/path/to/dev-release.key ./build.sh
#
# Output lands under dist/.

set -euo pipefail

VERSION="${VERSION:-0.1.0}"
SIGN_KEY="${SIGN_KEY:-../../desktop/cmd/monban-sign/testkeys/dev-release.key}"
MONBAN_SIGN="${MONBAN_SIGN:-/tmp/monban-sign}"

cd "$(dirname "$0")"

if [[ ! -x "$MONBAN_SIGN" ]]; then
    echo "building monban-sign → $MONBAN_SIGN"
    (cd ../../desktop && go build -o "$MONBAN_SIGN" ./cmd/monban-sign/)
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "admin-gate installer .pkg requires macOS (pkgbuild). Aborting." >&2
    exit 1
fi

rm -rf dist
mkdir -p dist

# --- 1. Build the installer sub-pkg ---
PKG_NAME="admin-gate-installer-${VERSION}.pkg"
PKG_ROOT="dist/pkg-root"
mkdir -p "$PKG_ROOT"   # empty payload; all work is in the postinstall

echo "building $PKG_NAME"
pkgbuild \
    --identifier "com.monban.admin-gate.installer" \
    --version "$VERSION" \
    --scripts installer \
    --root "$PKG_ROOT" \
    "dist/$PKG_NAME" > /dev/null

rm -rf "$PKG_ROOT"

# --- 2. Build per-platform Go binaries + tarballs ---
for target in "darwin-arm64:darwin:arm64" "darwin-amd64:darwin:amd64"; do
    plat="${target%%:*}"
    rest="${target#*:}"
    goos="${rest%%:*}"
    goarch="${rest#*:}"

    echo "building $plat..."
    stage="dist/stage-$plat"
    rm -rf "$stage"
    mkdir -p "$stage/bin"

    GOOS="$goos" GOARCH="$goarch" go build \
        -trimpath -ldflags="-w -s" \
        -o "$stage/bin/admin-gate" ./cmd/admin-gate/

    # Tarball contains the binary and the sub-pkg in the layout the host
    # installer expects: <binary> and <install_pkg> at tarball root.
    cp "dist/$PKG_NAME" "$stage/"

    tar_name="admin-gate-${VERSION}-${plat}.tar.gz"
    tar -C "$stage" -czf "dist/$tar_name" bin "$PKG_NAME"
    rm -rf "$stage"

    "$MONBAN_SIGN" sign --key "$SIGN_KEY" "dist/$tar_name"
done

# --- 3. Sign versioned manifest ---
cp manifest.json "dist/admin-gate-${VERSION}-manifest.json"
"$MONBAN_SIGN" sign --key "$SIGN_KEY" "dist/admin-gate-${VERSION}-manifest.json"

echo
echo "Artefacts:"
ls -1 dist/
