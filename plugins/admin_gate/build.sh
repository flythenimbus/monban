#!/usr/bin/env bash
# Build admin-gate for darwin. Produces, under dist/:
#   admin-gate-<version>-darwin-<arch>.tar.gz    (+ .sig)
#   admin-gate-<version>-manifest.json           (+ .sig)
#
# Each tarball contains:
#   bin/admin-gate                       — the stdio plugin binary
#   admin-gate-installer-<version>.pkg   — the sub-pkg that drops
#       monban-pam-helper + pam_monban.so + writes /etc/pam.d/sudo_local
#
# The PAM helper lives under ../../desktop/cmd/pam-helper (has to,
# because it imports monban's internal crypto). This script
# cross-compiles it from that module per arch using the same CGo +
# libfido2 flags the main desktop build uses.
#
# NOTE: only darwin-arm64 is built by default. darwin-amd64 requires
# an amd64 libfido2 + openssl symlink that CI sets up; enable by
# passing INCLUDE_AMD64=1.

set -euo pipefail

VERSION="${VERSION:-0.1.0}"
SIGN_KEY="${SIGN_KEY:-../../desktop/cmd/monban-sign/testkeys/dev-release.key}"
MONBAN_SIGN="${MONBAN_SIGN:-/tmp/monban-sign}"
INCLUDE_AMD64="${INCLUDE_AMD64:-0}"

cd "$(dirname "$0")"
DESKTOP_DIR="$(cd ../../desktop && pwd)"

if [[ ! -x "$MONBAN_SIGN" ]]; then
    echo "building monban-sign → $MONBAN_SIGN"
    (cd "$DESKTOP_DIR" && go build -o "$MONBAN_SIGN" ./cmd/monban-sign/)
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "admin-gate requires macOS to build (needs pkgbuild + libpam + libfido2)." >&2
    exit 1
fi

rm -rf dist
mkdir -p dist

platforms=("darwin-arm64:darwin:arm64")
if [[ "$INCLUDE_AMD64" == "1" ]]; then
    platforms+=("darwin-amd64:darwin:amd64")
fi

for target in "${platforms[@]}"; do
    plat="${target%%:*}"
    rest="${target#*:}"
    goos="${rest%%:*}"
    goarch="${rest#*:}"

    echo "=========================================="
    echo "building $plat"
    echo "=========================================="

    # Payload contains only the files we can legitimately deliver.
    # /etc/pam.d/sudo_local is SIP-protected on macOS Tahoe — even
    # signed pkgs can't drop it via payload. Apple's only blessed
    # path is `cp /etc/pam.d/sudo_local.template /etc/pam.d/sudo_local`
    # from root, which the postinstall does.
    payload="dist/payload-$plat"
    pkg_scripts="dist/pkg-scripts-$plat"
    rm -rf "$payload" "$pkg_scripts"
    # N20: /Library/Monban/ replaces /usr/local/{bin,lib/pam} as the
    # install root for the PAM helper + module. /Library/ is root-owned
    # by default on macOS and cannot be user-chowned without admin
    # action; /usr/local/ is user-owned on Intel Macs with Homebrew.
    mkdir -p "$payload/Library/Monban"
    mkdir -p "$payload/Library/Monban/pam"
    mkdir -p "$payload/Library/Security/SecurityAgentPlugins"
    mkdir -p "$pkg_scripts"

    cp installer/postinstall "$pkg_scripts/postinstall"
    cp installer/gated-rights.sh "$pkg_scripts/gated-rights.sh"
    chmod 0755 "$pkg_scripts/postinstall"

    # --- 1. Build the PAM helper with CGo (from the desktop module).
    # Imports monban/internal/monban for FIDO2 + config loading.
    cc_arch="$goarch"
    if [[ "$goarch" == "amd64" ]]; then cc_arch="x86_64"; fi
    echo "  building monban-pam-helper ($plat, cgo)..."
    local_brew="/opt/homebrew"
    if [[ "$goarch" == "amd64" ]]; then local_brew="/usr/local"; fi
    (
        cd "$DESKTOP_DIR"
        GOOS="$goos" GOARCH="$goarch" \
        CGO_ENABLED=1 \
        CGO_CFLAGS="-I${local_brew}/include -mmacosx-version-min=10.15" \
        CGO_LDFLAGS="-L${local_brew}/lib -lfido2 -mmacosx-version-min=10.15" \
        go build \
            -trimpath -ldflags="-w -s" \
            -o "$(pwd)/../plugins/admin_gate/$payload/Library/Monban/monban-pam-helper" \
            ./cmd/pam-helper/
    )

    # --- 2. Compile the PAM module (.so) straight into the payload.
    echo "  compiling pam_monban.so ($plat)..."
    cc -arch "$cc_arch" -shared -fPIC \
        -o "$payload/Library/Monban/pam/pam_monban.so" \
        native/pam_monban.c \
        -lpam

    # --- 2b. Build the SecurityAgent authorization-plugin bundle.
    echo "  building monban-auth.bundle ($plat)..."
    bundle_dir="$payload/Library/Security/SecurityAgentPlugins/monban-auth.bundle"
    mkdir -p "$bundle_dir/Contents/MacOS"
    cc -arch "$cc_arch" -bundle \
        -o "$bundle_dir/Contents/MacOS/monban-auth" \
        native/monban_auth_plugin.m \
        -framework Foundation -framework Security -framework SystemConfiguration
    cp native/Info.plist "$bundle_dir/Contents/"

    # --- 3. Build the sub-pkg: payload + scripts.
    PKG_NAME="admin-gate-installer-${VERSION}.pkg"
    echo "  building $PKG_NAME ($plat)..."
    pkgbuild \
        --identifier "com.monban.admin-gate.installer" \
        --version "$VERSION" \
        --scripts "$pkg_scripts" \
        --root "$payload" \
        "dist/$PKG_NAME-$plat" > /dev/null

    rm -rf "$payload" "$pkg_scripts"

    # --- 4. Plugin binary (pure Go, no cgo) + final tarball.
    echo "  building admin-gate plugin binary ($plat)..."
    stage="dist/stage-$plat"
    rm -rf "$stage"
    mkdir -p "$stage/bin"

    GOOS="$goos" GOARCH="$goarch" go build \
        -trimpath -ldflags="-w -s" \
        -o "$stage/bin/admin-gate" ./cmd/admin-gate/

    # Pin the SHA-256 of the binary into the manifest. Host checks this
    # before spawn — same-uid malware that replaces the extracted
    # binary with its own copy is caught when the hash doesn't match.
    bin_sha=$(shasum -a 256 "$stage/bin/admin-gate" | awk '{print $1}')
    echo "  binary sha256 ($plat) = $bin_sha"
    printf '%s\t%s\n' "$plat" "$bin_sha" >> "dist/_sha256-$VERSION.tsv"

    cp "dist/$PKG_NAME-$plat" "$stage/$PKG_NAME"
    rm -f "dist/$PKG_NAME-$plat"

    tar_name="admin-gate-${VERSION}-${plat}.tar.gz"
    tar -C "$stage" -czf "dist/$tar_name" bin "$PKG_NAME"
    rm -rf "$stage"

    "$MONBAN_SIGN" sign --key "$SIGN_KEY" "dist/$tar_name"
done

# Compose the final manifest with binary_sha256 populated for every
# platform we built, then sign it. jq picks the $tsv into an object.
jq_args=(--rawfile tsv "dist/_sha256-$VERSION.tsv")
jq_filter='
  .binary_sha256 = (
    $tsv | split("\n") | map(select(. != "") | split("\t") | {(.[0]): .[1]}) | add
  )
'
jq "${jq_args[@]}" "$jq_filter" manifest.json > "dist/admin-gate-${VERSION}-manifest.json"
rm -f "dist/_sha256-$VERSION.tsv"
"$MONBAN_SIGN" sign --key "$SIGN_KEY" "dist/admin-gate-${VERSION}-manifest.json"

echo
echo "Artefacts:"
ls -1 dist/
