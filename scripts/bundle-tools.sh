#!/bin/bash
# Copies openvpn and openfortivpn from Homebrew into an app bundle together with every non-system
# dylib they need, rewrites their load paths so nothing points into Homebrew, and collects licenses.
#
#   scripts/bundle-tools.sh build/PassTunnel.app
#
# Layout produced:
#   Contents/Resources/bin/{openvpn,openfortivpn,dns-updown}
#   Contents/Frameworks/*.dylib
#   Contents/Resources/licenses/*
# Binaries are ad-hoc signed here so they stay runnable; build-app.sh re-signs them. The Homebrew
# versions must match the pins in scripts/release.env (see "pinned versions" below).
set -euo pipefail

APP="${1:?usage: $0 <App.app>}"
BREW="${HOMEBREW_PREFIX:-/opt/homebrew}"
OPENVPN="$BREW/opt/openvpn/sbin/openvpn"
OPENFORTIVPN="$BREW/opt/openfortivpn/bin/openfortivpn"

[[ -d "$APP/Contents" ]] || { echo "error: $APP is not an app bundle" >&2; exit 1; }
for t in "$OPENVPN" "$OPENFORTIVPN"; do
    [[ -x "$t" ]] || { echo "error: $t not found (brew install openvpn openfortivpn)" >&2; exit 1; }
done

BIN="$APP/Contents/Resources/bin"
FW="$APP/Contents/Frameworks"
LIC="$APP/Contents/Resources/licenses"
rm -rf "$BIN" "$FW" "$LIC"
mkdir -p "$BIN" "$FW" "$LIC"

is_system() { [[ "$1" == /usr/lib/* || "$1" == /System/* ]]; }

# Non-system dependencies of a Mach-O file (skips the file's own install name).
deps_of() {
    local file="$1" self
    self=$(otool -D "$file" 2>/dev/null | sed -n 2p)
    otool -L "$file" | tail -n +2 | awk '{print $1}' | while read -r dep; do
        [[ "$dep" == "$self" ]] && continue
        is_system "$dep" && continue
        echo "$dep"
    done
}

# Homebrew formula and Cellar dir owning a path ("" if not under the Cellar).
cellar_dir_of() {
    local real
    real=$(realpath "$1")
    if [[ "$real" =~ ^($BREW/Cellar/[^/]+/[^/]+)/ ]]; then echo "${BASH_REMATCH[1]}"; fi
}

# --- tools --------------------------------------------------------------------------------------
cp "$(realpath "$OPENVPN")" "$BIN/openvpn"
cp "$(realpath "$OPENFORTIVPN")" "$BIN/openfortivpn"
chmod 755 "$BIN/openvpn" "$BIN/openfortivpn"

# OpenVPN's DNS hook; the helper passes it explicitly (--dns-updown) after checking its signature.
DNS_UPDOWN="$(cellar_dir_of "$OPENVPN")/libexec/openvpn/dns-updown"
if [[ -f "$DNS_UPDOWN" ]]; then
    cp "$DNS_UPDOWN" "$BIN/dns-updown"
    chmod 755 "$BIN/dns-updown"
else
    echo "warning: dns-updown not found; OpenVPN will run without DNS configuration" >&2
fi

# --- dependency closure ---------------------------------------------------------------------------
# Breadth-first over load commands. Libraries are keyed by file name (libcrypto.3 and libcrypto.4
# are different names, so OpenSSL 3 and 4 coexist).
queue=("$BIN/openvpn" "$BIN/openfortivpn")
sources=("$OPENVPN" "$OPENFORTIVPN")
seen_list="$FW/.seen"            # "<name> <real path>" per collected library
: > "$seen_list"
i=0
while ((i < ${#queue[@]})); do
    file="${queue[$i]}"; i=$((i + 1))
    while read -r dep; do
        [[ -z "$dep" ]] && continue
        name=$(basename "$dep")
        case "$dep" in
            @*) src="$BREW/lib/$name" ;;   # @rpath/@loader_path refs: resolve via the prefix
            *)  src="$dep" ;;
        esac
        [[ -f "$src" ]] || { echo "error: cannot resolve $dep (needed by $file)" >&2; exit 1; }
        real=$(realpath "$src")
        prev=$(awk -v n="$name" '$1 == n {print $2}' "$seen_list")
        if [[ -n "$prev" ]]; then
            [[ "$prev" == "$real" ]] || { echo "error: two different $name ($prev, $real)" >&2; exit 1; }
            continue
        fi
        echo "$name $real" >> "$seen_list"
        cp "$real" "$FW/$name"
        chmod 644 "$FW/$name"
        sources+=("$real")
        queue+=("$FW/$name")
    done < <(deps_of "$file")
done
rm -f "$seen_list"

# --- pinned versions ------------------------------------------------------------------------------
# Every bundled formula must have the Cellar version pinned in release.env (openssl@3 →
# OPENSSL3_VERSION, pkcs11-helper → PKCS11_HELPER_VERSION, …), and every pin must be bundled.
# PASSTUNNEL_ALLOW_UNPINNED_TOOLS=1 only warns (local builds; release.sh refuses it).
source "$(dirname "$0")/release.env"
pin_var() { echo "$(tr '[:lower:]-' '[:upper:]_' <<<"${1//@/}")_VERSION"; }
pin_errors=0
pinned_vars=" "
echo "Bundled Homebrew formulae (pins in scripts/release.env):"
for src in "${sources[@]}"; do
    cellar=$(cellar_dir_of "$src")
    if [[ -z "$cellar" ]]; then
        echo "  error: $src is not from a formula in $BREW/Cellar" >&2
        pin_errors=1
        continue
    fi
    formula=$(basename "$(dirname "$cellar")")
    version=$(basename "$cellar")
    var=$(pin_var "$formula")
    [[ "$pinned_vars" == *" $var "* ]] && continue
    pinned_vars+="$var "
    want="${!var:-}"
    if [[ "$version" == "$want" ]]; then
        status="ok"
    elif [[ -z "$want" ]]; then
        status="NOT PINNED: add $var=$version"
        pin_errors=1
    else
        status="MISMATCH: $var=$want"
        pin_errors=1
    fi
    printf '  %-16s %-10s %s\n' "$formula" "$version" "$status"
done
for var in $(sed -n 's/^\([A-Z0-9_]*_VERSION\)=.*/\1/p' "$(dirname "$0")/release.env"); do
    if [[ "$pinned_vars" != *" $var "* ]]; then
        echo "  $var=${!var} is pinned but not bundled; remove it from release.env" >&2
        pin_errors=1
    fi
done
if ((pin_errors)); then
    if [[ "${PASSTUNNEL_ALLOW_UNPINNED_TOOLS:-}" == 1 ]]; then
        echo "warning: bundled versions differ from scripts/release.env (PASSTUNNEL_ALLOW_UNPINNED_TOOLS=1)" >&2
    else
        echo "error: bundled versions differ from scripts/release.env; see docs/RELEASING.md (Bundled tools)" >&2
        exit 1
    fi
fi

# --- rewrite load paths ---------------------------------------------------------------------------
rewrite() {
    local file="$1" prefix="$2" dep name
    while read -r dep; do
        [[ -z "$dep" ]] && continue
        name=$(basename "$dep")
        install_name_tool -change "$dep" "$prefix/$name" "$file" 2>/dev/null
    done < <(deps_of "$file")
    # Drop rpaths that point outside the bundle.
    otool -l "$file" | awk '/cmd LC_RPATH/{r=1} r && /path /{print $2; r=0}' | while read -r rp; do
        [[ "$rp" == @* ]] || install_name_tool -delete_rpath "$rp" "$file" 2>/dev/null
    done
}

for tool in "$BIN/openvpn" "$BIN/openfortivpn"; do
    rewrite "$tool" "@executable_path/../../Frameworks"
done
for lib in "$FW"/*.dylib; do
    install_name_tool -id "@rpath/$(basename "$lib")" "$lib" 2>/dev/null
    rewrite "$lib" "@loader_path"
done

# install_name_tool invalidates signatures; arm64 needs at least an ad-hoc one to run.
for f in "$FW"/*.dylib "$BIN/openvpn" "$BIN/openfortivpn"; do
    codesign --force --sign - "$f" 2>/dev/null
done

# --- verify ---------------------------------------------------------------------------------------
bad=0
for f in "$BIN/openvpn" "$BIN/openfortivpn" "$FW"/*.dylib; do
    if otool -L "$f" | tail -n +2 | grep -E "$BREW|/usr/local/" >/dev/null; then
        echo "error: $f still links into Homebrew:" >&2
        otool -L "$f" | grep -E "$BREW|/usr/local/" >&2
        bad=1
    fi
    if otool -l "$f" | grep -A2 LC_RPATH | grep -E "path ($BREW|/usr/local/)" >/dev/null; then
        echo "error: $f still has a Homebrew rpath" >&2
        bad=1
    fi
done
((bad == 0)) || exit 1

# --- licenses -------------------------------------------------------------------------------------
notice="$LIC/THIRD_PARTY_NOTICES.txt"
{
    echo "PassTunnel bundles the following third-party software, unmodified, built by Homebrew."
    echo "Their licenses are in this folder. Source code is available from the upstream projects"
    echo "listed below and from https://github.com/Homebrew/homebrew-core."
    echo
} > "$notice"
done_formulas=" "
for src in "${sources[@]}"; do
    cellar=$(cellar_dir_of "$src")
    [[ -n "$cellar" ]] || continue
    formula=$(basename "$(dirname "$cellar")")
    version=$(basename "$cellar")
    [[ "$done_formulas" == *" $formula "* ]] && continue
    done_formulas+="$formula "
    found=0
    for lf in "$cellar"/LICENSE* "$cellar"/COPYING* "$cellar"/COPYRIGHT* \
              "$cellar"/share/doc/*/LICENSE* "$cellar"/share/doc/*/COPYING*; do
        [[ -f "$lf" ]] || continue
        dest="$LIC/$formula-$(basename "$lf")"
        [[ -f "$dest" ]] && continue
        cp "$lf" "$dest"
        found=1
    done
    ((found)) || echo "warning: no license file found for $formula in $cellar" >&2
    homepage=$(sed -n 's/.*"homepage": *"\([^"]*\)".*/\1/p' "$cellar/sbom.spdx.json" 2>/dev/null | head -1)
    case "$formula" in
        openvpn) lic="GPL-2.0 (with OpenSSL linking exception)"; url="https://openvpn.net/community-downloads/" ;;
        openfortivpn) lic="GPL-3.0 (with OpenSSL linking exception)"; url="https://github.com/adrienverge/openfortivpn" ;;
        openssl@*) lic="Apache-2.0"; url="https://www.openssl.org/source/" ;;
        lzo) lic="GPL-2.0"; url="https://www.oberhumer.com/opensource/lzo/" ;;
        lz4) lic="BSD-2-Clause"; url="https://github.com/lz4/lz4" ;;
        pkcs11-helper) lic="BSD-3-Clause or GPL-2.0"; url="https://github.com/OpenSC/pkcs11-helper" ;;
        *) lic="see license files"; url="${homepage:-}" ;;
    esac
    printf '%-16s %-10s %s\n%16s %s\n\n' "$formula" "$version" "$lic" "" "$url" >> "$notice"
done
if [[ -f "$BIN/dns-updown" ]]; then
    echo "dns-updown (part of OpenVPN, BSD-2-Clause, see the header of Resources/bin/dns-updown)" >> "$notice"
fi

echo "Bundled tools into $APP:"
for f in "$BIN"/* "$FW"/*; do echo "  ${f#"$APP"/}"; done
echo "Licenses: $(ls "$LIC" | wc -l | tr -d ' ') files in Contents/Resources/licenses"
