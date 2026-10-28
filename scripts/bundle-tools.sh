#!/bin/bash
# Copies openvpn, openfortivpn and openconnect from Homebrew into an app bundle together with every
# non-system dylib they need, rewrites their load paths so nothing points into Homebrew, and collects
# licenses.
#
#   scripts/bundle-tools.sh build/PassTunnel.app
#
# Layout produced:
#   Contents/Resources/bin/{openvpn,openfortivpn,openconnect,dns-updown}
#   Contents/Frameworks/*.dylib
#   Contents/Resources/licenses/*
# Binaries are ad-hoc signed here so they stay runnable; build-app.sh re-signs them. The Homebrew
# versions must match the pins in scripts/release.env (see "pinned versions" below), and what the tools
# import from macOS must exist on the app's minimum macOS (check-tool-symbols.sh).
set -euo pipefail

APP="${1:?usage: $0 <App.app>}"
BREW="${HOMEBREW_PREFIX:-/opt/homebrew}"
OPENVPN="$BREW/opt/openvpn/sbin/openvpn"
OPENFORTIVPN="$BREW/opt/openfortivpn/bin/openfortivpn"
# Homebrew installs openconnect in bin (--sbindir=#{bin}). Only the binary and its libraries: never
# etc/vpnc/vpnc-script or anything in libexec/openconnect (csd-wrapper, hipreport, tncc).
OPENCONNECT="$BREW/opt/openconnect/bin/openconnect"

[[ -d "$APP/Contents" ]] || { echo "error: $APP is not an app bundle" >&2; exit 1; }
for t in "$OPENVPN" "$OPENFORTIVPN" "$OPENCONNECT"; do
    [[ -x "$t" ]] || { echo "error: $t not found (brew install openvpn openfortivpn openconnect)" >&2; exit 1; }
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
cp "$(realpath "$OPENCONNECT")" "$BIN/openconnect"
chmod 755 "$BIN/openvpn" "$BIN/openfortivpn" "$BIN/openconnect"

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
queue=("$BIN/openvpn" "$BIN/openfortivpn" "$BIN/openconnect")
sources=("$OPENVPN" "$OPENFORTIVPN" "$OPENCONNECT")
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
# Every bundled formula must have the Cellar version pinned in release.env (openssl@4 →
# OPENSSL4_VERSION, pkcs11-helper → PKCS11_HELPER_VERSION, …), and every pin must be bundled.
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

for tool in "$BIN/openvpn" "$BIN/openfortivpn" "$BIN/openconnect"; do
    rewrite "$tool" "@executable_path/../../Frameworks"
done
for lib in "$FW"/*.dylib; do
    install_name_tool -id "@rpath/$(basename "$lib")" "$lib" 2>/dev/null
    rewrite "$lib" "@loader_path"
done

# --- configuration paths compiled into the libraries -------------------------------------------------
# Some libraries read files from the Homebrew prefix by themselves, whatever the command line says, and
# the tools run as root: whoever can write the prefix (the user who installed Homebrew) would get root.
# libp11-kit loads its system configuration and module files (pkcs11.conf, etc/modules,
# etc/pkcs11/modules) as soon as GnuTLS initializes PKCS#11, which openconnect does before it reads its
# options, even for --version; a module file can name a command to run ("remote: |command") or a
# library to load, and no environment variable moves the system paths. GnuTLS's system configuration
# (etc/gnutls/config) can name a PKCS#11 provider library to load, and its default trust store
# (etc/gnutls/cert.pem) would trust whatever certificate is added there. Each such string is
# overwritten in place with NEUTRAL_PATH, NUL-padded to its length, so the library finds nothing:
# /var/empty is root-owned and empty, and only root could create anything in it. Nothing else of the
# libraries changes (the same bytes in, the same bytes out). Other Homebrew paths left in the tools
# are handled where they are run (docs/ARCHITECTURE.md, Bundling and pins).
NEUTRAL_PATH=/var/empty/none
NEUTRALIZE=(
    "libp11-kit.0.dylib:$BREW/"           # every path: configuration, module directories, module path
    "libgnutls.30.dylib:$BREW/etc/"       # gnutls/config, gnutls/cert.pem
)
neutralize() {
    local file="$1" prefix="$2"
    perl -e '
        my ($file, $prefix, $neutral) = @ARGV;
        open(my $in, "<:raw", $file) or die "error: $file: $!\n";
        my $data = do { local $/; <$in> };
        close($in);
        my $count = 0;
        # Whole C strings only: at the start of the file or after a NUL, up to the next NUL.
        $data =~ s{(?<![^\0])(\Q$prefix\E[^\0]*)(?=\0)}{
            my $old = $1;
            length($old) >= length($neutral) or die "error: $file: \"$old\" is shorter than $neutral\n";
            $count++;
            print "  $file: $old\n";
            $neutral . ("\0" x (length($old) - length($neutral)));
        }ge;
        $count or die "error: $file has no strings under $prefix (has the library changed?)\n";
        open(my $out, ">:raw", $file) or die "error: $file: $!\n";
        print $out $data;
        close($out) or die "error: $file: $!\n";
    ' "$file" "$prefix" "$NEUTRAL_PATH"
}
echo "Neutralized paths (now $NEUTRAL_PATH):"
for entry in "${NEUTRALIZE[@]}"; do
    lib="$FW/${entry%%:*}"
    [[ -f "$lib" ]] || { echo "error: ${entry%%:*} is not bundled; update NEUTRALIZE in $0" >&2; exit 1; }
    (cd "$FW" && neutralize "$(basename "$lib")" "${entry#*:}")
done

# install_name_tool invalidates signatures; arm64 needs at least an ad-hoc one to run.
for f in "$FW"/*.dylib "$BIN/openvpn" "$BIN/openfortivpn" "$BIN/openconnect"; do
    codesign --force --sign - "$f" 2>/dev/null
done

# --- verify ---------------------------------------------------------------------------------------
bad=0
for f in "$BIN/openvpn" "$BIN/openfortivpn" "$BIN/openconnect" "$FW"/*.dylib; do
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
for entry in "${NEUTRALIZE[@]}"; do
    lib="$FW/${entry%%:*}"
    if LC_ALL=C grep -aq -- "${entry#*:}" "$lib"; then
        echo "error: $lib still holds a path under ${entry#*:}:" >&2
        strings -a "$lib" | grep -F -- "${entry#*:}" >&2
        bad=1
    fi
done
if LC_ALL=C grep -aqE "$BREW/|/usr/local/" "$FW/libp11-kit.0.dylib"; then
    echo "error: libp11-kit.0.dylib still names the Homebrew prefix" >&2
    bad=1
fi
((bad == 0)) || exit 1

# --- minimum macOS ----------------------------------------------------------------------------------
# What the tools and libraries import from macOS must be there on the app's minimum macOS (or on a
# tool's own, later one): dyld stops a tool at launch otherwise ("Symbol not found").
"$(dirname "$0")/check-tool-symbols.sh" "$APP"

# --- licenses -------------------------------------------------------------------------------------
notice="$LIC/THIRD_PARTY_NOTICES.txt"
{
    echo "PassTunnel bundles the following third-party software, built by Homebrew. It is unmodified"
    echo "apart from library load paths and, in libp11-kit (p11-kit) and libgnutls (GnuTLS), the"
    echo "configuration paths compiled in, overwritten with $NEUTRAL_PATH (a path that does not exist)."
    echo "Their licenses are in this folder. Source code is available from the upstream projects"
    echo "listed below and from https://github.com/Homebrew/homebrew-core. How to run PassTunnel with a"
    echo "modified LGPL library: THIRD_PARTY_NOTICES.md in https://github.com/$GITHUB_REPO."
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
        openconnect) lic="LGPL-2.1"; url="https://www.infradead.org/openconnect/download.html" ;;
        gnutls) lic="LGPL-2.1 or later (the library; its GPL-3.0 tools are not bundled)"; url="https://www.gnutls.org/download.html" ;;
        nettle) lic="LGPL-3.0 or later, or GPL-2.0 or later"; url="https://www.lysator.liu.se/~nisse/nettle/" ;;
        gmp) lic="LGPL-3.0 or later, or GPL-2.0 or later"; url="https://gmplib.org/#DOWNLOAD" ;;
        p11-kit) lic="BSD-3-Clause"; url="https://github.com/p11-glue/p11-kit/releases" ;;
        libtasn1) lic="LGPL-2.1 or later"; url="https://www.gnu.org/software/libtasn1/" ;;
        libidn2) lic="LGPL-3.0 or later, or GPL-2.0 or later (the library)"; url="https://www.gnu.org/software/libidn/#libidn2" ;;
        libunistring) lic="LGPL-3.0 or later, or GPL-2.0 or later"; url="https://www.gnu.org/software/libunistring/" ;;
        # Only libintl is bundled; its license text is the LGPL-2.1 (gnutls-COPYING.LESSERv2).
        gettext) lic="LGPL-2.1 or later (libintl; its GPL-3.0 tools are not bundled)"; url="https://www.gnu.org/software/gettext/" ;;
        stoken) lic="LGPL-2.1 or later"; url="https://github.com/stoken-dev/stoken" ;;
        libtomcrypt) lic="Public domain or WTFPL-2.0"; url="https://github.com/libtom/libtomcrypt" ;;
        libtommath) lic="Unlicense"; url="https://github.com/libtom/libtommath" ;;
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
