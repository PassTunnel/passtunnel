# Third-party notices

PassTunnel's own source code is released under the [MIT License](LICENSE). The app's only
third-party Swift dependency is [Sparkle](https://sparkle-project.org) (MIT), the update framework,
linked into the app and shipped as `Contents/Frameworks/Sparkle.framework`. The Linux binaries link
the Swift runtime, Foundation and swift-crypto instead; their notices are in
[`packaging/linux/THIRD_PARTY_NOTICES.md`](packaging/linux/THIRD_PARTY_NOTICES.md), which the Linux
release tarball carries with the license texts.

The PassTunnel **app bundle** also ships the VPN tools it drives and the libraries they need. They
are **separate, independent programs** that PassTunnel starts as child processes. They are not
linked into PassTunnel's code. They are distributed alongside it (mere aggregation), each under its
own license.

## Bundled components

| Component | License | Upstream source |
|---|---|---|
| [OpenVPN](https://openvpn.net) (`openvpn`) | GPL-2.0, with OpenSSL linking exception | https://openvpn.net/community-downloads/ · https://github.com/OpenVPN/openvpn |
| `dns-updown` (part of OpenVPN) | BSD-2-Clause | https://github.com/OpenVPN/openvpn |
| [openfortivpn](https://github.com/adrienverge/openfortivpn) (`openfortivpn`) | GPL-3.0, with OpenSSL linking exception | https://github.com/adrienverge/openfortivpn |
| [OpenSSL](https://www.openssl.org) (`libssl`, `libcrypto`) | Apache-2.0 | https://www.openssl.org/source/ · https://github.com/openssl/openssl |
| [LZO](https://www.oberhumer.com/opensource/lzo/) (`liblzo2`) | GPL-2.0 | https://www.oberhumer.com/opensource/lzo/ |
| [LZ4](https://lz4.org) (`liblz4`) | BSD-2-Clause | https://github.com/lz4/lz4 |
| [pkcs11-helper](https://github.com/OpenSC/pkcs11-helper) (`libpkcs11-helper`) | BSD-3-Clause or GPL-2.0 (dual) | https://github.com/OpenSC/pkcs11-helper |
| [OpenConnect](https://www.infradead.org/openconnect/) (`openconnect`, `libopenconnect`) | LGPL-2.1 | https://www.infradead.org/openconnect/download.html · https://gitlab.com/openconnect/openconnect |
| [GnuTLS](https://www.gnutls.org) (`libgnutls`) | LGPL-2.1 or later (the library; its GPL-3.0 tools are not bundled) | https://www.gnutls.org/download.html |
| [Nettle](https://www.lysator.liu.se/~nisse/nettle/) (`libnettle`, `libhogweed`) | LGPL-3.0 or later, or GPL-2.0 or later (dual) | https://www.lysator.liu.se/~nisse/nettle/ |
| [GMP](https://gmplib.org) (`libgmp`) | LGPL-3.0 or later, or GPL-2.0 or later (dual) | https://gmplib.org/#DOWNLOAD |
| [p11-kit](https://p11-glue.github.io/p11-glue/p11-kit.html) (`libp11-kit`) | BSD-3-Clause | https://github.com/p11-glue/p11-kit/releases |
| [libtasn1](https://www.gnu.org/software/libtasn1/) (`libtasn1`) | LGPL-2.1 or later | https://ftp.gnu.org/gnu/libtasn1/ |
| [libidn2](https://www.gnu.org/software/libidn/#libidn2) (`libidn2`) | LGPL-3.0 or later, or GPL-2.0 or later (dual; the library) | https://ftp.gnu.org/gnu/libidn/ |
| [libunistring](https://www.gnu.org/software/libunistring/) (`libunistring`) | LGPL-3.0 or later, or GPL-2.0 or later (dual) | https://ftp.gnu.org/gnu/libunistring/ |
| [gettext](https://www.gnu.org/software/gettext/) (`libintl` only) | LGPL-2.1 or later (libintl; the gettext tools, GPL-3.0, are not bundled) | https://ftp.gnu.org/gnu/gettext/ |
| [stoken](https://github.com/stoken-dev/stoken) (`libstoken`) | LGPL-2.1 or later | https://github.com/stoken-dev/stoken |
| [LibTomCrypt](https://www.libtom.net) (`libtomcrypt`) | Public domain or WTFPL-2.0 (dual) | https://github.com/libtom/libtomcrypt |
| [LibTomMath](https://www.libtom.net/LibTomMath/) (`libtommath`) | Unlicense | https://github.com/libtom/libtommath |
| [Sparkle](https://sparkle-project.org) (`Sparkle.framework`, app updates) | MIT (includes notices for its own bundled code) | https://github.com/sparkle-project/Sparkle |

The exact set of libraries and their versions depend on the build. Depending on how the tools were
built, more than one OpenSSL major version may be included (for example `libcrypto.3` and
`libcrypto.4`).

`openconnect` and the libraries from OpenConnect to LibTomMath above are bundled for Cisco AnyConnect
support, which is not available in the app yet; nothing runs `openconnect` so far. It will need
macOS 15.4 or later (the app itself runs on macOS 13). `libstoken`, `libtomcrypt`, `libtommath` and
`libintl` are loaded by `openconnect` but not used by PassTunnel.

## How they are built and where to find them

[`scripts/bundle-tools.sh`](scripts/bundle-tools.sh) copies the tools and every non-system library
they load from [Homebrew](https://github.com/Homebrew/homebrew-core), rewrites their library load
paths so they point into the app bundle, and re-signs them. Their code is not otherwise modified,
with one exception: in `libp11-kit` (p11-kit) and `libgnutls` (GnuTLS), the configuration paths
compiled into the library under Homebrew's prefix (p11-kit's `pkcs11.conf` and module directories,
GnuTLS's `config` and `cert.pem`) are overwritten in place with `/var/empty/none`, a path that does
not exist, so that the tools never read configuration or modules from a directory another user may
be able to write ([SECURITY.md](SECURITY.md#paths-compiled-into-the-homebrew-build)). The build
log lists each overwritten string.

Inside the app:

```
PassTunnel.app/Contents/Resources/bin/            openvpn, openfortivpn, openconnect, dns-updown
PassTunnel.app/Contents/Frameworks/               libssl, libcrypto, liblzo2, liblz4, libpkcs11-helper,
                                                  libopenconnect, libgnutls, libnettle, libhogweed,
                                                  libgmp, libp11-kit, libtasn1, libidn2, libunistring,
                                                  libintl, libstoken, libtomcrypt, libtommath,
                                                  Sparkle.framework
PassTunnel.app/Contents/Resources/licenses/       full license texts + THIRD_PARTY_NOTICES.txt
```

`Contents/Resources/licenses/THIRD_PARTY_NOTICES.txt` is generated at build time and lists each
bundled component with its **exact version**, license and source URL. The full license texts
(`openvpn-COPYING`, `openfortivpn-LICENSE`, `openssl@4-LICENSE.txt`, `lzo-COPYING`, `lz4-LICENSE`,
`pkcs11-helper-COPYING*`, `openconnect-COPYING.LGPL`, `gnutls-COPYING.LESSERv2`, `gmp-COPYING.LESSERv3`,
`Sparkle-LICENSE.txt`, …) are in the same folder; libintl's license is the LGPL-2.1 of
`gnutls-COPYING.LESSERv2`. You can also open them from **Settings →
Helper → Show Licenses…**.

## Source code for GPL and LGPL components

The corresponding source code for OpenVPN, openfortivpn and LZO (GPL), and for OpenConnect, GnuTLS,
Nettle, GMP, libtasn1, libidn2, libunistring, gettext's libintl and stoken (LGPL), is available
from the upstream projects linked above. The Homebrew formulae used for the build (in
[homebrew-core](https://github.com/Homebrew/homebrew-core)) record the exact source archive and
checksum for each version. If you need the source for the exact version included in a PassTunnel
release and cannot find it, open an issue at
[github.com/passtunnel/passtunnel/issues](https://github.com/passtunnel/passtunnel/issues).

### Using a modified LGPL library

Each LGPL library is a separate dynamic library in `Contents/Frameworks`, unmodified apart from its
load paths and code signature (and, in GnuTLS, the two configuration paths above), so a compatible build of it can take its place. A released PassTunnel
does not accept one, though: its privileged helper runs the tools only with the exact library builds
the release was made with (their code-signing hashes are compiled into the helper, see
[SECURITY.md](SECURITY.md)), and the tools are signed with library validation, so they load only
libraries signed with the same Team ID. To run PassTunnel with a modified library, build it from
source ([README](README.md#build-from-source)): install the modified library in your Homebrew,
build with `PASSTUNNEL_ALLOW_UNPINNED_TOOLS=1 scripts/build-app.sh` (the variable lets the build use
versions other than the ones pinned in `scripts/release.env`), and sign it with your own Team ID as
the README describes. `build-app.sh` pins whatever it bundled, so that build's helper runs your
library.

## Trademarks

OpenVPN is a registered trademark of OpenVPN Inc. Fortinet and FortiGate are registered trademarks
of Fortinet, Inc. Cisco and AnyConnect are trademarks or registered trademarks of Cisco Systems, Inc.
PassTunnel is an independent project and is not affiliated with or endorsed by any of these
companies.
