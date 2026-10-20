# Third-party notices

PassTunnel's own source code is released under the [MIT License](LICENSE). It has no third-party
Swift dependencies.

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

The exact set of libraries and their versions depend on the build. Depending on how the tools were
built, more than one OpenSSL major version may be included (for example `libcrypto.3` and
`libcrypto.4`).

## How they are built and where to find them

[`scripts/bundle-tools.sh`](scripts/bundle-tools.sh) copies the tools and every non-system library
they load from [Homebrew](https://github.com/Homebrew/homebrew-core), rewrites their library load
paths so they point into the app bundle, and re-signs them. Their code is not otherwise modified.

Inside the app:

```
PassTunnel.app/Contents/Resources/bin/            openvpn, openfortivpn, dns-updown
PassTunnel.app/Contents/Frameworks/               libssl, libcrypto, liblzo2, liblz4, libpkcs11-helper
PassTunnel.app/Contents/Resources/licenses/       full license texts + THIRD_PARTY_NOTICES.txt
```

`Contents/Resources/licenses/THIRD_PARTY_NOTICES.txt` is generated at build time and lists each
bundled component with its **exact version**, license and source URL. The full license texts
(`openvpn-COPYING`, `openfortivpn-LICENSE`, `openssl@3-LICENSE.txt`, `lzo-COPYING`, `lz4-LICENSE`,
`pkcs11-helper-COPYING*`, …) are in the same folder. You can also open them from **Settings →
Helper → Show Licenses…**.

## Source code for GPL components

The corresponding source code for OpenVPN, openfortivpn and LZO is available from the upstream
projects linked above. The Homebrew formulae used for the build (in
[homebrew-core](https://github.com/Homebrew/homebrew-core)) record the exact source archive and
checksum for each version. If you need the source for the exact version included in a PassTunnel
release and cannot find it, open an issue at
[github.com/Furkanprlk/passtunnel/issues](https://github.com/Furkanprlk/passtunnel/issues).

## Trademarks

OpenVPN is a registered trademark of OpenVPN Inc. Fortinet and FortiGate are registered trademarks
of Fortinet, Inc. PassTunnel is an independent project and is not affiliated with or endorsed by
either company.
