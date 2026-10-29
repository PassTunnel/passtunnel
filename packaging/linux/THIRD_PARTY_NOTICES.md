# Third-party notices (Linux)

PassTunnel's own source code is released under the MIT License (`LICENSE`). The Linux binaries,
`passtunnel` and `passtunneld`, are built with the Swift standard library linked statically
(`--static-swift-stdlib`), so they contain the code listed below. The full license texts are in
`licenses/`. The release tarball holds this file as `THIRD_PARTY_NOTICES.md`;
`scripts/build-linux.sh` adds the versions of the build at the end.

The VPN tools (`openvpn`, `openfortivpn`, `pppd`), the secret stores' tools (`secret-tool`,
`systemd-creds`) and the C and C++ runtime libraries (glibc, libstdc++, libgcc) are not included:
they come from the distribution and are separate programs or system libraries under their own
licenses.

## Linked into the binaries

| Component | License | License text | Upstream source |
|---|---|---|---|
| Swift standard library and runtime, Synchronization, Regex (`_StringProcessing`), the Glibc overlay | Apache-2.0 with the Runtime Library Exception | `licenses/Swift-LICENSE.txt` | https://github.com/swiftlang/swift |
| Dispatch (swift-corelibs-libdispatch, with BlocksRuntime) | Apache-2.0 with the Runtime Library Exception | `licenses/Swift-LICENSE.txt` | https://github.com/swiftlang/swift-corelibs-libdispatch |
| Foundation (swift-corelibs-foundation, swift-foundation's FoundationEssentials and FoundationInternationalization, and the parts of swift-collections it embeds) | Apache-2.0 with the Runtime Library Exception | `licenses/Swift-LICENSE.txt` | https://github.com/swiftlang/swift-corelibs-foundation · https://github.com/swiftlang/swift-foundation |
| ICU (swift-foundation-icu: ICU4C with its data, used by Foundation) | Unicode-3.0, with the third-party terms in its license file | `licenses/ICU-LICENSE.txt` | https://github.com/swiftlang/swift-foundation-icu · https://github.com/unicode-org/icu |
| [swift-crypto](https://github.com/apple/swift-crypto) (`Crypto`; `CryptoExtras` in `passtunnel` only) | Apache-2.0 | `licenses/swift-crypto-LICENSE.txt`, `licenses/swift-crypto-NOTICE.txt` | https://github.com/apple/swift-crypto |
| BoringSSL, vendored in swift-crypto (`CCryptoBoringSSL`), with fiat-crypto | Apache-2.0 (fiat-crypto: MIT, Apache-2.0 or BSD-1-Clause, used under Apache-2.0) | `licenses/swift-crypto-LICENSE.txt` | https://boringssl.googlesource.com/boringssl · https://github.com/mit-plv/fiat-crypto |
| XKCP (Keccak code, SHA-3), vendored in swift-crypto (`CXKCP`) | CC0-1.0 (public domain dedication) | none needed | https://github.com/XKCP/XKCP |
| [swift-asn1](https://github.com/apple/swift-asn1) (used by `CryptoExtras`; `passtunnel` only) | Apache-2.0 | `licenses/swift-asn1-LICENSE.txt`, `licenses/swift-asn1-NOTICE.txt` | https://github.com/apple/swift-asn1 |

`passtunneld` links all of them but `CryptoExtras` and swift-asn1. Parts of the Swift runtime come
from LLVM (Apache-2.0 with LLVM Exceptions, which, like the Runtime Library Exception, needs no
attribution in compiled form).

## Trademarks

OpenVPN is a registered trademark of OpenVPN Inc. Fortinet and FortiGate are registered trademarks
of Fortinet, Inc. Cisco and AnyConnect are trademarks or registered trademarks of Cisco Systems, Inc.
PassTunnel is an independent project and is not affiliated with or endorsed by any of these
companies.
