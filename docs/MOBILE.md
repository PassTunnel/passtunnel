# PassTunnel for iPhone and Android

This is the spec for the mobile apps: what each app is, how they share logic with the Mac app, the
order they are built in, and the rules they follow. [ARCHITECTURE.md](ARCHITECTURE.md) and
[APP.md](APP.md) remain the source of truth for the behavior that the apps share with the Mac
(profiles, code formats, the fresh-code rule, share files).

## The two apps

| | Android | iPhone |
|---|---|---|
| What it is | A VPN client, like the Mac app: it connects OpenVPN profiles and fills in the one-time code | A companion: profiles, live codes, copy and AutoFill; the connection is made by the VPN app the user already has |
| Why | `VpnService` is open to any developer, and the engine below keeps the app MIT | App Store Guideline 5.4 allows VPN apps only from organizations; PassTunnel publishes from a personal account |
| Identifier | `com.digilabs.passtunnel` (registered in Play Console; permanent) | `com.furkanprlk.passtunnel.ios`, team YH4NUPFH74 (never the Mac's bundle id, so the two can never meet on one Mac) |
| Repository | [PassTunnel/passtunnel-android](https://github.com/PassTunnel/passtunnel-android) | [PassTunnel/passtunnel-ios](https://github.com/PassTunnel/passtunnel-ios) |
| Language and UI | Kotlin, Jetpack Compose, Material 3 | Swift, SwiftUI |
| Minimum OS | Android 10 (API 29); target the API level Play requires | iOS 17 |
| Store | Google Play | App Store |

Both are free, MIT, without accounts, analytics, ads or network access of their own (the Android
VPN talks only to the user's VPN server). FortiGate is not on either phone for now: there is no
library we may use under MIT, and FortiOS 7.6.3 removed SSL VPN tunnel mode altogether. It is
revisited after the Android VPN ships.

## Shared logic

The portable part of `PassTunnelCore` is about 1,800 lines that need only Foundation and CryptoKit:
the model, TOTP, `otpauth://` parsing, code composition, the OpenVPN analyzer, inliner and sanitizer,
FortiGate config, share files, slugs, profile fields and merging, and the secret envelope.

- **`PassTunnelKit`** is a new library target and product in this repository's `Package.swift`
  holding exactly that code, buildable for macOS 13 and iOS 17. `PassTunnelCore` depends on it, so
  the Mac app behaves exactly as before; the move is a pure refactor with no behavior change. The
  OpenVPN sanitizer and the FortiGate config are in `PassTunnelVPNConfig`, a second target of the
  same product, because the privileged helper uses them and must not link the rest. The iPhone app
  depends on the product `PassTunnelKit` of this repository, pinned to a commit.
- **Android** has its own Kotlin port of the same code (`core` module). There is one behavior, so
  the two implementations must not drift:
- **`fixtures/`** in this repository is a corpus of golden cases in JSON: RFC 6238 vectors and
  PassTunnel's own TOTP cases, every code format and template, `otpauth://` URIs that parse and
  ones that must fail, OpenVPN configs the sanitizer accepts and rejects, inlining results, and
  `.passtunnel` files with their decoded profiles. The Swift tests read it, so it can never be
  wrong for the Mac; the Android tests read a copy pinned to a commit of this repository, and a
  check fails when the copy is not that commit's corpus. A change to shared behavior lands here
  first (code, tests and fixtures), then in Android.

Swift on Android (official SDK since Swift 6.3) is reconsidered when its Java bridge reaches 1.0;
until then the Kotlin port is simpler and safer.

## Android: the VPN client

- **Engine: OpenVPN 3 Core** (OpenVPN/openvpn3, C++), used under **MPL-2.0** (it is dual
  AGPLv3/MPL-2.0 since 2024-09-30, for use in app stores). Built from a pinned release tag with
  its permissive dependencies (OpenSSL 3, asio, fmt, lz4, xxhash, jsoncpp). A thin JNI bridge of our
  own: a `TunBuilderBase` that maps to `VpnService.Builder`, credentials, events and logs. Changed
  openvpn3 files, if any, are published; all notices are in an in-app Licenses screen.
- **Never copied from**: ics-openvpn (GPLv2, "any part … creates derivative work"), Partout
  (GPLv3), openfortivpn, OpenConnect. Reading their docs is fine; their code stays out.
- **Limits of openvpn3**: no TAP, no `fragment`, no static-key mode. The analyzer reports these at
  import, with a clear message, instead of failing at connect. If real users need them, the
  fallback is upstream openvpn 2.6 built for Android as a separate executable driven over the
  management socket (the Mac model), decided then.
- **Codes and credentials**: the same rules as the Mac. The app computes the code when it connects,
  sends password and code in the profile's format (or the static-challenge response), and waits
  for a fresh window when 5 seconds or less are left; a code is never reused.
- **Secrets**: an AES-GCM key in the Android Keystore wraps passwords and TOTP secrets; files live
  in app-private storage, excluded from backups. Profiles marked for confirmation use a key that
  requires strong biometrics or the device credential (`BiometricPrompt` with a `CryptoObject`).
  Always-on VPN and reconnects after a reboot can only use profiles that need no confirmation, the
  same rule as unattended profiles on the Mac.
- **Import**: `.passtunnel` and `.ovpn` files (share sheet and file picker), and `otpauth://` QR
  codes from the camera or from an image.
- **Play**: the listing states that the app uses `VpnService`; the VPN declaration and its demo
  video are filed when the VPN ships (phase 2), not before.

## iPhone: the companion

- **In the app**: profiles, live codes with the countdown ring, "Copy code" and "Copy password and
  code" (local-only pasteboard that expires at the end of the code window), Face ID or Touch ID per
  profile with the Mac's Secure Enclave design, Keychain items `…ThisDeviceOnly`.
- **Import**: `.passtunnel` and `.ovpn` files (Files, AirDrop from the Mac, Mail), `otpauth://` QR
  codes from the camera or a photo. The Mac app exports the `.passtunnel` type (see phase 0); the
  iPhone imports it. Share files carry no secrets, so the TOTP QR is scanned again on the phone.
- **Handing off**: "Open in OpenVPN Connect" shares the profile's configuration (no credentials)
  through the share sheet. FortiClient has no documented import format, so none is generated.
- **Phase 3 additions**: an AutoFill credential provider that offers password-plus-code as the
  password, the code for one-time-code fields and, on iOS 18, text to insert into any field; App
  Intents and Shortcuts ("Get code", "Copy password and code") that require an unlocked device;
  widgets with profile shortcuts (widgets cannot show live 30-second codes).
- **App Store**: the listing leads with what generic authenticators do not do (VPN profiles, code
  formats, password-plus-code, the Mac companion) and names OpenVPN and FortiGate only factually.
  No sync with the Mac in the first versions: today's design keeps secrets out of iCloud on
  purpose; changing that is its own decision.

## Phases

0. **Preparation** (this repository and the site)
   - Extract `PassTunnelKit` (refactor, no behavior change) and make it build for iOS.
   - Create `fixtures/` and make the Swift tests read it.
   - The Mac app exports the `.passtunnel` document type (`com.furkanprlk.passtunnel.profile`).
   - A privacy policy at `https://passtunnel.github.io/privacy/`, linked from both stores and both
     apps: nothing is collected, secrets stay on the device, the only connection is to the user's
     VPN server.
   - Create both repositories with the same branch flow and rules as this one.
1. **"Codes" on both stores**: profiles, import, live codes, copy, biometric lock. On Android it goes
   out through a closed test (this also keeps the Play developer account active; the closed test
   with 12 testers for 14 days applies if the account was created after 2023-11-13). The Android
   listing makes no VPN claims yet.
2. **Android VPN**: openvpn3, the credential rules above, always-on for profiles without
   confirmation, VPN declaration and demo video.
3. **iPhone additions**: AutoFill, App Intents and Shortcuts, widgets.
4. **Later, each decided on its own**: FortiGate on Android, sync between Mac and iPhone, Linux and
   Windows.

## Rules for both apps

The rules of this repository apply unchanged: no company or customer names or real hostnames in
examples, no secrets in logs, tests never touch real data, signed commits, the issue → branch →
pull request flow with Conventional Commits titles. Dependencies are kept to the platform and the
VPN engine, plus AndroidX and ZXing core (Apache-2.0, for reading QR codes without Google Play
services) on Android, all pinned to exact versions.
