// swift-tools-version:5.10
import PackageDescription

/// swift-crypto's `Crypto` (CryptoKit's API), for the targets that hash or encrypt; Linux only.
let crypto: Target.Dependency = .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux]))
/// swift-crypto's `CryptoExtras` (scrypt, for the Linux file secret store); Linux only.
let cryptoExtras: Target.Dependency = .product(name: "CryptoExtras", package: "swift-crypto", condition: .when(platforms: [.linux]))

let package = Package(
    name: "PassTunnel",
    defaultLocalization: "en",
    // iOS only for PassTunnelKit (and PassTunnelVPNConfig, which it uses); everything else is macOS.
    // Linux builds the portable targets and the `passtunnel` command (end of this file).
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [
        .executable(name: "PassTunnel", targets: ["PassTunnel"]),
        .executable(name: "PassTunnelHelper", targets: ["PassTunnelHelper"]),
        // Parsing libraries, so the out-of-tree fuzz package (fuzz/) can link the exact
        // sources that run in the app. Not part of any shipped binary.
        .library(name: "PassTunnelShared", targets: ["PassTunnelShared"]),
        .library(name: "PassTunnelCore", targets: ["PassTunnelCore"]),
        // The portable logic (macOS 13, iOS 17), for the iPhone app and the fuzzers.
        .library(name: "PassTunnelKit", targets: ["PassTunnelKit", "PassTunnelVPNConfig"])
    ],
    // Declared on every platform, so one Package.resolved (and Dependabot, which runs on Linux) covers them all.
    dependencies: [
        // App updates. The `passtunnel` CLI never starts the updater.
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.0"),
        // CryptoKit's API on Linux (`crypto` above); Apple platforms use CryptoKit and never build it.
        .package(url: "https://github.com/apple/swift-crypto", exact: "5.0.3")
    ],
    targets: [
        // The OpenVPN config sanitizer and the openfortivpn config renderer: the only portable code the
        // privileged helper runs, kept apart so the helper links nothing else from PassTunnelKit.
        .target(name: "PassTunnelVPNConfig"),
        // Portable logic, Foundation, CryptoKit and Security only (on Linux swift-crypto's Crypto, no
        // Security): model, errors, TOTP, otpauth links, code composition, OpenVPN analyzer and inliner,
        // share files, slugs, profile fields and merging, secret envelope.
        .target(name: "PassTunnelKit", dependencies: ["PassTunnelVPNConfig", crypto]),
        // Shared by the app and the privileged helper: XPC protocol, request types, tool launching.
        .target(name: "PassTunnelShared", dependencies: ["PassTunnelVPNConfig", crypto]),
        // Everything else that is not UI: profile store, secrets, connections, preferences, CLI parsing, MCP.
        .target(name: "PassTunnelCore", dependencies: ["PassTunnelKit", "PassTunnelVPNConfig", "PassTunnelShared", crypto, cryptoExtras]),
        // The `passtunnel` command: run by the app binary in CLI mode on the Mac, by its own
        // executable on Linux.
        .target(name: "PassTunnelCLI", dependencies: ["PassTunnelCore", "PassTunnelKit", "PassTunnelShared"]),
        // Root helper registered with SMAppService; starts/stops the bundled VPN tools.
        .executableTarget(name: "PassTunnelHelper", dependencies: ["PassTunnelShared"]),
        // The app (SwiftUI) and the `passtunnel` CLI are the same binary.
        .executableTarget(
            name: "PassTunnel",
            dependencies: [
                "PassTunnelCLI", "PassTunnelCore", "PassTunnelKit", "PassTunnelVPNConfig",
                "PassTunnelShared", .product(name: "Sparkle", package: "Sparkle")
            ],
            resources: [.process("Resources")]),
        .testTarget(
            name: "PassTunnelCoreTests",
            dependencies: [
                "PassTunnelCLI", "PassTunnelCore", "PassTunnelKit", "PassTunnelVPNConfig",
                "PassTunnelShared", crypto
            ]),
        // The golden cases in fixtures/ (also read by the Android port), against PassTunnelKit alone.
        .testTarget(name: "PassTunnelKitTests", dependencies: ["PassTunnelKit", "PassTunnelVPNConfig"])
    ]
)

#if os(Linux)
// Linux builds the portable targets, the `passtunnel` command and the tests that build there (the Linux
// jobs in .github/workflows/ci.yml), none of the macOS app and helper targets. The dependencies stay as
// declared above; no target uses Sparkle here.
let linuxTargets: Set = [
    "PassTunnelVPNConfig", "PassTunnelKit", "PassTunnelShared", "PassTunnelCore", "PassTunnelCLI",
    "PassTunnelKitTests", "PassTunnelCoreTests"
]
package.targets.removeAll { !linuxTargets.contains($0.name) }
package.products.removeAll { !["PassTunnelKit", "PassTunnelShared", "PassTunnelCore"].contains($0.name) }
// Linux only: on the Mac the app binary is the command. The product names the binary.
package.targets.append(.executableTarget(name: "PassTunnelCommand", dependencies: ["PassTunnelCLI"]))
package.products.append(.executable(name: "passtunnel", targets: ["PassTunnelCommand"]))
// passtunneld, the root daemon (docs/LINUX.md). Like PassTunnelHelper it is built from Shared and
// VPNConfig and nothing else: its logic is the library PassTunnelDaemon (so the tests can run it with
// injected paths and uids), which the executable PassTunnelDaemonCommand wraps.
package.targets.append(.target(name: "PassTunnelDaemon", dependencies: ["PassTunnelShared", "PassTunnelVPNConfig"]))
package.targets.append(.executableTarget(name: "PassTunnelDaemonCommand", dependencies: ["PassTunnelDaemon", "PassTunnelShared"]))
package.products.append(.executable(name: "passtunneld", targets: ["PassTunnelDaemonCommand"]))
package.targets.append(
    .testTarget(
        name: "PassTunnelDaemonTests",
        dependencies: ["PassTunnelDaemon", "PassTunnelShared", "PassTunnelCore", "PassTunnelVPNConfig"]))
#endif

// CI builds our own targets with warnings as errors (PASSTUNNEL_STRICT_WARNINGS=1, see
// .github/workflows/ci.yml). It is a per-target flag, not `swift build -Xswiftc -warnings-as-errors`,
// which would also apply to swift-crypto on Linux, whose warnings are not ours to fix. Off by default:
// a package that uses unsafeFlags cannot be a dependency of the fuzz package (fuzz/).
if Context.environment["PASSTUNNEL_STRICT_WARNINGS"] == "1" {
    for target in package.targets {
        target.swiftSettings = (target.swiftSettings ?? []) + [.unsafeFlags(["-warnings-as-errors"])]
    }
}
