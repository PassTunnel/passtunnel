// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "PassTunnel",
    defaultLocalization: "en",
    // iOS only for PassTunnelKit (and PassTunnelVPNConfig, which it uses); everything else is macOS.
    // Linux builds those two and their tests only (end of this file).
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [
        .executable(name: "PassTunnel", targets: ["PassTunnel"]),
        .executable(name: "PassTunnelHelper", targets: ["PassTunnelHelper"]),
        // Parsing libraries, so the out-of-tree fuzz package (fuzz/) can link the exact
        // sources that run in the app. Not part of any shipped binary.
        .library(name: "PassTunnelShared", targets: ["PassTunnelShared"]),
        .library(name: "PassTunnelCore", targets: ["PassTunnelCore"]),
        // The portable logic (macOS 13, iOS 17), for the iPhone app and the fuzzers.
        .library(name: "PassTunnelKit", targets: ["PassTunnelKit", "PassTunnelVPNConfig"]),
    ],
    // Declared on every platform, so one Package.resolved (and Dependabot, which runs on Linux) covers them all.
    dependencies: [
        // App updates. The `passtunnel` CLI never starts the updater.
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.0"),
        // CryptoKit's API for PassTunnelKit on Linux; Apple platforms use CryptoKit and never build it.
        .package(url: "https://github.com/apple/swift-crypto", exact: "5.0.3"),
    ],
    targets: [
        // The OpenVPN config sanitizer and the openfortivpn config renderer: the only portable code the
        // privileged helper runs, kept apart so the helper links nothing else from PassTunnelKit.
        .target(name: "PassTunnelVPNConfig"),
        // Portable logic, Foundation, CryptoKit and Security only (on Linux swift-crypto's Crypto, no
        // Security): model, errors, TOTP, otpauth links, code composition, OpenVPN analyzer and inliner,
        // share files, slugs, profile fields and merging, secret envelope.
        .target(name: "PassTunnelKit",
                dependencies: ["PassTunnelVPNConfig",
                               .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux]))]),
        // Shared by the app and the privileged helper: XPC protocol, request types, tool launching.
        .target(name: "PassTunnelShared", dependencies: ["PassTunnelVPNConfig"]),
        // Everything else that is not UI: profile store, keychain, connections, preferences, CLI, MCP.
        .target(name: "PassTunnelCore", dependencies: ["PassTunnelKit", "PassTunnelVPNConfig", "PassTunnelShared"]),
        // Root helper registered with SMAppService; starts/stops the bundled VPN tools.
        .executableTarget(name: "PassTunnelHelper", dependencies: ["PassTunnelShared"]),
        // The app (SwiftUI) and the `passtunnel` CLI are the same binary.
        .executableTarget(name: "PassTunnel",
                          dependencies: ["PassTunnelCore", "PassTunnelKit", "PassTunnelVPNConfig", "PassTunnelShared",
                                         .product(name: "Sparkle", package: "Sparkle")],
                          resources: [.process("Resources")]),
        .testTarget(name: "PassTunnelCoreTests",
                    dependencies: ["PassTunnelCore", "PassTunnelKit", "PassTunnelVPNConfig", "PassTunnelShared"]),
        // The golden cases in fixtures/ (also read by the Android port), against PassTunnelKit alone.
        .testTarget(name: "PassTunnelKitTests", dependencies: ["PassTunnelKit", "PassTunnelVPNConfig"]),
    ]
)

#if os(Linux)
// Linux builds only the portable code and its tests (the Linux jobs in .github/workflows/ci.yml), none of
// the macOS targets. The dependencies stay as declared above; no target uses Sparkle here.
let linuxTargets: Set = ["PassTunnelVPNConfig", "PassTunnelKit", "PassTunnelKitTests"]
package.targets.removeAll { !linuxTargets.contains($0.name) }
package.products.removeAll { $0.name != "PassTunnelKit" }
#endif
