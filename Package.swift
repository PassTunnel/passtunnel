// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "PassTunnel",
    defaultLocalization: "en",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "PassTunnel", targets: ["PassTunnel"]),
        .executable(name: "PassTunnelHelper", targets: ["PassTunnelHelper"]),
        // Parsing libraries, so the out-of-tree fuzz package (fuzz/) can link the exact
        // sources that run in the app. Not part of any shipped binary.
        .library(name: "PassTunnelShared", targets: ["PassTunnelShared"]),
        .library(name: "PassTunnelCore", targets: ["PassTunnelCore"]),
    ],
    dependencies: [
        // App updates. The `passtunnel` CLI never starts the updater.
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.0"),
    ],
    targets: [
        // Shared by the app and the privileged helper: XPC protocol, request types, config sanitizer.
        .target(name: "PassTunnelShared"),
        // Everything that is not UI: profiles, keychain, TOTP, connections, preferences.
        .target(name: "PassTunnelCore", dependencies: ["PassTunnelShared"]),
        // Root helper registered with SMAppService; starts/stops the bundled VPN tools.
        .executableTarget(name: "PassTunnelHelper", dependencies: ["PassTunnelShared"]),
        // The app (SwiftUI) and the `passtunnel` CLI are the same binary.
        .executableTarget(name: "PassTunnel",
                          dependencies: ["PassTunnelCore", "PassTunnelShared",
                                         .product(name: "Sparkle", package: "Sparkle")],
                          resources: [.process("Resources")]),
        .testTarget(name: "PassTunnelCoreTests", dependencies: ["PassTunnelCore", "PassTunnelShared"]),
    ]
)
