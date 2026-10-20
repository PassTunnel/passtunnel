// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "PassTunnel",
    defaultLocalization: "en",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "PassTunnel", targets: ["PassTunnel"]),
        .executable(name: "PassTunnelHelper", targets: ["PassTunnelHelper"]),
    ],
    targets: [
        // Shared by the app and the privileged helper: XPC protocol, request types, config sanitizer.
        .target(name: "PassTunnelShared"),
        // Everything that is not UI: profiles, keychain, TOTP, connections, preferences.
        .target(name: "PassTunnelCore", dependencies: ["PassTunnelShared"]),
        // Root helper registered with SMAppService; starts/stops the bundled VPN tools.
        .executableTarget(name: "PassTunnelHelper", dependencies: ["PassTunnelShared"]),
        // The app (SwiftUI) and the `passtunnel` CLI are the same binary.
        .executableTarget(name: "PassTunnel", dependencies: ["PassTunnelCore", "PassTunnelShared"],
                          resources: [.process("Resources")]),
        .testTarget(name: "PassTunnelCoreTests", dependencies: ["PassTunnelCore", "PassTunnelShared"]),
    ]
)
