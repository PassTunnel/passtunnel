// swift-tools-version:5.10
import PackageDescription

// libFuzzer harnesses for the code that parses untrusted text. This package is NOT part of the
// app: `swift build` / `swift test` at the repository root never see it, and nothing here ships in
// any binary. It links the parsing libraries of the main package by path so the fuzzers exercise
// the exact sources the app and the helper run.
//
// Build and run with the open-source Swift toolchain (the Xcode toolchain has no libFuzzer runtime
// on macOS). See ../CONTRIBUTING.md, "Fuzzing".
let package = Package(
    name: "PassTunnelFuzz",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(name: "PassTunnel", path: ".."),
    ],
    targets: [
        // C shim: the one libFuzzer entry point we call ourselves, so each harness is a normal
        // executable that drives the fuzzer instead of letting libFuzzer own `main`.
        .target(name: "FuzzDriver"),
        .target(name: "FuzzSupport", dependencies: ["FuzzDriver"]),
        .executableTarget(name: "FuzzOVPNSanitizer",
                          dependencies: ["FuzzSupport", .product(name: "PassTunnelKit", package: "PassTunnel")]),
        .executableTarget(name: "FuzzFortiConfig",
                          dependencies: ["FuzzSupport", .product(name: "PassTunnelKit", package: "PassTunnel")]),
        .executableTarget(name: "FuzzManagementParser",
                          dependencies: ["FuzzSupport", .product(name: "PassTunnelCore", package: "PassTunnel")]),
        .executableTarget(name: "FuzzOTPAuthURI",
                          dependencies: ["FuzzSupport", .product(name: "PassTunnelKit", package: "PassTunnel")]),
        .executableTarget(name: "FuzzMCPDecode",
                          dependencies: ["FuzzSupport", .product(name: "PassTunnelCore", package: "PassTunnel")]),
    ]
)
