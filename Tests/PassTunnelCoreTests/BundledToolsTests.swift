import Foundation
import PassTunnelShared
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit

/// `diagnose` running the app's VPN tools with `--version` (`BundledTools`), with stand-in scripts in a
/// temporary directory: never the tools of an installed app.
final class BundledToolsTests: XCTestCase {
    var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("bundled-tools-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    /// A stand-in tool. The checks below give it more than `BundledTools.timeout`: the first start of a
    /// new executable can take a few seconds while macOS scans it.
    private func tool(_ name: String, _ body: String) throws {
        let url = dir.appendingPathComponent(name)
        try Data("#!/bin/sh\n\(body)\n".utf8).write(to: url)
        XCTAssertEqual(chmod(url.path, 0o755), 0)
    }

    func testToolsThatStartReportTheirVersion() async throws {
        // openvpn prints its version and, in some builds, exits with 1; it gets no environment.
        try tool(
            "openvpn",
            """
            [ "$1" = --version ] || exit 2
            [ -z "$HOME" ] || { echo "HOME=$HOME"; exit 0; }
            echo "OpenVPN 2.7.8 aarch64-apple-darwin25.6.0 [SSL (OpenSSL)]"
            echo "library versions: OpenSSL 4.0.3, LZO 2.10"
            exit 1
            """)
        try tool("openfortivpn", "echo '  '; echo 1.24.1")
        let checks = await BundledTools.check(directory: dir.path, tools: ["openvpn", "openfortivpn"], timeout: 20)
        XCTAssertEqual(
            checks,
            [
                ToolCheck(name: "openvpn", ok: true, version: "OpenVPN 2.7.8 aarch64-apple-darwin25.6.0 [SSL (OpenSSL)]"),
                ToolCheck(name: "openfortivpn", ok: true, version: "1.24.1")
            ])
    }

    /// dyld stopping the tool (SIGABRT, its lines on standard error) is told as "does not run on this macOS".
    /// The Mac only (dyld; Linux runs no bundled tools).
    func testAToolDyldStopsIsReported() async throws {
        #if os(macOS)
        try tool(
            "openvpn",
            """
            echo 'dyld[4242]: Symbol not found: _strchrnul' >&2
            echo '  Referenced from: <3C3A9F0E-1D6B-3C2E-9E4A-0B6E1C9A7F21> /x/libidn2.0.dylib (built for macOS 26.0 which is newer than running OS)' >&2
            kill -ABRT $$
            """)
        let checks = await BundledTools.check(directory: dir.path, tools: ["openvpn"], timeout: 20)
        XCTAssertEqual(
            checks,
            [
                ToolCheck(
                    name: "openvpn", ok: false,
                    problem: "This VPN tool does not run on this version of macOS (Symbol not found: _strchrnul). Check for a PassTunnel update.")
            ])
        #else
        throw XCTSkip("dyld is the Mac's")
        #endif
    }

    /// openconnect needs macOS 15.4 (scripts/check-tool-symbols.sh, TOOL_MINIMUMS): below it, it is not
    /// run, and reported with a note rather than as a failure; from 15.4 on it is run like the others.
    func testOpenconnectIsNotRunBelowMacOS154() async throws {
        let marker = dir.appendingPathComponent("ran").path
        try tool("openconnect", "touch '\(marker)'; echo 'OpenConnect version v9.21'")
        try tool("openvpn", "echo 'OpenVPN 2.7.8'")
        func macOS(_ major: Int, _ minor: Int, _ patch: Int = 0) -> OperatingSystemVersion {
            OperatingSystemVersion(majorVersion: major, minorVersion: minor, patchVersion: patch)
        }
        for old in [macOS(13, 0), macOS(14, 7, 6), macOS(15, 3, 2)] {
            let checks = await BundledTools.check(directory: dir.path, tools: ["openvpn", "openconnect"], macOS: old, timeout: 20)
            XCTAssertEqual(
                checks,
                [
                    ToolCheck(name: "openvpn", ok: true, version: "OpenVPN 2.7.8"),
                    ToolCheck(name: "openconnect", ok: true, note: "Not run: it needs macOS 15.4 or later.")
                ], "\(old)")
            XCTAssertFalse(FileManager.default.fileExists(atPath: marker), "not started on \(old)")
        }
        for new in [macOS(15, 4), macOS(15, 7, 9), macOS(26, 0)] {
            let checks = await BundledTools.check(directory: dir.path, tools: ["openconnect"], macOS: new, timeout: 20)
            XCTAssertEqual(checks, [ToolCheck(name: "openconnect", ok: true, version: "OpenConnect version v9.21")], "\(new)")
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker))
    }

    func testToolMinimums() {
        XCTAssertEqual(HelperCore.Tool.allCases, [.openvpn, .openfortivpn, .openconnect])
        XCTAssertNil(HelperCore.Tool.openvpn.minimumMacOS)
        XCTAssertNil(HelperCore.Tool.openfortivpn.minimumMacOS)
        let minimum = HelperCore.Tool.openconnect.minimumMacOS
        XCTAssertEqual(minimum.map(BundledTools.versionText), "15.4")
        XCTAssertEqual(BundledTools.versionText(OperatingSystemVersion(majorVersion: 15, minorVersion: 4, patchVersion: 1)), "15.4.1")
        let v = { (a: Int, b: Int, c: Int) in OperatingSystemVersion(majorVersion: a, minorVersion: b, patchVersion: c) }
        XCTAssertFalse(HelperCore.Tool.openconnect.runs(on: v(15, 3, 9)))
        XCTAssertFalse(HelperCore.Tool.openconnect.runs(on: v(14, 9, 0)))
        XCTAssertTrue(HelperCore.Tool.openconnect.runs(on: v(15, 4, 0)))
        XCTAssertTrue(HelperCore.Tool.openconnect.runs(on: v(16, 0, 0)))
        XCTAssertTrue(HelperCore.Tool.openvpn.runs(on: v(13, 0, 0)))
        XCTAssertEqual(HelperCore.Tool.openconnect.signingIdentifier, "com.furkanprlk.passtunnel.openconnect")
    }

    /// TOOL_MINIMUMS in scripts/check-tool-symbols.sh, which holds the bundled files to these versions,
    /// says the same as `HelperCore.Tool.minimumMacOS`.
    func testToolMinimumsMatchTheSymbolCheck() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let script = try String(contentsOf: root.appendingPathComponent("scripts/check-tool-symbols.sh"), encoding: .utf8)
        let line = try XCTUnwrap(script.split(separator: "\n").first { $0.hasPrefix("TOOL_MINIMUMS=(") })
        let entries = line.dropFirst("TOOL_MINIMUMS=(".count).prefix { $0 != ")" }.split(separator: " ").map(String.init)
        let expected = HelperCore.Tool.allCases.compactMap { tool in
            tool.minimumMacOS.map { "\(tool.rawValue)=\(BundledTools.versionText($0))" }
        }
        XCTAssertEqual(entries, expected)
    }

    func testMissingAndSilentTools() async throws {
        try tool("crashes", "kill -KILL $$")
        let checks = await BundledTools.check(directory: dir.path, tools: ["missing", "crashes"], timeout: 20)
        XCTAssertEqual(
            checks,
            [
                ToolCheck(name: "missing", ok: false, problem: "It is missing from the app. Reinstall PassTunnel."),
                ToolCheck(name: "crashes", ok: false, problem: "It stopped without printing its version (exit status 137).")
            ])
    }

    func testAHangingToolIsStopped() async throws {
        try tool("hangs", "sleep 30")
        let started = Date()
        let checks = await BundledTools.check(directory: dir.path, tools: ["hangs"], timeout: 1)
        XCTAssertLessThan(Date().timeIntervalSince(started), 10, "stopped")
        XCTAssertEqual(checks, [ToolCheck(name: "hangs", ok: false, problem: "It did not answer within 1 seconds.")])
    }

    /// Only an app bundle has tools to check; a `swift build` binary has none.
    func testOnlyAnAppBundleIsChecked() async {
        let none = await BundledTools.check(app: AppInfo(version: "dev", build: nil, appPath: "/usr/local/bin/passtunnel"))
        XCTAssertNil(none)
        #if os(macOS)
        // An app bundle without tools: each one is reported missing, nothing is run.
        let app = dir.appendingPathComponent("Test.app").path
        let checks = await BundledTools.check(app: AppInfo(version: "1.0", build: nil, appPath: app))
        XCTAssertEqual(checks?.map(\.name), ["openvpn", "openfortivpn", "openconnect"])
        // openconnect is reported with a note, not as missing, on a macOS it does not run on.
        let openconnectRuns = HelperCore.Tool.openconnect.runs(on: ProcessInfo.processInfo.operatingSystemVersion)
        XCTAssertEqual(checks?.map(\.ok), [false, false, !openconnectRuns])
        #endif
    }

    func testJSONShape() throws {
        let json = try String(
            decoding: AutomationJSON.encoder(pretty: false).encode(ToolCheck(name: "openvpn", ok: true, version: "OpenVPN 2.7.8")),
            as: UTF8.self)
        XCTAssertEqual(json, #"{"name":"openvpn","ok":true,"version":"OpenVPN 2.7.8"}"#)
        let skipped = try String(
            decoding: AutomationJSON.encoder(pretty: false).encode(
                ToolCheck(name: "openconnect", ok: true, note: "Not run: it needs macOS 15.4 or later.")),
            as: UTF8.self)
        XCTAssertEqual(skipped, #"{"name":"openconnect","note":"Not run: it needs macOS 15.4 or later.","ok":true}"#)
    }
}
