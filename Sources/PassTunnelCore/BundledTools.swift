import Foundation
import PassTunnelKit
import PassTunnelShared

/// `diagnose` on the Mac: one VPN tool of the app bundle (`Contents/Resources/bin`), run with `--version`.
public struct ToolCheck: Codable, Equatable, Sendable {
    /// "openvpn", "openfortivpn", "openconnect".
    public var name: String
    /// Nothing wrong with it: it started and printed its version, or it was not run because this macOS
    /// is older than the tool needs (`note`), which only matters for the VPN type that uses it.
    public var ok: Bool
    /// The first line it printed ("OpenVPN 2.7.8 aarch64-apple-darwin25.6.0 …", "1.24.1").
    public var version: String?
    /// Why it did not: dyld did not let it start on this macOS ("This VPN tool does not run on this
    /// version of macOS (Symbol not found: _strchrnul). …"), it is missing, it did not answer in time.
    public var problem: String?
    /// Why it was not run: "Not run: it needs macOS 15.4 or later." (openconnect on an older macOS,
    /// where dyld would stop it; Cisco AnyConnect is not offered there).
    public var note: String?

    public init(name: String, ok: Bool, version: String? = nil, problem: String? = nil, note: String? = nil) {
        self.name = name
        self.ok = ok
        self.version = version
        self.problem = problem
        self.note = note
    }
}

/// Runs the VPN tools of the app bundle with `--version`, as the user and not through the helper: what
/// tells that a tool starts on this macOS. dyld stops a tool at launch when it or one of its libraries
/// imports a symbol this macOS lacks (scripts/check-tool-symbols.sh keeps that from shipping); the
/// helper's signature checks pass before that, so only running the tool shows it. `--version` reads no
/// configuration and contacts nothing; the tool gets an empty environment and no input. A tool that needs
/// a later macOS than this one (`HelperCore.Tool.minimumMacOS`: openconnect, 15.4) is not run at all.
public enum BundledTools {
    /// The longest a tool may take to print its version.
    static let timeout: TimeInterval = 10
    /// The longest `version` kept.
    static let maxVersionLength = 200

    /// The app's tools (`HelperCore.Tool`); nil outside an app bundle (`swift build`) and on Linux,
    /// whose tools are the distribution's.
    public static func check(app: AppInfo) async -> [ToolCheck]? {
        #if os(macOS)
        guard app.appPath.hasSuffix(".app") else { return nil }
        let bin = app.appPath + "/Contents/Resources/bin"
        return await check(
            directory: bin, tools: HelperCore.Tool.allCases.map(\.rawValue), macOS: ProcessInfo.processInfo.operatingSystemVersion)
        #else
        return nil
        #endif
    }

    /// Each of `tools` in `directory`, at the same time, off the main actor; on `macOS`, a tool that needs a
    /// later one is reported with a note instead of being run.
    static func check(
        directory: String, tools: [String], macOS: OperatingSystemVersion = ProcessInfo.processInfo.operatingSystemVersion,
        timeout: TimeInterval = timeout
    ) async -> [ToolCheck] {
        await withTaskGroup(of: (Int, ToolCheck).self) { group in
            for (index, name) in tools.enumerated() {
                if let tool = HelperCore.Tool(rawValue: name), !tool.runs(on: macOS), let minimum = tool.minimumMacOS {
                    let note = String(localized: "Not run: it needs macOS \(versionText(minimum)) or later.")
                    group.addTask { (index, ToolCheck(name: name, ok: true, note: note)) }
                    continue
                }
                group.addTask { (index, run(directory + "/" + name, name: name, timeout: timeout)) }
            }
            var checks: [(Int, ToolCheck)] = []
            for await check in group { checks.append(check) }
            return checks.sorted { $0.0 < $1.0 }.map(\.1)
        }
    }

    /// "15.4", "15.4.1".
    static func versionText(_ version: OperatingSystemVersion) -> String {
        "\(version.majorVersion).\(version.minorVersion)" + (version.patchVersion == 0 ? "" : ".\(version.patchVersion)")
    }

    static func run(_ path: String, name: String, timeout: TimeInterval) -> ToolCheck {
        guard FileManager.default.isExecutableFile(atPath: path) else {
            return ToolCheck(name: name, ok: false, problem: String(localized: "It is missing from the app. Reinstall PassTunnel."))
        }
        let result: ToolOutput
        do {
            result = try SystemToolRunner().run(path, ["--version"], environment: [:], input: Data(), timeout: timeout)
        } catch is ToolTimeout {
            return ToolCheck(
                name: name, ok: false, problem: String(localized: "It did not answer within \(Int(timeout)) seconds."))
        } catch {
            return ToolCheck(name: name, ok: false, problem: String(localized: "It could not be started."))
        }
        let text = String(decoding: result.output + result.errorOutput, as: UTF8.self)
        // dyld aborts the tool (SIGABRT, 128 + 6) after its lines.
        if result.status > 128, let reason = VPNLog.toolLoadFailure(String(decoding: result.errorOutput, as: UTF8.self)) {
            return ToolCheck(name: name, ok: false, problem: PTError.toolUnsupported(reason: reason, log: "").localizedDescription)
        }
        let first = text.split(whereSeparator: \.isNewline).lazy
            .map { $0.trimmingCharacters(in: .whitespaces) }.first { !$0.isEmpty }
        // A signal (128 + its number), or nothing printed: it did not get as far as its version. Some
        // openvpn builds exit with 1 after printing it.
        guard result.status <= 128, let first else {
            return ToolCheck(
                name: name, ok: false, problem: String(localized: "It stopped without printing its version (exit status \(Int(result.status)))."))
        }
        return ToolCheck(name: name, ok: true, version: String(first.prefix(maxVersionLength)))
    }
}
