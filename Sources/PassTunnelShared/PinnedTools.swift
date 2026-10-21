import Foundation

/// cdhashes of the bundled tools and their libraries, compiled into the helper by scripts/build-app.sh.
///
/// The identifier and Team ID check (`PT.toolRequirement`) accepts every build the team ever signed,
/// including an older release's openvpn. A helper built by build-app.sh also requires the exact builds
/// it was released with: their cdhashes are part of the helper's own signed code. A cdhash is the
/// 20-byte `CDHash` that `codesign -dvvv` prints, which is also what the kernel records for the running
/// process (`CodeSignature.verify(pid:)` returns it).
public enum PinnedTools {
    /// File name in `Contents/Resources/bin` → accepted cdhashes (lowercase hex, one per architecture).
    /// Empty: nothing pinned (`swift build`, tests, any build without build-app.sh).
    public static let cdhashes: [String: Set<String>] = generatedCDHashes
    /// File name in `Contents/Frameworks` → accepted cdhashes of the tools' libraries, which the helper
    /// stages with the tools (`ToolStager`). A pinned build stages exactly these and refuses any other build.
    public static let libraryCDHashes: [String: Set<String>] = generatedLibraryCDHashes

    public struct Mismatch: Error, Equatable, CustomStringConvertible {
        public let tool: String
        public let cdhash: String
        public var description: String {
            "\(tool) is not the build this PassTunnel was released with (cdhash \(cdhash)). Reinstall PassTunnel."
        }
    }

    /// The cdhashes `tool` may have; nil when nothing is pinned. A pinned build has an entry for every
    /// tool it bundles, so a tool without one gets an empty set: refused.
    public static func allowed(_ tool: String, pins: [String: Set<String>] = cdhashes) -> Set<String>? {
        pins.isEmpty ? nil : pins[tool] ?? []
    }

    /// Throws `Mismatch` unless `cdhash` is one of `allowed` (nil: anything goes).
    public static func check(_ tool: String, cdhash: String, allowed: Set<String>?) throws {
        guard let allowed else { return }
        let hash = cdhash.lowercased()
        guard allowed.contains(hash) else { throw Mismatch(tool: tool, cdhash: hash) }
    }
}

#if !PASSTUNNEL_TOOL_PINS
extension PinnedTools {
    /// Nothing pinned. build-app.sh writes the pins to PinnedTools+Generated.swift (not in the
    /// repository) and compiles with PASSTUNNEL_TOOL_PINS, which leaves this out.
    static let generatedCDHashes: [String: Set<String>] = [:]
    static let generatedLibraryCDHashes: [String: Set<String>] = [:]
}
#endif
