import Foundation
import XCTest

/// `scripts/release.env` names the GitHub repository and the Homebrew tap; every place that spells
/// them out (docs, the app's fallback link) must agree with it.
final class ProjectLinksTests: XCTestCase {
    static let root = LocalizationTests.root

    static func releaseEnv() throws -> [String: String] {
        let text = try String(contentsOf: root.appendingPathComponent("scripts/release.env"), encoding: .utf8)
        var values: [String: String] = [:]
        for line in text.split(separator: "\n") where !line.hasPrefix("#") {
            let parts = line.split(separator: "=", maxSplits: 1).map(String.init)
            if parts.count == 2 { values[parts[0]] = parts[1] }
        }
        return values
    }

    /// Text files that may mention the repository.
    static func files() throws -> [URL] {
        var out: [URL] = []
        for name in ["README.md", "SECURITY.md", "THIRD_PARTY_NOTICES.md", "Resources/Info.plist"] {
            out.append(root.appendingPathComponent(name))
        }
        for dir in ["docs", "scripts", "Sources", ".github"] {
            let base = root.appendingPathComponent(dir)
            guard let walker = FileManager.default.enumerator(at: base, includingPropertiesForKeys: nil) else { continue }
            for case let url as URL in walker
            where ["md", "swift", "sh", "template", "plist", "env"].contains(url.pathExtension) {
                out.append(url)
            }
        }
        return out
    }

    func testRepositoryAndTapMatchReleaseEnv() throws {
        let env = try Self.releaseEnv()
        let repo = try XCTUnwrap(env["GITHUB_REPO"])
        let tapRepo = try XCTUnwrap(env["TAP_REPO"])
        let tapOwner = try XCTUnwrap(tapRepo.split(separator: "/").first)
        let tapName = "\(tapOwner)/\(tapRepo.split(separator: "/")[1].replacingOccurrences(of: "homebrew-", with: ""))"

        let repoPattern = try NSRegularExpression(pattern: #"github\.com/([A-Za-z0-9_.-]+/(?:passtunnel|homebrew-tap))\b"#)
        let tapPattern = try NSRegularExpression(pattern: #"\b([A-Za-z0-9_.-]+/tap)/passtunnel\b|brew trust ([A-Za-z0-9_.-]+/tap)\b"#)
        var problems: [String] = []
        var seen = 0
        for url in try Self.files() {
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            let range = NSRange(text.startIndex..., in: text)
            let name = url.path.replacingOccurrences(of: Self.root.path + "/", with: "")
            for m in repoPattern.matches(in: text, range: range) {
                let found = String(text[Range(m.range(at: 1), in: text)!])
                seen += 1
                let expected = found.hasSuffix("/homebrew-tap") ? tapRepo : repo
                if found != expected { problems.append("\(name): github.com/\(found), expected \(expected)") }
            }
            for m in tapPattern.matches(in: text, range: range) {
                let group = m.range(at: 1).location != NSNotFound ? 1 : 2
                let found = String(text[Range(m.range(at: group), in: text)!])
                if found != tapName { problems.append("\(name): \(found), expected \(tapName)") }
            }
        }
        XCTAssertGreaterThan(seen, 3)
        XCTAssertEqual(problems, [])
    }

    func testAppFallbackRepositoryMatchesReleaseEnv() throws {
        let repo = try XCTUnwrap(try Self.releaseEnv()["GITHUB_REPO"])
        let source = try String(contentsOf: Self.root.appendingPathComponent("Sources/PassTunnel/App/Settings/SettingsView.swift"),
                                encoding: .utf8)
        XCTAssertTrue(source.contains(#"?? "\#(repo)""#), "AppInfo.repository fallback is not \(repo)")
    }

    func testInfoPlistTakesTheRepositoryFromBuildApp() throws {
        let plist = try String(contentsOf: Self.root.appendingPathComponent("Resources/Info.plist"), encoding: .utf8)
        XCTAssertTrue(plist.contains("https://github.com/__GITHUB_REPO__/releases/latest/download/appcast.xml"))
        XCTAssertTrue(plist.contains("<string>__GITHUB_REPO__</string>"))
    }
}
