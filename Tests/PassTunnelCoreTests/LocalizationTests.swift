import Foundation
import XCTest

@testable import PassTunnelCore

/// Checks `Sources/PassTunnel/Resources/Localizable.xcstrings`: every key has a Turkish translation
/// with the same placeholders, and every literal string the sources localize is in the catalog
/// (SwiftPM builds do not sync the catalog the way Xcode does, so new strings must be added by hand).
final class LocalizationTests: XCTestCase {
    static let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    static let catalogURL = root.appendingPathComponent("Sources/PassTunnel/Resources/Localizable.xcstrings")

    struct Catalog {
        var sourceLanguage: String
        /// key → language → all values (one, or one per plural/device variation).
        var values: [String: [String: [String]]]
        var states: [String: [String: [String]]]
    }

    static func loadCatalog() throws -> Catalog {
        let data = try Data(contentsOf: catalogURL)
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let strings = try XCTUnwrap(json["strings"] as? [String: [String: Any]])
        var values: [String: [String: [String]]] = [:]
        var states: [String: [String: [String]]] = [:]
        for (key, entry) in strings {
            let localizations = entry["localizations"] as? [String: Any] ?? [:]
            for (lang, loc) in localizations {
                var units: [[String: Any]] = []
                collectUnits(loc, into: &units)
                values[key, default: [:]][lang] = units.compactMap { $0["value"] as? String }
                states[key, default: [:]][lang] = units.compactMap { $0["state"] as? String }
            }
            values[key, default: [:]] = values[key] ?? [:]
        }
        return Catalog(sourceLanguage: json["sourceLanguage"] as? String ?? "", values: values, states: states)
    }

    /// Finds every `stringUnit` below a localization (plain, or nested in variations / substitutions).
    private static func collectUnits(_ node: Any, into units: inout [[String: Any]]) {
        guard let dict = node as? [String: Any] else { return }
        if let unit = dict["stringUnit"] as? [String: Any] { units.append(unit) }
        for (key, value) in dict where key != "stringUnit" { collectUnits(value, into: &units) }
    }

    // MARK: catalog

    func testEveryKeyHasATurkishTranslation() throws {
        let catalog = try Self.loadCatalog()
        XCTAssertEqual(catalog.sourceLanguage, "en")
        XCTAssertGreaterThan(catalog.values.count, 400)
        var untranslated: [String] = []
        for (key, langs) in catalog.values {
            let tr = langs["tr"] ?? []
            let states = catalog.states[key]?["tr"] ?? []
            if tr.isEmpty || tr.contains(where: { $0.trimmingCharacters(in: .whitespaces).isEmpty })
                || states.contains(where: { $0 != "translated" })
            {
                untranslated.append(key)
            }
        }
        XCTAssertEqual(untranslated.sorted(), [], "keys without a Turkish translation")
    }

    func testTranslationsKeepThePlaceholders() throws {
        let catalog = try Self.loadCatalog()
        for (key, langs) in catalog.values {
            let expected = Self.placeholders(key)
            for (lang, values) in langs {
                for value in values {
                    XCTAssertEqual(Self.placeholders(value), expected, "\(lang): “\(value)” for “\(key)”")
                }
            }
        }
    }

    /// Format specifiers by argument position, e.g. "%2$lld then %1$@" → [(1, "@"), (2, "lld")].
    static func placeholders(_ s: String) -> [String] {
        let regex = try! NSRegularExpression(pattern: #"%(?:(\d+)\$)?(@|lld|ld|llu|lu|d|lf|f)"#)
        let ns = s as NSString
        var index = 0
        return regex.matches(in: s, range: NSRange(location: 0, length: ns.length)).map { m in
            index += 1
            let position = m.range(at: 1).location == NSNotFound ? index : Int(ns.substring(with: m.range(at: 1)))!
            return "\(position):\(ns.substring(with: m.range(at: 2)))"
        }.sorted()
    }

    // MARK: sources

    func testLocalizedLiteralsInTheSourcesAreInTheCatalog() throws {
        let catalog = try Self.loadCatalog()
        let known = Set(catalog.values.keys.map(Self.normalizedKey))
        let literals = try Self.localizedLiterals()
        XCTAssertGreaterThan(literals.count, 300, "the source scan found too few strings")
        let missing = literals.filter { !known.contains(Self.normalizedLiteral($0.text)) }
            .map { "\($0.file):\($0.line): \($0.text)" }
        XCTAssertEqual(missing, [], "strings missing from Localizable.xcstrings")
    }

    struct Literal { var file: String; var line: Int; var text: String }

    /// Literal arguments of `String(localized:)` and of the SwiftUI initializers that take a
    /// `LocalizedStringKey` (raw source text, interpolations included).
    static func localizedLiterals() throws -> [Literal] {
        let prefixes = [
            "String(localized: ", "Text(", "Button(", "Toggle(", "Label(", "Section(", ".help(", "TextField(",
            "SecureField(", "Picker(", "LabeledContent(", "DisclosureGroup(", "Stepper(", "EditorHint(",
            ".navigationTitle(", "Menu(", "CommandMenu("
        ]
        var result: [Literal] = []
        let dirs = ["Sources/PassTunnel", "Sources/PassTunnelCLI", "Sources/PassTunnelCore", "Sources/PassTunnelKit"]
        for dir in dirs {
            let base = root.appendingPathComponent(dir)
            let files =
                FileManager.default.enumerator(at: base, includingPropertiesForKeys: nil)?
                .compactMap { $0 as? URL }.filter { $0.pathExtension == "swift" } ?? []
            for file in files {
                let source = Array(try String(contentsOf: file, encoding: .utf8))
                var i = 0
                var line = 1
                while i < source.count {
                    if source[i] == "\n" { line += 1 }
                    if let prefix = prefixes.first(where: { matches(source, at: i, $0) }) {
                        let start = i + prefix.count
                        let isWordStart =
                            i == 0 || !(source[i - 1].isLetter || source[i - 1].isNumber)
                            || prefix.hasPrefix(".")
                        if isWordStart, start < source.count, source[start] == "\"",
                            !matches(source, at: start, "\"\"\""),
                            let (text, end) = readLiteral(source, from: start)
                        {
                            result.append(Literal(file: file.lastPathComponent, line: line, text: text))
                            line += source[start..<end].filter { $0 == "\n" }.count
                            i = end
                            continue
                        }
                    }
                    i += 1
                }
            }
        }
        return result
    }

    private static func matches(_ s: [Character], at i: Int, _ prefix: String) -> Bool {
        var j = i
        for c in prefix {
            guard j < s.count, s[j] == c else { return false }
            j += 1
        }
        return true
    }

    /// Reads a one-line string literal starting at its opening quote. Interpolations are kept as
    /// `\(…)` (nested parentheses and strings included). Returns the raw text and the index after it.
    private static func readLiteral(_ s: [Character], from start: Int) -> (String, Int)? {
        var i = start + 1
        var text = ""
        while i < s.count {
            let c = s[i]
            if c == "\n" { return nil }
            if c == "\"" { return (text, i + 1) }
            if c == "\\", i + 1 < s.count {
                let next = s[i + 1]
                if next == "(" {
                    var depth = 0
                    var j = i + 1
                    var inString = false
                    while j < s.count {
                        let d = s[j]
                        if inString {
                            if d == "\\" { j += 2; continue }
                            if d == "\"" { inString = false }
                        } else if d == "\"" {
                            inString = true
                        } else if d == "(" {
                            depth += 1
                        } else if d == ")" {
                            depth -= 1
                            if depth == 0 { break }
                        }
                        j += 1
                    }
                    text += "\u{1}"
                    i = j + 1
                    continue
                }
                switch next {
                case "n": text += "\n"
                case "t": text += "\t"
                case "\"": text += "\""
                case "\\": text += "\\"
                case "u":
                    if let close = s[(i + 2)...].firstIndex(of: "}"),
                        let scalar = UInt32(String(s[(i + 3)..<close]), radix: 16).flatMap(Unicode.Scalar.init)
                    {
                        text.unicodeScalars.append(scalar)
                        i = close + 1
                        continue
                    }
                default: text.append(next)
                }
                i += 2
                continue
            }
            text.append(c)
            i += 1
        }
        return nil
    }

    /// Catalog key with its format specifiers replaced by a marker.
    static func normalizedKey(_ key: String) -> String {
        let regex = try! NSRegularExpression(pattern: #"%(?:\d+\$)?(@|lld|ld|llu|lu|d|lf|f)"#)
        let replaced = regex.stringByReplacingMatches(
            in: key, range: NSRange(location: 0, length: (key as NSString).length),
            withTemplate: "\u{1}")
        return replaced.replacingOccurrences(of: "%%", with: "%")
    }

    /// Source literal (interpolations already replaced by the marker).
    static func normalizedLiteral(_ text: String) -> String { text }

    func testSourceScannerReadsInterpolationsAndEscapes() {
        let source = Array(#"x String(localized: "Delete “\(p.name)”?\n") y"#)
        let start = source.firstIndex(of: "\"")!
        let literal = Self.readLiteral(source, from: start)
        XCTAssertEqual(literal?.0, "Delete “\u{1}”?\n")
        XCTAssertEqual(Self.normalizedKey("Delete “%@”?\n"), literal?.0)
        XCTAssertEqual(Self.placeholders("%2$lld of %1$@"), ["1:@", "2:lld"])
    }
}
