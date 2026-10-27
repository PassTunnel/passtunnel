import Foundation
import FuzzSupport
import PassTunnelKit
import PassTunnelVPNConfig

// Fuzzes the import review: which lines the helper's sanitizer refuses are skipped (turned into
// comments) and which block the file. Properties checked on every input (a trap is a finding):
//   * it never crashes or hangs, on any bytes;
//   * only the skipped lines change, each into one comment line OpenVPN reads whole, so no skip can
//     add, split or merge a line;
//   * with no blocking line, the helper's unchanged sanitizer accepts the rewritten text and the
//     configuration an import stores (credential block removed): nothing refused is ever stored, and
//     reading that text again skips nothing;
//   * with a blocking line, nothing is stored;
//   * a text the sanitizer already accepts is left as it is;
//   * the line texts shown in the app and the terminal hold no control characters.
// Files a configuration refers to are not read here (no folder): `OVPNInliner` has its own tests.
@_cdecl("LLVMFuzzerTestOneInput")
func LLVMFuzzerTestOneInput(_ data: UnsafePointer<UInt8>?, _ size: Int) -> CInt {
    guard let text = String(data: fuzzData(data, size), encoding: .utf8) else { return 0 }
    let result = OVPNSkipRules.apply(text)

    let before = lines(text), after = lines(result.text)
    precondition(before.count == after.count, "the number of lines changed")
    let skipped = Set(result.skipped.map(\.line))
    for (i, bytes) in after.enumerated() {
        if skipped.contains(i + 1) {
            let line = String(decoding: bytes, as: UTF8.self)
            precondition(line.hasPrefix(OVPNSkipRules.marker), "a skipped line is not a PassTunnel comment")
            precondition(bytes.count <= OVPNSanitizer.maxLineBytes, "a comment is longer than OpenVPN reads")
            precondition(OVPNSanitizer.tokens(of: line) == [], "a comment has tokens")
        } else {
            precondition(bytes.elementsEqual(before[i]), "a line that was not skipped changed")
        }
    }
    for shown in result.skipped.map(\.text) + result.blocking.map(\.text) {
        precondition(
            !shown.unicodeScalars.contains { $0.properties.generalCategory == .control },
            "a shown line has a control character")
    }

    let accepted = (try? OVPNSanitizer.sanitize(text)) != nil
    if accepted {
        precondition(
            result.text.utf8.elementsEqual(text.utf8) && result.skipped.isEmpty && result.blocking.isEmpty,
            "an accepted text was changed")
    }
    guard let report = try? OVPNImportReport.make(text, baseDir: nil) else {
        fatalError("the report threw without a folder to read")
    }
    if result.blocking.isEmpty {
        precondition((try? OVPNSanitizer.sanitize(result.text)) != nil, "the rewritten text is refused")
        guard let stored = report.config else { fatalError("nothing to store without a blocking line") }
        precondition((try? OVPNSanitizer.sanitize(stored)) != nil, "the stored configuration is refused")
        let again = OVPNSkipRules.apply(result.text)
        precondition(
            again.text.utf8.elementsEqual(result.text.utf8) && again.skipped.isEmpty && again.blocking.isEmpty,
            "the rewritten text is not stable")
    } else {
        precondition(!accepted, "an accepted text has blocking lines")
        precondition(report.config == nil, "a configuration with a blocking line would be stored")
    }
    return 0
}

/// The bytes of each line as the sanitizer numbers them: split at every "\n" byte.
func lines(_ text: String) -> [ArraySlice<UInt8>] {
    Array(text.utf8).split(separator: 0x0A, omittingEmptySubsequences: false)
}

runFuzzer(LLVMFuzzerTestOneInput)
