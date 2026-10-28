import Foundation
import FuzzDriver

/// The harness's `LLVMFuzzerTestOneInput`, set once by `runFuzzer` before libFuzzer starts. libFuzzer
/// takes a C function pointer, which cannot capture it, so `runOne` reads it from here.
nonisolated(unsafe) private var harness: (@convention(c) (UnsafePointer<UInt8>?, Int) -> CInt)?

/// Hands control to libFuzzer, routing every generated input to `LLVMFuzzerTestOneInput`, each in its
/// own autorelease pool. Call it as the last statement of a harness's `main`; it does not return.
public func runFuzzer(_ callback: @escaping @convention(c) (UnsafePointer<UInt8>?, Int) -> CInt) -> Never {
    harness = callback
    var argc = CommandLine.argc
    var argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>? = CommandLine.unsafeArgv
    exit(LLVMFuzzerRunDriver(&argc, &argv, runOne))
}

/// Runs one input through the harness inside its own autorelease pool. Foundation autoreleases
/// objects (strings, errors, dictionaries) in the parsing it does for the harness, and nothing in
/// libFuzzer's loop drains them, so without a pool per input they pile up for the whole run until it
/// hits the RSS limit. There is no autorelease pool outside Apple platforms.
private func runOne(_ data: UnsafePointer<UInt8>?, _ size: Int) -> CInt {
    #if canImport(ObjectiveC)
    return autoreleasepool { harness!(data, size) }
    #else
    return harness!(data, size)
    #endif
}

/// The input of one fuzzer iteration as `Data` (empty when libFuzzer passes a zero-length buffer).
public func fuzzData(_ data: UnsafePointer<UInt8>?, _ size: Int) -> Data {
    guard let data, size > 0 else { return Data() }
    return Data(bytes: data, count: size)
}

/// How openconnect 9.21 reads its config file (`next_option`, main.c 1199–1300), byte for byte, for the
/// harnesses that check what PassTunnel renders for it. `getline` splits on LF only; one trailing CR is
/// removed; the line is a C string (it ends at a NUL); leading blanks and CRs are skipped; empty and `#`
/// lines are comments. The first option in `table` order whose name the line starts with, followed by its
/// end, a blank or `=`, is the one; then blanks and (for an option with a value) one `=` are skipped and the
/// value is the rest of the line. Returns nil where openconnect stops with an error (an unknown option, a
/// value missing or one given to an option that takes none).
public func readLikeOpenConnect(_ bytes: [UInt8], table: [(name: String, takesValue: Bool)]) -> [(option: String, value: [UInt8]?)]? {
    var lines = bytes.split(separator: 0x0A, omittingEmptySubsequences: false)
    if bytes.last == 0x0A { lines.removeLast() }  // getline returns no line after the last LF
    var out: [(option: String, value: [UInt8]?)] = []
    for raw in lines {
        var line = Array(raw)
        if line.last == 0x0D { line.removeLast() }
        if let nul = line.firstIndex(of: 0) { line = Array(line[..<nul]) }
        var i = 0
        while i < line.count, line[i] == 0x20 || line[i] == 0x09 || line[i] == 0x0D { i += 1 }
        if i == line.count || line[i] == UInt8(ascii: "#") { continue }
        let rest = Array(line[i...])
        guard
            let option = table.first(where: { o in
                let name = Array(o.name.utf8)
                guard rest.starts(with: name) else { return false }
                let next = rest.count > name.count ? rest[name.count] : 0
                return next == 0 || next == 0x20 || next == 0x09 || next == UInt8(ascii: "=")
            })
        else { return nil }
        var j = option.name.utf8.count
        var ateEquals = false
        while j < rest.count {
            if rest[j] == 0x20 || rest[j] == 0x09 {
                j += 1
            } else if rest[j] == UInt8(ascii: "="), option.takesValue, !ateEquals {
                ateEquals = true
                j += 1
            } else {
                break
            }
        }
        let value = Array(rest[j...])
        if option.takesValue {
            guard !value.isEmpty else { return nil }
            out.append((option.name, value))
        } else {
            guard value.isEmpty else { return nil }
            out.append((option.name, nil))
        }
    }
    return out
}
