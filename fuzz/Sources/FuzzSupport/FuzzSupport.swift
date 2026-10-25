import FuzzDriver
import Foundation

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
