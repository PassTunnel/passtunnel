import FuzzDriver
import Foundation

/// Hands control to libFuzzer, routing every generated input to `LLVMFuzzerTestOneInput`. Call it as
/// the last statement of a harness's `main`; it does not return.
public func runFuzzer(_ callback: @escaping @convention(c) (UnsafePointer<UInt8>?, Int) -> CInt) -> Never {
    var argc = CommandLine.argc
    var argv: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>? = CommandLine.unsafeArgv
    exit(LLVMFuzzerRunDriver(&argc, &argv, callback))
}

/// The input of one fuzzer iteration as `Data` (empty when libFuzzer passes a zero-length buffer).
public func fuzzData(_ data: UnsafePointer<UInt8>?, _ size: Int) -> Data {
    guard let data, size > 0 else { return Data() }
    return Data(bytes: data, count: size)
}
