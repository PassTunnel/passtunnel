import Foundation
import FuzzSupport
import PassTunnelCore

// Fuzzes `otpauth://` URI parsing, which runs on whatever a scanned QR code or a pasted link
// contains: scheme and type handling, percent-decoding of the label and query, Base32/hex secret
// decoding and the numeric parameters. Property: it never crashes or hangs; bad input must throw.
@_cdecl("LLVMFuzzerTestOneInput")
func LLVMFuzzerTestOneInput(_ data: UnsafePointer<UInt8>?, _ size: Int) -> CInt {
    guard let uri = String(data: fuzzData(data, size), encoding: .utf8) else { return 0 }
    _ = try? OTPAuthURI(uri)
    return 0
}

runFuzzer(LLVMFuzzerTestOneInput)
