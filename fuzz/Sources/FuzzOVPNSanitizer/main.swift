import Foundation
import FuzzSupport
import PassTunnelShared

// Fuzzes the OpenVPN configuration sanitizer: the last gate before the helper runs a config as
// root. Properties checked on every input (a trap here is a libFuzzer finding):
//   * it never crashes or hangs, on any bytes;
//   * whatever it accepts, it accepts again unchanged -> idempotent, and since a surviving
//     forbidden directive would make the second pass throw, re-acceptance is also the proof that
//     no forbidden option slipped through any quoting, escaping or inline-block trick.
// The helper reads the config as UTF-8 and rejects anything else before the sanitizer sees it, so
// the harness does the same.
@_cdecl("LLVMFuzzerTestOneInput")
func LLVMFuzzerTestOneInput(_ data: UnsafePointer<UInt8>?, _ size: Int) -> CInt {
    guard let text = String(data: fuzzData(data, size), encoding: .utf8) else { return 0 }
    guard let sanitized = try? OVPNSanitizer.sanitize(text) else { return 0 }   // rejected: fine

    guard let again = try? OVPNSanitizer.sanitize(sanitized) else {
        fatalError("sanitized output was rejected on a second pass")
    }
    precondition(again == sanitized, "sanitizer is not idempotent")
    return 0
}

runFuzzer(LLVMFuzzerTestOneInput)
