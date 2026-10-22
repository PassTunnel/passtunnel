import Foundation
import FuzzSupport
import PassTunnelCore

// Fuzzes the parser for the OpenVPN management interface `state` reply. The app and the CLI read
// this from a local socket that only the tunnel's OpenVPN writes to, but it is still untrusted text
// (comma-separated fields, a unix timestamp, free-form state names). Properties: it never crashes or
// hangs; a malformed reply must throw, not trap; a reply it accepts has a finite, plausible timestamp
// (so the connection duration computed from it cannot trap either).
@_cdecl("LLVMFuzzerTestOneInput")
func LLVMFuzzerTestOneInput(_ data: UnsafePointer<UInt8>?, _ size: Int) -> CInt {
    guard let reply = String(data: fuzzData(data, size), encoding: .utf8) else { return 0 }
    guard let state = try? ManagementSocket.parseState(reply) else { return 0 }
    precondition(ManagementState.isPlausible(state.since), "implausible timestamp accepted")
    return 0
}

runFuzzer(LLVMFuzzerTestOneInput)
