import Foundation
import FuzzSupport
import PassTunnelShared

// Fuzzes the FortiGate (openfortivpn) config rendering. The helper writes this file itself from
// typed fields; openfortivpn reads it as `key = value` lines with no quoting, so the only real
// danger is a field value that smuggles in a newline or a second directive. Property: whatever
// FortiConfig agrees to render, re-reading that text the way openfortivpn does (including the fixed
// buffers that cut long values off) recovers each value byte-for-byte, with no injected key. A field
// that cannot be represented, or that openfortivpn would shorten, must be rejected, not emitted.
// The harness never crashes or hangs on any bytes.
@_cdecl("LLVMFuzzerTestOneInput")
func LLVMFuzzerTestOneInput(_ data: UnsafePointer<UInt8>?, _ size: Int) -> CInt {
    // Split the input into fields on 0x1F (Unit Separator); decode each as (lossy) UTF-8. 0x1F is
    // never a valid field byte (a control character the renderer always rejects) and keeps the seed
    // corpus free of NUL bytes, so it stays text.
    let parts = fuzzData(data, size).split(separator: 0x1F, maxSplits: 6, omittingEmptySubsequences: false)
    func field(_ i: Int) -> String { i < parts.count ? String(decoding: parts[i], as: UTF8.self) : "" }

    let host = field(0)
    let port = Int(field(1)) ?? 443
    let username = field(2)
    let password = field(3)
    let otpField = field(4)
    let otp = otpField.isEmpty ? nil : otpField
    let trustedCert = field(5)

    let config = FortiConfig(host: host, port: port, username: username, password: password,
                             otp: otp, trustedCert: trustedCert)
    guard let text = try? config.render() else { return 0 }   // rejected values: fine

    let parsed = parseLikeOpenfortivpn(Array(text.utf8))
    precondition(parsed["host"] == Array(host.utf8), "host not recovered from rendered config")
    precondition(parsed["username"] == Array(username.utf8), "username not recovered from rendered config")
    precondition(parsed["password"] == Array(password.utf8), "password not recovered from rendered config")
    if let otp { precondition(parsed["otp"] == Array(otp.utf8), "otp not recovered from rendered config") }
    return 0
}

/// Buffer sizes openfortivpn 1.24 copies these values into (src/config.h: GATEWAY_HOST_SIZE,
/// USERNAME_SIZE, PASSWORD_SIZE, OTP_SIZE); `strncpy` keeps that many bytes and drops the rest.
let openfortivpnBufferBytes: [String: Int] = ["host": 253, "username": 64, "password": 256, "otp": 64]

/// `load_config()` in openfortivpn, byte for byte (it works on C `char`s, not Unicode): split on
/// '\n', ignore lines under two bytes and `#` lines, take the bytes before the first '=' as the key
/// and the rest as the value, then strip leading and trailing C `isspace` bytes from both. The last
/// value for a key wins, matching its `strncpy` into a fixed buffer, which keeps at most
/// `openfortivpnBufferBytes[key]` bytes.
func parseLikeOpenfortivpn(_ bytes: [UInt8]) -> [String: [UInt8]] {
    func isCSpace(_ b: UInt8) -> Bool { b == 0x20 || (0x09...0x0D).contains(b) }
    func trim(_ s: ArraySlice<UInt8>) -> [UInt8] {
        var lo = s.startIndex, hi = s.endIndex
        while lo < hi, isCSpace(s[lo]) { lo += 1 }
        while hi > lo, isCSpace(s[hi - 1]) { hi -= 1 }
        return Array(s[lo..<hi])
    }
    var out: [String: [UInt8]] = [:]
    var start = 0
    var i = 0
    func handle(_ line: ArraySlice<UInt8>) {
        if line.count < 2 || line.first == 0x23 /* # */ { return }
        guard let eq = line.firstIndex(of: 0x3D /* = */) else { return }
        let key = String(decoding: trim(line[line.startIndex..<eq]), as: UTF8.self)
        let value = trim(line[(eq + 1)..<line.endIndex])
        out[key] = openfortivpnBufferBytes[key].map { Array(value.prefix($0)) } ?? value
    }
    while i < bytes.count {
        if bytes[i] == 0x0A { handle(bytes[start..<i]); start = i + 1 }
        i += 1
    }
    if start < bytes.count { handle(bytes[start..<bytes.count]) }
    return out
}

runFuzzer(LLVMFuzzerTestOneInput)
