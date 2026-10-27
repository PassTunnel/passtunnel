import Foundation

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto  // swift-crypto: the same API, outside Apple platforms
#endif

/// RFC 6238 time-based one-time passwords.
public enum TOTP {
    public static func code(secret: Data, params: TOTPParams, at date: Date = Date()) -> String {
        let period = max(1, params.period)
        let digits = min(8, max(6, params.digits))
        var big = counter(params: TOTPParams(period: period), at: date).bigEndian
        let message = Data(bytes: &big, count: 8)
        let key = SymmetricKey(data: secret)

        let mac: [UInt8]
        switch params.algorithm {
        case .sha1: mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256: mac = Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512: mac = Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }
        let offset = Int(mac[mac.count - 1] & 0x0f)
        let binary =
            (UInt32(mac[offset] & 0x7f) << 24) | (UInt32(mac[offset + 1]) << 16)
            | (UInt32(mac[offset + 2]) << 8) | UInt32(mac[offset + 3])
        var modulo: UInt32 = 1
        for _ in 0..<digits { modulo *= 10 }
        let value = String(binary % modulo)
        return String(repeating: "0", count: digits - value.count) + value
    }

    /// RFC 6238 time step of `date` (0 before 1970; saturates instead of trapping on absurd dates).
    public static func counter(params: TOTPParams, at date: Date = Date()) -> UInt64 {
        let steps = (date.timeIntervalSince1970 / Double(max(1, params.period))).rounded(.down)
        guard steps.isFinite, steps > 0 else { return 0 }
        return steps >= Double(UInt64.max) ? UInt64.max : UInt64(steps)
    }

    /// Seconds left in the current time window (1...period).
    public static func remaining(params: TOTPParams, at date: Date = Date()) -> Int {
        let period = max(1, params.period)
        let t = date.timeIntervalSince1970.rounded(.down)
        guard t.isFinite else { return period }
        var elapsed = t.truncatingRemainder(dividingBy: Double(period))
        if elapsed < 0 { elapsed += Double(period) }  // before 1970
        return period - Int(elapsed)
    }

    /// Decodes a secret given as Base32 (any case, spaces/dashes/padding ignored) or hex
    /// (`0x` prefix, or a string that is valid hex but not Base32).
    public static func decodeSecret(_ s: String) throws -> Data {
        var clean = s.filter { !$0.isWhitespace && $0 != "-" }
        if clean.lowercased().hasPrefix("0x") {
            clean.removeFirst(2)
            guard let data = hex(clean) else { throw PTError.invalidSecret }
            return data
        }
        while clean.hasSuffix("=") { clean.removeLast() }
        guard !clean.isEmpty else { throw PTError.invalidSecret }
        if let data = base32(clean) { return data }
        if let data = hex(clean) { return data }
        throw PTError.invalidSecret
    }

    /// RFC 4648 Base32 without padding (the form authenticator apps show).
    public static func base32Encode(_ data: Data) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var out = ""
        var buffer: UInt32 = 0
        var bits = 0
        for byte in data {
            buffer = (buffer << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                out.append(alphabet[Int((buffer >> UInt32(bits)) & 0x1f)])
            }
        }
        if bits > 0 { out.append(alphabet[Int((buffer << UInt32(5 - bits)) & 0x1f)]) }
        return out
    }

    static func base32(_ s: String) -> Data? {
        var out = Data()
        var buffer: UInt32 = 0
        var bits = 0
        for ch in s.uppercased().unicodeScalars {
            let v: UInt32
            switch ch {
            case "A"..."Z": v = ch.value - 65
            case "2"..."7": v = ch.value - 50 + 26
            default: return nil
            }
            buffer = (buffer << 5) | v
            bits += 5
            if bits >= 8 {
                bits -= 8
                out.append(UInt8((buffer >> UInt32(bits)) & 0xff))
            }
        }
        return out.isEmpty ? nil : out
    }

    static func hex(_ s: String) -> Data? {
        let chars = Array(s.utf8)
        guard !chars.isEmpty, chars.count % 2 == 0 else { return nil }
        var out = Data(capacity: chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = nibble(chars[i]), let lo = nibble(chars[i + 1]) else { return nil }
            out.append(hi << 4 | lo)
            i += 2
        }
        return out
    }

    private static func nibble(_ c: UInt8) -> UInt8? {
        switch c {
        case 48...57: return c - 48
        case 65...70: return c - 55
        case 97...102: return c - 87
        default: return nil
        }
    }
}
