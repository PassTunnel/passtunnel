import Foundation
import PassTunnelShared

/// What a client asks for in its one line (`DaemonProtocol`).
public enum DaemonCall: Equatable {
    case hello
    /// The bytes of the `request` member exactly as sent, for `HelperCore.decodeRequest`.
    case perform(Data)

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case malformed
        case unknownOperation(String)
        case missingRequest

        public var description: String {
            switch self {
            case .malformed: return "Malformed message: not a JSON object with an “op”."
            case .unknownOperation(let op): return "Unknown operation “\(op)”."
            case .missingRequest: return "Malformed message: “perform” without a “request”."
            }
        }
    }

    /// Parses one line (without its newline). Every top-level key may appear once; other keys are
    /// ignored. The request is handed on as the client wrote it, so its checks (size, protocol version,
    /// type, fields) are `HelperCore.decodeRequest`'s, unchanged.
    public static func parse(_ line: Data) throws -> DaemonCall {
        guard (try? JSONSerialization.jsonObject(with: line)) is [String: Any] else { throw Failure.malformed }
        let bytes = [UInt8](line)
        guard let members = JSONMembers.of(bytes), let op = members["op"].flatMap({ JSONMembers.string(bytes[$0]) }) else {
            throw Failure.malformed
        }
        switch op {
        case "hello":
            return .hello
        case "perform":
            guard let request = members["request"] else { throw Failure.missingRequest }
            return .perform(Data(bytes[request]))
        default:
            throw Failure.unknownOperation(HelperCore.printable(op))
        }
    }
}

/// The top-level members of a JSON object as byte ranges of their values. The text has been checked
/// to be JSON already; this only finds where each value starts and ends (strings with their escapes,
/// nested objects and arrays). Nil when it is not an object or repeats a key.
enum JSONMembers {
    static let quote = UInt8(ascii: "\""), backslash = UInt8(ascii: "\\"), colon = UInt8(ascii: ":")
    static let comma = UInt8(ascii: ","), openBrace = UInt8(ascii: "{"), closeBrace = UInt8(ascii: "}")
    static let openBracket = UInt8(ascii: "["), closeBracket = UInt8(ascii: "]")
    static let whitespace: Set<UInt8> = [0x20, 0x09, 0x0A, 0x0D]

    static func of(_ bytes: [UInt8]) -> [String: Range<Int>]? {
        var scanner = Scanner(bytes: bytes)
        return scanner.members()
    }

    /// A JSON string literal (quotes included) as a Swift string.
    static func string(_ literal: ArraySlice<UInt8>) -> String? {
        try? JSONDecoder().decode(String.self, from: Data(literal))
    }

    struct Scanner {
        let bytes: [UInt8]
        var i = 0

        init(bytes: [UInt8]) { self.bytes = bytes }

        mutating func skipWhitespace() {
            while i < bytes.count, whitespace.contains(bytes[i]) { i += 1 }
        }

        mutating func members() -> [String: Range<Int>]? {
            skipWhitespace()
            guard i < bytes.count, bytes[i] == openBrace else { return nil }
            i += 1
            var result: [String: Range<Int>] = [:]
            skipWhitespace()
            if i < bytes.count, bytes[i] == closeBrace {
                i += 1
            } else {
                while true {
                    skipWhitespace()
                    guard let keyRange = stringLiteral(), let key = string(bytes[keyRange]) else { return nil }
                    skipWhitespace()
                    guard i < bytes.count, bytes[i] == colon else { return nil }
                    i += 1
                    guard let value = value(), result.updateValue(value, forKey: key) == nil else { return nil }
                    skipWhitespace()
                    guard i < bytes.count else { return nil }
                    if bytes[i] == comma { i += 1; continue }
                    guard bytes[i] == closeBrace else { return nil }
                    i += 1
                    break
                }
            }
            skipWhitespace()
            return i == bytes.count ? result : nil
        }

        /// At an opening quote: the literal's range, quotes included.
        mutating func stringLiteral() -> Range<Int>? {
            guard i < bytes.count, bytes[i] == quote else { return nil }
            let start = i
            i += 1
            while i < bytes.count {
                if bytes[i] == backslash {
                    i += 2
                } else if bytes[i] == quote {
                    i += 1
                    return start..<i
                } else {
                    i += 1
                }
            }
            return nil
        }

        mutating func value() -> Range<Int>? {
            skipWhitespace()
            guard i < bytes.count else { return nil }
            let start = i
            switch bytes[i] {
            case quote:
                return stringLiteral()
            case openBrace, openBracket:
                var depth = 0
                while i < bytes.count {
                    switch bytes[i] {
                    case quote:
                        guard stringLiteral() != nil else { return nil }
                        continue
                    case openBrace, openBracket:
                        depth += 1
                    case closeBrace, closeBracket:
                        depth -= 1
                        if depth == 0 {
                            i += 1
                            return start..<i
                        }
                    default:
                        break
                    }
                    i += 1
                }
                return nil
            default:
                while i < bytes.count, bytes[i] != comma, bytes[i] != closeBrace, bytes[i] != closeBracket,
                      !whitespace.contains(bytes[i]) {
                    i += 1
                }
                return i > start ? start..<i : nil
            }
        }
    }
}

/// Reading and writing one line on a connection with a deadline, so a slow or silent client cannot
/// hold the daemon. The descriptor is non-blocking.
enum LineIO {
    enum ReadResult: Equatable {
        case line(Data)
        case tooLarge
        case timedOut
        case closed
        case failed(Int32)
    }

    /// Reads up to the first newline (not included). More than `limit` bytes before it: `tooLarge`.
    /// End of file after some data counts as the end of the line.
    static func readLine(_ fd: Int32, limit: Int, deadline: Date) -> ReadResult {
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            switch wait(fd, for: Int16(POLLIN), until: deadline) {
            case .ready: break
            case .timedOut: return .timedOut
            case .failed(let e): return .failed(e)
            }
            let n = read(fd, &buffer, min(buffer.count, limit + 1 - data.count))
            if n < 0 {
                if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
                return .failed(errno)
            }
            if n == 0 { return data.isEmpty ? .closed : .line(data) }
            if let newline = buffer[0..<n].firstIndex(of: 0x0A) {
                data.append(contentsOf: buffer[0..<newline])
                return data.count > limit ? .tooLarge : .line(data)
            }
            data.append(contentsOf: buffer[0..<n])
            if data.count > limit { return .tooLarge }
        }
    }

    /// Writes all of `data`; false when the deadline passed or the peer went away.
    @discardableResult
    static func write(_ fd: Int32, _ data: Data, deadline: Date) -> Bool {
        let bytes = [UInt8](data)
        var offset = 0
        while offset < bytes.count {
            switch wait(fd, for: Int16(POLLOUT), until: deadline) {
            case .ready: break
            case .timedOut, .failed: return false
            }
            let n = bytes.withUnsafeBytes { Sys.send(fd, $0.baseAddress! + offset, bytes.count - offset) }
            if n < 0 {
                if errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK { continue }
                return false
            }
            offset += n
        }
        return true
    }

    enum Wait { case ready, timedOut, failed(Int32) }

    static func wait(_ fd: Int32, for events: Int16, until deadline: Date) -> Wait {
        while true {
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else { return .timedOut }
            var p = pollfd(fd: fd, events: events, revents: 0)
            let r = poll(&p, 1, Int32(min(remaining * 1000 + 1, 60_000)))
            if r < 0 {
                if errno == EINTR { continue }
                return .failed(errno)
            }
            if r > 0 { return .ready }
        }
    }
}
