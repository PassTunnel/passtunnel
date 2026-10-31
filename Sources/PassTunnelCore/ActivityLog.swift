import Foundation
import PassTunnelKit

/// One thing that happened to a profile's connection, as `ConnectionManager` saw it: typed facts, never
/// sentences (the app and the CLI word them: `sentence(showingCodeDigits:)`) and never a password. A
/// one-time code is kept as at most its first three digits (`codePrefix`), which only the app shows; the
/// CLI and the MCP server leave them out (`withoutCodeDigits()`).
public struct ActivityEvent: Equatable, Sendable {
    public var at: Date
    public var kind: Kind

    public init(at: Date, _ kind: Kind) {
        self.at = at
        self.kind = kind
    }

    public enum Kind: Equatable, Sendable {
        /// The VPN tool is started for this server (OpenVPN: the first `remote`): "vpn.example.com",
        /// 1194, "udp" or "tcp" (FortiGate: "tcp").
        case connecting(host: String, port: Int?, transport: String)
        /// The code of the current TOTP window is not sent; the next one comes in `seconds`.
        case waitingForCode(reason: CodeWait, seconds: Int, codePrefix: String?)
        /// The credentials were handed to the VPN tool.
        case sending(Sending)
        /// The server accepted the sign-in (OpenVPN pushed the tunnel settings, openfortivpn "Authenticated").
        case authAccepted
        /// The tunnel is up with this address ("" when unknown).
        case connected(address: String)
        /// The connection ended without anyone stopping it.
        case linkDropped(willReconnect: Bool)
        /// An automatic reconnect attempt starts.
        case reconnecting(attempt: Int, of: Int)
        /// The server did not answer after this many tries; `reason` in the tool's words ("Connection refused").
        /// The sign-in was not sent.
        case unreachable(tries: Int, reason: String?)
        /// The next automatic attempt starts then.
        case nextTry(at: Date)
        /// The server refused the sign-in; `reply` is what it answered ("AUTH_FAILED,…"), when it said anything.
        case rejected(reply: String?)
        /// The attempt failed otherwise (`ConnectionFailure.Kind`: host not found, configuration, setup,
        /// timeout, failed), with the tool's words when it gave some.
        case failed(kind: ConnectionFailure.Kind, reason: String?, credentialsSent: Bool)
        /// The user stopped a connect, a wait for a code or the automatic reconnects.
        case stoppedByUser
        /// The user ended a connection that was up.
        case disconnectedByUser
    }

    /// Why a connect waits for the next TOTP window.
    public enum CodeWait: String, Codable, Sendable {
        /// The code of the current window was already sent (by this process or another).
        case used
        /// The current code has `Preferences.freshCodeSeconds` or less left.
        case expiring
    }

    /// What was sent, without the password.
    public struct Sending: Equatable, Sendable {
        public var username: String
        /// A password went with it.
        public var password: Bool
        /// A one-time code went with it.
        public var code: Bool
        /// At most the first three digits of the code (`ActivityEvent.codePrefix`).
        public var codePrefix: String?
        /// Seconds the code's TOTP window had left when it was sent ("Sent with 22 s left"); nil for a
        /// code the user typed.
        public var secondsLeft: Int?
        /// How the code went with the password: the template ("{password}{otp}"), or "separate" when it
        /// is sent on its own (OpenVPN static challenge, FortiGate code field); nil without a code.
        public var format: String?

        public init(
            username: String, password: Bool, code: Bool, codePrefix: String? = nil, secondsLeft: Int? = nil,
            format: String? = nil
        ) {
            self.username = username
            self.password = password
            self.code = code
            self.codePrefix = codePrefix
            self.secondsLeft = secondsLeft
            self.format = format
        }
    }

    /// The `event` value in JSON.
    public var name: String {
        switch kind {
        case .connecting: return "connecting"
        case .waitingForCode: return "waiting_for_code"
        case .sending: return "sending"
        case .authAccepted: return "auth_accepted"
        case .connected: return "connected"
        case .linkDropped: return "link_dropped"
        case .reconnecting: return "reconnecting"
        case .unreachable: return "unreachable"
        case .nextTry: return "next_try"
        case .rejected: return "rejected"
        case .failed: return "failed"
        case .stoppedByUser: return "stopped_by_user"
        case .disconnectedByUser: return "disconnected_by_user"
        }
    }

    /// Every `event` value, for schemas.
    public static let names = [
        "connecting", "waiting_for_code", "sending", "auth_accepted", "connected", "link_dropped",
        "reconnecting", "unreachable", "next_try", "rejected", "failed", "stopped_by_user",
        "disconnected_by_user"
    ]

    /// At most the first three digits of `code`, never more than half of it, so a short typed code is not
    /// kept whole; nil when it does not start with a digit.
    public static func codePrefix(_ code: String?) -> String? {
        guard let code else { return nil }
        let digits = code.prefix { $0.isASCII && $0.isNumber }
        let prefix = digits.prefix(min(3, code.count / 2))
        return prefix.isEmpty ? nil : String(prefix)
    }

    /// How the app colors an event: a failure red, a wait for a code amber, anything else plain. The words
    /// always say what happened too.
    public enum Tone: Sendable {
        case neutral, wait, error
    }

    public var tone: Tone {
        switch kind {
        case .waitingForCode: return .wait
        case .linkDropped, .unreachable, .rejected, .failed: return .error
        case .connecting, .sending, .authAccepted, .connected, .reconnecting, .nextTry, .stoppedByUser,
            .disconnectedByUser:
            return .neutral
        }
    }

    /// "09:41:02": the time of day in `timeZone`, 24-hour whatever the Mac's region.
    public static func clockTime(_ date: Date, timeZone: TimeZone = .current) -> String {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let c = calendar.dateComponents([.hour, .minute, .second], from: date)
        return String(format: "%02d:%02d:%02d", c.hour ?? 0, c.minute ?? 0, c.second ?? 0)
    }

    /// The day of `date` as the activity names it: "Today", "Yesterday", else a short date ("Fri, Oct 23").
    public static func dayTitle(_ date: Date, now: Date, calendar: Calendar = .current, locale: Locale = .current) -> String {
        if calendar.isDate(date, inSameDayAs: now) { return String(localized: "Today") }
        if let yesterday = calendar.date(byAdding: .day, value: -1, to: now), calendar.isDate(date, inSameDayAs: yesterday) {
            return String(localized: "Yesterday")
        }
        let formatter = DateFormatter()
        formatter.locale = locale
        formatter.calendar = calendar
        formatter.timeZone = calendar.timeZone
        formatter.setLocalizedDateFormatFromTemplate("EEEMMMd")
        return formatter.string(from: date)
    }

    /// The time of an event in a list that has no day headings: "17:09:07" for today, "Yesterday 17:09:07" or
    /// "Fri, Oct 23 17:09:07" for an earlier day, so a list never reads out of order.
    public func timeLabel(now: Date, calendar: Calendar = .current, locale: Locale = .current) -> String {
        let time = Self.clockTime(at, timeZone: calendar.timeZone)
        if calendar.isDate(at, inSameDayAs: now) { return time }
        return Self.dayTitle(at, now: now, calendar: calendar, locale: locale) + " " + time
    }

    /// The last `sending` in `events` (oldest first): when the credentials went to the VPN tool, and the
    /// code's seconds left then.
    public static func lastSending(in events: [ActivityEvent]) -> (at: Date, sending: Sending)? {
        for event in events.reversed() {
            if case .sending(let s) = event.kind { return (event.at, s) }
        }
        return nil
    }

    /// When the sign-in of a connection that is up since `since` was sent: the last `sending`, if it came
    /// shortly before the tunnel did (the connect takes seconds, a FortiGate up to two minutes). A `sending`
    /// from an earlier session, or none, gives nil.
    public static func sentAt(connectedSince since: Date, in events: [ActivityEvent]) -> Date? {
        guard let sent = lastSending(in: events)?.at else { return nil }
        let before = since.timeIntervalSince(sent)
        return before >= -5 && before <= 300 ? sent : nil
    }

    /// The event without any code digits: what the CLI and the MCP server report.
    public func withoutCodeDigits() -> ActivityEvent {
        var copy = self
        switch kind {
        case let .waitingForCode(reason, seconds, _):
            copy.kind = .waitingForCode(reason: reason, seconds: seconds, codePrefix: nil)
        case var .sending(s):
            s.codePrefix = nil
            copy.kind = .sending(s)
        default:
            break
        }
        return copy
    }

    /// Text from outside (a server's reply, a user name) as it is kept: control characters replaced by
    /// spaces (nothing in it can steer a terminal), trimmed, at most `limit` characters.
    static func clean(_ text: String, limit: Int = 200) -> String {
        let scalars = text.unicodeScalars.map { $0.properties.generalCategory == .control ? " " : Character($0) }
        let cleaned = String(scalars).trimmingCharacters(in: .whitespaces)
        return cleaned.count > limit ? String(cleaned.prefix(limit)) + "…" : cleaned
    }

    // MARK: wording

    /// The event as a sentence in the user's language: "Connecting to vpn.example.com:1194 (UDP)".
    /// `showingCodeDigits`: a code shows its first digits ("482 •••"), which only the app does; otherwise
    /// bullets ("••• •••").
    public func sentence(showingCodeDigits: Bool = false) -> String {
        func code(_ prefix: String?) -> String {
            guard showingCodeDigits, let prefix else { return "••• •••" }
            return prefix + " •••"
        }
        switch kind {
        case let .connecting(host, port, transport):
            guard !host.isEmpty else { return String(localized: "Connecting…") }
            var address = host.contains(":") ? "[\(host)]" : host
            if let port { address += ":\(port)" }
            return String(localized: "Connecting to \(address) (\(transport.uppercased()))")
        case let .waitingForCode(.used, _, prefix):
            return String(localized: "Code \(code(prefix)) was already used, waiting for the next one")
        case let .waitingForCode(.expiring, seconds, prefix):
            return String(localized: "Code \(code(prefix)) has \(seconds) s left, waiting for the next one")
        case let .sending(s):
            let password = "••••••••"  // always 8 bullets, never the password's length
            var text: String
            if s.code && s.password && s.format == "separate" {
                text = String(localized: "Sending \(s.username) / \(password), code \(code(s.codePrefix)) separately")
            } else if s.code && s.password {
                text = String(localized: "Sending \(s.username) / \(Self.masked(s, password: password, code: code(s.codePrefix)))")
            } else if s.code || s.password {
                text = String(localized: "Sending \(s.username) / \(s.code ? code(s.codePrefix) : password)")
            } else {
                text = String(localized: "Sending \(s.username)")
            }
            if let left = s.secondsLeft { text += " · " + String(localized: "\(left) s left") }
            return text
        case .authAccepted:
            return String(localized: "Authentication accepted")
        case .connected(let address):
            return address.isEmpty ? String(localized: "Connected") : String(localized: "Connected, \(address)")
        case .linkDropped(let willReconnect):
            return willReconnect ? String(localized: "Link dropped, reconnecting") : String(localized: "Link dropped")
        case let .reconnecting(attempt, of):
            return String(localized: "Reconnecting, attempt \(attempt) of \(of)")
        case let .unreachable(tries, reason):
            let text = tries > 1 ? String(localized: "No answer after \(tries) tries") : String(localized: "No answer")
            return Self.adding(reason, to: text)
        case .nextTry(let next):
            return String(localized: "Next try in \(max(0, Int(next.timeIntervalSince(at).rounded(.up)))) s")
        case .rejected(let reply):
            guard let reply, !reply.isEmpty else { return String(localized: "Sign-in rejected. Stopped. Not retrying, to avoid a lockout") }
            return String(localized: "Sign-in rejected: \(reply). Stopped. Not retrying, to avoid a lockout")
        case let .failed(kind, reason, _):
            let text: String
            switch kind {
            case .hostNotFound: text = String(localized: "Server name not found")
            case .configuration: text = String(localized: "Configuration or certificate refused")
            case .setup: text = String(localized: "Network setup failed")
            case .timeout: text = String(localized: "Did not connect in time")
            case .toolUnsupported: text = String(localized: "The VPN tool does not run on this macOS")
            case .hostScanRequired: text = String(localized: "The server requires a host scan")
            case .ssoRequired: text = String(localized: "The server requires single sign-on")
            case .authRejected, .unreachable, .cancelled, .failed: text = String(localized: "Could not connect")
            }
            return Self.adding(reason, to: text)
        case .stoppedByUser:
            return String(localized: "Stopped by you")
        case .disconnectedByUser:
            return String(localized: "Disconnected by you")
        }
    }

    /// `sentence` for VoiceOver: the bullets of a hidden password or code are read as "hidden"
    /// ("Sending alice / hidden+604 hidden").
    public func spokenSentence(showingCodeDigits: Bool = false) -> String {
        sentence(showingCodeDigits: showingCodeDigits)
            .replacingOccurrences(of: "•+(?: •+)*", with: String(localized: "hidden"), options: .regularExpression)
    }

    /// "No answer (Connection refused)": the tool's words, untranslated, after the sentence.
    private static func adding(_ reason: String?, to text: String) -> String {
        guard let reason, !reason.isEmpty else { return text }
        return text + " (" + reason + ")"
    }

    /// The password and code as the template puts them together: "••••••••+482 •••" for
    /// "{password}{otp}" (a "+" between the two when nothing else is), "••••••••:482 •••" for "{password}:{otp}".
    private static func masked(_ s: Sending, password: String, code: String) -> String {
        let parts = OTPComposer.parts(delivery: .combined, template: s.format ?? OTPTemplatePreset.append.rawValue).secret
        var out = ""
        var previous: OTPComposer.Part?
        for part in parts {
            switch part {
            case .password, .code:
                if let previous, previous != part, !previous.isText { out += "+" }
                out += part == .password ? password : code
            case .text(let text):
                out += text
            }
            previous = part
        }
        return out
    }

    /// "2026-10-25 09:41:02  Connecting to vpn.example.com:1194 (UDP)", the time in `timeZone`.
    public func line(timeZone: TimeZone = .current, showingCodeDigits: Bool = false) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = timeZone
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f.string(from: at) + "  " + sentence(showingCodeDigits: showingCodeDigits)
    }
}

private extension OTPComposer.Part {
    var isText: Bool { if case .text = self { return true }; return false }
}

// MARK: - JSON

/// One flat object per event: `{"at": "2026-10-25T09:41:02Z", "event": "connecting", "host": …}`. An unknown
/// `event` (from a newer version) does not decode, so readers skip it like a damaged line.
extension ActivityEvent: Codable {
    enum Key: String, CodingKey {
        case at, event, host, port, transport = "protocol", reason, seconds, codePrefix = "code_prefix", username,
            password, code, secondsLeft = "seconds_left", format, address, willReconnect = "will_reconnect",
            attempt, of, tries, nextAt = "next_at", reply, failure, credentialsSent = "credentials_sent"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: Key.self)
        at = try c.decode(Date.self, forKey: .at)
        switch try c.decode(String.self, forKey: .event) {
        case "connecting":
            kind = .connecting(
                host: try c.decode(String.self, forKey: .host), port: try c.decodeIfPresent(Int.self, forKey: .port),
                transport: try c.decode(String.self, forKey: .transport))
        case "waiting_for_code":
            kind = .waitingForCode(
                reason: try c.decode(CodeWait.self, forKey: .reason), seconds: try c.decode(Int.self, forKey: .seconds),
                codePrefix: try c.decodeIfPresent(String.self, forKey: .codePrefix))
        case "sending":
            kind = .sending(
                Sending(
                    username: try c.decode(String.self, forKey: .username),
                    password: try c.decode(Bool.self, forKey: .password),
                    code: try c.decode(Bool.self, forKey: .code),
                    codePrefix: try c.decodeIfPresent(String.self, forKey: .codePrefix),
                    secondsLeft: try c.decodeIfPresent(Int.self, forKey: .secondsLeft),
                    format: try c.decodeIfPresent(String.self, forKey: .format)))
        case "auth_accepted": kind = .authAccepted
        case "connected": kind = .connected(address: try c.decode(String.self, forKey: .address))
        case "link_dropped": kind = .linkDropped(willReconnect: try c.decode(Bool.self, forKey: .willReconnect))
        case "reconnecting":
            kind = .reconnecting(attempt: try c.decode(Int.self, forKey: .attempt), of: try c.decode(Int.self, forKey: .of))
        case "unreachable":
            kind = .unreachable(tries: try c.decode(Int.self, forKey: .tries), reason: try c.decodeIfPresent(String.self, forKey: .reason))
        case "next_try": kind = .nextTry(at: try c.decode(Date.self, forKey: .nextAt))
        case "rejected": kind = .rejected(reply: try c.decodeIfPresent(String.self, forKey: .reply))
        case "failed":
            kind = .failed(
                kind: try c.decode(ConnectionFailure.Kind.self, forKey: .failure),
                reason: try c.decodeIfPresent(String.self, forKey: .reason),
                credentialsSent: try c.decode(Bool.self, forKey: .credentialsSent))
        case "stopped_by_user": kind = .stoppedByUser
        case "disconnected_by_user": kind = .disconnectedByUser
        case let other:
            throw DecodingError.dataCorruptedError(forKey: .event, in: c, debugDescription: "unknown event \(other)")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: Key.self)
        try c.encode(at, forKey: .at)
        try c.encode(name, forKey: .event)
        switch kind {
        case let .connecting(host, port, transport):
            try c.encode(host, forKey: .host)
            try c.encodeIfPresent(port, forKey: .port)
            try c.encode(transport, forKey: .transport)
        case let .waitingForCode(reason, seconds, codePrefix):
            try c.encode(reason, forKey: .reason)
            try c.encode(seconds, forKey: .seconds)
            try c.encodeIfPresent(codePrefix, forKey: .codePrefix)
        case let .sending(s):
            try c.encode(s.username, forKey: .username)
            try c.encode(s.password, forKey: .password)
            try c.encode(s.code, forKey: .code)
            try c.encodeIfPresent(s.codePrefix, forKey: .codePrefix)
            try c.encodeIfPresent(s.secondsLeft, forKey: .secondsLeft)
            try c.encodeIfPresent(s.format, forKey: .format)
        case .connected(let address):
            try c.encode(address, forKey: .address)
        case .linkDropped(let willReconnect):
            try c.encode(willReconnect, forKey: .willReconnect)
        case let .reconnecting(attempt, of):
            try c.encode(attempt, forKey: .attempt)
            try c.encode(of, forKey: .of)
        case let .unreachable(tries, reason):
            try c.encode(tries, forKey: .tries)
            try c.encodeIfPresent(reason, forKey: .reason)
        case .nextTry(let next):
            try c.encode(next, forKey: .nextAt)
        case .rejected(let reply):
            try c.encodeIfPresent(reply, forKey: .reply)
        case let .failed(kind, reason, credentialsSent):
            try c.encode(kind, forKey: .failure)
            try c.encodeIfPresent(reason, forKey: .reason)
            try c.encode(credentialsSent, forKey: .credentialsSent)
        case .authAccepted, .stoppedByUser, .disconnectedByUser:
            break
        }
    }
}

/// An event `ConnectionManager` recorded, with the profile it is about (`ConnectionManager.activity`).
public struct ActivityRecord: Equatable, Sendable {
    public var profileID: String
    public var event: ActivityEvent

    public init(profileID: String, event: ActivityEvent) {
        self.profileID = profileID
        self.event = event
    }
}

// MARK: - File

/// A profile's activity: `profiles/<id>/activity.jsonl`, one `ActivityEvent` per line, oldest first, the
/// last `maxEvents`, mode 0600. The app and `passtunnel` commands write it at the same time, so each append
/// holds `.activity.lock` (flock) while it reads the file and replaces it (temp file + rename) with the
/// lines kept plus the new one: a reader never sees a partial line, and lines it cannot read are skipped.
public struct ActivityLog {
    public static let fileName = "activity.jsonl"
    static let lockName = ".activity.lock"
    public static let maxEvents = 500
    /// The most read of the file; a longer one (written by something else) is read from its end.
    static let maxReadBytes = 1024 * 1024
    /// Longer lines are not ours and are dropped.
    static let maxLineBytes = 4096

    public let url: URL

    public init(url: URL) {
        self.url = url
    }

    /// Appends `event`, keeping the last `maxEvents`. Does nothing when the profile directory is gone (a
    /// profile deleted meanwhile is not created again).
    public func append(_ event: ActivityEvent) throws {
        let dir = url.deletingLastPathComponent()
        guard FileManager.default.fileExists(atPath: dir.path) else { return }
        let line = try Self.encoder().encode(event)
        try withLock(in: dir) {
            var lines = Self.lines(readTail())
            lines.append(line)
            var data = Data()
            for kept in lines.suffix(Self.maxEvents) {
                data.append(kept)
                data.append(0x0A)
            }
            try FileIO.writeAtomically(data, to: url, mode: 0o600)
        }
    }

    /// The events, oldest first (at most `maxEvents`); lines that do not decode are skipped.
    public func read() -> [ActivityEvent] {
        let decoder = Self.decoder()
        return Self.lines(readTail()).compactMap { try? decoder.decode(ActivityEvent.self, from: $0) }.suffix(Self.maxEvents)
    }

    static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return e
    }

    static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }

    /// Non-empty lines no longer than `maxLineBytes`.
    private static func lines(_ data: Data) -> [Data] {
        data.split(separator: 0x0A).filter { !$0.isEmpty && $0.count <= maxLineBytes }.map { Data($0) }
    }

    /// The file, or its last `maxReadBytes` from the first whole line on; empty when it cannot be read.
    private func readTail() -> Data {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return Data() }
        defer { try? handle.close() }
        let size = (try? handle.seekToEnd()) ?? 0
        let start = size > UInt64(Self.maxReadBytes) ? size - UInt64(Self.maxReadBytes) : 0
        try? handle.seek(toOffset: start)
        let data = (try? handle.readToEnd()) ?? Data()
        guard start > 0 else { return data }
        return data.firstIndex(of: 0x0A).map { Data(data[data.index(after: $0)...]) } ?? Data()
    }

    /// Serialises writers across processes; the lock file is never replaced, unlike the log.
    private func withLock<T>(in dir: URL, _ body: () throws -> T) throws -> T {
        let path = dir.appendingPathComponent(Self.lockName).path
        let fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw PTError.fileError(path) }
        defer { close(fd) }
        while flock(fd, LOCK_EX) != 0 {
            guard errno == EINTR else { throw PTError.fileError(path) }
        }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }
}
