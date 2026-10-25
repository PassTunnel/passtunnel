import Foundation

/// How far this device's clock is from a time source: the FortiGate gateway's HTTP `Date` (checked after
/// a rejected sign-in) or a time server (SNTP, only on request). One-time codes are worked out from the
/// clock, so a clock that is off makes every code wrong (`isWrong`). Measured by `ServerClock` (Core);
/// in JSON `offset_seconds`, `source`, `server`, `checked_at` (docs/CLI-JSON.md).
public struct ClockOffset: Codable, Equatable, Sendable {
    public enum Source: String, Codable, CaseIterable, Sendable {
        /// The FortiGate gateway's HTTP `Date` header (whole seconds).
        case gateway
        /// A time server asked with SNTP.
        case timeServer = "time_server"
    }

    /// The source's time minus this device's, in whole seconds: positive when this device's clock is
    /// behind, negative when it is ahead.
    public var offsetSeconds: Int
    public var source: Source
    /// The host that was asked ("vpn.example.com", "time.apple.com").
    public var server: String?
    /// When it was measured, by this device's clock.
    public var checkedAt: Date

    public init(offsetSeconds: Int, source: Source, server: String? = nil, checkedAt: Date) {
        self.offsetSeconds = offsetSeconds
        self.source = source
        self.server = server
        self.checkedAt = checkedAt
    }

    /// `offset` (seconds, `offset(serverTime:…)`) rounded to whole seconds.
    public init(offset: TimeInterval, source: Source, server: String? = nil, checkedAt: Date) {
        self.init(offsetSeconds: Self.wholeSeconds(offset), source: source, server: server, checkedAt: checkedAt)
    }

    /// Off by this many seconds or more counts as wrong: half of the usual 30-second code period, so for
    /// at least half of every period the code this device makes is not the one the server expects.
    public static let warnSeconds = 15

    /// The clock is off far enough to make one-time codes fail (`warnSeconds`).
    public var isWrong: Bool { offsetSeconds.magnitude >= UInt(Self.warnSeconds) }

    /// This device's clock is behind the source.
    public var isBehind: Bool { offsetSeconds > 0 }

    /// The source's time minus this device's, from a time the source reported between `sent` and
    /// `received` (this device's clock): it is compared with the middle of that interval. `resolution`:
    /// how coarse the source's time is (1 for an HTTP `Date`, which is cut to whole seconds, so its
    /// middle is half a second later).
    public static func offset(serverTime: Date, resolution: TimeInterval = 0, sent: Date, received: Date) -> TimeInterval {
        let middle = sent.timeIntervalSince1970 + received.timeIntervalSince(sent) / 2
        return serverTime.timeIntervalSince1970 + resolution / 2 - middle
    }

    /// Rounded to whole seconds; never traps (a value that is not finite counts as 0, a huge one is
    /// capped at about 31 700 years).
    static func wholeSeconds(_ seconds: TimeInterval) -> Int {
        guard seconds.isFinite else { return 0 }
        let limit = 1e12
        return Int(min(max(seconds, -limit), limit).rounded())
    }

    // MARK: HTTP Date

    /// The `Date` of an HTTP response head (status line and header fields, as received): nil when the
    /// text is not an HTTP/1.x response, has no `Date`, or has two that disagree.
    public static func dateHeader(inResponse head: String) -> Date? {
        let lines = head.split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\n" || $0 == "\r\n" })
            .map { $0.hasSuffix("\r") ? $0.dropLast() : $0 }
        guard let status = lines.first, isStatusLine(status) else { return nil }
        var found: Date?
        for line in lines.dropFirst() {
            if line.isEmpty { break }   // the end of the head
            guard let colon = line.firstIndex(of: ":") else { continue }
            guard line[..<colon].lowercased() == "date" else { continue }
            guard let date = httpDate(String(line[line.index(after: colon)...])) else { return nil }
            if let found, found != date { return nil }
            found = date
        }
        return found
    }

    /// "HTTP/1.1 302 Found": HTTP/1.0 or 1.1 and a three-digit status.
    private static func isStatusLine(_ line: Substring) -> Bool {
        let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2, parts[0] == "HTTP/1.1" || parts[0] == "HTTP/1.0" else { return false }
        return parts[1].count == 3 && parts[1].allSatisfy { $0.isASCII && $0.isNumber }
    }

    /// An HTTP-date (RFC 9110 §5.6.7): the IMF-fixdate servers send ("Sun, 06 Nov 1994 08:49:37 GMT")
    /// and the two obsolete forms recipients must still read: RFC 850 ("Sunday, 06-Nov-94 08:49:37 GMT")
    /// and asctime ("Sun Nov  6 08:49:37 1994"). Surrounding spaces and tabs are allowed; anything else
    /// that does not fit (a time zone other than GMT, a day the month does not have) is refused.
    public static func httpDate(_ text: String) -> Date? {
        let s = text.trimmingCharacters(in: CharacterSet(charactersIn: " \t"))
        guard !s.isEmpty, s.unicodeScalars.allSatisfy({ (0x20...0x7E).contains($0.value) }) else { return nil }
        let fields = s.split(separator: " ", omittingEmptySubsequences: false)
        if fields.count == 6, fields[5] == "GMT", fields[0].count == 4, fields[0].hasSuffix(","),
           shortDays.contains(String(fields[0].dropLast())) {
            // IMF-fixdate
            guard let day = number(fields[1], digits: 2...2), let month = month(fields[2]),
                  let year = number(fields[3], digits: 4...4) else { return nil }
            return date(year: year, month: month, day: day, time: fields[4])
        }
        if fields.count == 4, fields[3] == "GMT", fields[0].hasSuffix(","), longDays.contains(String(fields[0].dropLast())) {
            // RFC 850: two-digit years 70–99 are 1970–1999, 00–69 are 2000–2069.
            let parts = fields[1].split(separator: "-", omittingEmptySubsequences: false)
            guard parts.count == 3, let day = number(parts[0], digits: 2...2), let month = month(parts[1]),
                  let yy = number(parts[2], digits: 2...2) else { return nil }
            return date(year: yy >= 70 ? 1900 + yy : 2000 + yy, month: month, day: day, time: fields[2])
        }
        // asctime: the day is padded with a space ("Nov  6"), so there are 5 or 6 fields.
        let words = fields.filter { !$0.isEmpty }
        if words.count == 5, shortDays.contains(String(words[0])), s.count == 24 {
            guard let month = month(words[1]), let day = number(words[2], digits: 1...2),
                  let year = number(words[4], digits: 4...4) else { return nil }
            return date(year: year, month: month, day: day, time: words[3])
        }
        return nil
    }

    private static let shortDays: Set = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    private static let longDays: Set = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    private static let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

    private static func month(_ s: Substring) -> Int? {
        months.firstIndex(of: String(s)).map { $0 + 1 }
    }

    /// ASCII digits only, with a digit count in `digits`.
    private static func number(_ s: Substring, digits: ClosedRange<Int>) -> Int? {
        guard digits.contains(s.count), s.allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        return Int(s)
    }

    /// The UTC date of a calendar day and an "hh:mm:ss" time (second 60: a leap second).
    private static func date(year: Int, month: Int, day: Int, time: Substring) -> Date? {
        let hms = time.split(separator: ":", omittingEmptySubsequences: false)
        guard (1900...9999).contains(year), (1...12).contains(month), hms.count == 3,
              let h = number(hms[0], digits: 2...2), let m = number(hms[1], digits: 2...2),
              let sec = number(hms[2], digits: 2...2), h < 24, m < 60, sec <= 60,
              (1...daysIn(month, of: year)).contains(day) else { return nil }
        let days = daysFromCivil(year: year, month: month, day: day)
        return Date(timeIntervalSince1970: TimeInterval(days * 86_400 + h * 3600 + m * 60 + sec))
    }

    private static func daysIn(_ month: Int, of year: Int) -> Int {
        switch month {
        case 2: return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) ? 29 : 28
        case 4, 6, 9, 11: return 30
        default: return 31
        }
    }

    /// Days from 1970-01-01 to a day of the proleptic Gregorian calendar (H. Hinnant's `days_from_civil`).
    static func daysFromCivil(year: Int, month: Int, day: Int) -> Int {
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yearOfEra = y - era * 400
        let dayOfYear = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1
        let dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
        return era * 146_097 + dayOfEra - 719_468
    }
}
