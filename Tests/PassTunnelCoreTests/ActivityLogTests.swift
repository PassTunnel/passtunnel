import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

/// The activity log file (`ActivityLog`) and its events (`ActivityEvent`): JSON, bounds, concurrent writers,
/// masking and wording. What `ConnectionManager` records is tested in `ConnectionManagerTests`.
final class ActivityLogTests: CoreTestCase {
    let t0 = Date(timeIntervalSince1970: 1_700_000_000)

    var dir: URL { store.dir("acme") }
    var log: ActivityLog { ActivityLog(url: store.activityURL("acme")) }

    override func setUpWithError() throws {
        try super.setUpWithError()
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    static let sending = ActivityEvent.Sending(username: "alice", password: true, code: true, codePrefix: "482",
                                               secondsLeft: 22, format: "{password}{otp}")

    /// One of every kind.
    var everyKind: [ActivityEvent.Kind] {
        [.connecting(host: "vpn.example.com", port: 1194, transport: "udp"),
         .connecting(host: "vpn.example.com", port: nil, transport: "tcp"),
         .waitingForCode(reason: .used, seconds: 12, codePrefix: "482"),
         .waitingForCode(reason: .expiring, seconds: 4, codePrefix: nil),
         .sending(Self.sending),
         .sending(.init(username: "alice", password: true, code: false)),
         .authAccepted, .connected(address: "10.8.0.6"), .linkDropped(willReconnect: true),
         .reconnecting(attempt: 2, of: 3), .unreachable(tries: 3, reason: "Connection refused"),
         .unreachable(tries: 1, reason: nil), .nextTry(at: t0.addingTimeInterval(30)),
         .rejected(reply: "AUTH_FAILED,Invalid OTP"), .rejected(reply: nil),
         .failed(kind: .hostNotFound, reason: "Name or service not known", credentialsSent: false),
         .failed(kind: .timeout, reason: nil, credentialsSent: true), .stoppedByUser, .disconnectedByUser]
    }

    // MARK: JSON

    func testEveryKindRoundTrips() throws {
        let names = Set(everyKind.map { ActivityEvent(at: t0, $0).name })
        XCTAssertEqual(names, Set(ActivityEvent.names), "every name is listed for the schema")
        for kind in everyKind {
            let event = ActivityEvent(at: t0, kind)
            let data = try ActivityLog.encoder().encode(event)
            XCTAssertFalse(data.contains(0x0A), "one line")
            XCTAssertEqual(try ActivityLog.decoder().decode(ActivityEvent.self, from: data), event)
        }
    }

    func testFlatSnakeCaseObjects() throws {
        let data = try ActivityLog.encoder().encode(ActivityEvent(at: t0, .sending(Self.sending)))
        XCTAssertEqual(String(decoding: data, as: UTF8.self),
                       #"{"at":"2023-11-14T22:13:20Z","code":true,"code_prefix":"482","event":"sending","format":"{password}{otp}","password":true,"seconds_left":22,"username":"alice"}"#)
        let connecting = try ActivityLog.encoder().encode(ActivityEvent(at: t0, .connecting(host: "vpn.example.com", port: 443, transport: "tcp")))
        XCTAssertEqual(String(decoding: connecting, as: UTF8.self),
                       #"{"at":"2023-11-14T22:13:20Z","event":"connecting","host":"vpn.example.com","port":443,"protocol":"tcp"}"#)
    }

    // MARK: file

    func testAppendsKeepTheLast500WithMode0600() throws {
        for i in 0..<(ActivityLog.maxEvents + 20) {
            try log.append(ActivityEvent(at: t0.addingTimeInterval(Double(i)), .reconnecting(attempt: i, of: 999)))
        }
        let events = log.read()
        XCTAssertEqual(events.count, ActivityLog.maxEvents)
        XCTAssertEqual(events.first?.kind, .reconnecting(attempt: 20, of: 999), "the oldest are dropped")
        XCTAssertEqual(events.last?.kind, .reconnecting(attempt: ActivityLog.maxEvents + 19, of: 999))
        XCTAssertEqual(try mode(store.activityURL("acme")), 0o600)
        let lines = try String(contentsOf: store.activityURL("acme"), encoding: .utf8).split(separator: "\n")
        XCTAssertEqual(lines.count, ActivityLog.maxEvents, "the file itself is bounded")
        let leftovers = try FileManager.default.contentsOfDirectory(atPath: dir.path).filter { $0.hasSuffix(".tmp") }
        XCTAssertEqual(leftovers, [])
    }

    func testDamagedAndUnknownLinesAreSkipped() throws {
        try log.append(ActivityEvent(at: t0, .authAccepted))
        let url = store.activityURL("acme")
        var text = try String(contentsOf: url, encoding: .utf8)
        text += "not json\n{\"at\":\"2023-11-14T22:13:20Z\",\"event\":\"from_the_future\"}\n{\"event\":\"connected\"}\n"
        text += "{\"at\":\"2023-11-14T22:13:2" + "\n" + String(repeating: "x", count: ActivityLog.maxLineBytes + 1) + "\n"
        try Data(text.utf8).write(to: url)
        try log.append(ActivityEvent(at: t0, .connected(address: "10.8.0.6")))
        XCTAssertEqual(log.read().map(\.kind), [.authAccepted, .connected(address: "10.8.0.6")])
    }

    func testNothingIsWrittenForAProfileThatIsGone() throws {
        try FileManager.default.removeItem(at: dir)
        try log.append(ActivityEvent(at: t0, .stoppedByUser))
        XCTAssertFalse(FileManager.default.fileExists(atPath: dir.path), "a deleted profile is not created again")
        XCTAssertEqual(log.read(), [])
    }

    /// The app and `passtunnel` commands append at the same time: every append holds the lock, so none is
    /// lost and every line stays whole.
    func testConcurrentWritersLoseNothing() throws {
        let url = store.activityURL("acme")
        let writers = 8, each = 40
        DispatchQueue.concurrentPerform(iterations: writers) { w in
            let own = ActivityLog(url: url)   // its own descriptors, as another process would have
            for i in 0..<each {
                try? own.append(ActivityEvent(at: t0, .reconnecting(attempt: i, of: w)))
            }
        }
        let events = ActivityLog(url: url).read()
        XCTAssertEqual(events.count, writers * each)
        for w in 0..<writers {
            let mine = events.compactMap { e -> Int? in
                if case let .reconnecting(attempt, of) = e.kind, of == w { return attempt }
                return nil
            }
            XCTAssertEqual(mine, Array(0..<each), "writer \(w): all, in order")
        }
        let lines = try String(contentsOf: url, encoding: .utf8).split(separator: "\n")
        XCTAssertEqual(lines.count, writers * each)
    }

    func testALongFileIsReadFromItsEnd() throws {
        let url = store.activityURL("acme")
        let line = try ActivityLog.encoder().encode(ActivityEvent(at: t0, .authAccepted))
        var data = Data(repeating: 0x20, count: ActivityLog.maxReadBytes)   // no line break: dropped whole
        data.append(0x0A)
        data.append(line)
        data.append(0x0A)
        try data.write(to: url)
        XCTAssertEqual(log.read().map(\.kind), [.authAccepted])
    }

    // MARK: masking

    func testCodePrefixIsAtMostThreeDigitsAndHalfTheCode() {
        XCTAssertEqual(ActivityEvent.codePrefix("482913"), "482")
        XCTAssertEqual(ActivityEvent.codePrefix("48291377"), "482")
        XCTAssertEqual(ActivityEvent.codePrefix("4829"), "48")
        XCTAssertEqual(ActivityEvent.codePrefix("48"), "4")
        XCTAssertNil(ActivityEvent.codePrefix("4"))
        XCTAssertNil(ActivityEvent.codePrefix("abc123"))
        XCTAssertEqual(ActivityEvent.codePrefix("12ab56"), "12")
        XCTAssertNil(ActivityEvent.codePrefix(nil))
    }

    func testWithoutCodeDigits() {
        let waiting = ActivityEvent(at: t0, .waitingForCode(reason: .used, seconds: 3, codePrefix: "482")).withoutCodeDigits()
        XCTAssertEqual(waiting.kind, .waitingForCode(reason: .used, seconds: 3, codePrefix: nil))
        guard case .sending(let s) = ActivityEvent(at: t0, .sending(Self.sending)).withoutCodeDigits().kind else { return XCTFail() }
        XCTAssertNil(s.codePrefix)
        XCTAssertEqual(s.secondsLeft, 22)
    }

    func testCleanTextFromOutside() {
        XCTAssertEqual(ActivityEvent.clean(" AUTH_FAILED,\u{1B}[31mno\u{07} "), "AUTH_FAILED, [31mno")
        XCTAssertEqual(ActivityEvent.clean(String(repeating: "a", count: 300)).count, 201)
    }

    // MARK: wording

    func testSentencesHideCodeDigitsUnlessAsked() {
        func say(_ kind: ActivityEvent.Kind, digits: Bool = false) -> String {
            ActivityEvent(at: t0, kind).sentence(showingCodeDigits: digits)
        }
        XCTAssertEqual(say(.connecting(host: "vpn.example.com", port: 1194, transport: "udp")), "Connecting to vpn.example.com:1194 (UDP)")
        XCTAssertEqual(say(.connecting(host: "2001:db8::1", port: 443, transport: "tcp")), "Connecting to [2001:db8::1]:443 (TCP)")
        XCTAssertEqual(say(.connecting(host: "", port: nil, transport: "udp")), "Connecting…")
        XCTAssertEqual(say(.waitingForCode(reason: .used, seconds: 9, codePrefix: "482")),
                       "Code ••• ••• was already used, waiting for the next one")
        XCTAssertEqual(say(.waitingForCode(reason: .expiring, seconds: 4, codePrefix: "482"), digits: true),
                       "Code 482 ••• has 4 s left, waiting for the next one")
        XCTAssertEqual(say(.sending(Self.sending), digits: true), "Sending alice / ••••••••+482 ••• · 22 s left")
        XCTAssertEqual(say(.sending(Self.sending)), "Sending alice / ••••••••+••• ••• · 22 s left")
        var colon = Self.sending
        colon.format = "{otp}:{password}"
        colon.secondsLeft = nil
        XCTAssertEqual(say(.sending(colon), digits: true), "Sending alice / 482 •••:••••••••")
        var separate = Self.sending
        separate.format = "separate"
        XCTAssertEqual(say(.sending(separate)), "Sending alice / ••••••••, code ••• ••• separately · 22 s left")
        XCTAssertEqual(say(.sending(.init(username: "alice", password: true, code: false))), "Sending alice / ••••••••")
        XCTAssertEqual(say(.sending(.init(username: "alice", password: false, code: false))), "Sending alice")
        XCTAssertEqual(say(.authAccepted), "Authentication accepted")
        XCTAssertEqual(say(.connected(address: "10.8.0.6")), "Connected, 10.8.0.6")
        XCTAssertEqual(say(.linkDropped(willReconnect: true)), "Link dropped, reconnecting")
        XCTAssertEqual(say(.reconnecting(attempt: 2, of: 3)), "Reconnecting, attempt 2 of 3")
        XCTAssertEqual(say(.unreachable(tries: 3, reason: nil)), "No answer after 3 tries")
        XCTAssertEqual(say(.unreachable(tries: 1, reason: "Connection refused")), "No answer (Connection refused)")
        XCTAssertEqual(say(.failed(kind: .hostNotFound, reason: "Name or service not known", credentialsSent: false)),
                       "Server name not found (Name or service not known)")
        XCTAssertEqual(say(.failed(kind: .configuration, reason: "certificate has expired", credentialsSent: false)),
                       "Configuration or certificate refused (certificate has expired)")
        XCTAssertEqual(say(.failed(kind: .setup, reason: nil, credentialsSent: true)), "Network setup failed")
        XCTAssertEqual(say(.failed(kind: .timeout, reason: nil, credentialsSent: true)), "Did not connect in time")
        XCTAssertEqual(say(.failed(kind: .failed, reason: nil, credentialsSent: false)), "Could not connect")
        XCTAssertEqual(say(.nextTry(at: t0.addingTimeInterval(30))), "Next try in 30 s")
        XCTAssertEqual(say(.rejected(reply: "AUTH_FAILED")), "Sign-in rejected: AUTH_FAILED. Stopped. Not retrying, to avoid a lockout")
        XCTAssertEqual(say(.stoppedByUser), "Stopped by you")
        XCTAssertEqual(say(.disconnectedByUser), "Disconnected by you")
        XCTAssertEqual(ActivityEvent(at: t0, .authAccepted).line(timeZone: TimeZone(identifier: "UTC")!),
                       "2023-11-14 22:13:20  Authentication accepted")
    }

    // MARK: the app's views

    func testToneByKind() {
        let tones = Dictionary(grouping: everyKind.map { ActivityEvent(at: t0, $0) }, by: \.tone).mapValues { Set($0.map(\.name)) }
        XCTAssertEqual(tones[.error], ["link_dropped", "unreachable", "rejected", "failed"])
        XCTAssertEqual(tones[.wait], ["waiting_for_code"])
        XCTAssertEqual(tones[.neutral], ["connecting", "sending", "auth_accepted", "connected", "reconnecting", "next_try",
                                         "stopped_by_user", "disconnected_by_user"])
    }

    func testClockTimeIs24HourInTheGivenZone() {
        let utc = TimeZone(identifier: "UTC")!
        XCTAssertEqual(ActivityEvent.clockTime(t0, timeZone: utc), "22:13:20")
        XCTAssertEqual(ActivityEvent.clockTime(Date(timeIntervalSince1970: 1_700_040_062), timeZone: utc), "09:21:02",
                       "zero-padded")
        XCTAssertEqual(ActivityEvent.clockTime(t0, timeZone: TimeZone(secondsFromGMT: 3 * 3600)!), "01:13:20")
    }

    func testDaysAreNamedForEventsOfEarlierDays() {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let locale = Locale(identifier: "en_US")
        let now = Date(timeIntervalSince1970: 1_700_000_000)   // Tue 2023-11-14 22:13:20 UTC
        func event(_ ago: TimeInterval) -> ActivityEvent { ActivityEvent(at: now.addingTimeInterval(-ago), .authAccepted) }
        func label(_ ago: TimeInterval) -> String { event(ago).timeLabel(now: now, calendar: calendar, locale: locale) }
        XCTAssertEqual(label(0), "22:13:20")
        XCTAssertEqual(label(22 * 3600), "00:13:20", "after midnight is still today")
        XCTAssertEqual(label(22 * 3600 + 14 * 60 + 20), "Yesterday 23:59:00")
        XCTAssertEqual(label(24 * 3600), "Yesterday 22:13:20")
        XCTAssertEqual(label(2 * 24 * 3600), "Sun, Nov 12 22:13:20")
        XCTAssertEqual(ActivityEvent.dayTitle(now, now: now, calendar: calendar, locale: locale), "Today")
        XCTAssertEqual(ActivityEvent.dayTitle(now.addingTimeInterval(-86400), now: now, calendar: calendar, locale: locale), "Yesterday")
        XCTAssertEqual(ActivityEvent.dayTitle(now.addingTimeInterval(-5 * 86400), now: now, calendar: calendar, locale: locale),
                       "Thu, Nov 9")
    }

    func testSpokenSentenceReadsHiddenValuesAsHidden() {
        func spoken(_ kind: ActivityEvent.Kind) -> String { ActivityEvent(at: t0, kind).spokenSentence(showingCodeDigits: true) }
        XCTAssertEqual(spoken(.sending(Self.sending)), "Sending alice / hidden+482 hidden · 22 s left")
        XCTAssertEqual(spoken(.sending(.init(username: "alice", password: true, code: false))), "Sending alice / hidden")
        XCTAssertEqual(spoken(.waitingForCode(reason: .used, seconds: 12, codePrefix: "482")),
                       "Code 482 hidden was already used, waiting for the next one")
        XCTAssertEqual(spoken(.connected(address: "10.8.0.6")), "Connected, 10.8.0.6")
        XCTAssertFalse(ActivityEvent(at: t0, .sending(Self.sending)).spokenSentence().contains("•"))
    }

    func testTheLastSendingAndWhenTheConnectionSignedIn() {
        let events = [ActivityEvent(at: t0, .sending(Self.sending)),
                      ActivityEvent(at: t0.addingTimeInterval(2), .connected(address: "10.8.0.6")),
                      ActivityEvent(at: t0.addingTimeInterval(60), .disconnectedByUser),
                      ActivityEvent(at: t0.addingTimeInterval(100), .sending(.init(username: "alice", password: true, code: true)))]
        XCTAssertEqual(ActivityEvent.lastSending(in: events)?.at, t0.addingTimeInterval(100))
        XCTAssertNil(ActivityEvent.lastSending(in: []))
        XCTAssertNil(ActivityEvent.lastSending(in: Array(events[1...2])))
        // Up since shortly after the second sending: that one; up since long after it, or before it: none.
        XCTAssertEqual(ActivityEvent.sentAt(connectedSince: t0.addingTimeInterval(103), in: events), t0.addingTimeInterval(100))
        XCTAssertEqual(ActivityEvent.sentAt(connectedSince: t0.addingTimeInterval(100), in: events), t0.addingTimeInterval(100))
        XCTAssertNil(ActivityEvent.sentAt(connectedSince: t0.addingTimeInterval(1000), in: events), "an earlier session's")
        XCTAssertNil(ActivityEvent.sentAt(connectedSince: t0.addingTimeInterval(50), in: events), "a later sign-in")
        XCTAssertNil(ActivityEvent.sentAt(connectedSince: t0, in: []))
    }

    // MARK: tool log

    func testSignInFactsFromTheToolLogs() {
        XCTAssertEqual(VPNLog.authFailureReply("2026-01-01 10:00:01 AUTH: Received control message: AUTH_FAILED\n"), "AUTH_FAILED")
        XCTAssertEqual(VPNLog.authFailureReply("PUSH: Received control message: 'AUTH_FAILED,Invalid OTP'"), "AUTH_FAILED,Invalid OTP")
        XCTAssertNil(VPNLog.authFailureReply("SIGTERM[soft,auth-failure] received, process exiting"))
        XCTAssertTrue(VPNLog.authAccepted("PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.8.0.1,ifconfig 10.8.0.6 255.255.255.0'"))
        XCTAssertTrue(VPNLog.authAccepted("INFO:   Authenticated."))
        XCTAssertFalse(VPNLog.authAccepted("SENT CONTROL [vpn.example.com]: 'PUSH_REQUEST' (status=1)"))
        XCTAssertFalse(VPNLog.authAccepted("INFO:   Connected to gateway."))
    }
}
