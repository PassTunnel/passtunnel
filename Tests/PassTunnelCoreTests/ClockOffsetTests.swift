import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

/// `ClockOffset` (PassTunnelKit): HTTP dates, the midpoint rule and the threshold, with fixed dates only.
final class ClockOffsetTests: XCTestCase {
    /// 1994-11-06 08:49:37 UTC, the example of RFC 9110.
    let rfcExample = Date(timeIntervalSince1970: 784_111_777)

    func testTheThreeHTTPDateFormats() {
        XCTAssertEqual(ClockOffset.httpDate("Sun, 06 Nov 1994 08:49:37 GMT"), rfcExample)
        XCTAssertEqual(ClockOffset.httpDate("Sunday, 06-Nov-94 08:49:37 GMT"), rfcExample)
        XCTAssertEqual(ClockOffset.httpDate("Sun Nov  6 08:49:37 1994"), rfcExample)
        XCTAssertEqual(ClockOffset.httpDate(" \tSun, 06 Nov 1994 08:49:37 GMT "), rfcExample, "spaces around the value")
        XCTAssertEqual(ClockOffset.httpDate("Sun, 25 Oct 2026 09:41:02 GMT"), Date(timeIntervalSince1970: 1_792_921_262))
        XCTAssertEqual(ClockOffset.httpDate("Thu, 01 Jan 1970 00:00:00 GMT"), Date(timeIntervalSince1970: 0))
        XCTAssertEqual(ClockOffset.httpDate("Tue, 29 Feb 2028 12:00:00 GMT"), Date(timeIntervalSince1970: 1_835_438_400))
        XCTAssertEqual(ClockOffset.httpDate("Wed, 31 Dec 2025 23:59:60 GMT"), Date(timeIntervalSince1970: 1_767_225_600),
                       "a leap second")
        XCTAssertEqual(ClockOffset.httpDate("Friday, 01-Jan-38 00:00:00 GMT"), Date(timeIntervalSince1970: 2_145_916_800),
                       "two-digit years below 70 are 20xx")
    }

    func testRefusesAnythingElse() {
        for text in ["", "GMT", "Sun, 06 Nov 1994 08:49:37 UTC", "Sun, 06 Nov 1994 08:49:37 +0000", "Sun, 6 Nov 1994 08:49:37 GMT",
                     "Sun 06 Nov 1994 08:49:37 GMT", "Sun, 06 nov 1994 08:49:37 GMT", "Xyz, 06 Nov 1994 08:49:37 GMT",
                     "Sun, 31 Nov 1994 08:49:37 GMT", "Sun, 29 Feb 2026 08:49:37 GMT", "Sun, 06 Nov 1994 24:00:00 GMT",
                     "Sun, 06 Nov 1994 08:60:00 GMT", "Sun, 06 Nov 1994 08:49:61 GMT", "Sun, 06 Nov 1994 8:49:37 GMT",
                     "Sun, 06 Nov 0994 08:49:37 GMT", "Sun, 06 Nov 1994 08:49:37 GMT extra", "Sun, 06 Nov 1994 08:49:37 GMT\r\nX: 1",
                     "Sun, ٠٦ Nov 1994 08:49:37 GMT", "Sun, 00 Nov 1994 08:49:37 GMT", "Sunday, 06-Nov-1994 08:49:37 GMT",
                     "Sun Nov  6 08:49:37 1994 GMT", "1792921262"] {
            XCTAssertNil(ClockOffset.httpDate(text), text)
        }
    }

    func testTheDateHeaderOfAResponseHead() {
        let head = "HTTP/1.1 302 Found\r\nLocation: /remote/login\r\ndate: Sun, 06 Nov 1994 08:49:37 GMT\r\nServer: xxxxxxxx\r\n"
        XCTAssertEqual(ClockOffset.dateHeader(inResponse: head), rfcExample, "header names are case-insensitive")
        XCTAssertEqual(ClockOffset.dateHeader(inResponse: "HTTP/1.0 200 OK\nDate:Sun, 06 Nov 1994 08:49:37 GMT\n\n"), rfcExample)
        XCTAssertEqual(ClockOffset.dateHeader(inResponse: head + "Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n"), rfcExample,
                       "the same date twice")

        XCTAssertNil(ClockOffset.dateHeader(inResponse: "HTTP/1.1 200 OK\r\nServer: x\r\n\r\n"), "no Date")
        XCTAssertNil(ClockOffset.dateHeader(inResponse: head + "Date: Mon, 07 Nov 1994 08:49:37 GMT\r\n"), "two that disagree")
        XCTAssertNil(ClockOffset.dateHeader(inResponse: "HTTP/1.1 200 OK\r\nDate: yesterday\r\n"), "not a date")
        XCTAssertNil(ClockOffset.dateHeader(inResponse: "SSH-2.0-OpenSSH\r\nDate: Sun, 06 Nov 1994 08:49:37 GMT\r\n"), "not HTTP")
        XCTAssertNil(ClockOffset.dateHeader(inResponse: "HTTP/2 200\r\nDate: Sun, 06 Nov 1994 08:49:37 GMT\r\n"))
        XCTAssertNil(ClockOffset.dateHeader(inResponse: "HTTP/1.1 2000 OK\r\nDate: Sun, 06 Nov 1994 08:49:37 GMT\r\n"))
        XCTAssertNil(ClockOffset.dateHeader(inResponse: "HTTP/1.1 200 OK\r\nX-Date: Sun, 06 Nov 1994 08:49:37 GMT\r\n"))
        XCTAssertNil(ClockOffset.dateHeader(inResponse: "HTTP/1.1 200 OK\r\n\r\nDate: Sun, 06 Nov 1994 08:49:37 GMT\r\n"),
                     "after the head: the body")
        XCTAssertNil(ClockOffset.dateHeader(inResponse: ""))
    }

    /// The source's time is compared with the middle of the exchange; an HTTP date counts from the
    /// middle of its second.
    func testOffsetFromTheMiddleOfTheExchange() {
        let sent = Date(timeIntervalSince1970: 1_000)
        let received = Date(timeIntervalSince1970: 1_002)
        XCTAssertEqual(ClockOffset.offset(serverTime: Date(timeIntervalSince1970: 1_049), sent: sent, received: received), 48)
        XCTAssertEqual(ClockOffset.offset(serverTime: Date(timeIntervalSince1970: 1_048), resolution: 1, sent: sent, received: received),
                       47.5)
        XCTAssertEqual(ClockOffset.offset(serverTime: Date(timeIntervalSince1970: 952), sent: sent, received: received), -49)

        let c = ClockOffset(offset: 47.5, source: .gateway, server: "vpn.example.com", checkedAt: received)
        XCTAssertEqual(c.offsetSeconds, 48)
        XCTAssertTrue(c.isBehind)
        XCTAssertEqual(ClockOffset(offset: -47.5, source: .gateway, checkedAt: received).offsetSeconds, -48)
        XCTAssertEqual(ClockOffset(offset: .nan, source: .gateway, checkedAt: received).offsetSeconds, 0)
        XCTAssertEqual(ClockOffset(offset: .infinity, source: .gateway, checkedAt: received).offsetSeconds, 0)
        XCTAssertEqual(ClockOffset(offset: -1e300, source: .gateway, checkedAt: received).offsetSeconds, -1_000_000_000_000)
    }

    func testFifteenSecondsOrMoreIsWrong() {
        func wrong(_ seconds: Int) -> Bool { ClockOffset(offsetSeconds: seconds, source: .timeServer, checkedAt: Date()).isWrong }
        XCTAssertEqual(ClockOffset.warnSeconds, 15)
        XCTAssertFalse(wrong(0))
        XCTAssertFalse(wrong(14))
        XCTAssertFalse(wrong(-14))
        XCTAssertTrue(wrong(15))
        XCTAssertTrue(wrong(-15))
        XCTAssertTrue(wrong(48))
        XCTAssertTrue(wrong(Int.min), "never traps")
    }

    func testJSONAndSentences() throws {
        let c = ClockOffset(offsetSeconds: 48, source: .gateway, server: "vpn.example.com", checkedAt: Date(timeIntervalSince1970: 1_700_000_000))
        let text = String(decoding: try AutomationJSON.encoder(pretty: false).encode(c), as: UTF8.self)
        XCTAssertEqual(text, #"{"checked_at":"2023-11-14T22:13:20Z","offset_seconds":48,"server":"vpn.example.com","source":"gateway"}"#)
        let decoder = JSONCoding.decoder()
        decoder.dateDecodingStrategy = .iso8601
        XCTAssertEqual(try decoder.decode(ClockOffset.self, from: Data(text.utf8)), c)
        XCTAssertEqual(ClockOffset.Source.allCases.map(\.rawValue), ["gateway", "time_server"])

        XCTAssertEqual(c.sentence, "Your clock is 48 s behind the gateway’s, so one-time codes made from it are likely refused. Fix the clock, then try again.")
        var ahead = c
        ahead.offsetSeconds = -20
        XCTAssertEqual(ahead.sentence, "Your clock is 20 s ahead of the gateway’s, so one-time codes made from it are likely refused. Fix the clock, then try again.")
        var close = c
        close.offsetSeconds = -2
        XCTAssertEqual(close.sentence, "Your clock matches the gateway’s, 2 s apart.")
        let server = ClockOffset(offsetSeconds: 31, source: .timeServer, server: "time.apple.com", checkedAt: c.checkedAt)
        XCTAssertEqual(server.sentence, "Your clock is 31 s behind the time server time.apple.com, so one-time codes made from it are likely refused. Fix the clock, then try again.")
        XCTAssertEqual(ClockOffset(offsetSeconds: 0, source: .timeServer, server: "time.apple.com", checkedAt: c.checkedAt).sentence,
                       "Your clock matches the time server time.apple.com, 0 s apart.")
    }

    func testDaysFromCivil() {
        XCTAssertEqual(ClockOffset.daysFromCivil(year: 1970, month: 1, day: 1), 0)
        XCTAssertEqual(ClockOffset.daysFromCivil(year: 2000, month: 3, day: 1), 11_017)
        XCTAssertEqual(ClockOffset.daysFromCivil(year: 1969, month: 12, day: 31), -1)
        XCTAssertEqual(ClockOffset.daysFromCivil(year: 2036, month: 2, day: 7), 24_143)
    }
}
