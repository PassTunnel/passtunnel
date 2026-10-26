import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

/// The one status a profile shows in the app's views: which state the facts Core reports give (also when
/// several apply), and its words.
final class DisplayStatusTests: XCTestCase {
    private typealias Facts = DisplayStatus.Facts
    private typealias Connection = DisplayStatus.Connection

    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private var since: Date { now.addingTimeInterval(-(72 * 60 + 14)) }
    private var up: ConnectionState { .connected(ip: "10.8.0.6", since: since) }
    private var connection: Connection { Connection(since: since, address: "10.8.0.6") }
    private var reconnect: ReconnectInfo { ReconnectInfo(attempt: 1, maxAttempts: 3, at: now.addingTimeInterval(5)) }
    private let rejected = "The server rejected the sign-in. Check the user name, password and one-time code."

    private func status(_ f: Facts) -> DisplayStatus { DisplayStatus(f) }

    // MARK: one state each

    func testAtRest() {
        XCTAssertEqual(status(Facts()), .off)
        XCTAssertEqual(status(Facts(asksToConnect: true)), .protected)
    }

    func testConnecting() {
        XCTAssertEqual(status(Facts(state: .connecting(ConnectionManager.Phase.signingIn))),
                       .connecting(phase: ConnectionManager.Phase.signingIn))
    }

    func testWaitingForAFreshCode() {
        let until = now.addingTimeInterval(4)
        XCTAssertEqual(status(Facts(state: .connecting(ConnectionManager.Phase.waitingForCode), codeWaitUntil: until)),
                       .waitingForCode(until: until))
        // The deadline is published just before the state: the wait shows at once.
        XCTAssertEqual(status(Facts(codeWaitUntil: until)), .waitingForCode(until: until))
    }

    func testConnected() {
        XCTAssertEqual(status(Facts(state: up)), .connected(connection))
        XCTAssertEqual(status(Facts(state: .connected(ip: "", since: nil))), .connected(Connection(since: nil, address: "")))
    }

    func testConnectedWithAProblem() {
        XCTAssertEqual(status(Facts(state: up, warning: "route add failed")),
                       .setupIncomplete(connection, warning: "route add failed"))
        XCTAssertEqual(status(Facts(state: up, statusUnavailable: true)), .statusUnavailable(connection))
        XCTAssertEqual(status(Facts(state: up, notResponding: true)), .notResponding(connection))
    }

    func testReconnecting() {
        XCTAssertEqual(status(Facts(reconnect: reconnect)), .reconnecting(reconnect, freshCode: false))
        XCTAssertEqual(status(Facts(reconnect: reconnect, usesCode: true)), .reconnecting(reconnect, freshCode: true))
    }

    func testDroppedAndNotReconnecting() {
        XCTAssertEqual(status(Facts(droppedUnseen: true)), .dropped)
    }

    func testFailed() {
        XCTAssertEqual(status(Facts(lastError: rejected)), .failed(.message(rejected)))
    }

    private func failure(_ kind: ConnectionFailure.Kind) -> ConnectionFailure { ConnectionFailure(kind: kind, at: now) }

    private func retry(next: TimeInterval? = 18, waiting: Bool = false) -> UnreachableRetry {
        UnreachableRetry(tries: 3, maxTries: 5, nextTryAt: next.map { now.addingTimeInterval($0) }, waitingForNetwork: waiting,
                         firstFailedAt: now.addingTimeInterval(-60), lastFailedAt: now.addingTimeInterval(-12))
    }

    /// The typed reason of the failure decides what is shown; a kind with no case of its own keeps the error's words.
    func testTheFailureKindDecidesTheReason() {
        XCTAssertEqual(status(Facts(lastError: rejected, failure: failure(.authRejected))), .failed(.signInRejected))
        XCTAssertEqual(status(Facts(lastError: "x", failure: failure(.hostNotFound))), .failed(.hostNotFound))
        XCTAssertEqual(status(Facts(lastError: "x", failure: failure(.unreachable))), .failed(.unreachable(retry: nil)))
        for kind in [ConnectionFailure.Kind.configuration, .setup, .timeout, .failed] {
            XCTAssertEqual(status(Facts(lastError: "boom", failure: failure(kind))), .failed(.message("boom")), "\(kind)")
        }
        XCTAssertEqual(status(Facts(lastError: "boom")), .failed(.message("boom")), "no typed failure")
    }

    /// An unreachable server is shown while its tries go on, also during one (the failure is cleared then), but
    /// not over a connection that is up, a reconnect or a wait for a fresh code.
    func testTheTriesOfAnUnreachableServerAreShownThroughout() {
        let shown = DisplayStatus.failed(.unreachable(retry: retry()))
        XCTAssertEqual(status(Facts(lastError: "x", failure: failure(.unreachable), retry: retry())), shown)
        XCTAssertEqual(status(Facts(state: .connecting(ConnectionManager.Phase.starting), retry: retry())), shown)
        XCTAssertEqual(status(Facts(state: up, retry: retry())), .connected(connection))
        XCTAssertEqual(status(Facts(reconnect: reconnect, retry: retry())), .reconnecting(reconnect, freshCode: false))
        XCTAssertEqual(status(Facts(codeWaitUntil: now, retry: retry())), .waitingForCode(until: now))
    }

    // MARK: precedence

    /// Not responding is the worst (the tunnel carries nothing), then a failed setup step, then a state that
    /// could not be read.
    func testTheWorstProblemOfAConnectionWins() {
        XCTAssertEqual(status(Facts(state: up, warning: "w", notResponding: true, statusUnavailable: true)),
                       .notResponding(connection))
        XCTAssertEqual(status(Facts(state: up, warning: "w", statusUnavailable: true)),
                       .setupIncomplete(connection, warning: "w"))
    }

    /// A connection that is up wins over what is left from before it (a reconnect that just ended, an old error,
    /// a drop not seen yet).
    func testAConnectionThatIsUpWins() {
        let all = Facts(state: up, reconnect: reconnect, codeWaitUntil: now, lastError: rejected, droppedUnseen: true,
                        asksToConnect: true, usesCode: true)
        XCTAssertEqual(status(all), .connected(connection))
    }

    /// A reconnect covers its own attempts: their waits for a fresh code, their phases and their failures,
    /// and the drop and the setup warning it started from.
    func testAReconnectCoversItsAttempts() {
        let shown = DisplayStatus.reconnecting(reconnect, freshCode: true)
        XCTAssertEqual(status(Facts(reconnect: reconnect, warning: "w", droppedUnseen: true, usesCode: true)), shown)
        XCTAssertEqual(status(Facts(state: .connecting(ConnectionManager.Phase.waitingForCode), reconnect: reconnect,
                                    codeWaitUntil: now.addingTimeInterval(3), usesCode: true)), shown)
        XCTAssertEqual(status(Facts(state: .connecting(ConnectionManager.Phase.signingIn), reconnect: reconnect,
                                    usesCode: true)), shown)
        XCTAssertEqual(status(Facts(reconnect: reconnect, lastError: "boom", droppedUnseen: true, asksToConnect: true,
                                    usesCode: true)), shown)
    }

    func testAConnectUnderWayWinsOverAnOldFailure() {
        XCTAssertEqual(status(Facts(state: .connecting(ConnectionManager.Phase.starting), lastError: rejected)),
                       .connecting(phase: ConnectionManager.Phase.starting))
        XCTAssertEqual(status(Facts(codeWaitUntil: now, lastError: rejected)), .waitingForCode(until: now))
    }

    /// Once a reconnect gives up, its last failure shows; a drop that never reconnected shows until seen.
    func testAtRestTheFailureThenTheDropThenTheSetting() {
        XCTAssertEqual(status(Facts(lastError: "boom", droppedUnseen: true, asksToConnect: true)), .failed(.message("boom")))
        XCTAssertEqual(status(Facts(droppedUnseen: true, asksToConnect: true)), .dropped)
    }

    // MARK: facts from the profile

    /// Either level of "Confirm with Touch ID" asks before connecting (the redesign shows one switch), and only
    /// when connecting uses a stored secret.
    func testTouchIDToConnectFollowsTheSetting() {
        var p = Profile(id: "work", name: "Work", type: .openvpn)
        XCTAssertFalse(Facts.asksToConnect(p))
        for level in [AuthRequirement.connect, .always] {
            p.requireAuth = level
            XCTAssertTrue(Facts.asksToConnect(p), "\(level)")
        }
        p.passwordMode = .ask
        XCTAssertFalse(Facts.asksToConnect(p), "nothing stored, nothing to confirm")
        p.otpMode = .totp
        XCTAssertTrue(Facts.asksToConnect(p))

        XCTAssertEqual(status(Facts(p, state: .disconnected)), .protected)
        p.requireAuth = .off
        XCTAssertEqual(status(Facts(p, state: .disconnected)), .off)
    }

    func testFreshCodeOnlyForProfilesThatSendOne() {
        var p = Profile(id: "work", name: "Work", type: .openvpn)
        XCTAssertEqual(status(Facts(p, state: .disconnected, reconnect: reconnect)), .reconnecting(reconnect, freshCode: false))
        p.otpMode = .ask
        XCTAssertFalse(Facts(p, state: .disconnected).usesCode, "a code typed in is not made again")
        p.otpMode = .totp
        XCTAssertEqual(status(Facts(p, state: .disconnected, reconnect: reconnect)), .reconnecting(reconnect, freshCode: true))
    }

    // MARK: main button

    func testTheMainButtonFollowsTheStatus() {
        let cases: [(DisplayStatus, DisplayStatus.Action)] = [
            (.off, .connect),
            (.protected, .connect),
            (.dropped, .connect),
            (.connecting(phase: "Signing in…"), .cancel),
            (.waitingForCode(until: now), .cancel),
            (.connected(connection), .disconnect),
            (.setupIncomplete(connection, warning: "w"), .disconnect),
            (.notResponding(connection), .disconnect),
            (.statusUnavailable(connection), .disconnect),
            (.reconnecting(reconnect, freshCode: true), .stop),
            (.failed(.message(rejected)), .tryAgain),
            (.failed(.signInRejected), .tryAgain),
            (.failed(.hostNotFound), .tryAgain),
            (.failed(.unreachable(retry: nil)), .tryAgain),
            (.failed(.unreachable(retry: retry())), .stop),
        ]
        for (status, action) in cases {
            XCTAssertEqual(status.action, action, "\(status)")
        }
    }

    func testOnlyConnectAndTryAgainStartAConnection() {
        XCTAssertEqual(DisplayStatus.Action.allCases.filter(\.connects), [.connect, .tryAgain])
        XCTAssertEqual(DisplayStatus.Action.allCases.map(\.title), ["Connect", "Cancel", "Disconnect", "Stop", "Try again"])
    }

    // MARK: words

    func testWords() {
        let server = "vpn.example.com:1194"
        let cases: [(DisplayStatus, String, String)] = [
            (.off, "Disconnected", "Disconnected"),
            (.protected, "Touch ID to connect", "Disconnected · asks for Touch ID"),
            (.connecting(phase: "Signing in…"), "Connecting…", "Connecting to vpn.example.com:1194…"),
            (.waitingForCode(until: now.addingTimeInterval(3.25)), "Waiting for a fresh code · 4 s",
             "Waiting for a fresh code · sends in 4 s"),
            (.connected(connection), "Connected · 1h 12m", "Connected · 1h 12m · 10.8.0.6"),
            (.setupIncomplete(connection, warning: "w"), "Connected · setup incomplete",
             "Connected · 1h 12m · 10.8.0.6 · setup incomplete"),
            (.notResponding(connection), "Connected · not responding", "Connected · 1h 12m · 10.8.0.6 · not responding"),
            (.statusUnavailable(connection), "Connected · status unavailable",
             "Connected · 1h 12m · 10.8.0.6 · status unavailable"),
            (.reconnecting(reconnect, freshCode: true), "Dropped, reconnecting…", "Dropped, reconnecting with a fresh code…"),
            (.reconnecting(reconnect, freshCode: false), "Dropped, reconnecting…", "Dropped, reconnecting…"),
            (.dropped, "Connection dropped", "Connection dropped"),
            (.failed(.message(rejected)), "Couldn’t connect", rejected),
            (.failed(.signInRejected), "Sign-in rejected", "Sign-in rejected by the server"),
            (.failed(.hostNotFound), "Server not found", "Can’t find the server"),
            (.failed(.unreachable(retry: nil)), "Unreachable", "Can’t reach the server"),
            (.failed(.unreachable(retry: retry(next: 17.2))), "Unreachable, retrying",
             "Can’t reach the server · next try in 18 s"),
            (.failed(.unreachable(retry: retry(next: nil, waiting: true))), "Unreachable, retrying",
             "Can’t reach the server · waiting for the network"),
            (.failed(.unreachable(retry: retry(next: nil))), "Unreachable, retrying",
             "Can’t reach the server · trying again…"),
        ]
        for (status, summary, line) in cases {
            XCTAssertEqual(status.summary(at: now), summary, "\(status)")
            XCTAssertEqual(status.line(at: now, server: server), line, "\(status)")
        }
    }

    /// The wait for the next try counts down, then the try itself is "trying again".
    func testTheWaitForTheNextTryCountsDown() {
        let waiting = DisplayStatus.failed(.unreachable(retry: retry(next: 3.5)))
        XCTAssertEqual(waiting.line(at: now), "Can’t reach the server · next try in 4 s")
        XCTAssertEqual(waiting.line(at: now.addingTimeInterval(2)), "Can’t reach the server · next try in 2 s")
        XCTAssertEqual(waiting.line(at: now.addingTimeInterval(3.5)), "Can’t reach the server · trying again…")
    }

    func testConnectingWithoutAServerShowsThePhase() {
        XCTAssertEqual(DisplayStatus.connecting(phase: "Signing in…").line(at: now), "Signing in…")
        XCTAssertEqual(DisplayStatus.connecting(phase: "").line(at: now), "Connecting…")
    }

    func testConnectedLeavesOutWhatIsUnknown() {
        XCTAssertEqual(DisplayStatus.connected(Connection(since: nil, address: "")).summary(at: now), "Connected")
        XCTAssertEqual(DisplayStatus.connected(Connection(since: nil, address: "")).line(at: now), "Connected")
        XCTAssertEqual(DisplayStatus.connected(Connection(since: nil, address: "10.8.0.6")).line(at: now),
                       "Connected · 10.8.0.6")
        XCTAssertEqual(DisplayStatus.notResponding(Connection(since: nil, address: "")).line(at: now),
                       "Connected · not responding")
    }

    /// The first attempt reconnects as the design says; after a failed one, the wait for the next counts down.
    func testReconnectCountsDownAfterAFailedAttempt() {
        let second = ReconnectInfo(attempt: 2, maxAttempts: 3, at: now.addingTimeInterval(11.5))
        XCTAssertEqual(DisplayStatus.reconnecting(second, freshCode: true).line(at: now), "Dropped · next try in 12 s")
        XCTAssertEqual(DisplayStatus.reconnecting(second, freshCode: true).summary(at: now), "Dropped, reconnecting…")
        // The attempt itself is under way.
        XCTAssertEqual(DisplayStatus.reconnecting(second, freshCode: true).line(at: second.at),
                       "Dropped, reconnecting with a fresh code…")
        XCTAssertEqual(DisplayStatus.reconnecting(second, freshCode: false).line(at: second.at.addingTimeInterval(9)),
                       "Dropped, reconnecting…")
    }

    func testAFailureWithoutWordsSaysItCouldNotConnect() {
        XCTAssertEqual(DisplayStatus.failed(.message(" \n")).line(at: now), "Couldn’t connect")
    }

    func testTheWaitForAFreshCodeCountsDown() {
        let until = now.addingTimeInterval(4.25)
        let waiting = DisplayStatus.waitingForCode(until: until)
        XCTAssertEqual(waiting.summary(at: now), "Waiting for a fresh code · 5 s")
        XCTAssertEqual(waiting.summary(at: now.addingTimeInterval(1.25)), "Waiting for a fresh code · 3 s")
        XCTAssertEqual(waiting.summary(at: until.addingTimeInterval(-0.1)), "Waiting for a fresh code · 1 s")
        XCTAssertEqual(waiting.summary(at: until.addingTimeInterval(2)), "Waiting for a fresh code · 0 s")
    }

    func testUptime() {
        func uptime(_ seconds: TimeInterval) -> String { DisplayStatus.uptime(since: now.addingTimeInterval(-seconds), now: now) }
        XCTAssertEqual(uptime(0), "just now")
        XCTAssertEqual(uptime(59.9), "just now")
        XCTAssertEqual(uptime(60), "1 min")
        XCTAssertEqual(uptime(8 * 60 + 30), "8 min")
        XCTAssertEqual(uptime(3600), "1h 0m")
        XCTAssertEqual(uptime(72 * 60 + 14), "1h 12m")
        XCTAssertEqual(uptime(26 * 3600 + 3 * 60), "26h 3m")
        // A start in the future (the clock moved back) or out of range never traps.
        XCTAssertEqual(uptime(-30), "just now")
        XCTAssertEqual(DisplayStatus.uptime(since: .distantFuture, now: now), "just now")
        XCTAssertFalse(DisplayStatus.uptime(since: .distantPast, now: now).isEmpty)
        XCTAssertEqual(DisplayStatus.uptime(since: Date(timeIntervalSince1970: .nan), now: now), "just now")
    }

    func testCountdownsNeverTrap() {
        XCTAssertEqual(DisplayStatus.seconds(until: .distantPast, now: now), 0)
        XCTAssertGreaterThan(DisplayStatus.seconds(until: .distantFuture, now: now), 0)
        XCTAssertEqual(DisplayStatus.seconds(until: Date(timeIntervalSince1970: .infinity), now: now), 0)
    }
}
