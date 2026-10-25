import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

/// A `FakeClock` whose sleeps of `held` seconds (the wait before the next try) last until `release`, or until
/// the sleeper is cancelled; every other sleep returns at once, as `FakeClock`'s do.
final class HoldingClock: ConnectionClock, @unchecked Sendable {
    let base: FakeClock
    let held: TimeInterval
    private let lock = NSLock()
    private var releases = 0
    private var _waiting = 0

    init(_ base: FakeClock, holding held: TimeInterval) {
        self.base = base
        self.held = held
    }

    /// Sleepers held now.
    var waiting: Int { lock.lock(); defer { lock.unlock() }; return _waiting }

    /// Lets one held sleeper go.
    func release() { lock.lock(); releases += 1; lock.unlock() }

    func now() -> Date { base.now() }

    func sleep(_ seconds: TimeInterval) async throws {
        if seconds == held {
            lock.lock(); _waiting += 1; lock.unlock()
            defer { lock.lock(); _waiting -= 1; lock.unlock() }
            while true {
                let go = { () -> Bool in
                    lock.lock(); defer { lock.unlock() }
                    guard releases > 0 else { return false }
                    releases -= 1
                    return true
                }()
                if go { break }
                try await Task.sleep(nanoseconds: 2_000_000)
            }
        }
        try await base.sleep(seconds)
    }
}

/// A network path the test sets.
@MainActor
final class FakeNetworkPath: NetworkPathWatching {
    var status = NetworkStatus.unknown
    func start(_ onChange: @escaping @MainActor (NetworkStatus) -> Void) {}
    func stop() {}
}

extension FakeHelper {
    /// The server answers again (also from `onStart`, while the start request is handled).
    func answer() {
        openVPNStateLine = { LoopingManagementServer.connectedLine(since: $0) }
        startLog = ""
    }
}

// MARK: - Retrying a server that does not answer

extension ConnectionManagerTests {
    /// A server that refuses every connection: the tool says so in its log and never comes up.
    func makeServerUnreachable() {
        helper.openVPNStateLine = nil
        helper.startLog = Self.refusedLog
    }

    func makeServerReachable() { helper.answer() }

    /// The app's manager: it retries. A connect that gets no answer gives up after 2 s.
    func makeRetryingManager(clock: ConnectionClock? = nil, delay: TimeInterval = 30) -> ConnectionManager {
        var timing = ConnectionManager.Timing()
        timing.openVPNTimeout = 2
        timing.unreachableRetryDelay = delay
        let m = makeManager(clock: clock, timing: timing)
        m.retriesUnreachable = true
        return m
    }

    func retryFile(_ id: String) -> URL { store.dir(id).appendingPathComponent(ConnectionManager.sharedRetryFile) }

    /// Within one TOTP window: the code of a try that never reached the server is given back, so the next
    /// try sends it at once instead of waiting for a fresh one, and the record from before is restored.
    func testAnUnreachableServerIsTriedAgainUntilItAnswers() async throws {
        let p = try makeOpenVPN(otp: .totp)
        prefs.waitForFreshCode = false
        let before = ConnectionManager.UsedOTPWindow(counter: TOTP.counter(params: p.totp, at: t0) - 1, period: 30)
        try JSONCoding.write(before, to: store.dir(p.id).appendingPathComponent(ConnectionManager.usedOTPFile), mode: 0o600)
        makeServerUnreachable()
        helper.onStart = { [helper] _ in if helper!.starts.count == 3 { helper!.answer() } }
        let m = makeRetryingManager(delay: 1)

        do { try await m.connect(p.id); XCTFail("connected") } catch {
            XCTAssertEqual(AutomationErrorCode.of(error), .serverUnreachable)
        }
        let first = try XCTUnwrap(m.unreachableRetries[p.id])
        XCTAssertEqual(first, UnreachableRetry(tries: 1, maxTries: 10, nextTryAt: t0.addingTimeInterval(3),
                                               firstFailedAt: t0.addingTimeInterval(2), lastFailedAt: t0.addingTimeInterval(2)))
        XCTAssertEqual(m.usedCode(p.id), before, "the code never reached the server")
        let shared = try JSONCoding.read(ConnectionManager.SharedRetry.self, from: retryFile(p.id))
        XCTAssertEqual(shared, ConnectionManager.SharedRetry(writer: getpid(), retry: first))

        await waitUntil { m.state(p.id).isConnected }
        XCTAssertNil(m.unreachableRetries[p.id])
        XCTAssertFalse(FileManager.default.fileExists(atPath: retryFile(p.id).path))
        #if os(macOS)
        XCTAssertFalse(ProfilesWatcher.isRelevant(path: retryFile(p.id).path), "no reload of the app for it")
        #endif
        XCTAssertEqual(helper.starts.count, 3)
        let secrets = helper.starts.compactMap(secretSent)
        XCTAssertEqual(Set(secrets).count, 1, "the same window's code each time, never a wait for a fresh one")
        XCTAssertEqual(secrets.first, "pw" + (try code(at: t0)))
        let kinds = m.activity(p.id).map(\.kind)
        XCTAssertFalse(kinds.contains { if case .waitingForCode = $0 { return true }; return false })
        XCTAssertEqual(kinds.filter { if case .unreachable = $0 { return true }; return false },
                       [.unreachable(tries: 1, reason: "Connection refused"), .unreachable(tries: 2, reason: "Connection refused")])
        XCTAssertEqual(kinds.filter { if case .nextTry = $0 { return true }; return false }.count, 2)
        XCTAssertEqual(kinds.last, .connected(address: "10.8.0.6"))
        XCTAssertTrue(events.isEmpty, "a manual connect's retries tell nothing: \(events)")
    }

    /// After a drop: the reconnects (5, 15, 45 s), then tries every 30 s up to 10 in all; the end is the
    /// reconnect's (`reconnectFailed`).
    func testADropsReconnectsGoOnWithRetriesAndGiveUp() async throws {
        let p = try makeOpenVPN(autoReconnect: true)
        let m = makeRetryingManager()
        try await m.connect(p.id)
        makeServerUnreachable()
        helper.simulateExit(p.id)
        await m.refresh()
        XCTAssertEqual(events.first, .dropped(profileID: p.id, willReconnect: true))
        await waitUntil { self.events.count == 2 }
        guard case .reconnectFailed(let id, let reason) = events.last else { return XCTFail("\(events)") }
        XCTAssertEqual(id, p.id)
        XCTAssertFalse(reason.isEmpty)
        XCTAssertEqual(helper.starts.count, 1 + 3 + 7, "3 reconnects, then tries 4 to 10")
        XCTAssertEqual(clock.sleeps.filter { $0 == 30 }.count, 7)
        XCTAssertEqual(m.failures[p.id]?.tries, 10)
        XCTAssertNil(m.unreachableRetries[p.id])
        XCTAssertEqual(m.state(p.id), .disconnected)
    }

    /// A drop's retries that reach the server end as its reconnect.
    func testADropsRetriesThatConnectReportTheReconnect() async throws {
        let p = try makeOpenVPN(autoReconnect: true)
        let m = makeRetryingManager()
        try await m.connect(p.id)
        makeServerUnreachable()
        helper.onStart = { [helper] _ in if helper!.starts.count == 6 { helper!.answer() } }
        helper.simulateExit(p.id)
        await m.refresh()
        await waitUntil { self.events.count == 2 }
        XCTAssertEqual(events.last, .reconnected(profileID: p.id))
        XCTAssertTrue(m.state(p.id).isConnected)
        XCTAssertEqual(helper.starts.count, 6)
    }

    /// A name that does not resolve, a rejected sign-in and anything else are not retried; nor is
    /// anything without `retriesUnreachable` (the CLI and the MCP server).
    func testOnlyAnUnreachableServerIsRetried() async throws {
        let p = try makeOpenVPN()
        let m = makeRetryingManager()
        helper.openVPNStateLine = nil
        helper.startLog = "2026-10-25 09:41:00 RESOLVE: Cannot resolve host address: vpn.example.com:1194 (Name or service not known)\n"
        do { try await m.connect(p.id); XCTFail("connected") } catch { XCTAssertEqual(AutomationErrorCode.of(error), .hostNotFound) }
        XCTAssertNil(m.unreachableRetries[p.id])
        helper.startLog = "2026-10-25 09:41:01 Control Channel: TLSv1.3\n2026-10-25 09:41:02 AUTH: Received control message: AUTH_FAILED\n"
        do { try await m.connect(p.id); XCTFail("connected") } catch PTError.authFailed {}
        XCTAssertNil(m.unreachableRetries[p.id])
        helper.failStarts = 1
        do { try await m.connect(p.id); XCTFail("connected") } catch PTError.helperFailed {}
        XCTAssertNil(m.unreachableRetries[p.id])

        makeServerUnreachable()
        var timing = ConnectionManager.Timing()
        timing.openVPNTimeout = 2
        let cli = makeManager(timing: timing)
        do { try await cli.connect(p.id); XCTFail("connected") } catch { XCTAssertEqual(AutomationErrorCode.of(error), .serverUnreachable) }
        XCTAssertNil(cli.unreachableRetries[p.id])
        XCTAssertEqual(helper.starts.count, 4)
    }

    /// Offline, the retries wait for the network; back online (or on another network) they start over.
    func testTheRetriesFollowTheNetwork() async throws {
        let p = try makeOpenVPN()
        let hold = HoldingClock(clock, holding: 30)
        let m = makeRetryingManager(clock: hold)
        m.networkChanged(NetworkStatus(online: true, interface: .wifi))   // the first answer
        makeServerUnreachable()
        do { try await m.connect(p.id); XCTFail("connected") } catch {}
        XCTAssertEqual(m.unreachableRetries[p.id]?.tries, 1)
        await waitUntil { hold.waiting == 1 }

        m.networkChanged(NetworkStatus(online: false))
        XCTAssertEqual(m.networkStatus, NetworkStatus(online: false))
        let parked = try XCTUnwrap(m.unreachableRetries[p.id])
        XCTAssertNil(parked.nextTryAt)
        XCTAssertTrue(parked.waitingForNetwork)
        await waitUntil { hold.waiting == 0 }
        XCTAssertEqual(helper.starts.count, 1, "nothing is tried while offline")

        makeServerReachable()
        m.networkChanged(NetworkStatus(online: true, interface: .ethernet))
        XCTAssertEqual(m.unreachableRetries[p.id]?.tries, 0, "the count starts over")
        XCTAssertEqual(m.unreachableRetries[p.id]?.nextTryAt, hold.now().addingTimeInterval(2))
        await waitUntil { m.state(p.id).isConnected }
        XCTAssertNil(m.unreachableRetries[p.id])
        XCTAssertEqual(helper.starts.count, 2)
        XCTAssertEqual(m.networkStatus.interface, .ethernet)
    }

    /// "Try now" counts like any try; "Stop" is a disconnect, which nothing was running for.
    func testTryNowAndStop() async throws {
        let p = try makeOpenVPN()
        let hold = HoldingClock(clock, holding: 30)
        let m = makeRetryingManager(clock: hold)
        makeServerUnreachable()
        XCTAssertFalse(m.retryNow(p.id), "nothing to try again")
        do { try await m.connect(p.id); XCTFail("connected") } catch {}
        await waitUntil { hold.waiting == 1 }

        XCTAssertTrue(m.retryNow(p.id))
        await waitUntil { m.unreachableRetries[p.id]?.tries == 2 && hold.waiting == 1 }
        XCTAssertEqual(helper.starts.count, 2)
        XCTAssertEqual(m.failures[p.id]?.tries, 2)
        XCTAssertEqual(m.activity(p.id).last?.kind, .nextTry(at: hold.now().addingTimeInterval(30)))

        let stopped = try await m.disconnect(p.id)
        XCTAssertFalse(stopped, "no VPN was running")
        XCTAssertNil(m.unreachableRetries[p.id])
        XCTAssertFalse(FileManager.default.fileExists(atPath: retryFile(p.id).path))
        XCTAssertEqual(m.activity(p.id).last?.kind, .stoppedByUser)
        await waitUntil { hold.waiting == 0 }
        XCTAssertEqual(helper.starts.count, 2)
        XCTAssertFalse(m.retryNow(p.id))
    }

    /// A manual connect replaces the retries (and, failing the same way, starts them again).
    func testAManualConnectReplacesTheRetries() async throws {
        let p = try makeOpenVPN()
        let hold = HoldingClock(clock, holding: 30)
        let m = makeRetryingManager(clock: hold)
        makeServerUnreachable()
        do { try await m.connect(p.id); XCTFail("connected") } catch {}
        await waitUntil { hold.waiting == 1 }
        makeServerReachable()
        try await m.connect(p.id)
        XCTAssertNil(m.unreachableRetries[p.id])
        await waitUntil { hold.waiting == 0 }
        XCTAssertEqual(helper.starts.count, 2)
    }

    /// A protected profile is retried with what the user already confirmed (the reuse window), never with a
    /// new prompt; once that is gone, the retries stop with the confirmation rule.
    func testAProtectedProfileIsRetriedWithoutAPrompt() async throws {
        let m = makeRetryingManager()
        let p = try await makeProtected(in: m)
        makeServerUnreachable()
        do { try await m.connect(p.id); XCTFail("connected") } catch {}
        XCTAssertEqual(authenticator.calls, 1)
        await waitUntil { m.unreachableRetries[p.id] == nil }
        XCTAssertEqual(authenticator.calls, 1, "no prompt from a retry")
        XCTAssertEqual(helper.starts.count, 2, "the second try still had the confirmed password, the third did not")
        XCTAssertEqual(m.lastError[p.id], PTError.confirmationRequired.localizedDescription)
        XCTAssertNotEqual(m.failures[p.id]?.kind, .unreachable)
    }

    /// The CLI and the MCP server show the retries the app runs (shared through the profile directory, while
    /// that process lives); a disconnect there stops them in the app.
    func testAnotherProcessSeesAndStopsTheRetries() async throws {
        let p = try makeOpenVPN()
        let cli = makeManager()
        let retry = UnreachableRetry(tries: 3, maxTries: 10, nextTryAt: t0.addingTimeInterval(18),
                                     firstFailedAt: t0.addingTimeInterval(-62), lastFailedAt: t0.addingTimeInterval(-12))
        try JSONCoding.write(ConnectionManager.SharedRetry(writer: getppid(), retry: retry), to: retryFile(p.id), mode: 0o600)
        XCTAssertEqual(cli.unreachableRetry(p.id), retry)
        let status = AutomationService(store: store, manager: cli).status(p)
        XCTAssertEqual(status.nextTryAt, retry.nextTryAt)
        XCTAssertEqual(status.tries, 3)
        let json = String(decoding: try AutomationJSON.encoder().encode(status), as: UTF8.self)
        XCTAssertTrue(json.contains("\"next_try_at\" : \"2023-11-14T22:13:38Z\""), json)
        XCTAssertTrue(json.contains("\"tries\" : 3"), json)

        try JSONCoding.write(ConnectionManager.SharedRetry(writer: Int32.max, retry: retry), to: retryFile(p.id), mode: 0o600)
        XCTAssertNil(cli.unreachableRetry(p.id), "the process that wrote it is gone")
        try JSONCoding.write(ConnectionManager.SharedRetry(writer: getppid(), retry: retry), to: retryFile(p.id), mode: 0o600)
        try await cli.disconnect(p.id)
        XCTAssertFalse(FileManager.default.fileExists(atPath: retryFile(p.id).path))
        XCTAssertEqual(cli.activity(p.id).last?.kind, .stoppedByUser)

        // The app's own retries end on its next poll after that disconnect.
        let hold = HoldingClock(clock, holding: 30)
        let app = makeRetryingManager(clock: hold)
        makeServerUnreachable()
        do { try await app.connect(p.id); XCTFail("connected") } catch {}
        XCTAssertNotNil(app.unreachableRetries[p.id])
        XCTAssertNil(cli.unreachableRetry(p.id), "the same process: only its own count")
        try await cli.disconnect(p.id)
        await app.refresh()
        XCTAssertNil(app.unreachableRetries[p.id])
        await waitUntil { hold.waiting == 0 }
        XCTAssertEqual(helper.starts.count, 1)
    }

    /// "Copy details": what the user can send, in plain text, without a password, code or user name.
    func testFailureDetailsOfAnUnreachableServer() async throws {
        let p = try makeOpenVPN(otp: .totp)
        let hold = HoldingClock(clock, holding: 30)
        let m = makeRetryingManager(clock: hold)
        m.networkChanged(NetworkStatus(online: true, interface: .wifi))
        makeServerUnreachable()
        XCTAssertNil(m.failureDetails(p.id), "nothing failed yet")
        do { try await m.connect(p.id); XCTFail("connected") } catch {}
        let app = AppInfo(version: "1.2.0", build: "45", appPath: "/Applications/PassTunnel.app")
        let details = try XCTUnwrap(m.failureDetails(p.id, app: app))
        XCTAssertEqual(details.server, "vpn.example.com:1194 (UDP)")
        XCTAssertEqual(details.network, NetworkStatus(online: true, interface: .wifi))
        let text = details.text(timeZone: TimeZone(identifier: "UTC")!)
        XCTAssertEqual(text, """
            PassTunnel 1.2.0 (45)
            Profile: Acme
            Server: vpn.example.com:1194 (UDP)
            Result: The server did not answer (Connection refused)
            Your sign-in was not sent.
            Tries: 1, the first at 2023-11-14 22:13:22 +00:00, the last at 2023-11-14 22:13:22 +00:00
            Next try at 2023-11-14 22:13:52 +00:00
            Network: Online · Wi-Fi
            """)
        XCTAssertFalse(text.contains("alice"))
        XCTAssertFalse(text.contains(try code(at: t0)))
    }
}

// MARK: - Network path, details

final class NetworkPathTests: XCTestCase {
    func testStatus() throws {
        XCTAssertEqual(NetworkStatus(online: false, interface: .wifi).interface, nil, "no interface offline")
        XCTAssertEqual(NetworkStatus(online: true, interface: .wifi).summary, "Online · Wi-Fi")
        XCTAssertEqual(NetworkStatus(online: true).summary, "Online")
        XCTAssertEqual(NetworkStatus(online: false).summary, "Offline")
        XCTAssertEqual(NetworkStatus.unknown.summary, "Unknown")
        let encoder = AutomationJSON.encoder(pretty: false)
        XCTAssertEqual(String(decoding: try encoder.encode(NetworkStatus(online: true, interface: .ethernet)), as: UTF8.self),
                       #"{"interface":"ethernet","online":true}"#)
        XCTAssertEqual(String(decoding: try encoder.encode(NetworkStatus.unknown), as: UTF8.self), "{}")
    }

    /// `NWPathMonitor`'s answer: satisfied is online, the first kind of interface the path uses (a VPN's
    /// tunnel is `other`, so Wi-Fi under a VPN still reads Wi-Fi).
    func testApplePath() {
        XCTAssertEqual(NetworkPath.status(satisfied: false) { _ in true }, NetworkStatus(online: false))
        XCTAssertEqual(NetworkPath.status(satisfied: true) { [.wifi, .other].contains($0) },
                       NetworkStatus(online: true, interface: .wifi))
        XCTAssertEqual(NetworkPath.status(satisfied: true) { $0 == .cellular }, NetworkStatus(online: true, interface: .cellular))
        XCTAssertEqual(NetworkPath.status(satisfied: true) { _ in false }, NetworkStatus(online: true, interface: .other))
    }

    /// Linux: a route that carries all traffic through a link that is up.
    func testLinuxPath() {
        typealias Route = RoutingTable.Route
        let state = ["wlp2s0": "up", "eth0": "up", "enp3s0": "down", "tun0": "unknown", "wwan0": "dormant"]
        func status(_ routes: [Route]) -> NetworkStatus {
            NetworkPath.linuxStatus(routes: routes, operstate: { state[$0] }, isWireless: { $0.hasPrefix("wl") },
                                    linkType: { $0.hasPrefix("e") ? 1 : 65534 })
        }
        let wifi = Route(destination: "0.0.0.0", prefixLength: 0, interface: "wlp2s0")
        let ethernet = Route(destination: "::", prefixLength: 0, interface: "eth0")
        let unplugged = Route(destination: "0.0.0.0", prefixLength: 0, interface: "enp3s0")
        let vpnHalf = Route(destination: "0.0.0.0", prefixLength: 1, interface: "tun0", tunnelDevice: true)
        XCTAssertEqual(status([]), NetworkStatus(online: false), "no default route")
        XCTAssertEqual(status([unplugged]), NetworkStatus(online: false), "its link is down")
        XCTAssertEqual(status([wifi]), NetworkStatus(online: true, interface: .wifi))
        XCTAssertEqual(status([ethernet]), NetworkStatus(online: true, interface: .ethernet))
        XCTAssertEqual(status([vpnHalf, unplugged, wifi]), NetworkStatus(online: true, interface: .wifi), "the link under the VPN")
        XCTAssertEqual(status([vpnHalf]), NetworkStatus(online: true, interface: .other))
        XCTAssertEqual(status([Route(destination: "0.0.0.0", prefixLength: 0, interface: "wwan0")]), NetworkStatus(online: false))
        XCTAssertEqual(status([Route(destination: "10.0.0.0", prefixLength: 8, interface: "eth0")]), NetworkStatus(online: false),
                       "not a route for all traffic")
    }

    @MainActor
    func testCurrentAnswers() async {
        // Read-only: whatever the machine's state, an answer within the limit.
        let started = Date()
        _ = await NetworkPath.current(timeout: 2)
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
    }

    func testFailureDetailsWording() {
        let at = Date(timeIntervalSince1970: 1_700_000_000)
        let app = AppInfo(version: "1.2.0", build: nil, appPath: "")
        var details = FailureDetails(profileName: "Work", server: "",
                                     failure: ConnectionFailure(kind: .authRejected, at: at, reply: "AUTH_FAILED", credentialsSent: true,
                                                                codeSent: true, codeSecondsLeft: 22),
                                     network: .unknown, app: app, at: at)
        XCTAssertEqual(details.text(timeZone: TimeZone(identifier: "UTC")!), """
            PassTunnel 1.2.0
            Profile: Work
            Result: The server rejected the sign-in (AUTH_FAILED)
            Your sign-in reached the server.
            The code was sent with 22 s left.
            Failed at 2023-11-14 22:13:20 +00:00
            Network: Unknown
            """)
        details.failure = ConnectionFailure(kind: .unreachable, at: at, reason: "Server poll timeout", tries: 3)
        details.retry = UnreachableRetry(tries: 3, maxTries: 10, waitingForNetwork: true, firstFailedAt: at.addingTimeInterval(-60),
                                         lastFailedAt: at)
        details.network = NetworkStatus(online: false)
        XCTAssertEqual(details.text(timeZone: TimeZone(identifier: "Europe/Istanbul")!), """
            PassTunnel 1.2.0
            Profile: Work
            Result: The server did not answer (Server poll timeout)
            Your sign-in was not sent.
            Tries: 3, the first at 2023-11-15 01:12:20 +03:00, the last at 2023-11-15 01:13:20 +03:00
            Next try when the network is back
            Network: Offline
            """)
        for kind in ConnectionFailure.Kind.allCases { XCTAssertFalse(FailureDetails.result(kind).isEmpty) }
    }
}
