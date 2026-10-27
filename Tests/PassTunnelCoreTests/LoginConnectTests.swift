import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit

/// Connect at login (`LoginConnector`): which profiles connect, which are offered in a notification, and what it
/// waits for. Never a prompt.
extension ConnectionManagerTests {
    @discardableResult
    func setConnectAtLogin(_ p: Profile, order: Int, _ on: Bool = true) throws -> Profile {
        try store.update(p.id) {
            $0.connectAtLogin = on
            $0.order = order
        }
    }

    func runLogin(
        _ m: ConnectionManager, readiness: @escaping () -> LoginConnector.Readiness = { .init(helper: true, network: true) },
        timeout: TimeInterval = LoginConnector.readinessTimeout
    ) async -> (steps: [LoginConnector.Step], notices: [ConnectionNotice]) {
        var notices: [ConnectionNotice] = []
        let connector = LoginConnector(manager: m, clock: clock, readiness: readiness, notify: { notices.append($0) })
        let steps = await connector.run(timeout: timeout)
        return (steps, notices)
    }

    func testLoginConnectsUnattendedProfilesInTheSidebarOrder() async throws {
        let lab = try setConnectAtLogin(try makeOpenVPN("Lab"), order: 2)
        try setConnectAtLogin(try makeOpenVPN("Home"), order: 1, false)
        let work = try setConnectAtLogin(try makeOpenVPN("Work", otp: .totp), order: 0)
        let m = makeManager()

        let (steps, notices) = await runLogin(m)
        XCTAssertEqual(steps, [.init(work.id, .connected), .init(lab.id, .connected)])
        XCTAssertEqual(
            helper.starts.compactMap { r -> String? in
                if case .startOpenVPN(let s) = r { return s.profileID }
                return nil
            }, [work.id, lab.id], "one after the other, in order; the profile without the switch stays off")
        XCTAssertTrue(m.state(work.id).isConnected)
        XCTAssertEqual(m.state("home"), .disconnected)
        XCTAssertEqual(
            notices,
            [
                ConnectionNotice(title: "Connected to Work", body: "10.8.0.6 · vpn.example.com", profileID: work.id),
                ConnectionNotice(title: "Connected to Lab", body: "10.8.0.6 · vpn.example.com", profileID: lab.id)
            ])
        XCTAssertEqual(clock.sleeps, [], "ready at once: no wait")
        XCTAssertEqual(authenticator.calls, 0)
    }

    func testLoginOffersProfilesThatAskInsteadOfPrompting() async throws {
        let m = makeManager()
        let protected = try setConnectAtLogin(try await makeProtected("Acme VPN", .connect, in: m), order: 0)
        var asks = try makeOpenVPN("Lab")
        asks.passwordMode = .ask
        try store.save(asks)
        asks = try setConnectAtLogin(asks, order: 1)

        let (steps, notices) = await runLogin(m)
        XCTAssertEqual(steps, [.init(protected.id, .offered), .init(asks.id, .offered)])
        XCTAssertEqual(authenticator.calls, 0, "no Touch ID prompt at login")
        XCTAssertTrue(helper.starts.isEmpty)
        XCTAssertEqual(
            notices,
            [
                ConnectionNotice(
                    title: "“Acme VPN” is set to connect at login", body: "Click to connect.", profileID: protected.id,
                    actions: .connect, connectOnClick: true),
                ConnectionNotice(
                    title: "“Lab” is set to connect at login", body: "Click to connect.", profileID: asks.id,
                    actions: .connect, connectOnClick: true)
            ])
    }

    func testLoginWaitsForTheHelperAndTheNetwork() async throws {
        let p = try setConnectAtLogin(try makeOpenVPN(), order: 0)
        let m = makeManager()
        var asked = 0
        let (steps, _) = await runLogin(
            m,
            readiness: {
                asked += 1
                return .init(helper: asked > 2, network: asked > 4)
            })
        XCTAssertEqual(steps, [.init(p.id, .connected)])
        XCTAssertEqual(asked, 5)
        XCTAssertEqual(clock.sleeps, [1, 1, 1, 1])
    }

    func testLoginGivesUpWhenNothingIsReadyInTime() async throws {
        let p = try setConnectAtLogin(try makeOpenVPN(), order: 0)
        let m = makeManager()
        let (steps, notices) = await runLogin(m, readiness: { .init(helper: false, network: true) }, timeout: 10)
        XCTAssertEqual(steps, [.init(p.id, .failed(reason: "The PassTunnel helper is not ready."))])
        XCTAssertEqual(
            notices,
            [
                ConnectionNotice(
                    title: "Could not connect “Acme” at login",
                    body: "The PassTunnel helper is not ready.", profileID: p.id,
                    actions: .connect)
            ])
        XCTAssertEqual(clock.sleeps.reduce(0, +), 10, "a bounded wait")
        XCTAssertTrue(helper.starts.isEmpty)

        let offline = await runLogin(m, readiness: { .init(helper: true, network: false) }, timeout: 3)
        XCTAssertEqual(offline.steps, [.init(p.id, .failed(reason: "This Mac is offline."))])
    }

    func testLoginWithoutProfilesWaitsForNothing() async throws {
        try makeOpenVPN()
        let m = makeManager()
        var asked = false
        let (steps, notices) = await runLogin(
            m,
            readiness: {
                asked = true
                return .init(helper: false, network: false)
            })
        XCTAssertEqual(steps, [])
        XCTAssertEqual(notices, [])
        XCTAssertFalse(asked)
        XCTAssertEqual(clock.sleeps, [])
    }

    func testLoginLeavesARunningSessionAlone() async throws {
        let p = try setConnectAtLogin(try makeOpenVPN(), order: 0)
        helper.simulateExternalStart(p.id, profileDir: store.dir(p.id).path, since: t0)
        let m = makeManager()
        let (steps, notices) = await runLogin(m)
        XCTAssertEqual(steps, [.init(p.id, .alreadyActive)])
        XCTAssertEqual(notices, [])
        XCTAssertTrue(helper.starts.isEmpty)
    }

    func testLoginReportsAFailedConnect() async throws {
        let p = try setConnectAtLogin(try makeOpenVPN(), order: 0)
        Secrets.delete(p.id, .password)
        let m = makeManager()
        let (steps, notices) = await runLogin(m)
        let reason = PTError.missingPassword(p.id).localizedDescription
        XCTAssertEqual(steps, [.init(p.id, .failed(reason: reason))])
        XCTAssertEqual(
            notices,
            [
                ConnectionNotice(
                    title: "Could not connect “Acme” at login", body: reason, profileID: p.id,
                    actions: .connect)
            ])
    }

    func testLoginSkipsAProfileSwitchedOffWhileWaiting() async throws {
        let p = try setConnectAtLogin(try makeOpenVPN(), order: 0)
        let m = makeManager()
        var asked = 0
        let (steps, _) = await runLogin(
            m,
            readiness: { [self] in
                asked += 1
                if asked == 1 { _ = try? setConnectAtLogin(p, order: 0, false) }
                return .init(helper: asked > 1, network: true)
            })
        XCTAssertEqual(steps, [])
        XCTAssertTrue(helper.starts.isEmpty)
    }

    func testConnectThatMayNotAskRefusesInsteadOfPrompting() async throws {
        let m = makeManager()
        let p = try await makeProtected(in: m)
        do {
            try await m.connect(p.id, interactive: false)
            XCTFail("connected without the confirmation")
        } catch {
            XCTAssertEqual(error as? PTError, .confirmationRequired)
        }
        XCTAssertEqual(authenticator.calls, 0)
        XCTAssertTrue(helper.starts.isEmpty)
    }
}
