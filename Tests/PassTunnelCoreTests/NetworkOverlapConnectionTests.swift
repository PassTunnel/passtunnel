#if canImport(Combine)
import Combine
#endif
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit
import PassTunnelShared

/// `ConnectionManager.checkCanStart` / `overlaps(for:)` with the fake helper: PassTunnel's own sessions only,
/// the routing table never read.
@MainActor
final class NetworkOverlapConnectionTests: XCTestCase {
    var home: String!
    var service: String!
    var helper: FakeHelper!
    var clock: FakeClock!
    /// What the manager sees of a tunnel interface's routes (never the real table; as `RoutingTable.routes(onInterface:)`
    /// gives them, without the link-local peer and multicast).
    var tunnelTable: [String: [RoutingTable.Route]] = [:]
    var store: ProfileStore { ProfileStore() }

    let t0 = Date(timeIntervalSince1970: 1_700_000_000)
    static let push = "2026-10-25 09:41:02 PUSH: Received control message: 'PUSH_REPLY,route 172.16.0.0 255.240.0.0,"
        + "dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN-ROUTE example.com,ifconfig 10.8.0.6 255.255.255.0,auth-token SESS_ID_x'\n"

    override func setUp() async throws {
        var template = Array("/tmp/pt-ov-XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { throw XCTSkip("mkdtemp failed") }
        home = String(cString: made)
        service = "PassTunnelTests-\(UUID().uuidString)"
        setenv("PASSTUNNEL_HOME", home, 1)
        useTestSecrets(service: service)
        helper = FakeHelper()
        clock = FakeClock(t0)
        tunnelTable = [:]
    }

    override func tearDown() async throws {
        helper.shutdown()
        Secrets.deleteAllInOverriddenService()
        try? FileManager.default.removeItem(atPath: home)
    }

    func makeManager(routes: [RoutingTable.Route] = []) -> ConnectionManager {
        let m = ConnectionManager(store: store, helper: helper, clock: clock, healthProbe: { _ in (false, 0) },
                                  preferences: { Preferences() }, routes: { routes }, authenticator: FakeAuthenticator())
        m.tunnelRoutes = { [weak self] in self?.tunnelTable[$0] ?? [] }
        return m
    }

    @discardableResult
    func makeOpenVPN(_ name: String, lines: String = "") throws -> Profile {
        var p = try store.create(name: name, type: .openvpn)
        p.username = "alice"
        try store.save(p)
        try Data("client\nremote vpn.example.com 1194\nauth-user-pass\n\(lines)".utf8).write(to: store.ovpnURL(p.id))
        try Secrets.set(p.id, .password, "pw")
        return p
    }

    func cache(_ p: Profile) -> URL { store.dir(p.id).appendingPathComponent(ProfileNetwork.fileName) }

    func testWarnsAboutAConnectedProfileWithTheSameNetworksAndNames() async throws {
        let work = try makeOpenVPN("Work", lines: "route 10.0.0.0 255.0.0.0\ndhcp-option DOMAIN-ROUTE example.com\ndhcp-option DNS 10.8.0.1\n")
        let lab = try makeOpenVPN("Lab", lines: "route 10.9.0.0 255.255.0.0\ndhcp-option DOMAIN-ROUTE Example.com.\ndhcp-option DNS 10.9.0.1\n")
        let m = makeManager()
        let before = try await m.checkCanStart(lab.id)
        XCTAssertEqual(before, [], "Work is not connected")
        try await m.connect(work.id)

        let found = try await m.checkCanStart(lab.id)
        XCTAssertEqual(found.count, 1)
        let overlap = try XCTUnwrap(found.first)
        XCTAssertEqual(overlap.profileID, work.id)
        XCTAssertEqual(overlap.name, "Work")
        XCTAssertEqual(overlap.summary.routes.map(\.description), ["10.9.0.0/16"])
        XCTAssertEqual(overlap.summary.domains, ["example.com"])
        XCTAssertEqual(overlap.mine.dnsServers, ["10.9.0.1"], "the sheet names each side's DNS server")
        XCTAssertEqual(overlap.theirs.dnsServers, ["10.8.0.1"])
        let again = await m.overlaps(for: lab.id)
        XCTAssertEqual(again, found)

        // A warning, never a refusal: both connect.
        try await m.connect(lab.id)
        XCTAssertTrue(m.state(work.id).isConnected)
        XCTAssertTrue(m.state(lab.id).isConnected)
        XCTAssertEqual(helper.starts.count, 2)
    }

    func testNoOverlapNoWarning() async throws {
        let work = try makeOpenVPN("Work", lines: "route 10.0.0.0 255.0.0.0\ndhcp-option DOMAIN-ROUTE example.com\n")
        let lab = try makeOpenVPN("Lab", lines: "route 172.16.0.0 255.240.0.0\nroute-ipv6 2001:db8::/32\ndhcp-option DOMAIN-ROUTE notexample.com\n")
        let m = makeManager()
        try await m.connect(work.id)
        let found = try await m.checkCanStart(lab.id)
        XCTAssertEqual(found, [])
        // A tunnel that claims nothing next to one that claims something.
        let plain = try makeOpenVPN("Plain")
        let none = try await m.checkCanStart(plain.id)
        XCTAssertEqual(none, [])
    }

    func testAFullTunnelMeetsAnyConnectedTunnel() async throws {
        let work = try makeOpenVPN("Work", lines: "route 10.0.0.0 255.0.0.0\n")
        let all = try makeOpenVPN("All", lines: "redirect-gateway def1\n")
        let m = makeManager()
        try await m.connect(work.id)
        let found = try await m.checkCanStart(all.id)
        XCTAssertEqual(found.first?.summary.firstTakesAllTraffic, true)
        XCTAssertEqual(found.first?.summary.secondTakesAllTraffic, false)
        // And the other way round.
        try await m.disconnect(work.id)
        try await m.connect(all.id)
        let back = try await m.checkCanStart(work.id)
        XCTAssertEqual(back.first?.profileID, all.id)
        XCTAssertEqual(back.first?.summary.secondTakesAllTraffic, true)
    }

    func testAProfileThatIsRunningIsNotChecked() async throws {
        let work = try makeOpenVPN("Work", lines: "route 10.0.0.0 255.0.0.0\n")
        let lab = try makeOpenVPN("Lab", lines: "route 10.0.0.0 255.0.0.0\n")
        let m = makeManager()
        try await m.connect(work.id)
        try await m.connect(lab.id)
        let running = try await m.checkCanStart(lab.id)
        XCTAssertEqual(running, [], "connect would follow that session")
        let force = await m.overlaps(for: lab.id)
        XCTAssertEqual(force, [])
    }

    func testASessionAnotherProcessStartedCounts() async throws {
        let work = try makeOpenVPN("Work", lines: "route 10.0.0.0 255.0.0.0\n")
        let lab = try makeOpenVPN("Lab", lines: "route 10.0.0.0 255.0.0.0\n")
        helper.simulateExternalStart(work.id, profileDir: store.dir(work.id).path, since: t0)
        let m = makeManager()
        let found = try await m.checkCanStart(lab.id)
        XCTAssertEqual(found.map(\.profileID), [work.id], "the app's session, seen from the CLI")
        helper.simulateExternalStart(lab.id, profileDir: store.dir(lab.id).path, since: t0)
        let elsewhere = try await m.checkCanStart(lab.id)
        XCTAssertEqual(elsewhere, [], "already running: connect follows it")
    }

    // MARK: what a connect remembers

    func testAConnectRemembersWhatTheServerPushed() async throws {
        let work = try makeOpenVPN("Work")
        helper.startLog = Self.push
        let m = makeManager()
        XCTAssertFalse(FileManager.default.fileExists(atPath: cache(work).path))
        try await m.connect(work.id)

        let text = try String(contentsOf: cache(work), encoding: .utf8)
        XCTAssertTrue(text.contains("route 172.16.0.0 255.240.0.0"), text)
        XCTAssertFalse(text.contains("auth-token"), "only routes and DNS")
        XCTAssertFalse(text.contains("SESS_ID"), text)
        XCTAssertFalse(text.contains("ifconfig"), text)
        XCTAssertEqual(ProfileNetwork.savedOptions(work, store: store),
                       ["route 172.16.0.0 255.240.0.0", "dhcp-option DNS 10.8.0.1", "dhcp-option DOMAIN-ROUTE example.com"])
        let attributes = try FileManager.default.attributesOfItem(atPath: cache(work).path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testTheFirstConnectHasNoWarningAndTheNextOneDoes() async throws {
        let work = try makeOpenVPN("Work")
        let lab = try makeOpenVPN("Lab")
        helper.startLog = Self.push
        let m = makeManager()
        try await m.connect(work.id)

        // Lab never connected: nothing is known of what its server pushes.
        let first = try await m.checkCanStart(lab.id)
        XCTAssertEqual(first, [])
        try await m.connect(lab.id)
        try await m.disconnect(lab.id)

        let second = try await m.checkCanStart(lab.id)
        XCTAssertEqual(second.count, 1)
        XCTAssertEqual(second.first?.profileID, work.id)
        XCTAssertEqual(second.first?.summary.routes.map(\.description), ["172.16.0.0/12"])
        XCTAssertEqual(second.first?.summary.domains, ["example.com"])
    }

    func testAConnectThatFailedLeavesWhatWasKnown() async throws {
        let work = try makeOpenVPN("Work")
        helper.startLog = Self.push
        let m = makeManager()
        try await m.connect(work.id)
        try await m.disconnect(work.id)
        let known = try Data(contentsOf: cache(work))

        helper.failStarts = 1
        do { try await m.connect(work.id); XCTFail("connected") } catch {}
        XCTAssertEqual(try Data(contentsOf: cache(work)), known)

        // A connect whose log has no push (a low verbosity) does not erase it either.
        helper.startLog = "2026-10-25 09:41:02 Initialization Sequence Completed\n"
        try await m.connect(work.id)
        XCTAssertEqual(try Data(contentsOf: cache(work)), known)
    }

    func testAnUnreadableFileGetsInNoOnesWay() async throws {
        let work = try makeOpenVPN("Work", lines: "route 10.0.0.0 255.0.0.0\n")
        let lab = try makeOpenVPN("Lab", lines: "route 10.1.0.0 255.255.0.0\n")
        try Data("{ not json".utf8).write(to: cache(lab))
        try Data(repeating: 0x41, count: 1 << 20).write(to: cache(work))
        helper.startLog = "2026-10-25 09:41:02 PUSH: Received control message: 'PUSH_REPLY,route 192.0.2.0 255.255.255.0'\n"
        let m = makeManager()
        try await m.connect(work.id)
        let found = try await m.checkCanStart(lab.id)
        XCTAssertEqual(found.count, 1, "the config's own lines still count")
        try await m.connect(lab.id)
        XCTAssertTrue(m.state(lab.id).isConnected)
        XCTAssertNotNil(ProfileNetwork.savedOptions(lab, store: store), "the next connect writes a good one")
    }

    func testTheOtherVPNCheckComesFirst() async throws {
        let lab = try makeOpenVPN("Lab", lines: "redirect-gateway def1\n")
        let work = try makeOpenVPN("Work", lines: "route 10.0.0.0 255.0.0.0\n")
        let m = makeManager(routes: [RoutingTable.Route(destination: "0.0.0.0", prefixLength: 1, interface: "utun9"),
                                     RoutingTable.Route(destination: "128.0.0.0", prefixLength: 1, interface: "utun9")])
        try await m.connect(work.id)
        do {
            try await m.checkCanStart(lab.id)
            XCTFail("allowed over another VPN")
        } catch {
            XCTAssertEqual(error as? PTError, .otherVPNActive("utun9"))
        }
        // `--force` skips that check; the overlaps are still there to report.
        let found = await m.overlaps(for: lab.id)
        XCTAssertEqual(found.first?.profileID, work.id)
    }

    // MARK: FortiGate

    static let fortiUp = "INFO:   Got addresses: [10.212.134.200], ns [198.51.100.53, 198.51.100.54], ns_suffix [example.com]\n"
        + "INFO:   Interface ppp0 is UP.\nINFO:   Tunnel is up and running.\n"
        + "passtunneld: DNS of ppp0 set through systemd-resolved: 198.51.100.53, 198.51.100.54\n"

    func makeForti(setDNS: Bool = true, setRoutes: Bool = true) throws -> Profile {
        var p = try store.create(name: "Office", type: .forti)
        p.host = "vpn.example.com"
        p.username = "alice"
        p.setDNS = setDNS
        p.setRoutes = setRoutes
        try store.save(p)
        try Secrets.set(p.id, .password, "pw")
        return p
    }

    func testFortiGateRoutesAndDNSComeFromTheTunnel() async throws {
        let office = try makeForti()
        helper.startLog = Self.fortiUp
        tunnelTable["ppp0"] = [
            RoutingTable.Route(destination: "10.20.0.0", prefixLength: 16, interface: "ppp0"),
            RoutingTable.Route(destination: "10.212.134.200", prefixLength: 32, interface: "ppp0"),   // its own address
            RoutingTable.Route(destination: "192.0.2.77", prefixLength: 32, interface: "ppp0"),      // a real host route
        ]
        let m = makeManager()
        try await m.connect(office.id)
        XCTAssertEqual(ProfileNetwork.savedOptions(office, store: store),
                       ["dhcp-option DNS 198.51.100.53", "dhcp-option DNS 198.51.100.54", "dhcp-option DOMAIN example.com",
                        "route 10.20.0.0 255.255.0.0", "route 192.0.2.77 255.255.255.255"])

        // Another profile that sends part of the same network, and looks up a name inside its suffix.
        let lab = try makeOpenVPN("Lab", lines: "route 10.20.1.0 255.255.255.0\ndhcp-option DOMAIN-ROUTE corp.example.com\n")
        let found = try await m.checkCanStart(lab.id)
        XCTAssertEqual(found.first?.profileID, office.id)
        XCTAssertEqual(found.first?.summary.routes.map(\.description), ["10.20.1.0/24"])
        XCTAssertEqual(found.first?.summary.domains, ["corp.example.com"])
        // And a Forti profile is checked before it connects, like any other.
        try await m.disconnect(office.id)
        try await m.connect(lab.id)
        let reverse = try await m.checkCanStart(office.id)
        XCTAssertEqual(reverse.first?.profileID, lab.id)
    }

    func testFortiGateOnlyClaimsWhatItSets() async throws {
        let office = try makeForti(setDNS: false, setRoutes: false)
        helper.startLog = Self.fortiUp
        tunnelTable["ppp0"] = [RoutingTable.Route(destination: "10.20.0.0", prefixLength: 16, interface: "ppp0")]
        let m = makeManager()
        try await m.connect(office.id)
        XCTAssertEqual(ProfileNetwork.savedOptions(office, store: store), [], "it changes neither DNS nor routes")
    }

    func testFortiGateDefaultRouteIsAFullTunnel() async throws {
        let office = try makeForti(setDNS: false)
        helper.startLog = Self.fortiUp
        tunnelTable["ppp0"] = [RoutingTable.Route(destination: "0.0.0.0", prefixLength: 0, interface: "ppp0")]
        let m = makeManager()
        try await m.connect(office.id)
        let claims = ProfileNetwork.claims(for: office, store: store, live: true) { _ in [] }
        XCTAssertTrue(claims.fullTunnel)
        let lab = try makeOpenVPN("Lab", lines: "route 10.0.0.0 255.0.0.0\n")
        let found = try await m.checkCanStart(lab.id)
        XCTAssertEqual(found.first?.summary.secondTakesAllTraffic, true)
    }
}
