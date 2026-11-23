import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelShared

/// What the app does with the Mac's DNS after an OpenVPN session: the helper's notes in the profile's log go into
/// the activity, and a server name that is not found while a VPN's DNS is left behind says so
/// (`ConnectionManager+DNS`, `DNSLeftBehind`).
extension ConnectionManagerTests {
    static let wifiLeft = DNSLeftBehind(service: "Wi-Fi", servers: ["10.8.0.1"])
    static let notFoundLog =
        "2026-10-25 09:41:00 RESOLVE: Cannot resolve host address: vpn.example.com:1194 (nodename nor servname provided, or not known)\n"

    func testANameNotFoundWithAVPNsDNSLeftBehindSaysSo() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        m.leftBehindDNS = { [Self.wifiLeft] }
        helper.openVPNStateLine = nil
        helper.startLog = Self.notFoundLog
        do { try await m.connect(p.id); XCTFail("connected") } catch {}
        let failure = try XCTUnwrap(m.failures[p.id])
        XCTAssertEqual(failure.kind, .hostNotFound)
        XCTAssertEqual(failure.dnsLeftBehind, Self.wifiLeft)
        XCTAssertEqual(
            failure.details,
            "This Mac’s DNS still points to a VPN’s DNS server (10.8.0.1 on Wi-Fi), which only that VPN can reach, so no name can be found. Restarting the Mac sets it back."
        )
        let kinds = m.activity(p.id).map(\.kind)
        XCTAssertEqual(kinds.suffix(2).first, .dnsLeftBehind(service: "Wi-Fi", settings: ["10.8.0.1"]))
        guard case .failed(.hostNotFound, _, _)? = kinds.last else { return XCTFail("\(kinds)") }

        let json = try XCTUnwrap(try AutomationJSON.object(failure) as? [String: Any])
        let dns = try XCTUnwrap(json["dns_left_behind"] as? [String: Any])
        XCTAssertEqual(dns["service"] as? String, "Wi-Fi")
        XCTAssertEqual(dns["servers"] as? [String], ["10.8.0.1"])
        let details = FailureDetails(
            profileName: p.name, server: "", failure: failure, network: NetworkStatus(online: true, interface: .wifi),
            app: AppInfo(
                version: "1", build: nil, appPath: "/Applications/PassTunnel.app"), at: t0
        ).text(timeZone: TimeZone(identifier: "UTC")!)
        XCTAssertTrue(details.contains(Self.wifiLeft.sentence))
    }

    /// Only a name that is not found asks; without anything left behind, nothing is added.
    func testOtherFailuresDoNotLookAtTheDNS() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        var asked = 0
        m.leftBehindDNS = {
            asked += 1
            return []
        }
        helper.openVPNStateLine = nil
        helper.startLog = Self.notFoundLog
        do { try await m.connect(p.id); XCTFail("connected") } catch {}
        XCTAssertEqual(asked, 1)
        XCTAssertNil(m.failures[p.id]?.dnsLeftBehind)
        XCTAssertFalse(m.activity(p.id).contains { if case .dnsLeftBehind = $0.kind { return true } else { return false } })
        helper.failStarts = 1
        do { try await m.connect(p.id); XCTFail("connected") } catch {}
        XCTAssertEqual(asked, 1)
    }

    /// The helper's notes: those of the start (before the tool ran) when the connect ends, those of the end after
    /// the disconnect; each once, also when another process looks again.
    func testTheHelpersDNSNotesGoIntoTheActivity() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        let earlier = OpenVPNDNS.Note(.restored, service: "Wi-Fi", settings: ["10.8.0.1"])
        let left = OpenVPNDNS.Note(.leftBehind, service: "Ethernet", settings: ["10.9.0.1"])
        helper.startLog = earlier.line + "\n" + left.line + "\n"
        try await m.connect(p.id)
        let atConnect = m.activity(p.id).map(\.kind)
        XCTAssertEqual(
            atConnect.suffix(3),
            [
                .dnsRestored(service: "Wi-Fi", settings: ["10.8.0.1"]), .dnsLeftBehind(service: "Ethernet", settings: ["10.9.0.1"]),
                .connected(address: "10.8.0.6")
            ])

        // The session ends: the helper writes what it gave back before it answers the stop.
        let handle = try FileHandle(forWritingTo: store.logURL(p.id))
        _ = try handle.seekToEnd()
        try handle.write(contentsOf: Data((OpenVPNDNS.Note(.restored, service: "Wi-Fi", settings: ["10.8.0.1"]).line + "\n").utf8))
        try handle.close()
        try await m.disconnect(p.id)
        let atEnd = m.activity(p.id).map(\.kind)
        XCTAssertEqual(atEnd.count, atConnect.count + 2)
        XCTAssertEqual(atEnd.suffix(2), [.disconnectedByUser, .dnsRestored(service: "Wi-Fi", settings: ["10.8.0.1"])])

        let cli = ConnectionManager(store: store, helper: helper, clock: clock)
        cli.recordDNSNotes(p.id)
        XCTAssertEqual(cli.activity(p.id).map(\.kind), atEnd, "nothing twice")
    }

    func testUnrecordedCountsEachOnce() {
        let a = ActivityEvent.Kind.dnsRestored(service: "Wi-Fi", settings: ["10.8.0.1"])
        let b = ActivityEvent.Kind.dnsLeftBehind(service: "Wi-Fi", settings: ["10.8.0.1"])
        let events = [a, acme, a].map { ActivityEvent(at: t0, $0) }
        XCTAssertEqual(ConnectionManager.unrecorded([a, a, b], in: events), [a, b], "only what follows the last connect counts")
        XCTAssertEqual(ConnectionManager.unrecorded([a], in: []), [a])
        XCTAssertEqual(
            ConnectionManager.dnsEvents(in: OpenVPNDNS.Note(.notRestored, service: "Wi-Fi", settings: ["10.8.0.1"], reason: "x").line), [b])
    }
}
