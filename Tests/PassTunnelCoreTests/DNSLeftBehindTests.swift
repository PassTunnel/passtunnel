import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelShared

/// What the app does with the Mac's DNS after an OpenVPN session: the helper's notes in the profile's log go into
/// the activity, and a server name that is not found while a VPN's DNS is left behind says so
/// (`ConnectionManager+DNS`, `DNSLeftBehind`).
extension ConnectionManagerTests {
    static let wifiLeft = DNSLeftBehind(service: "Wi-Fi", servers: ["10.8.0.1"], inEffect: true)
    static let unusedLeft = DNSLeftBehind(service: "USB LAN", servers: ["10.7.0.1"], inEffect: false)

    // MARK: with the last known server address (#292)

    /// The name is not found while a VPN's DNS is left on the service the Mac uses, and the try at the server's last
    /// known address fails too: the failure is `host_not_found` with both what was tried and the DNS behind it, in
    /// the message, the card's lines, Copy details and the JSON; the activity says the DNS once, before the try.
    func testALeftoverAndAFailedTryAtTheLastKnownAddress() async throws {
        let r = try await connectedOnce()
        r.manager.leftBehindDNS = { [Self.wifiLeft] }
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.output(status: 1, stderr: Out.refused)]
        do { try await r.manager.connect(r.profile.id); XCTFail("connected") } catch {}
        let failure = try XCTUnwrap(r.manager.failures[r.profile.id])
        XCTAssertEqual(failure.kind, .hostNotFound)
        XCTAssertEqual(failure.lastKnownAddress, tried(.unreachable, "Connection refused"))
        XCTAssertEqual(failure.dnsLeftBehind, Self.wifiLeft)
        XCTAssertEqual(failure.details, Self.wifiLeft.sentence)
        XCTAssertTrue(
            try XCTUnwrap(r.manager.lastError[r.profile.id]).contains("Check the network connection and its DNS"),
            "the try's own words point at the DNS too: no contradiction")

        let details = try XCTUnwrap(r.manager.failureDetails(r.profile.id)).text(timeZone: TimeZone(identifier: "UTC")!)
        let triedLine = try XCTUnwrap(details.range(of: "Tried instead: the last known address 192.0.2.10"))
        let dnsLine = try XCTUnwrap(details.range(of: Self.wifiLeft.sentence))
        XCTAssertLessThan(triedLine.lowerBound, dnsLine.lowerBound)

        let json = try XCTUnwrap(try AutomationJSON.object(failure) as? [String: Any])
        XCTAssertNotNil(json["last_known_address"])
        XCTAssertEqual((json["dns_left_behind"] as? [String: Any])?["service"] as? String, "Wi-Fi")

        let kinds = r.manager.activity(r.profile.id).map(\.kind)
        let since = kinds.suffix(from: try XCTUnwrap(kinds.lastIndex { if case .connecting = $0 { return true } else { return false } }))
        let left = ActivityEvent.Kind.dnsLeftBehind(service: "Wi-Fi", settings: ["10.8.0.1"])
        XCTAssertEqual(since.filter { $0 == left }.count, 1, "once, though the failure carries it as well: \(since)")
        let leftAt = try XCTUnwrap(since.firstIndex(of: left))
        let tryingAt = try XCTUnwrap(since.firstIndex { if case .tryingLastKnownAddress = $0 { return true } else { return false } })
        XCTAssertLessThan(leftAt, tryingAt)
        XCTAssertEqual(since.last, .lastKnownAddressFailed(tried(.unreachable, "Connection refused")))
    }

    /// The try at the last known address connects while the VPN's DNS is still left behind: no failure, and the
    /// activity says the DNS once, before the try and the connection through the address.
    func testALeftoverAndAConnectionThroughTheLastKnownAddress() async throws {
        let r = try await connectedOnce()
        r.manager.leftBehindDNS = { [Self.wifiLeft] }
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.success]
        try await r.manager.connect(r.profile.id)
        XCTAssertNil(r.manager.failures[r.profile.id])
        let kinds = r.manager.activity(r.profile.id).map(\.kind)
        let since = Array(kinds.suffix(from: try XCTUnwrap(kinds.lastIndex { if case .connecting = $0 { return true } else { return false } })))
        let left = ActivityEvent.Kind.dnsLeftBehind(service: "Wi-Fi", settings: ["10.8.0.1"])
        XCTAssertEqual(since.filter { $0 == left }.count, 1, "\(since)")
        XCTAssertEqual(since.last, .connected(address: "10.11.0.2", viaLastKnownAddress: "192.0.2.10"))

        // Ended and connected again the same way: once per connect.
        try await r.manager.disconnect(r.profile.id)
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.success]
        try await r.manager.connect(r.profile.id)
        XCTAssertEqual(r.manager.activity(r.profile.id).map(\.kind).filter { $0 == left }.count, 2)
    }

    /// A leftover on a service the Mac does not use now explains nothing: it is not attached, and its sentence says
    /// it is not in use.
    func testOnlyALeftoverInEffectExplainsANameNotFound() async throws {
        let p = try makeOpenVPN()
        let m = makeManager()
        m.leftBehindDNS = { [Self.unusedLeft] }
        helper.openVPNStateLine = nil
        helper.startLog = Self.notFoundLog
        do { try await m.connect(p.id); XCTFail("connected") } catch {}
        XCTAssertNil(m.failures[p.id]?.dnsLeftBehind)
        m.leftBehindDNS = { [Self.unusedLeft, Self.wifiLeft] }
        do { try await m.connect(p.id); XCTFail("connected") } catch {}
        XCTAssertEqual(m.failures[p.id]?.dnsLeftBehind, Self.wifiLeft)
        XCTAssertEqual(
            Self.unusedLeft.sentence,
            "USB LAN still has a VPN’s DNS server (10.7.0.1), which only that VPN can reach. It is not in use now; once it is, no name can be found. Restarting the Mac sets it back."
        )
    }

    /// The notes are read from OpenVPN logs only (openfortivpn prints a gateway's words into its log), and only
    /// around the tool's own lines.
    func testNotesOnlyFromOpenVPNLogsAndAroundTheToolsLines() async throws {
        let forti = try makeForti()
        let note = OpenVPNDNS.Note(.restored, service: "Wi-Fi", settings: ["10.8.0.1"])
        try Data((note.line + "\n").utf8).write(to: store.logURL(forti.id))
        let m = makeManager()
        m.recordDNSNotes(forti.id)
        XCTAssertEqual(m.activity(forti.id), [])

        let p = try makeOpenVPN()
        try Data(("2026-11-22 11:00:00 OpenVPN 2.7.9\n" + note.line + "\n2026-11-22 11:00:01 Initialization Sequence Completed\n").utf8)
            .write(to: store.logURL(p.id))
        m.recordDNSNotes(p.id)
        XCTAssertEqual(m.activity(p.id), [], "a line the tool printed")
    }
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
        XCTAssertEqual(dns["in_effect"] as? Bool, true)
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
