import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelShared
@testable import PassTunnelVPNConfig

/// #298: an OpenVPN profile whose server name cannot be resolved is tried at the address its server had at the last
/// connection by that name, through OpenVPN's remote query (`--management-query-remote`, `remote MOD`), with the
/// config's certificate checks unchanged.
extension ConnectionManagerTests {
    /// One named server and an explicit identity of it: the fallback applies.
    nonisolated static let knownAddressOVPN =
        "client\nremote vpn.example.com 1194\nremote-cert-tls server\nverify-x509-name vpn.example.com name\nauth-user-pass\n"
    nonisolated static let ovpnNotFound =
        "2026-11-20 09:41:00 RESOLVE: Cannot resolve host address: vpn.example.com:1194 (nodename nor servname provided, or not known)\n"
        + "2026-11-20 09:41:00 SIGTERM[soft,init_instance] received, process exiting\n"
    nonisolated static let ovpnRefused = "2026-11-20 09:41:00 TCP: connect to [AF_INET]203.0.113.5:1194 failed: Connection refused\n"

    /// A state line of a connection to `server`.
    func connectedLine(server: String) -> (Date) -> String {
        { "\(Int($0.timeIntervalSince1970)),CONNECTED,SUCCESS,10.8.0.6,\(server),1194,,," }
    }

    @discardableResult
    func makeKnownAddressOpenVPN(_ name: String = "Acme", config: String = ConnectionManagerTests.knownAddressOVPN) throws -> Profile {
        let p = try makeOpenVPN(name)
        try Data(config.utf8).write(to: store.ovpnURL(p.id))
        return p
    }

    /// An OpenVPN profile that connected once by its name (its OpenVPN reported 203.0.113.5) and is disconnected again.
    func openVPNConnectedOnce() async throws -> (profile: Profile, manager: ConnectionManager) {
        let p = try makeKnownAddressOpenVPN("Acme \(UUID().uuidString.prefix(8))")
        helper.openVPNStateLine = connectedLine(server: "203.0.113.5")
        let m = makeManager()
        try await m.connect(p.id)
        try await m.disconnect(p.id)
        clock.advance(3600)
        return (p, m)
    }

    func knownOpenVPN(_ p: Profile) -> LastKnownAddress.Entry? {
        LastKnownAddress.read(p, destination: ProfileDestination.of(p, store: store), store: store)
    }

    func openVPNStarts() -> [OpenVPNStart] {
        helper.starts.compactMap {
            if case .startOpenVPN(let s) = $0 { return s }
            return nil
        }
    }

    /// The first OpenVPN start after the profile connected once gets `firstLog`, later ones `laterLog`.
    func logs(first firstLog: String, later laterLog: String) {
        let helper = self.helper!
        var starts = 0
        helper.onStart = { _ in
            starts += 1
            helper.startLog = starts == 1 ? firstLog : laterLog
        }
    }

    // MARK: learning

    /// The server address OpenVPN reports for the connected state is kept, with the connection's time; the run by
    /// the name never asks for the remote.
    func testOpenVPNRemembersTheServerAddressItConnectedTo() async throws {
        let r = try await openVPNConnectedOnce()
        let entry = try XCTUnwrap(knownOpenVPN(r.profile))
        XCTAssertEqual(entry.host, "vpn.example.com")
        XCTAssertEqual(entry.address, "203.0.113.5")
        XCTAssertEqual(entry.confirmedAt.timeIntervalSinceNow, 0, accuracy: 5)
        XCTAssertEqual(openVPNStarts().map(\.queryRemote), [nil])
    }

    /// A config without an explicit identity of the server, with several servers, `<connection>` blocks, a proxy or an
    /// IP address learns nothing, and a file put in place is never used.
    func testOpenVPNConfigsThatDoNotFitLearnNothing() async throws {
        let configs = [
            "client\nremote vpn.example.com 1194\nauth-user-pass\n",
            "client\nremote vpn.example.com 1194\nremote-cert-tls server\nauth-user-pass\n",
            "client\nremote vpn.example.com 1194\nremote vpn2.example.com 1194\nremote-cert-tls server\n",
            "client\n<connection>\nremote vpn.example.com 1194\n</connection>\nremote-cert-tls server\n",
            "client\nremote vpn.example.com 1194\nhttp-proxy proxy.example.com 3128\nremote-cert-tls server\n",
            "client\nremote 192.0.2.10 1194\nremote-cert-tls server\n"
        ]
        for (index, config) in configs.enumerated() {
            let p = try makeKnownAddressOpenVPN("Acme \(index)", config: config)
            helper.openVPNStateLine = connectedLine(server: "203.0.113.5")
            let m = makeManager()
            try await m.connect(p.id)
            try await m.disconnect(p.id)
            XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(p.id, store: store).path), config)
            XCTAssertNil(LastKnownAddress.host(of: p, store: store), config)
        }
    }

    // MARK: the fallback

    /// The name is not found and nothing was sent: a second run asks OpenVPN for the remote, every question is
    /// answered with the remembered address and the port OpenVPN asked about, and it connects. The connection is
    /// marked, and the date stays the one of the last connection by the name.
    func testOpenVPNConnectsAtTheLastKnownAddressWhenTheNameIsNotFound() async throws {
        let r = try await openVPNConnectedOnce()
        let before = try XCTUnwrap(knownOpenVPN(r.profile))
        logs(first: Self.ovpnNotFound, later: "")
        helper.openVPNStateLine = connectedLine(server: "198.51.100.77")  // where the name would have gone
        try await r.manager.connect(r.profile.id)

        XCTAssertEqual(openVPNStarts().map(\.queryRemote), [nil, nil, true], "the name is looked up first")
        XCTAssertEqual(helper.remoteAnswers(r.profile.id), ["remote MOD 203.0.113.5 1194"])
        XCTAssertTrue(r.manager.state(r.profile.id).isConnected)
        let kinds = r.manager.activity(r.profile.id).map(\.kind)
        XCTAssertTrue(
            kinds.contains(.tryingLastKnownAddress(host: "vpn.example.com", address: "203.0.113.5", confirmedAt: before.confirmedAt)),
            "\(kinds)")
        XCTAssertEqual(kinds.last, .connected(address: "10.8.0.6", viaLastKnownAddress: "203.0.113.5"))
        XCTAssertEqual(r.manager.notices(r.profile.id), [.connectedThroughLastKnownAddress])
        XCTAssertEqual(knownOpenVPN(r.profile), before, "a connection at the address confirms nothing")
        XCTAssertNil(r.manager.failures[r.profile.id])
        let status = AutomationService(store: store, manager: r.manager).status(try store.get(r.profile.id))
        XCTAssertEqual(status.notices?.map(\.kind), ["connected_through_last_known_address"])
    }

    /// The name resolves: one run, no question, nothing about it in the activity, and the address it used replaces
    /// the remembered one with the new date.
    func testOpenVPNNothingChangesWhenTheNameResolves() async throws {
        let r = try await openVPNConnectedOnce()
        helper.openVPNStateLine = connectedLine(server: "198.51.100.77")
        try await r.manager.connect(r.profile.id)
        XCTAssertEqual(openVPNStarts().map(\.queryRemote), [nil, nil])
        XCTAssertEqual(helper.remoteAnswers(r.profile.id), [])
        XCTAssertEqual(r.manager.activity(r.profile.id).last?.kind, .connected(address: "10.8.0.6"))
        XCTAssertEqual(r.manager.notices(r.profile.id), [])
        XCTAssertEqual(knownOpenVPN(r.profile)?.address, "198.51.100.77")
    }

    /// Other failures, and a name that is not the profile's server, never try the address.
    func testOpenVPNOtherFailuresDoNotTryTheAddress() async throws {
        let r = try await openVPNConnectedOnce()
        helper.openVPNStateLine = { "\(Int($0.timeIntervalSince1970)),CONNECTING,,,,,,," }
        let other = Self.ovpnNotFound.replacingOccurrences(of: "vpn.example.com", with: "other.example.com")
        for log in [Self.ovpnRefused, other] {
            let count = openVPNStarts().count
            helper.startLog = log
            helper.onStart = nil
            do {
                try await r.manager.connect(r.profile.id)
                XCTFail("connected")
            } catch {}
            XCTAssertEqual(openVPNStarts().count, count + 1, log)
            XCTAssertNotNil(knownOpenVPN(r.profile), "kept")
        }
    }

    /// The try at the address cannot reach it either: `host_not_found` that says which address was tried and what
    /// happened there, in the error, the failure, the activity and "Copy details"; the address is kept.
    func testOpenVPNAFailedTryAtTheAddressExplainsItself() async throws {
        let r = try await openVPNConnectedOnce()
        let before = try XCTUnwrap(knownOpenVPN(r.profile))
        logs(first: Self.ovpnNotFound, later: Self.ovpnRefused)
        helper.openVPNStateLine = { "\(Int($0.timeIntervalSince1970)),CONNECTING,,,,,,," }
        do {
            try await r.manager.connect(r.profile.id)
            XCTFail("connected")
        } catch {
            guard case let .knownAddressFailed(server, tried, _)? = error as? PTError else { return XCTFail("\(error)") }
            XCTAssertEqual(server, "vpn.example.com:1194")
            XCTAssertEqual(
                tried, KnownAddressTry(address: "203.0.113.5", confirmedAt: before.confirmedAt, outcome: .unreachable, reason: "Connection refused"))
        }
        let failure = try XCTUnwrap(r.manager.failures[r.profile.id])
        XCTAssertEqual(failure.kind, .hostNotFound)
        XCTAssertFalse(failure.credentialsSent)
        XCTAssertEqual(failure.lastKnownAddress?.outcome, .unreachable)
        XCTAssertEqual(
            r.manager.activity(r.profile.id).last?.kind,
            .lastKnownAddressFailed(
                KnownAddressTry(address: "203.0.113.5", confirmedAt: before.confirmedAt, outcome: .unreachable, reason: "Connection refused")))
        let details = try XCTUnwrap(r.manager.failureDetails(r.profile.id)).text()
        XCTAssertTrue(details.contains("203.0.113.5"), details)
        XCTAssertNotNil(knownOpenVPN(r.profile), "an address that does not answer is kept")
    }

    /// A server at the address fails the config's certificate checks: the address is forgotten.
    func testOpenVPNACertificateFailureAtTheAddressForgetsIt() async throws {
        let r = try await openVPNConnectedOnce()
        let verify =
            "2026-11-20 09:41:01 VERIFY KU ERROR\n"
            + "2026-11-20 09:41:01 OpenSSL: error:0A000086:SSL routines::certificate verify failed\n"
            + "2026-11-20 09:41:01 TLS Error: TLS handshake failed\n"
        logs(first: Self.ovpnNotFound, later: verify)
        // The run at the address is told the address, fails its handshake there and gets no further.
        helper.openVPNStateLine = { "\(Int($0.timeIntervalSince1970)),CONNECTING,,,,,,," }
        do {
            try await r.manager.connect(r.profile.id)
            XCTFail("connected")
        } catch {
            guard case let .knownAddressFailed(_, tried, _)? = error as? PTError else { return XCTFail("\(error)") }
            XCTAssertEqual(tried.outcome, .certificateRefused)
        }
        XCTAssertNil(knownOpenVPN(r.profile))
        XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(r.profile.id, store: store).path))
    }

    /// A helper that predates the question ignores it: the second run goes by the name, nothing is recorded about the
    /// address, and its failure is the plain `host_not_found`.
    func testOpenVPNWithAnOlderHelperTheSecondRunGoesByTheName() async throws {
        let r = try await openVPNConnectedOnce()
        helper.knowsRemoteQuery = false
        logs(first: Self.ovpnNotFound, later: Self.ovpnNotFound)
        do {
            try await r.manager.connect(r.profile.id)
            XCTFail("connected")
        } catch {
            guard case .hostNotFound? = error as? PTError else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(openVPNStarts().map(\.queryRemote), [nil, nil, true])
        XCTAssertNil(r.manager.failures[r.profile.id]?.lastKnownAddress)
        XCTAssertFalse(
            r.manager.activity(r.profile.id).contains {
                if case .tryingLastKnownAddress = $0.kind { return true }; return false
            })
        XCTAssertNotNil(knownOpenVPN(r.profile))
    }

    /// No address is known (or the config does not fit): `host_not_found` after one run, as before.
    func testOpenVPNWithoutARememberedAddressTheFailureIsUnchanged() async throws {
        let p = try makeKnownAddressOpenVPN()
        helper.startLog = Self.ovpnNotFound
        let m = makeManager()
        do {
            try await m.connect(p.id)
            XCTFail("connected")
        } catch {
            guard case .hostNotFound? = error as? PTError else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(openVPNStarts().count, 1)
    }

    /// A run at the address that is told `remote ACCEPT` (here: the address was forgotten after it started) goes by the
    /// name: it is neither marked nor treated as a try at the address, and it learns what it connected to.
    func testOpenVPNARunNotToldTheAddressIsARunByTheName() async throws {
        let r = try await openVPNConnectedOnce()
        let helper = self.helper!, store = self.store, id = r.profile.id
        var starts = 0
        helper.onStart = { _ in
            starts += 1
            helper.startLog = starts == 1 ? Self.ovpnNotFound : ""
            if starts == 2 { LastKnownAddress.forget(id, store: store) }
        }
        helper.openVPNStateLine = connectedLine(server: "198.51.100.77")
        try await r.manager.connect(r.profile.id)
        XCTAssertEqual(openVPNStarts().map(\.queryRemote), [nil, nil, true])
        XCTAssertEqual(helper.remoteAnswers(r.profile.id), ["remote ACCEPT"])
        let kinds = r.manager.activity(r.profile.id).map(\.kind)
        XCTAssertFalse(
            kinds.contains {
                if case .tryingLastKnownAddress = $0 { return true }; return false
            }, "\(kinds)")
        XCTAssertEqual(kinds.last, .connected(address: "10.8.0.6"))
        XCTAssertEqual(r.manager.notices(r.profile.id), [])
        XCTAssertEqual(knownOpenVPN(r.profile)?.address, "198.51.100.77", "a connection by the name")
    }

    /// The address is learned only from the run this attempt started: when the helper no longer reports that process,
    /// the management socket's answer may be another run's, and nothing changes.
    func testOpenVPNLearnsOnlyFromTheRunItStarted() async throws {
        let r = try await openVPNConnectedOnce()
        helper.statusPID = 9999
        helper.openVPNStateLine = connectedLine(server: "198.51.100.77")
        try await r.manager.connect(r.profile.id)
        XCTAssertEqual(knownOpenVPN(r.profile)?.address, "203.0.113.5", "kept as it was")

        let fresh = try makeKnownAddressOpenVPN("Acme Fresh")
        try await makeManager().connect(fresh.id)
        XCTAssertNil(knownOpenVPN(fresh))
    }

    /// Only the resolver's own records count, and only in a log read whole: words in other lines (a server's `ECHO`)
    /// or a log too long to read whole never start a second run.
    func testOpenVPNOnlyTheResolversRecordsInAWholeLogFallBack() async throws {
        let r = try await openVPNConnectedOnce()
        let echoed =
            "2026-11-20 09:41:00 ECHO: RESOLVE: Cannot resolve host address: vpn.example.com:1194 (x)\n"
            + "2026-11-20 09:41:00 Exiting due to fatal error\n"
        let long = String(repeating: "2026-11-20 09:41:00 noise\n", count: 11_000) + Self.ovpnNotFound
        for log in [echoed, long] {
            let count = openVPNStarts().count
            helper.startLog = log
            helper.onStart = nil
            do {
                try await r.manager.connect(r.profile.id)
                XCTFail("connected")
            } catch {}
            XCTAssertEqual(openVPNStarts().count, count + 1, String(log.prefix(60)))
        }
        XCTAssertEqual(VPNLog.openVPNUnresolvedHosts(echoed), [])
    }

    // MARK: staleness, export, diagnose

    /// Another configuration (edited or imported) or another type drops the address; the profile's other settings do not.
    func testOpenVPNChangingTheServerDropsTheAddress() async throws {
        let r = try await openVPNConnectedOnce()
        _ = try store.update(r.profile.id) { $0.name = "Acme Renamed" }
        XCTAssertNotNil(knownOpenVPN(try store.get(r.profile.id)))
        try Data(Self.knownAddressOVPN.replacingOccurrences(of: "vpn.example.com", with: "vpn2.example.com").utf8)
            .write(to: store.ovpnURL(r.profile.id))
        XCTAssertNil(knownOpenVPN(try store.get(r.profile.id)), "another configuration: stale")

        let s = try await openVPNConnectedOnce()
        let file = URL(fileURLWithPath: home).appendingPathComponent("new.ovpn")
        try Data(Self.knownAddressOVPN.utf8).write(to: file)
        _ = try store.setOVPN(s.profile.id, from: file)
        XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(s.profile.id, store: store).path), "imported")

        let t = try await openVPNConnectedOnce()
        _ = try store.update(t.profile.id) {
            $0.type = .forti; $0.host = "vpn.example.com"
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(t.profile.id, store: store).path), "type")
    }

    /// The address stays on this computer; `diagnose` reports it.
    func testOpenVPNTheAddressIsNotExportedAndDiagnoseShowsIt() async throws {
        let r = try await openVPNConnectedOnce()
        let out = URL(fileURLWithPath: home).appendingPathComponent("export.passtunnel")
        try store.exportShare(r.profile.id, to: out)
        let text = String(decoding: try Data(contentsOf: out), as: UTF8.self)
        XCTAssertFalse(text.contains("203.0.113.5"), text)
        let imported = try store.importShare(out, name: "Acme Copy")
        XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(imported.id, store: store).path))

        let check = AutomationService(store: store, manager: r.manager).check(try store.get(r.profile.id))
        XCTAssertEqual(check.lastKnownAddress?.address, "203.0.113.5")
        XCTAssertEqual(check.lastKnownAddress?.host, "vpn.example.com")
    }

    // MARK: the answer

    /// `remote MOD` only for the remembered host, with the port OpenVPN asked about; `remote ACCEPT` otherwise.
    func testTheRemoteAnswer() async throws {
        let entry = LastKnownAddress.Entry(host: "vpn.example.com", address: "203.0.113.5", confirmedAt: t0)
        func query(_ host: String, _ port: String = "443") -> OpenVPNRemoteQuery { .init(host: host, port: port, proto: "tcp-client") }
        XCTAssertEqual(OpenVPNRemoteAnswer.command(for: query("vpn.example.com"), entry: entry), "remote MOD 203.0.113.5 443")
        XCTAssertEqual(OpenVPNRemoteAnswer.command(for: query("VPN.Example.com"), entry: entry), "remote MOD 203.0.113.5 443")
        XCTAssertEqual(OpenVPNRemoteAnswer.command(for: query("vpn2.example.com"), entry: entry), "remote ACCEPT")
        XCTAssertEqual(OpenVPNRemoteAnswer.command(for: query("vpn.example.com", "0"), entry: entry), "remote ACCEPT")
        XCTAssertEqual(OpenVPNRemoteAnswer.command(for: query("vpn.example.com", "x 1"), entry: entry), "remote ACCEPT")
        XCTAssertEqual(OpenVPNRemoteAnswer.command(for: query("vpn.example.com"), entry: nil), "remote ACCEPT")

        XCTAssertEqual(OpenVPNRemoteQuery(line: ">REMOTE:vpn.example.com,1194,udp"), query("vpn.example.com", "1194").with(proto: "udp"))
        XCTAssertEqual(OpenVPNRemoteQuery(line: ">REMOTE:2001:db8::1,443,tcp-client")?.host, "2001:db8::1")
        XCTAssertNil(OpenVPNRemoteQuery(line: ">STATE:1,CONNECTING,,,"))
        XCTAssertNil(OpenVPNRemoteQuery(line: ">REMOTE:,1194,udp"))
        // Every question is answered: one OpenVPN cut short (a long host) with ACCEPT; other lines are not questions.
        let mod: (OpenVPNRemoteQuery) -> String = { _ in "remote MOD 203.0.113.5 1194" }
        XCTAssertEqual(OpenVPNRemoteQuery.answer(to: ">REMOTE:vpn.example.com,1194,udp", with: mod), "remote MOD 203.0.113.5 1194")
        XCTAssertEqual(OpenVPNRemoteQuery.answer(to: ">REMOTE:" + String(repeating: "a", count: 247), with: mod), "remote ACCEPT")
        XCTAssertNil(OpenVPNRemoteQuery.answer(to: ">STATE:1,CONNECTING,,,", with: mod))
        XCTAssertEqual(OpenVPNRemoteAnswer.command(for: query("vpn.example.com", "https"), entry: entry), "remote ACCEPT")

        // By the socket's session directory: the profile's file decides, whatever process asks.
        let r = try await openVPNConnectedOnce()
        let answer = OpenVPNRemoteAnswer(store: store)
        let socket = PT.mgmtSocketPath(uid: getuid(), profileID: r.profile.id)
        OpenVPNRemoteAnswer.clearRecord(r.profile.id, store: store)
        XCTAssertEqual(answer.command(for: query("other.example.com", "1194"), socketPath: socket), "remote ACCEPT")
        XCTAssertNil(OpenVPNRemoteAnswer.recordedAddress(r.profile.id, store: store), "ACCEPT is not recorded")
        XCTAssertEqual(answer.command(for: query("vpn.example.com", "1194"), socketPath: socket), "remote MOD 203.0.113.5 1194")
        XCTAssertEqual(OpenVPNRemoteAnswer.recordedAddress(r.profile.id, store: store), "203.0.113.5", "MOD is recorded first")
        XCTAssertEqual(answer.command(for: query("vpn.example.com", "1194"), socketPath: "/tmp/nobody/mgmt.sock"), "remote ACCEPT")
    }

    /// Which configs fit, and why the others do not.
    func testWhichOpenVPNConfigsFit() {
        let id = "verify-x509-name vpn.example.com name\n"
        let one = OVPNAnalyzer.Server(host: "vpn.example.com", port: "1194", tcp: false)
        let cases: [(String, OVPNAnalyzer.KnownAddressFit)] = [
            ("remote vpn.example.com 1194\n" + id, .fits(one)),
            ("remote vpn.example.com 1194\nverify-x509-name \"C=US, CN=vpn.example.com\"\n", .fits(one)),
            ("remote vpn.example.com 1194\nverify-x509-name vpn.example.com subject\n", .fits(one)),
            ("remote vpn.example.com 443 tcp\nremote-random\n" + id, .fits(.init(host: "vpn.example.com", port: "443", tcp: true))),
            ("remote vpn.example.com\n<peer-fingerprint>\nAB:CD\n</peer-fingerprint>\n", .fits(one)),
            ("remote vpn.example.com\npeer-fingerprint AB:CD\n", .fits(one)),
            ("remote vpn.example.com\nsetenv opt verify-x509-name vpn.example.com name\n", .fits(one)),
            ("--remote vpn.example.com\n--verify-x509-name vpn.example.com name\n", .fits(one)),
            // Roles, not this server: any server of the CA has them.
            ("remote vpn.example.com 1194\nremote-cert-tls server\n", .noPeerIdentity),
            ("remote vpn.example.com\nremote-cert-eku \"TLS Web Server Authentication\"\n", .noPeerIdentity),
            ("remote vpn.example.com\nverify-x509-name vpn name-prefix\n", .noPeerIdentity),
            // Spellings OpenVPN refuses or ignores never count.
            ("remote vpn.example.com\nVERIFY-X509-NAME vpn.example.com name\n", .noPeerIdentity),
            ("remote vpn.example.com\nignore-unknown-option VERIFY-X509-NAME\nVERIFY-X509-NAME vpn.example.com name\n", .noPeerIdentity),
            ("remote vpn.example.com\nsetenv opt VERIFY-X509-NAME vpn.example.com name\n", .noPeerIdentity),
            ("remote vpn.example.com\n<Peer-Fingerprint>\nAB:CD\n</Peer-Fingerprint>\n", .noPeerIdentity),
            ("remote vpn.example.com 1194\n", .noPeerIdentity),
            ("remote vpn.example.com 1194\n# verify-x509-name vpn.example.com name\n", .noPeerIdentity),
            ("client\n" + id, .noRemote),
            ("REMOTE vpn.example.com\n" + id, .noRemote),
            ("remote a.example.com\nremote b.example.com\n" + id, .severalRemotes),
            ("remote a.example.com\nREMOTE b.example.com\n" + id, .severalRemotes),
            ("<connection>\nremote vpn.example.com\n</connection>\n" + id, .connectionBlocks),
            ("remote vpn.example.com\n<connection>\nremote vpn.example.com\n</connection>\n" + id, .connectionBlocks),
            ("remote vpn.example.com\nsocks-proxy 192.0.2.1 1080\n" + id, .proxy),
            ("remote vpn.example.com\nHTTP-PROXY 192.0.2.1 3128\n" + id, .proxy),
            ("remote vpn.example.com\nremote-random-hostname\n" + id, .randomHostname),
            ("remote vpn.example.com\npreresolve\n" + id, .resolvesFirst),
            ("remote vpn.example.com\nip-remote-hint 192.0.2.1\n" + id, .resolvesFirst),
            ("remote vpn.example.com https\n" + id, .portNotNumeric),
            ("remote vpn.example.com 01194\n" + id, .portNotNumeric),
            ("remote \(String(repeating: "a", count: 190)).example.com\n" + id, .hostTooLong)
        ]
        for (config, fit) in cases {
            XCTAssertEqual(OVPNAnalyzer.knownAddressFit(config), fit, config)
        }
    }

    /// What OpenVPN's log says about names it could not resolve, and about a server that failed the checks.
    func testOpenVPNLogLines() {
        XCTAssertEqual(VPNLog.openVPNUnresolvedHosts(Self.ovpnNotFound), ["vpn.example.com"])
        XCTAssertEqual(VPNLog.openVPNUnresolvedHosts(Self.ovpnRefused), [])
        XCTAssertNil(VPNLog.openVPNPeerCheckFailure(Self.ovpnRefused))
        XCTAssertEqual(
            VPNLog.openVPNPeerCheckFailure("2026-11-20 09:41:01 VERIFY ERROR: depth=0, error=certificate has expired: CN=vpn\n"),
            "certificate has expired")
        XCTAssertEqual(VPNLog.openVPNPeerCheckFailure("VERIFY X509NAME ERROR: CN=other, must be vpn.example.com\n"), "VERIFY X509NAME ERROR")
        XCTAssertEqual(ConnectionManager.plainAddress("::ffff:192.0.2.10"), "192.0.2.10")
        XCTAssertEqual(ConnectionManager.plainAddress("2001:db8::1"), "2001:db8::1")
    }
}

extension OpenVPNRemoteQuery {
    fileprivate func with(proto: String) -> OpenVPNRemoteQuery {
        var copy = self
        copy.proto = proto
        return copy
    }
}

// MARK: - The management clients

extension ManagementSocketTests {
    /// A one-shot client answers a pending `>REMOTE:` question after its command, reads the command's reply, then the
    /// answer's, so OpenVPN has it before the connection closes. Without an answer it only reads the reply.
    func testAOneShotClientAnswersTheRemoteQuestion() throws {
        var answered: String?
        let server = FakeManagementServer(
            path: sockPath,
            handlers: [
                { fd in
                    FakeManagementServer.send(fd, FakeManagementServer.banner + ">REMOTE:vpn.example.com,1194,udp\r\n")
                    XCTAssertEqual(FakeManagementServer.readLine(fd), "state")
                    FakeManagementServer.send(fd, "1700000000,CONNECTING,,,,,,,\r\nEND\r\n")
                    answered = FakeManagementServer.readLine(fd)
                    FakeManagementServer.send(fd, "SUCCESS: remote command succeeded\r\n")
                },
                { fd in
                    FakeManagementServer.send(fd, FakeManagementServer.banner + ">REMOTE:vpn.example.com,1194,udp\r\n")
                    XCTAssertEqual(FakeManagementServer.readLine(fd), "state")
                    FakeManagementServer.send(fd, "1700000000,CONNECTING,,,,,,,\r\nEND\r\n")
                }
            ])
        waitForSocket()
        var socket = ManagementSocket(path: sockPath)
        socket.remoteAnswer = { "remote MOD 203.0.113.5 \($0.port)" }
        XCTAssertEqual(try socket.state().name, "CONNECTING")
        socket.remoteAnswer = nil
        XCTAssertEqual(try socket.state().name, "CONNECTING")
        server.wait()
        XCTAssertEqual(answered, "remote MOD 203.0.113.5 1194")
    }
}

extension PersistentManagementQuerierTests {
    /// A held connection that ends while a question is pending is replaced by the next query, and OpenVPN's question
    /// (repeated after the new banner) is answered there; a question that cannot be read gets `remote ACCEPT`.
    func testAQuestionLeftOnAnEndedConnectionIsAnsweredOnTheNext() async throws {
        var answers: [String] = []
        let server = FakeManagementServer(
            path: sock,
            handlers: [
                { fd in
                    Self.open(fd, state: Self.auth)
                    FakeManagementServer.send(fd, ">REMOTE:" + String(repeating: "a", count: 247) + "\r\n")
                    answers.append(FakeManagementServer.readLine(fd))
                    FakeManagementServer.send(fd, ">REMOTE:vpn.example.com,1194,udp\r\n")
                    // Gone before the answer arrives.
                },
                { fd in
                    FakeManagementServer.send(fd, FakeManagementServer.banner + ">REMOTE:vpn.example.com,1194,udp\r\n")
                    XCTAssertEqual(FakeManagementServer.readLine(fd), "state on")
                    FakeManagementServer.send(fd, "SUCCESS: real-time state notification set to ON\r\n")
                    XCTAssertEqual(FakeManagementServer.readLine(fd), "state")
                    answers.append(FakeManagementServer.readLine(fd))
                    FakeManagementServer.send(fd, "SUCCESS: remote command succeeded\r\n" + Self.connected + "\r\nEND\r\n")
                    var b: UInt8 = 0
                    while read(fd, &b, 1) == 1 {}
                }
            ])
        waitForSocket()
        let q = PersistentManagementQuerier()
        q.remoteAnswer = OpenVPNRemoteAnswer(store: ProfileStore(paths: AppPaths(root: URL(fileURLWithPath: dir))))
        _ = try await q.state(socketPath: sock, timeout: 2)
        _ = try await eventually(q, "CONNECTED")
        q.releaseAll()
        server.wait()
        XCTAssertEqual(answers, ["remote ACCEPT", "remote ACCEPT"])
    }

    /// The app's held connection answers the question when it opens (OpenVPN repeats a pending one after the banner)
    /// and when it comes later, on every try.
    func testTheHeldConnectionAnswersEveryRemoteQuestion() async throws {
        var answers: [String] = []
        let done = DispatchSemaphore(value: 0)
        let server = FakeManagementServer(
            path: sock,
            handlers: [
                { fd in
                    FakeManagementServer.send(fd, FakeManagementServer.banner + ">REMOTE:vpn.example.com,1194,udp\r\n")
                    XCTAssertEqual(FakeManagementServer.readLine(fd), "state on")
                    FakeManagementServer.send(fd, "SUCCESS: real-time state notification set to ON\r\n")
                    XCTAssertEqual(FakeManagementServer.readLine(fd), "state")
                    answers.append(FakeManagementServer.readLine(fd))  // answered while it opens
                    FakeManagementServer.send(fd, "SUCCESS: remote command succeeded\r\n" + Self.auth + "\r\nEND\r\n")
                    FakeManagementServer.send(fd, ">REMOTE:vpn.example.com,443,tcp-client\r\n")
                    answers.append(FakeManagementServer.readLine(fd))
                    done.signal()
                    var b: UInt8 = 0
                    while read(fd, &b, 1) == 1 {}
                }
            ])
        waitForSocket()
        let q = PersistentManagementQuerier()
        let store = ProfileStore(paths: AppPaths(root: URL(fileURLWithPath: dir)))
        q.remoteAnswer = OpenVPNRemoteAnswer(store: store)
        _ = try await q.state(socketPath: sock, timeout: 2)
        XCTAssertEqual(done.wait(timeout: .now() + 3), .success)
        q.releaseAll()
        server.wait()
        XCTAssertEqual(answers, ["remote ACCEPT", "remote ACCEPT"], "no profile, no address: as without the question")
    }
}

// MARK: - The helper

extension HelperMessageTests {
    /// `--management-query-remote` only when the start asks for it, right after the management options; the request
    /// carries a flag and no text, and an older request (or helper) without the key is unchanged.
    func testTheRemoteQueryIsAFlagOfTheStartRequest() throws {
        let plain = HelperCore.openVPNArguments(configPath: "/c", mgmtSocket: "/s", clientUser: "alice", authFile: nil, dnsUpdown: nil)
        XCTAssertFalse(plain.contains("--management-query-remote"))
        let asking = HelperCore.openVPNArguments(
            configPath: "/c", mgmtSocket: "/s", clientUser: "alice", authFile: nil, dnsUpdown: nil, queryRemote: true)
        let user = try XCTUnwrap(asking.firstIndex(of: "--management-client-user"))
        XCTAssertEqual(Array(asking[user...].prefix(3)), ["--management-client-user", "alice", "--management-query-remote"])
        XCTAssertEqual(asking.filter { $0 != "--management-query-remote" }, plain, "nothing else changes")

        let start = OpenVPNStart(profileID: "acme", profileDir: "/d", logPath: "/d/vpn.log")
        let json = String(decoding: try HelperRequest.startOpenVPN(start).jsonData(), as: UTF8.self)
        XCTAssertFalse(json.contains("query_remote"), json)
        var asked = start
        asked.queryRemote = true
        let askedJSON = String(decoding: try HelperRequest.startOpenVPN(asked).jsonData(), as: UTF8.self)
        XCTAssertTrue(askedJSON.contains("\"query_remote\":true"), askedJSON)
        guard case .startOpenVPN(let decoded) = try HelperCore.decodeRequest(Data(askedJSON.utf8)) else { return XCTFail() }
        XCTAssertEqual(decoded.queryRemote, true)

        let reply = String(decoding: try HelperResponse.started(pid: 1, mgmtSocket: "/s", remoteQuery: true).jsonData(), as: UTF8.self)
        XCTAssertTrue(reply.contains("\"remote_query\":true"), reply)
        let old = String(decoding: try HelperResponse.started(pid: 1, mgmtSocket: "/s", remoteQuery: false).jsonData(), as: UTF8.self)
        XCTAssertFalse(old.contains("remote_query"), old)
        XCTAssertNil(try HelperResponse(jsonData: Data(old.utf8)).remoteQuery)
    }
}

#if os(macOS)
extension HelperCoreTests {
    /// The plan of a start that asks for the remote query has the flag and says so (`HelperResponse.remoteQuery`).
    func testPrepareOpenVPNWithTheRemoteQuery() throws {
        var start = openVPNStart()
        start.queryRemote = true
        let plan = try core().prepareOpenVPN(start, uid: me)
        defer { close(plan.logFD); core().removeRunDir(profileID: "acme", uid: me) }
        XCTAssertTrue(plan.queriesRemote)
        XCTAssertEqual(plan.arguments.filter { $0 == "--management-query-remote" }.count, 1)
        core().removeRunDir(profileID: "acme", uid: me)
        let plain = try core().prepareOpenVPN(openVPNStart(), uid: me)
        defer { close(plain.logFD) }
        XCTAssertFalse(plain.queriesRemote)
        XCTAssertFalse(plain.arguments.contains("--management-query-remote"))
    }
}
#endif
