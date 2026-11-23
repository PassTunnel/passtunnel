import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelShared
@testable import PassTunnelVPNConfig

/// #292: a profile whose server name cannot be resolved is tried at the address its server had at the last
/// successful connection (`LastKnownAddress`), with the certificate checked against the name as before.
extension ConnectionManagerTests {
    var knownAddressLine: String { "resolve vpn.example.com:192.0.2.10\n" }

    /// A Cisco AnyConnect profile that connected once by its name (192.0.2.10), and is disconnected again.
    func connectedOnce(pin: String = Out.pin) async throws -> (profile: Profile, manager: ConnectionManager, fake: FakeOpenConnect) {
        let p = try makeAnyConnect("Acme \(UUID().uuidString.prefix(8))", pin: pin)
        let fake = FakeOpenConnect()
        fake.results = [pin.isEmpty ? Out.output(stdout: Out.stdout(fingerprint: Out.otherPin), stderr: Out.signedIn) : Out.success]
        helper.startLog = Out.hookUp
        let m = try makeAnyConnectManager(fake)
        try await m.connect(p.id)
        try await m.disconnect(p.id)
        clock.advance(3600)
        return (p, m, fake)
    }

    func known(_ p: Profile) -> LastKnownAddress.Entry? {
        LastKnownAddress.read(p, destination: ProfileDestination.of(p, store: store), store: store)
    }

    // MARK: learning

    /// The address the sign-in printed (and the tunnel run used) is kept once the tunnel is up, with when; the file is
    /// the user's alone.
    func testASuccessfulConnectionRemembersTheAddressItUsed() async throws {
        let r = try await connectedOnce()
        let entry = try XCTUnwrap(known(r.profile))
        XCTAssertEqual(entry.host, "vpn.example.com")
        XCTAssertEqual(entry.address, "192.0.2.10")
        XCTAssertEqual(entry.learnedAt, t0)
        let url = store.dir(r.profile.id).appendingPathComponent(LastKnownAddress.fileName)
        let mode = try XCTUnwrap(FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber)
        XCTAssertEqual(mode.intValue, 0o600)
        #if os(macOS)
        XCTAssertFalse(ProfilesWatcher.isRelevant(path: url.path), "the app does not reload for it")
        #endif
    }

    /// A failed sign-in learns nothing.
    func testAFailedConnectLearnsNothing() async throws {
        let r = try await signInFailure(Out.output(status: 1, stderr: Out.refused))
        XCTAssertNil(known(r.profile))
        XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(r.profile.id, store: store).path))
    }

    // MARK: the fallback

    /// The name is not found: the sign-in runs again with the address for the name, and connects. The file differs
    /// from the first run's only by the `resolve` line, so the trust (pin or CA bundle) and the server name are the
    /// same; the code never reached a server, so the second run takes it again.
    func testConnectsAtTheLastKnownAddressWhenTheNameIsNotFound() async throws {
        let r = try await connectedOnce()
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.success]
        try await r.manager.connect(r.profile.id)

        let calls = r.fake.calls
        XCTAssertEqual(calls.count, 3)
        let byName = calls[1], atAddress = calls[2]
        XCTAssertFalse(byName.config.contains("resolve"), "the name is looked up first")
        XCTAssertTrue(atAddress.config.contains("server https://vpn.example.com:8443/engineering\n" + knownAddressLine), atAddress.config)
        XCTAssertEqual(atAddress.config.replacingOccurrences(of: knownAddressLine, with: ""), byName.config, "nothing else changes")
        XCTAssertTrue(atAddress.config.contains("servercert \(Out.pin)\n"))
        XCTAssertEqual(atAddress.input, byName.input, "the code that never left is used again")
        XCTAssertEqual(r.manager.usedCode(r.profile.id), .init(counter: TOTP.counter(params: r.profile.totp, at: clock.now()), period: 30))

        XCTAssertTrue(r.manager.state(r.profile.id).isConnected)
        XCTAssertEqual(openConnectStarts().last?.resolve, "vpn.example.com:192.0.2.10", "the tunnel run goes to the same address")
        let kinds = r.manager.activity(r.profile.id).map(\.kind)
        XCTAssertTrue(kinds.contains(.tryingLastKnownAddress(host: "vpn.example.com", address: "192.0.2.10")), "\(kinds)")
        XCTAssertEqual(kinds.last, .connected(address: "10.11.0.2", viaLastKnownAddress: "192.0.2.10"))
        XCTAssertEqual(r.manager.notices(r.profile.id), [.connectedThroughLastKnownAddress])
        XCTAssertEqual(known(r.profile)?.learnedAt, t0.addingTimeInterval(3600), "refreshed by the connection")
        XCTAssertNil(r.manager.failures[r.profile.id])
    }

    /// The name resolves: one run, no `resolve`, nothing in the activity about it, and the address the connection
    /// used now replaces the remembered one (a server that moved is picked up at once).
    func testNothingChangesWhenTheNameResolves() async throws {
        let r = try await connectedOnce()
        r.fake.results = [Out.output(stdout: Out.stdout(host: "192.0.2.99", resolve: "vpn.example.com:192.0.2.99"), stderr: Out.signedIn)]
        try await r.manager.connect(r.profile.id)
        XCTAssertEqual(r.fake.calls.count, 2)
        XCTAssertFalse(r.fake.calls[1].config.contains("resolve"))
        let kinds = r.manager.activity(r.profile.id).map(\.kind)
        XCTAssertFalse(
            kinds.contains {
                if case .tryingLastKnownAddress = $0 { return true }; return false
            })
        XCTAssertEqual(kinds.last, .connected(address: "10.11.0.2"))
        XCTAssertEqual(r.manager.notices(r.profile.id), [])
        XCTAssertEqual(known(r.profile)?.address, "192.0.2.99")
        XCTAssertEqual(known(r.profile)?.learnedAt, t0.addingTimeInterval(3600))
    }

    /// A profile that never connected fails with `host_not_found` as before, after one run.
    func testWithoutARememberedAddressTheFailureIsUnchanged() async throws {
        let r = try await signInFailure(Out.output(status: 1, stderr: Out.notFound))
        XCTAssertEqual(r.error as? PTError, .hostNotFound(server: "vpn.example.com:8443", log: VPNLog.tail(Out.notFound)))
        XCTAssertNil(r.failure.lastKnownAddress)
        XCTAssertEqual(r.manager.activity(r.profile.id).last?.kind, .failed(kind: .hostNotFound, reason: nil, credentialsSent: false))
    }

    /// The address does not answer either: `host_not_found` (the root cause) that says which address, from when, was
    /// tried and what it gave, in the error, the failure, the activity and "Copy details". The address is kept.
    func testAFailedTryAtTheAddressExplainsItself() async throws {
        let r = try await connectedOnce()
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.output(status: 1, stderr: Out.refused)]
        do {
            try await r.manager.connect(r.profile.id)
            XCTFail("connected")
        } catch {
            XCTAssertEqual(
                error as? PTError,
                .knownAddressFailed(
                    server: "vpn.example.com:8443", address: "192.0.2.10", learnedAt: t0, reason: "Connection refused",
                    certificateRefused: false, log: VPNLog.tail(Out.refused)))
            XCTAssertEqual(AutomationErrorCode.of(error), .hostNotFound)
            let text = error.localizedDescription
            XCTAssertTrue(text.contains("vpn.example.com:8443") && text.contains("192.0.2.10") && text.contains(PTError.dateText(t0)), text)
            XCTAssertTrue(text.contains("could not be found") && text.contains("did not answer"), text)
        }
        XCTAssertEqual(r.fake.calls.count, 3)
        let failure = try XCTUnwrap(r.manager.failures[r.profile.id])
        XCTAssertEqual(failure.kind, .hostNotFound)
        XCTAssertEqual(failure.reason, "Connection refused")
        XCTAssertFalse(failure.credentialsSent)
        XCTAssertEqual(failure.lastKnownAddress, .init(address: "192.0.2.10", learnedAt: t0, certificateRefused: false))
        XCTAssertNotNil(failure.lastKnownAddressSentence)
        XCTAssertEqual(r.manager.lastError[r.profile.id]?.contains("192.0.2.10"), true)
        XCTAssertEqual(
            r.manager.usedCode(r.profile.id), .init(counter: TOTP.counter(params: r.profile.totp, at: t0), period: 30),
            "the code never left: given back, the first connect's record stays")
        XCTAssertEqual(
            r.manager.activity(r.profile.id).last?.kind,
            .lastKnownAddressFailed(address: "192.0.2.10", learnedAt: t0, reason: "Connection refused", certificateRefused: false))
        let details = try XCTUnwrap(r.manager.failureDetails(r.profile.id)).text(timeZone: TimeZone(identifier: "UTC")!)
        XCTAssertTrue(details.contains("Result: The server name was not found\n"), details)
        XCTAssertTrue(details.contains("192.0.2.10"), details)
        XCTAssertNotNil(known(r.profile), "no answer is no reason to forget it")

        // The JSON of `status --json` and the MCP tools.
        let json = try XCTUnwrap(String(data: try JSONCoding.encode(failure), encoding: .utf8))
        XCTAssertTrue(json.contains("\"last_known_address\""), json)
        XCTAssertTrue(json.contains("\"certificate_refused\" : false"), json)
        XCTAssertEqual(try JSONCoding.decode(ConnectionFailure.self, from: Data(json.utf8)), failure)
    }

    /// A server at the address fails the certificate check: still `host_not_found`, the address is forgotten, and
    /// that server's key is not offered to be trusted.
    func testACertificateFailureAtTheAddressForgetsItAndOffersNoTrust() async throws {
        let r = try await connectedOnce(pin: "")
        XCTAssertNotNil(known(r.profile))
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.output(status: 1, stderr: Out.untrusted)]
        do {
            try await r.manager.connect(r.profile.id)
            XCTFail("connected")
        } catch {
            guard case .knownAddressFailed(_, "192.0.2.10", _, "signer not found", true, _)? = error as? PTError else {
                return XCTFail("\(error)")
            }
            XCTAssertTrue(error.localizedDescription.contains("forgotten"), error.localizedDescription)
        }
        XCTAssertTrue(r.fake.calls[2].config.contains("no-system-trust\ncafile "), "the CA bundle, as by the name")
        XCTAssertEqual(r.manager.failures[r.profile.id]?.kind, .hostNotFound)
        XCTAssertNil(r.manager.trustOffers[r.profile.id], "no Trust This Server for a server reached at the address")
        XCTAssertNil(known(r.profile))
        XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(r.profile.id, store: store).path))
        guard case .lastKnownAddressFailed(_, _, _, true)? = r.manager.activity(r.profile.id).last?.kind else {
            return XCTFail("\(String(describing: r.manager.activity(r.profile.id).last))")
        }
    }

    /// The server at the address refuses the sign-in: a rejection as any other (never retried), the address kept.
    func testARejectionAtTheAddressIsARejection() async throws {
        let r = try await connectedOnce()
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.output(status: 1, stderr: Out.rejected)]
        do {
            try await r.manager.connect(r.profile.id)
            XCTFail("connected")
        } catch {
            guard case .authFailed? = error as? PTError else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(r.fake.calls.count, 3, "no third run")
        XCTAssertEqual(r.manager.failures[r.profile.id]?.kind, .authRejected)
        XCTAssertNotNil(known(r.profile))
    }

    /// Only a name that was not found leads to the address: a server that did not answer by its name is not tried
    /// elsewhere.
    func testOtherFailuresDoNotTryTheAddress() async throws {
        let r = try await connectedOnce()
        r.fake.results = [Out.output(status: 1, stderr: Out.refused), Out.success]
        do {
            try await r.manager.connect(r.profile.id)
            XCTFail("connected")
        } catch {
            XCTAssertEqual(AutomationErrorCode.of(error), .serverUnreachable)
        }
        XCTAssertEqual(r.fake.calls.count, 2)
    }

    // MARK: staleness

    /// Changing the profile's server (host, port, pin) drops the address; other edits keep it.
    func testChangingTheServerDropsTheAddress() async throws {
        let r = try await connectedOnce()
        let url = LastKnownAddress.url(r.profile.id, store: store)
        _ = try store.update(r.profile.id) { $0.name = "Acme Renamed" }
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path), "not the server")
        _ = try store.update(r.profile.id) { $0.port = 9443 }
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path), "another port")

        let s = try await connectedOnce()
        _ = try store.update(s.profile.id) { $0.host = "vpn2.example.com" }
        XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(s.profile.id, store: store).path), "another host")

        let t = try await connectedOnce()
        _ = try store.update(t.profile.id) { $0.serverCert = Out.otherPin }
        XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(t.profile.id, store: store).path), "another pin")
    }

    /// A file written for another destination (the profile was edited by hand) is never used, and a connect removes it.
    func testAFileForAnotherDestinationIsNeverUsed() async throws {
        let r = try await connectedOnce()
        var edited = r.profile
        edited.host = "vpn3.example.com"
        try JSONCoding.write(edited, to: store.dir(r.profile.id).appendingPathComponent("profile.json"), mode: 0o600)
        XCTAssertNil(known(try store.get(r.profile.id)))
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound.replacingOccurrences(of: "vpn.example.com", with: "vpn3.example.com"))]
        do {
            try await r.manager.connect(r.profile.id)
            XCTFail("connected")
        } catch {
            XCTAssertEqual(AutomationErrorCode.of(error), .hostNotFound)
            guard case .hostNotFound? = error as? PTError else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(r.fake.calls.count, 2)
        XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(r.profile.id, store: store).path))
    }

    /// A file that is not the user's alone is ignored.
    func testAFileOthersCanReadIsIgnored() async throws {
        let r = try await connectedOnce()
        let url = LastKnownAddress.url(r.profile.id, store: store)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
        XCTAssertNil(known(r.profile))
    }

    // MARK: types, export, diagnose

    /// OpenVPN and FortiGate never learn or use an address, even from a file put in place.
    func testOpenVPNAndFortiGateHaveNoFallback() throws {
        XCTAssertTrue(LastKnownAddress.isSupported(.anyconnect))
        XCTAssertTrue(LastKnownAddress.isSupported(.globalprotect))
        XCTAssertFalse(LastKnownAddress.isSupported(.openvpn))
        XCTAssertFalse(LastKnownAddress.isSupported(.forti))
        var forti = try store.create(name: "Acme Forti", type: .forti)
        forti.host = "vpn.example.com"
        try store.save(forti)
        let destination = ProfileDestination.of(forti, store: store)
        LastKnownAddress.save("192.0.2.10", for: forti, destination: destination, store: store, at: t0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(forti.id, store: store).path))
        let saved = LastKnownAddress.Saved(
            version: LastKnownAddress.version, destination: destination.fingerprint, host: "vpn.example.com", address: "192.0.2.10",
            learnedAt: t0)
        try JSONCoding.write(saved, to: LastKnownAddress.url(forti.id, store: store), mode: 0o600)
        XCTAssertNil(LastKnownAddress.read(forti, destination: destination, store: store))
    }

    /// An IP-address host has nothing to look up: nothing is kept.
    func testAnIPAddressHostKeepsNothing() throws {
        var p = try makeAnyConnect("Acme Literal")
        p.host = "192.0.2.10"
        try store.save(p)
        LastKnownAddress.save("192.0.2.10", for: p, destination: ProfileDestination.of(p, store: store), store: store, at: t0)
        XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(p.id, store: store).path))
    }

    /// The address stays on this computer: an exported profile does not carry it.
    func testTheAddressIsNotExported() async throws {
        let r = try await connectedOnce()
        XCTAssertNotNil(known(r.profile))
        let out = URL(fileURLWithPath: home).appendingPathComponent("export.passtunnel")
        try store.exportShare(r.profile.id, to: out)
        let text = String(decoding: try Data(contentsOf: out), as: UTF8.self)
        XCTAssertFalse(text.contains("192.0.2.10"), text)
        XCTAssertFalse(text.contains("last_known") || text.contains(LastKnownAddress.fileName), text)
        let imported = try store.importShare(out, name: "Acme Copy")
        XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(imported.id, store: store).path))
    }

    /// `diagnose` reports the address and since when, read from the file only.
    func testDiagnoseShowsTheRememberedAddress() async throws {
        let r = try await connectedOnce()
        let check = AutomationService(store: store, manager: r.manager).check(try store.get(r.profile.id))
        XCTAssertEqual(check.lastKnownAddress, .init(host: "vpn.example.com", address: "192.0.2.10", learnedAt: t0))
        let json = try XCTUnwrap(String(data: try JSONCoding.encode(check), encoding: .utf8))
        XCTAssertTrue(json.contains("\"last_known_address\""), json)
        XCTAssertTrue(json.contains("\"learned_at\""), json)

        let fresh = try makeAnyConnect("Acme Fresh")
        XCTAssertNil(AutomationService(store: store, manager: r.manager).check(fresh).lastKnownAddress)
    }

    // MARK: Palo Alto GlobalProtect

    /// A gateway on the portal's host (here `skip_portal`): learned, and tried the same way.
    func testGlobalProtectOnTheProfilesHostConnectsAtTheLastKnownAddress() async throws {
        let p = try makeGlobalProtectProfile("Acme GP Skip", otp: .none, gateway: "", skipPortal: true)
        helper.startLog = GP.hipAndUp
        let signedIn =
            "POST https://vpn.example.com:8443/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac\n" + GP.portalTLS
            + "POST https://vpn.example.com:8443/ssl-vpn/login.esp\n"
        let stdout = GP.stdout(
            host: "192.0.2.10", connectURL: "https://vpn.example.com:8443/", fingerprint: GP.portalPin, resolve: "vpn.example.com:192.0.2.10")
        let notFound =
            "POST https://vpn.example.com:8443/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac\n"
            + "getaddrinfo failed for host 'vpn.example.com': nodename nor servname provided, or not known\n"
            + "Failed to open HTTPS connection to vpn.example.com\n" + GP.failed
        let fake = FakeOpenConnect()
        fake.results = [Out.output(stdout: stdout, stderr: signedIn)]
        let m = try makeGlobalProtectManager(fake)
        try await m.connect(p.id)
        XCTAssertEqual(known(p)?.address, "192.0.2.10")
        try await m.disconnect(p.id)
        clock.advance(3600)

        fake.results = [Out.output(status: 1, stderr: notFound), Out.output(stdout: stdout, stderr: signedIn)]
        try await m.connect(p.id)
        XCTAssertEqual(fake.calls.count, 3)
        XCTAssertFalse(fake.calls[1].config.contains("resolve"))
        XCTAssertTrue(fake.calls[2].config.contains("server https://vpn.example.com:8443/gateway\n" + knownAddressLine), fake.calls[2].config)
        XCTAssertEqual(fake.calls[2].config.replacingOccurrences(of: knownAddressLine, with: ""), fake.calls[1].config)
        XCTAssertEqual(m.activity(p.id).map(\.kind).last, .connected(address: "10.12.0.2", viaLastKnownAddress: "192.0.2.10"))
    }

    /// A gateway on another host than the portal's is not the server whose name a connect looks up first: nothing
    /// is learned.
    func testGlobalProtectGatewayElsewhereLearnsNothing() async throws {
        let p = try makeGlobalProtectProfile()
        helper.startLog = GP.hipAndUp
        let fake = FakeGlobalProtect(
            clock: clock, script: [.stderr(GP.untilSecondSignIn), .advance(4), .advance(6), .stderr(GP.afterSecondSignIn)],
            stdout: GP.stdout())
        let m = try makeGlobalProtectManager(fake)
        try await m.connect(p.id)
        XCTAssertTrue(m.state(p.id).isConnected)
        XCTAssertNil(known(p))
    }
}

// MARK: - Pure parts

final class LastKnownAddressUnitTests: XCTestCase {
    let at = Date(timeIntervalSince1970: 1_700_000_000)

    /// The sign-in file's `resolve` line: right after `server`, for that host only, an IP address only, never for an
    /// IP-address host; the trust lines are the same with it.
    func testTheSignInFileTakesTheAddressForTheNameOnly() throws {
        let plain = OpenConnectAuthConfig(host: "VPN.example.com", port: 8443, username: "alice", serverCert: examplePin)
        var withAddress = plain
        withAddress.resolveAddress = "192.0.2.10"
        let a = try plain.render(noExternalAuth: true)
        let b = try withAddress.render(noExternalAuth: true)
        XCTAssertEqual(
            b,
            a.replacingOccurrences(
                of: "server https://vpn.example.com:8443/\n", with: "server https://vpn.example.com:8443/\nresolve vpn.example.com:192.0.2.10\n"))
        withAddress.resolveAddress = "2001:db8::10"
        XCTAssertTrue(try withAddress.render(noExternalAuth: true).contains("resolve vpn.example.com:2001:db8::10\n"))

        var literal = OpenConnectAuthConfig(host: "192.0.2.10", username: "alice", resolveAddress: "192.0.2.10")
        XCTAssertThrowsError(try literal.render(noExternalAuth: true))
        literal.host = "vpn.example.com"
        literal.resolveAddress = "vpn2.example.com"
        XCTAssertThrowsError(try literal.render(noExternalAuth: true), "a name is no address")
        literal.resolveAddress = "192.0.2.10\nno-system-trust"
        XCTAssertThrowsError(try literal.render(noExternalAuth: true))
    }

    /// The final check refuses a `resolve` for another host, for an IP-address server, or out of place.
    func testTheCheckRefusesAResolveForAnotherHost() throws {
        let text = try OpenConnectAuthConfig(host: "vpn.example.com", username: "alice", resolveAddress: "192.0.2.10").render(noExternalAuth: true)
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).count - 1
        let ca = OpenConnectConfig.systemCAFile
        XCTAssertNoThrow(try OpenConnectAuthConfig.checkRendered(text, lineCount: lines, caFile: ca))
        for bad in [
            text.replacingOccurrences(of: "resolve vpn.example.com:", with: "resolve vpn2.example.com:"),
            text.replacingOccurrences(of: "resolve vpn.example.com:192.0.2.10", with: "resolve vpn.example.com:vpn2.example.com"),
            text.replacingOccurrences(of: "server https://vpn.example.com/", with: "server https://192.0.2.10/")
                .replacingOccurrences(of: "resolve vpn.example.com:", with: "resolve 192.0.2.10:")
        ] {
            XCTAssertThrowsError(try OpenConnectAuthConfig.checkRendered(bad, lineCount: lines, caFile: ca), bad)
        }
        let moved = text.replacingOccurrences(of: "resolve vpn.example.com:192.0.2.10\n", with: "")
            .replacingOccurrences(of: "non-inter\n", with: "non-inter\nresolve vpn.example.com:192.0.2.10\n")
        XCTAssertThrowsError(try OpenConnectAuthConfig.checkRendered(moved, lineCount: lines, caFile: ca), "out of place")
    }

    /// The activity events: JSON round trip and sentences.
    func testTheActivityEvents() throws {
        let events: [ActivityEvent] = [
            ActivityEvent(at: at, .tryingLastKnownAddress(host: "vpn.example.com", address: "192.0.2.10")),
            ActivityEvent(at: at, .connected(address: "10.11.0.2", viaLastKnownAddress: "192.0.2.10")),
            ActivityEvent(at: at, .connected(address: "10.11.0.2")),
            ActivityEvent(
                at: at, .lastKnownAddressFailed(address: "192.0.2.10", learnedAt: at, reason: "Connection refused", certificateRefused: false)),
            ActivityEvent(at: at, .lastKnownAddressFailed(address: "192.0.2.10", learnedAt: at, reason: nil, certificateRefused: true))
        ]
        for event in events {
            let data = try ActivityLog.encoder().encode(event)
            XCTAssertEqual(try ActivityLog.decoder().decode(ActivityEvent.self, from: data), event)
            XCTAssertTrue(ActivityEvent.names.contains(event.name), event.name)
        }
        let json = String(decoding: try ActivityLog.encoder().encode(events[1]), as: UTF8.self)
        XCTAssertTrue(json.contains("\"last_known_address\":\"192.0.2.10\""), json)
        XCTAssertFalse(String(decoding: try ActivityLog.encoder().encode(events[2]), as: UTF8.self).contains("last_known_address"))
        XCTAssertEqual(events[0].name, "trying_last_known_address")
        XCTAssertEqual(events[3].name, "last_known_address_failed")
        XCTAssertEqual(events[0].sentence(), "Server name vpn.example.com not found, trying its last known address 192.0.2.10")
        XCTAssertEqual(events[1].sentence(), "Connected, 10.11.0.2, through the last known server address 192.0.2.10")
        XCTAssertEqual(events[2].sentence(), "Connected, 10.11.0.2")
        XCTAssertEqual(
            events[3].sentence(),
            "Server name not found, and its last known address 192.0.2.10 (from \(PTError.dateText(at))) did not answer (Connection refused)")
        XCTAssertTrue(events[4].sentence().contains("certificate check"))
        XCTAssertEqual(events[3].tone, .error)
        XCTAssertEqual(ActivityEvent.lastConnection(in: events)?.viaLastKnownAddress, nil, "the last connected one counts")
        XCTAssertEqual(ActivityEvent.lastConnection(in: Array(events.prefix(2)))?.viaLastKnownAddress, "192.0.2.10")
    }

    /// Only a missing name or a missing answer at the address becomes `knownAddressFailed`; anything the server there
    /// said stays as it was.
    func testWhichFailuresAtTheAddressAreExplained() {
        let entry = LastKnownAddress.Entry(host: "vpn.example.com", address: "192.0.2.10", learnedAt: at)
        let unreachable = PTError.serverUnreachable(server: "x", reason: "Connection refused", log: "tail")
        XCTAssertEqual(
            ConnectionManager.explaining(unreachable, triedAt: entry, server: "vpn.example.com:443") as? PTError,
            .knownAddressFailed(
                server: "vpn.example.com:443", address: "192.0.2.10", learnedAt: at, reason: "Connection refused", certificateRefused: false,
                log: "tail"))
        let untrusted = PTError.serverCertificateRejected(reason: "signer not found", pin: Out.otherPin, log: "tail")
        guard case .knownAddressFailed(_, _, _, _, true, _)? = ConnectionManager.explaining(untrusted, triedAt: entry, server: "") as? PTError
        else { return XCTFail() }
        for other in [PTError.authFailed("tail"), .connectTimeout(60), .hostScanRequired(log: "")] {
            XCTAssertEqual(ConnectionManager.explaining(other, triedAt: entry, server: "") as? PTError, other)
        }
        let failure = ConnectionFailure.of(
            PTError.knownAddressFailed(
                server: "s", address: "192.0.2.10", learnedAt: at, reason: "Connection refused", certificateRefused: false, log: ""),
            log: nil, handed: nil, at: at)
        XCTAssertEqual(failure.kind, .hostNotFound)
        XCTAssertEqual(failure.reason, "Connection refused")
        XCTAssertEqual(failure.lastKnownAddress?.address, "192.0.2.10")
        XCTAssertFalse(failure.credentialsSent)
        XCTAssertEqual(StatusNotice.allCases.count, 2)
        XCTAssertFalse(StatusNotice.connectedThroughLastKnownAddress.message.isEmpty)
    }

    private typealias Out = OpenConnectOutput
}
