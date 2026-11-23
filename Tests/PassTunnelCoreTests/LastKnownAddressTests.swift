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
        XCTAssertEqual(entry.confirmedAt, t0)
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
    /// same; the code never reached a server, so the second run takes it again. The date stays the one of the last
    /// connection by the name, and the connection is marked as made at the address before its state changes.
    func testConnectsAtTheLastKnownAddressWhenTheNameIsNotFound() async throws {
        let r = try await connectedOnce()
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.success]
        // What an observer of the state change reads (the source of the app's notices): this session's event already.
        var lastConnectionWhenConnected: String??
        r.manager.$states.sink { [weak m = r.manager, id = r.profile.id] states in
            if states[id]?.isConnected == true, lastConnectionWhenConnected == nil, let m {
                lastConnectionWhenConnected = .some(ActivityEvent.lastConnection(in: m.activity(id))?.viaLastKnownAddress)
            }
        }.store(in: &bag)
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
        XCTAssertTrue(
            kinds.contains(.tryingLastKnownAddress(host: "vpn.example.com", address: "192.0.2.10", confirmedAt: t0)), "\(kinds)")
        XCTAssertEqual(kinds.last, .connected(address: "10.11.0.2", viaLastKnownAddress: "192.0.2.10"))
        XCTAssertEqual(r.manager.notices(r.profile.id), [.connectedThroughLastKnownAddress])
        XCTAssertEqual(lastConnectionWhenConnected, .some("192.0.2.10"), "recorded before the state changed")
        XCTAssertEqual(known(r.profile)?.confirmedAt, t0, "a connection at the address confirms nothing: the date stays")
        XCTAssertNil(r.manager.failures[r.profile.id])
        // The status of `status --json` and the MCP get_status.
        let status = AutomationService(store: store, manager: r.manager).status(try store.get(r.profile.id))
        XCTAssertEqual(status.notices?.map(\.kind), ["connected_through_last_known_address"])
    }

    /// The name resolves: one run, no `resolve`, nothing in the activity about it, and the address the connection
    /// used now replaces the remembered one, with the time (a server that moved is picked up at once).
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
        XCTAssertEqual(known(r.profile)?.confirmedAt, t0.addingTimeInterval(3600))
    }

    /// A profile that never connected fails with `host_not_found` as before, after one run.
    func testWithoutARememberedAddressTheFailureIsUnchanged() async throws {
        let r = try await signInFailure(Out.output(status: 1, stderr: Out.notFound))
        XCTAssertEqual(r.error as? PTError, .hostNotFound(server: "vpn.example.com:8443", log: VPNLog.tail(Out.notFound)))
        XCTAssertNil(r.failure.lastKnownAddress)
        XCTAssertEqual(r.manager.activity(r.profile.id).last?.kind, .failed(kind: .hostNotFound, reason: nil, credentialsSent: false))
    }

    func tried(_ outcome: KnownAddressTry.Outcome, _ reason: String) -> KnownAddressTry {
        KnownAddressTry(address: "192.0.2.10", confirmedAt: t0, outcome: outcome, reason: reason)
    }

    /// The address cannot be reached either: `host_not_found` (the root cause) that says which address, confirmed
    /// when, was tried and what it gave, in the error, the failure, the activity and "Copy details". The address is
    /// kept and the code goes back.
    func testAFailedTryAtTheAddressExplainsItself() async throws {
        let r = try await connectedOnce()
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.output(status: 1, stderr: Out.refused)]
        do {
            try await r.manager.connect(r.profile.id)
            XCTFail("connected")
        } catch {
            XCTAssertEqual(
                error as? PTError,
                .knownAddressFailed(server: "vpn.example.com:8443", tried: tried(.unreachable, "Connection refused"), log: VPNLog.tail(Out.refused)))
            XCTAssertEqual(AutomationErrorCode.of(error), .hostNotFound)
            XCTAssertEqual(
                error.localizedDescription,
                "The server name vpn.example.com:8443 could not be found, so its last known address 192.0.2.10, confirmed "
                    + PTError.dateText(t0) + ", was tried. It could not be reached there either (Connection refused). "
                    + "Check the network connection and its DNS. Your sign-in was not sent.")
        }
        XCTAssertEqual(r.fake.calls.count, 3)
        let failure = try XCTUnwrap(r.manager.failures[r.profile.id])
        XCTAssertEqual(failure.kind, .hostNotFound)
        XCTAssertEqual(failure.reason, "Connection refused")
        XCTAssertFalse(failure.credentialsSent)
        XCTAssertEqual(failure.lastKnownAddress, tried(.unreachable, "Connection refused"))
        XCTAssertEqual(r.manager.lastError[r.profile.id]?.contains("192.0.2.10"), true)
        XCTAssertEqual(
            r.manager.usedCode(r.profile.id), .init(counter: TOTP.counter(params: r.profile.totp, at: t0), period: 30),
            "the code never left: given back, the first connect's record stays")
        XCTAssertEqual(r.manager.activity(r.profile.id).last?.kind, .lastKnownAddressFailed(tried(.unreachable, "Connection refused")))
        let details = try XCTUnwrap(r.manager.failureDetails(r.profile.id)).text(timeZone: TimeZone(identifier: "UTC")!)
        XCTAssertTrue(details.contains("Result: The server name was not found\n"), details)
        XCTAssertTrue(
            details.contains(
                "Tried instead: the last known address 192.0.2.10, confirmed 2023-11-14 22:13:20 +00:00: it could not be reached (Connection refused)"
            ),
            details)
        XCTAssertNotNil(known(r.profile), "no answer is no reason to forget it")

        // The JSON of `status --json` and the MCP tools.
        let json = try XCTUnwrap(String(data: try JSONCoding.encode(failure), encoding: .utf8))
        XCTAssertTrue(json.contains("\"last_known_address\""), json)
        XCTAssertTrue(json.contains("\"outcome\" : \"unreachable\""), json)
        XCTAssertFalse(json.contains("by_name"), json)
        XCTAssertEqual(try JSONCoding.decode(ConnectionFailure.self, from: Data(json.utf8)), failure)
    }

    /// The address is silently dropped: the sign-in, killed at its time limit with all of its output read, shows
    /// nothing sent and no TLS session. That is no answer at the address, explained like any other (`host_not_found`,
    /// no retries of an unreachable server), and the code goes back.
    func testATimeoutAtTheAddressIsExplainedAndGivesTheCodeBack() async throws {
        let r = try await connectedOnce()
        r.manager.retriesUnreachable = true
        r.fake.results = [
            Out.output(status: 1, stderr: Out.notFound),
            .failure(ToolTimeout(seconds: 60, errorOutput: Data(Out.post.utf8), errorOutputComplete: true))
        ]
        do {
            try await r.manager.connect(r.profile.id)
            XCTFail("connected")
        } catch {
            XCTAssertEqual(
                error as? PTError,
                .knownAddressFailed(
                    server: "vpn.example.com:8443", tried: tried(.unreachable, "no answer within 60 seconds"), log: VPNLog.tail(Out.post)))
        }
        let failure = try XCTUnwrap(r.manager.failures[r.profile.id])
        XCTAssertEqual(failure.kind, .hostNotFound)
        XCTAssertFalse(failure.credentialsSent)
        XCTAssertFalse(failure.codeSent)
        XCTAssertEqual(r.manager.usedCode(r.profile.id), .init(counter: TOTP.counter(params: r.profile.totp, at: t0), period: 30), "given back")
        XCTAssertNil(r.manager.unreachableRetry(r.profile.id), "no retries of an unreachable server")
        XCTAssertNotNil(known(r.profile))
    }

    /// At the address, a timeout whose output may hide a sign-in counts as sent: output not read to its end, more than
    /// is kept, an unfinished TLS line, a TLS session. The code stays spent and nothing says "not sent".
    func testATimeoutAtTheAddressThatMayHaveSentCountsAsSent() async throws {
        let big = Out.post + String(repeating: "x", count: SystemToolRunner.maxOutput) + "\n"
        let cases: [(String, Bool)] = [
            (Out.post, false), (big, true), (Out.post + "Connected to HTTPS on vpn.example.com with", true), (Out.post + Out.tls, true)
        ]
        for (stderr, complete) in cases {
            let r = try await connectedOnce()
            r.fake.results = [
                Out.output(status: 1, stderr: Out.notFound),
                .failure(ToolTimeout(seconds: 60, errorOutput: Data(stderr.utf8), errorOutputComplete: complete))
            ]
            do {
                try await r.manager.connect(r.profile.id)
                XCTFail("connected")
            } catch {
                XCTAssertEqual(error as? PTError, .connectTimeout(60))
                XCTAssertFalse(error.localizedDescription.contains("not sent"))
            }
            let failure = try XCTUnwrap(r.manager.failures[r.profile.id])
            XCTAssertEqual(failure.kind, .timeout)
            XCTAssertTrue(failure.credentialsSent)
            XCTAssertNil(failure.lastKnownAddress)
            XCTAssertEqual(
                r.manager.usedCode(r.profile.id), .init(counter: TOTP.counter(params: r.profile.totp, at: clock.now()), period: 30),
                "the code stays spent")
        }
    }

    /// By the name, a sign-in that runs into its time limit stays a timeout with its code spent, as before #292,
    /// whatever its output: a hung lookup cannot be told from a hung connection to a correct address. No try at the
    /// address, no retries of an unreachable server.
    func testATimeoutByTheNameNeverFallsBack() async throws {
        for stderr in [Out.post, Out.post + "Connected to 192.0.2.10:8443\n"] {
            let r = try await connectedOnce()
            r.manager.retriesUnreachable = true
            r.fake.results = [.failure(ToolTimeout(seconds: 60, errorOutput: Data(stderr.utf8), errorOutputComplete: true)), Out.success]
            do {
                try await r.manager.connect(r.profile.id)
                XCTFail("connected")
            } catch {
                XCTAssertEqual(error as? PTError, .connectTimeout(60))
            }
            XCTAssertEqual(r.fake.calls.count, 2, "no try at the address")
            XCTAssertEqual(r.manager.failures[r.profile.id]?.kind, .timeout)
            XCTAssertNotNil(r.manager.usedCode(r.profile.id))
            XCTAssertNil(r.manager.unreachableRetry(r.profile.id))
        }
    }

    /// The sign-in at the address was accepted, then the tunnel run failed: that failure as it is, the code spent,
    /// nothing saying "not sent", the address kept.
    func testATunnelFailureAfterASignInAtTheAddressIsThatFailure() async throws {
        let r = try await connectedOnce()
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.success]
        helper.startLog = Out.hookFailed
        let reason = "INTERNAL_IP4_DNS is not a list of IPv4 and IPv6 addresses"
        helper.openConnectTunnel = TunnelStatus(state: .failed, reason: reason, interface: "utun5")
        do {
            try await r.manager.connect(r.profile.id)
            XCTFail("connected")
        } catch {
            XCTAssertEqual(error as? PTError, .setupFailed(reason: reason, log: VPNLog.tail(Out.hookFailed)))
            XCTAssertFalse(error.localizedDescription.contains("not sent"))
        }
        let failure = try XCTUnwrap(r.manager.failures[r.profile.id])
        XCTAssertEqual(failure.kind, .setup)
        XCTAssertTrue(failure.credentialsSent)
        XCTAssertNil(failure.lastKnownAddress)
        XCTAssertNotNil(r.manager.usedCode(r.profile.id))
        XCTAssertNotNil(known(r.profile))
        XCTAssertEqual(r.manager.activity(r.profile.id).last?.kind, .failed(kind: .setup, reason: reason, credentialsSent: true))
    }

    /// Palo Alto GlobalProtect (`skip_portal`): a timeout at the address with nothing sent is no answer there, and its
    /// code goes back; a second part written, or a run by the name, counts as sent.
    func testGlobalProtectTimeoutAtTheAddress() async throws {
        let p = try makeGlobalProtectProfile("Acme GP Time", gateway: "", skipPortal: true)
        helper.startLog = GP.hipAndUp
        let prelogin = "POST https://vpn.example.com:8443/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac\n"
        let signedIn = prelogin + GP.portalTLS + "POST https://vpn.example.com:8443/ssl-vpn/login.esp\n"
        let stdout = GP.stdout(
            host: "192.0.2.10", connectURL: "https://vpn.example.com:8443/", fingerprint: GP.portalPin, resolve: "vpn.example.com:192.0.2.10")
        let notFound =
            prelogin + "getaddrinfo failed for host 'vpn.example.com': nodename nor servname provided, or not known\n"
            + "Failed to open HTTPS connection to vpn.example.com\n" + GP.failed
        let fake = FakeOpenConnect()
        fake.results = [Out.output(stdout: stdout, stderr: signedIn)]
        let m = try makeGlobalProtectManager(fake)
        try await m.connect(p.id)
        try await m.disconnect(p.id)
        clock.advance(3600)
        fake.results = [
            Out.output(status: 1, stderr: notFound),
            .failure(ToolTimeout(seconds: 60, errorOutput: Data(prelogin.utf8), errorOutputComplete: true))
        ]
        do {
            try await m.connect(p.id)
            XCTFail("connected")
        } catch {
            guard case .knownAddressFailed(_, let t, _)? = error as? PTError else { return XCTFail("\(error)") }
            XCTAssertEqual(t.outcome, .unreachable)
        }
        XCTAssertEqual(m.usedCode(p.id), .init(counter: TOTP.counter(params: p.totp, at: t0), period: 30), "given back")

        let timeout = ToolTimeout(seconds: 90, errorOutput: Data(prelogin.utf8), errorOutputComplete: true)
        XCTAssertTrue(GlobalProtectSignIn.unanswered(timeout, atKnownAddress: true, secondPartWritten: false))
        XCTAssertFalse(GlobalProtectSignIn.unanswered(timeout, atKnownAddress: true, secondPartWritten: true), "a second part written")
        XCTAssertFalse(GlobalProtectSignIn.unanswered(timeout, atKnownAddress: false, secondPartWritten: false), "by the name")
        let sent = ToolTimeout(seconds: 90, errorOutput: Data(signedIn.utf8), errorOutputComplete: true)
        XCTAssertFalse(GlobalProtectSignIn.unanswered(sent, atKnownAddress: true, secondPartWritten: false), "a login request")
        let incomplete = ToolTimeout(seconds: 90, errorOutput: Data(prelogin.utf8), errorOutputComplete: false)
        XCTAssertFalse(GlobalProtectSignIn.unanswered(incomplete, atKnownAddress: true, secondPartWritten: false))
    }

    /// At the address, a sign-in whose printed result cannot be read says nothing about the address: it is kept.
    func testAnUnreadableResultAtTheAddressKeepsIt() async throws {
        let r = try await connectedOnce()
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.output(stdout: "COOKIE='x'\n", stderr: Out.signedIn)]
        do {
            try await r.manager.connect(r.profile.id)
            XCTFail("connected")
        } catch {
            guard case .signInUnusable? = error as? PTError else { return XCTFail("\(error)") }
        }
        XCTAssertNotNil(known(r.profile))
    }

    /// By the name, the sign-in went out and then a name it was sent on to could not be found: a name problem (never
    /// a rejection), the code spent, no try at the address, never retried.
    func testALookupFailureAfterTheSignInWasSentNeverFallsBack() async throws {
        let r = try await connectedOnce()
        let stderr =
            Out.post + Out.tls + "XML POST enabled\n" + Out.post
            + "getaddrinfo failed for host 'vpn2.example.com': nodename nor servname provided, or not known\n"
            + "Failed to open HTTPS connection to vpn2.example.com\n" + Out.failed
        r.fake.results = [Out.output(status: 1, stderr: stderr), Out.success]
        do {
            try await r.manager.connect(r.profile.id)
            XCTFail("connected")
        } catch {
            XCTAssertEqual(
                error as? PTError, .hostNotFoundAfterSignIn(server: "vpn.example.com:8443", host: "vpn2.example.com", log: VPNLog.tail(stderr)))
            XCTAssertFalse(ConnectionManager.isRetryable(error))
            XCTAssertEqual(AutomationErrorCode.of(error), .hostNotFound)
            XCTAssertTrue(error.localizedDescription.contains("vpn2.example.com"), error.localizedDescription)
        }
        XCTAssertEqual(r.fake.calls.count, 2, "no try at the address after the sign-in went out")
        let failure = try XCTUnwrap(r.manager.failures[r.profile.id])
        XCTAssertEqual(failure.kind, .hostNotFound)
        XCTAssertTrue(failure.credentialsSent)
        XCTAssertTrue(failure.codeSent)
        XCTAssertEqual(r.manager.usedCode(r.profile.id), .init(counter: TOTP.counter(params: r.profile.totp, at: clock.now()), period: 30))
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
            guard case .knownAddressFailed(_, let t, _)? = error as? PTError else { return XCTFail("\(error)") }
            XCTAssertEqual(t, tried(.certificateRefused, "signer not found"))
            XCTAssertTrue(error.localizedDescription.contains("so that address was forgotten"), error.localizedDescription)
        }
        XCTAssertTrue(r.fake.calls[2].config.contains("no-system-trust\ncafile "), "the CA bundle, as by the name")
        XCTAssertEqual(r.manager.failures[r.profile.id]?.kind, .hostNotFound)
        XCTAssertNil(r.manager.trustOffers[r.profile.id], "no Trust This Server for a server reached at the address")
        XCTAssertNil(known(r.profile))
        XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(r.profile.id, store: store).path))
        XCTAssertEqual(r.manager.activity(r.profile.id).last?.kind, .lastKnownAddressFailed(tried(.certificateRefused, "signer not found")))
    }

    /// The genuine server at the address (its certificate passed) refuses the sign-in, or answers something the
    /// profile does not fit: the address is kept, as it is the server's.
    func testAnAnswerOfTheServerAtTheAddressKeepsIt() async throws {
        for stderr in [Out.rejected, Out.noSuchGroup, Out.hostScan] {
            let r = try await connectedOnce()
            r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.output(status: 1, stderr: stderr)]
            do {
                try await r.manager.connect(r.profile.id)
                XCTFail("connected")
            } catch {
                if case .knownAddressFailed? = error as? PTError { XCTFail("\(error)") }
            }
            XCTAssertEqual(r.fake.calls.count, 3, "no third run")
            XCTAssertNotNil(known(r.profile), stderr)
        }
        let r = try await connectedOnce()
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.output(status: 1, stderr: Out.rejected)]
        do { try await r.manager.connect(r.profile.id) } catch {}
        XCTAssertEqual(r.manager.failures[r.profile.id]?.kind, .authRejected, "a rejection stays one, never retried")
    }

    /// The sign-in at the address ends on another server than the profile's: the address is forgotten.
    func testADestinationMismatchAtTheAddressForgetsIt() async throws {
        let r = try await connectedOnce()
        let other = Out.output(
            stdout: Out.stdout(connectURL: "https://vpn9.example.com:8443/", resolve: "vpn9.example.com:192.0.2.10"), stderr: Out.signedIn)
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), other]
        do {
            try await r.manager.connect(r.profile.id)
            XCTFail("connected")
        } catch {
            guard case .signInUnusable? = error as? PTError else { return XCTFail("\(error)") }
        }
        XCTAssertNil(known(r.profile))
    }

    /// Only a name that was not found (or did not answer at all) leads to the address: a server that refused by its
    /// name is not tried elsewhere.
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

    // MARK: cancelling and codes

    /// A disconnect during the try at the address stops it: no third run, a cancel, the address kept.
    func testDisconnectDuringTheTryAtTheAddress() async throws {
        let r = try await connectedOnce()
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.success]
        r.fake.blockFromRun = 2
        let task = Task { try await r.manager.connect(r.profile.id) }
        await waitUntil { r.fake.calls.count == 3 }
        try await r.manager.disconnect(r.profile.id)
        do {
            try await task.value
            XCTFail("connected")
        } catch {
            XCTAssertEqual(error as? PTError, .connectCancelled)
        }
        XCTAssertTrue(r.fake.sawCancel)
        XCTAssertEqual(r.fake.calls.count, 3)
        XCTAssertEqual(r.manager.failures[r.profile.id]?.kind, .cancelled)
        XCTAssertNotNil(known(r.profile))
        XCTAssertEqual(r.manager.activity(r.profile.id).last?.kind, .stoppedByUser)
    }

    /// A disconnect during the try by the name: the cancel is no failure to fall back from.
    func testDisconnectDuringTheTryByTheNameNeverTriesTheAddress() async throws {
        let r = try await connectedOnce()
        r.fake.blockFromRun = 1
        let task = Task { try await r.manager.connect(r.profile.id) }
        await waitUntil { r.fake.calls.count == 2 }
        try await r.manager.disconnect(r.profile.id)
        do {
            try await task.value
            XCTFail("connected")
        } catch {
            XCTAssertEqual(error as? PTError, .connectCancelled)
        }
        XCTAssertEqual(r.fake.calls.count, 2)
        XCTAssertFalse(
            r.manager.activity(r.profile.id).contains {
                if case .tryingLastKnownAddress = $0.kind { return true }; return false
            })
    }

    /// The code's window ends while the name is looked up: the try at the address takes the new window's code.
    func testACodeWindowRolloverBetweenTheTries() async throws {
        let r = try await connectedOnce()
        // 3600 s after t0 is 20 s into a window: 10 s left, enough not to wait first.
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.success]
        r.fake.onRun = { [clock] index in if index == 1 { clock?.advance(12) } }
        try await r.manager.connect(r.profile.id)
        let first = try code(at: t0.addingTimeInterval(3600))
        let second = try code(at: clock.now())
        XCTAssertNotEqual(first, second)
        XCTAssertTrue(String(decoding: r.fake.calls[1].input, as: UTF8.self).contains(first))
        XCTAssertTrue(String(decoding: r.fake.calls[2].input, as: UTF8.self).contains(second))
        XCTAssertEqual(r.manager.usedCode(r.profile.id), .init(counter: TOTP.counter(params: r.profile.totp, at: clock.now()), period: 30))
    }

    /// Another process sends the next window's code while the name is looked up (it saw this one spent, so it waited
    /// for the next, and wrote `.last-otp`): that record is not put back, and the try at the address, now in that
    /// window, waits for the one after it instead of sending the same code.
    func testAnotherProcessSpendingTheCodeBetweenTheTries() async throws {
        let r = try await connectedOnce()
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.success]
        let usedURL = store.dir(r.profile.id).appendingPathComponent(ConnectionManager.usedOTPFile)
        let window = ConnectionManager.UsedOTPWindow(counter: TOTP.counter(params: r.profile.totp, at: clock.now()) + 1, period: 30)
        r.fake.onRun = { [clock] index in
            guard index == 1 else { return }
            clock?.advance(12)
            try? JSONCoding.write(window, to: usedURL, mode: 0o600)
        }
        try await r.manager.connect(r.profile.id)
        let kinds = r.manager.activity(r.profile.id).map(\.kind)
        guard
            let trying = kinds.lastIndex(where: {
                if case .tryingLastKnownAddress = $0 { return true }; return false
            })
        else {
            return XCTFail("\(kinds)")
        }
        XCTAssertTrue(
            kinds[trying...].contains {
                if case .waitingForCode(.used, _, _) = $0 { return true }; return false
            }, "\(kinds)")
        XCTAssertNotEqual(r.fake.calls[2].input, r.fake.calls[1].input, "never the code another process sent")
        XCTAssertEqual(r.manager.usedCode(r.profile.id)?.counter, window.counter + 1)
    }

    // MARK: staleness

    /// Changing the profile's server (host, port, pin, user group, type) drops the address; other edits keep it.
    func testChangingTheServerDropsTheAddress() async throws {
        let r = try await connectedOnce()
        let url = LastKnownAddress.url(r.profile.id, store: store)
        _ = try store.update(r.profile.id) { $0.name = "Acme Renamed" }
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path), "not the server")
        _ = try store.update(r.profile.id) { $0.port = 9443 }
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path), "another port")

        let changes: [(String, (inout Profile) -> Void)] = [
            ("host", { $0.host = "vpn2.example.com" }), ("pin", { $0.serverCert = Out.otherPin }),
            ("user group", { $0.usergroup = "sales" }), ("type", { $0.type = .openvpn })
        ]
        for (what, change) in changes {
            let s = try await connectedOnce()
            _ = try store.update(s.profile.id, change)
            XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(s.profile.id, store: store).path), what)
        }
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
            confirmedAt: t0)
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
        XCTAssertEqual(check.lastKnownAddress, .init(host: "vpn.example.com", address: "192.0.2.10", confirmedAt: t0))
        let json = try XCTUnwrap(String(data: try JSONCoding.encode(check), encoding: .utf8))
        XCTAssertTrue(json.contains("\"last_known_address\""), json)
        XCTAssertTrue(json.contains("\"confirmed_at\""), json)

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

    /// A file for a portal profile (put there by hand, or from before): written as for its destination.
    func plantEntry(_ p: Profile) throws {
        let saved = LastKnownAddress.Saved(
            version: LastKnownAddress.version, destination: ProfileDestination.of(p, store: store).fingerprint, host: "vpn.example.com",
            address: "192.0.2.10", confirmedAt: t0)
        try JSONCoding.write(saved, to: LastKnownAddress.url(p.id, store: store), mode: 0o600)
    }

    /// With a portal (no `skip_portal`) the sign-in may be sent on to a gateway of another name, which a network
    /// without DNS could not find either, after the code went out: such a profile never uses an address, and a
    /// connection by the name that has none to keep forgets one that is there.
    func testGlobalProtectWithAPortalNeverUsesAnAddress() async throws {
        let p = try makeGlobalProtectProfile()
        XCTAssertFalse(LastKnownAddress.applies(to: p))
        try plantEntry(p)
        XCTAssertNil(known(p))
        let notFound =
            GP.portalPrelogin + "getaddrinfo failed for host 'vpn.example.com': nodename nor servname provided, or not known\n"
            + "Failed to open HTTPS connection to vpn.example.com\n" + GP.failed
        let failing = FakeGlobalProtect(clock: clock, script: [.stderr(notFound)], status: 1)
        let m = try makeGlobalProtectManager(failing)
        do {
            try await m.connect(p.id)
            XCTFail("connected")
        } catch {
            guard case .hostNotFound? = error as? PTError else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(failing.runs.count, 1, "no try at an address")

        helper.startLog = GP.hipAndUp
        let fake = FakeGlobalProtect(
            clock: clock, script: [.stderr(GP.untilSecondSignIn), .advance(4), .advance(6), .stderr(GP.afterSecondSignIn)],
            stdout: GP.stdout())
        let m2 = try makeGlobalProtectManager(fake)
        try await m2.connect(p.id)
        XCTAssertTrue(m2.state(p.id).isConnected)
        XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(p.id, store: store).path), "forgotten")
    }

    /// GlobalProtect: after the portal's sign-in, the gateway's name not found is a name problem, never a rejection.
    func testGlobalProtectGatewayNotFoundAfterTheSignInIsANameProblem() {
        let stderr =
            GP.portalPrelogin + GP.portalTLS + GP.portalConfig + "Challenge: " + GP.portalConfig + GP.oneGateway + GP.gatewayLogin
            + "getaddrinfo failed for host 'gw1.example.com': nodename nor servname provided, or not known\n"
            + "Failed to open HTTPS connection to gw1.example.com\n" + GP.failed
        XCTAssertTrue(VPNLog.globalProtectCredentialsSent(stderr))
        XCTAssertEqual(
            VPNLog.globalProtectSignInError(
                stderr, status: 1, credentialsSent: true, gateway: "US East", host: "vpn.example.com", port: 8443, server: "vpn.example.com:8443"),
            .hostNotFoundAfterSignIn(server: "vpn.example.com:8443", host: "gw1.example.com", log: VPNLog.tail(stderr)))
    }

    /// Changing `skip_portal` or the gateway pin of a GlobalProtect profile drops its address.
    func testGlobalProtectChangesDropTheAddress() throws {
        for change in [{ (p: inout Profile) in p.skipPortal = false }, { (p: inout Profile) in p.gatewayServerCert = GP.otherPin }] {
            let p = try makeGlobalProtectProfile("Acme GP \(UUID().uuidString.prefix(6))", gateway: "", skipPortal: true)
            try plantEntry(p)
            XCTAssertNotNil(known(p))
            _ = try store.update(p.id, change)
            XCTAssertFalse(FileManager.default.fileExists(atPath: LastKnownAddress.url(p.id, store: store).path))
        }
    }
}

// MARK: - With a stop in another process, kept session secrets and drop handling (#294, #296)

extension ConnectionManagerTests {
    /// What another process's `passtunnel disconnect` leaves for this one: the user-stopped marker.
    func stopElsewhere(_ id: String) {
        try? Data().write(to: store.dir(id).appendingPathComponent(ConnectionManager.userStoppedMarker))
    }

    func expectCancelled(_ m: ConnectionManager, _ id: String, file: StaticString = #filePath, line: UInt = #line) async {
        do {
            try await m.connect(id)
            XCTFail("connected", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? PTError, .connectCancelled, file: file, line: line)
        }
    }

    /// Another process stops the profile while the name is looked up: no second try, nothing sent, no tunnel.
    func testAStopElsewhereBetweenTheTriesEndsTheConnect() async throws {
        let r = try await connectedOnce()
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.success]
        r.fake.onRun = { [weak self] index in if index == 1 { self?.stopElsewhere(r.profile.id) } }
        await expectCancelled(r.manager, r.profile.id)
        XCTAssertEqual(r.fake.calls.count, 2, "no try at the address")
        XCTAssertEqual(helper.starts.count, 1, "no tunnel")
        XCTAssertEqual(r.manager.state(r.profile.id), .disconnected)
        XCTAssertTrue(stoppedMarker(r.profile.id), "the stop stands")
        XCTAssertFalse(
            r.manager.activity(r.profile.id).contains {
                if case .tryingLastKnownAddress = $0.kind { return true }; return false
            })
    }

    /// Another process stops the profile during the try at the address: the run is stopped there (as by this
    /// manager's own disconnect), and no tunnel follows.
    func testAStopElsewhereDuringTheTryAtTheAddressStopsIt() async throws {
        let r = try await connectedOnce()
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.success]
        r.fake.blockFromRun = 2
        let task = Task { try await r.manager.connect(r.profile.id) }
        await waitUntil { r.fake.calls.count == 3 }
        stopElsewhere(r.profile.id)
        do {
            try await task.value
            XCTFail("connected")
        } catch {
            XCTAssertEqual(error as? PTError, .connectCancelled)
        }
        XCTAssertTrue(r.fake.sawCancel, "the sign-in run was stopped")
        XCTAssertEqual(helper.starts.count, 1, "no tunnel")
        XCTAssertEqual(r.manager.failures[r.profile.id]?.kind, .cancelled)
        XCTAssertEqual(r.manager.state(r.profile.id), .disconnected)
        XCTAssertTrue(stoppedMarker(r.profile.id))
    }

    /// The try at the address signs in, and another process's stop comes before the tunnel starts: no tunnel.
    func testAStopElsewhereAfterTheSignInAtTheAddressStartsNoTunnel() async throws {
        let r = try await connectedOnce()
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.success]
        r.fake.onRun = { [weak self] index in if index == 2 { self?.stopElsewhere(r.profile.id) } }
        await expectCancelled(r.manager, r.profile.id)
        XCTAssertEqual(r.fake.calls.count, 3)
        XCTAssertEqual(helper.starts.count, 1, "no tunnel")
        XCTAssertEqual(r.manager.state(r.profile.id), .disconnected)
    }

    /// A protected Cisco AnyConnect profile, with its manager.
    func makeProtectedAnyConnect(_ fake: FakeOpenConnect) async throws -> (profile: Profile, manager: ConnectionManager) {
        let m = try makeAnyConnectManager(fake)
        let plain = try makeAnyConnect("Acme \(UUID().uuidString.prefix(8))", autoReconnect: true)
        var p = plain
        p.requireAuth = .connect
        try await m.vault.applyProtection(from: plain, to: p)
        try store.save(p)
        helper.startLog = Out.hookUp
        return (p, m)
    }

    /// A drop's reconnect of a protected profile, past the reuse window: both tries read the secrets the session
    /// kept, nobody is asked, one tunnel is started, and the poll that follows sees the same session (the sign-in runs
    /// are never the session's process), so its kept secrets stay for the next drop.
    func testAReconnectTriesTheAddressWithTheKeptSecrets() async throws {
        let fake = FakeOpenConnect()
        let (p, m) = try await makeProtectedAnyConnect(fake)
        fake.results = [Out.success]
        try await m.connect(p.id)
        XCTAssertEqual(authenticator.calls, 1)
        XCTAssertNotNil(known(p))
        try await clock.sleep(61)

        fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.success]
        helper.simulateExit(p.id)
        await m.refresh()
        await waitUntil { m.state(p.id).isConnected }
        XCTAssertEqual(fake.calls.count, 3)
        for call in fake.calls[1...] { XCTAssertTrue(String(decoding: call.input, as: UTF8.self).hasPrefix("hunter2-pw\n")) }
        XCTAssertTrue(fake.calls[2].config.contains(knownAddressLine))
        XCTAssertEqual(authenticator.calls, 1, "no prompt for either try")
        XCTAssertEqual(helper.starts.count, 2, "one tunnel for the reconnect")

        await m.refresh()
        XCTAssertTrue(m.state(p.id).isConnected, "the same session")
        fake.results = [Out.success]
        helper.simulateExit(p.id)
        await m.refresh()
        await waitUntil { m.state(p.id).isConnected }
        XCTAssertEqual(authenticator.calls, 1, "its kept secrets were still there")
    }

    /// The kept copy ended (another process stopped the session): a connect that never asks, as a reconnect or a
    /// retry makes, stops for a confirmation before either try runs.
    func testWithoutKeptSecretsNeitherTryRuns() async throws {
        let fake = FakeOpenConnect()
        let (p, m) = try await makeProtectedAnyConnect(fake)
        fake.results = [Out.success]
        try await m.connect(p.id)
        try await ConnectionManager(store: store, helper: helper, clock: clock).disconnect(p.id)
        await m.refresh()
        try await clock.sleep(61)
        fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.success]
        do {
            try await m.connect(p.id, interactive: false)
            XCTFail("connected")
        } catch {
            XCTAssertEqual(error as? PTError, .confirmationRequired)
        }
        XCTAssertEqual(fake.calls.count, 1, "no sign-in at all")
        XCTAssertEqual(helper.starts.count, 1)
        XCTAssertEqual(authenticator.calls, 1)
    }

    /// `handlesDrops` off (the MCP server): the fallback works the same inside a connect, and a drop afterwards is
    /// only shown: nothing reconnects, by the name or at the address.
    func testWithoutDropHandlingTheFallbackIsTheSameAndNothingReconnects() async throws {
        let r = try await connectedOnce()
        r.manager.handlesDrops = false
        r.fake.results = [Out.output(status: 1, stderr: Out.notFound), Out.success]
        try await r.manager.connect(r.profile.id)
        XCTAssertEqual(r.fake.calls.count, 3)
        XCTAssertEqual(r.manager.activity(r.profile.id).last?.kind, .connected(address: "10.11.0.2", viaLastKnownAddress: "192.0.2.10"))
        let recorded = r.manager.activity(r.profile.id)
        helper.simulateExit(r.profile.id)
        await r.manager.refresh()
        await r.manager.refresh()
        XCTAssertEqual(r.manager.state(r.profile.id), .disconnected)
        XCTAssertNil(r.manager.reconnecting[r.profile.id])
        XCTAssertEqual(r.fake.calls.count, 3, "no sign-in of its own")
        XCTAssertEqual(helper.starts.count, 2)
        XCTAssertEqual(r.manager.activity(r.profile.id), recorded)
        XCTAssertEqual(known(r.profile)?.confirmedAt, t0, "the connection at the address confirmed nothing")
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

    func tried(_ outcome: KnownAddressTry.Outcome, _ reason: String = "") -> KnownAddressTry {
        KnownAddressTry(address: "192.0.2.10", confirmedAt: at, outcome: outcome, reason: reason)
    }

    /// The activity events: JSON round trip, keys and sentences. `server_address` is the server's address and
    /// `address` stays the tunnel's (`connected`).
    func testTheActivityEvents() throws {
        let date = PTError.dateText(at)
        let events: [ActivityEvent] = [
            ActivityEvent(at: at, .tryingLastKnownAddress(host: "vpn.example.com", address: "192.0.2.10", confirmedAt: at)),
            ActivityEvent(at: at, .connected(address: "10.11.0.2", viaLastKnownAddress: "192.0.2.10")),
            ActivityEvent(at: at, .connected(address: "10.11.0.2")),
            ActivityEvent(at: at, .lastKnownAddressFailed(tried(.unreachable, "Connection refused"))),
            ActivityEvent(at: at, .lastKnownAddressFailed(tried(.certificateRefused))),
            ActivityEvent(at: at, .lastKnownAddressFailed(tried(.nameNotFound)))
        ]
        for event in events {
            let data = try ActivityLog.encoder().encode(event)
            XCTAssertEqual(try ActivityLog.decoder().decode(ActivityEvent.self, from: data), event)
            XCTAssertTrue(ActivityEvent.names.contains(event.name), event.name)
        }
        let json = try events.map { String(decoding: try ActivityLog.encoder().encode($0), as: UTF8.self) }
        XCTAssertTrue(json[0].contains("\"server_address\":\"192.0.2.10\""), json[0])
        XCTAssertFalse(json[0].contains("by_name"), json[0])
        XCTAssertTrue(json[1].contains("\"address\":\"10.11.0.2\"") && json[1].contains("\"via_server_address\":\"192.0.2.10\""), json[1])
        XCTAssertFalse(json[2].contains("via_server_address"))
        XCTAssertTrue(json[3].contains("\"outcome\":\"unreachable\"") && json[3].contains("\"server_address\""), json[3])
        XCTAssertFalse(json[4].contains("reason"), "no empty reason")
        XCTAssertEqual(events[0].name, "trying_last_known_address")
        XCTAssertEqual(events[3].name, "last_known_address_failed")
        XCTAssertEqual(events[0].sentence(), "Server name vpn.example.com not found, trying its last known address 192.0.2.10, confirmed \(date)")
        XCTAssertEqual(events[1].sentence(), "Connected, 10.11.0.2, through the last known server address 192.0.2.10")
        XCTAssertEqual(events[2].sentence(), "Connected, 10.11.0.2")
        XCTAssertEqual(events[3].sentence(), "The last known address 192.0.2.10 could not be reached either (Connection refused)")
        XCTAssertEqual(
            events[4].sentence(), "The server at the last known address 192.0.2.10 failed the certificate check; that address was forgotten",
            "no empty parentheses")
        XCTAssertEqual(events[5].sentence(), "At the last known address 192.0.2.10, a server name was still needed and could not be found")
        XCTAssertEqual(events[3].tone, .error)
        XCTAssertEqual(ActivityEvent.lastConnection(in: Array(events.prefix(3)))?.viaLastKnownAddress, nil, "the last connected one counts")
        XCTAssertEqual(ActivityEvent.lastConnection(in: Array(events.prefix(2)))?.viaLastKnownAddress, "192.0.2.10")
    }

    /// The messages: one wording for the date ("confirmed"), what happened by the name, then at the address, with no
    /// empty parentheses; the card's form says only the address part.
    func testTheMessages() {
        let date = PTError.dateText(at)
        XCTAssertEqual(
            PTError.knownAddressFailed(server: "vpn.example.com:443", tried: tried(.certificateRefused), log: "").localizedDescription,
            "The server name vpn.example.com:443 could not be found, so its last known address 192.0.2.10, confirmed \(date), was tried. "
                + "The server there failed the certificate check, so that address was forgotten. Your sign-in was not sent.")
        XCTAssertEqual(
            PTError.knownAddressFailed(server: "vpn.example.com:443", tried: tried(.nameNotFound), log: "").localizedDescription,
            "The server name vpn.example.com:443 could not be found, so its last known address 192.0.2.10, confirmed \(date), was tried. "
                + "A server name was still needed there and could not be found either. Check the network connection and its DNS. Your sign-in was not sent."
        )
        XCTAssertEqual(
            tried(.unreachable).addressSentences,
            "Its last known address 192.0.2.10, confirmed \(date), was tried as well. It could not be reached there either. "
                + "Check the network connection and its DNS.")
        XCTAssertFalse(tried(.unreachable).addressSentences.contains("()"))
        XCTAssertEqual(
            PTError.hostNotFoundAfterSignIn(server: "vpn.example.com:443", host: "", log: "").localizedDescription,
            "Your sign-in was sent to vpn.example.com:443, so a one-time code sent with it is used up, but a server name it was sent on to "
                + "could not be found. Check the network connection and its DNS.")
    }

    /// Only no answer, a certificate refused or a name still missing at the address becomes `knownAddressFailed`;
    /// anything the server there said, or a sign-in that went out, stays as it was.
    func testWhichFailuresAtTheAddressAreExplained() {
        let entry = LastKnownAddress.Entry(host: "vpn.example.com", address: "192.0.2.10", confirmedAt: at)
        func explained(_ error: PTError) -> PTError? {
            ConnectionManager.explaining(error, triedAt: entry, server: "vpn.example.com:443") as? PTError
        }
        XCTAssertEqual(
            explained(.serverUnreachable(server: "x", reason: "Connection refused", log: "tail")),
            .knownAddressFailed(server: "vpn.example.com:443", tried: tried(.unreachable, "Connection refused"), log: "tail"))
        XCTAssertEqual(
            explained(.serverCertificateRejected(reason: "signer not found", pin: Out.otherPin, log: "tail")),
            .knownAddressFailed(server: "vpn.example.com:443", tried: tried(.certificateRefused, "signer not found"), log: "tail"))
        XCTAssertEqual(
            explained(.hostNotFound(server: "x", log: "tail")),
            .knownAddressFailed(server: "vpn.example.com:443", tried: tried(.nameNotFound), log: "tail"))
        for other in [
            PTError.authFailed("tail"), .connectTimeout(60), .hostScanRequired(log: ""), .hostNotFoundAfterSignIn(server: "", host: "", log: "")
        ] {
            XCTAssertEqual(explained(other), other)
        }
        let failure = ConnectionFailure.of(
            PTError.knownAddressFailed(server: "s", tried: tried(.unreachable, "Connection refused"), log: ""), log: nil, handed: nil, at: at)
        XCTAssertEqual(failure.kind, .hostNotFound)
        XCTAssertEqual(failure.reason, "Connection refused")
        XCTAssertEqual(failure.lastKnownAddress?.address, "192.0.2.10")
        XCTAssertFalse(failure.credentialsSent)
        let noReason = ConnectionFailure.of(
            PTError.knownAddressFailed(server: "s", tried: tried(.unreachable), log: ""), log: nil, handed: nil, at: at)
        XCTAssertEqual(noReason.kind, .hostNotFound)
        XCTAssertNil(noReason.reason)
        let after = ConnectionFailure.of(
            PTError.hostNotFoundAfterSignIn(server: "s", host: "gw1.example.com", log: ""), log: nil, handed: .init(code: true), at: at)
        XCTAssertEqual(after.kind, .hostNotFound)
        XCTAssertTrue(after.credentialsSent && after.codeSent)
        // The app shows it with its own message, which says the sign-in went out, not as "check the address".
        XCTAssertEqual(DisplayStatus.Failure(after, error: "sent, then not found"), .message("sent, then not found"))
        XCTAssertEqual(DisplayStatus.Failure(failure, error: "x"), .hostNotFound)
        // Its lines: only in openconnect's exact shape at the end.
        func lookup(_ text: String) -> String? { VPNLog.openConnectLookupFailure(VPNLog.openConnectLines(text)) }
        let shape =
            "getaddrinfo failed for host 'gw1.example.com': nodename nor servname provided, or not known\n"
            + "Failed to open HTTPS connection to gw1.example.com\n"
        XCTAssertEqual(lookup(shape + "Failed to complete authentication\n"), "gw1.example.com")
        XCTAssertEqual(lookup(shape), "gw1.example.com")
        XCTAssertNil(lookup(shape + "Login failed.\nFailed to complete authentication\n"), "not at the end")
        XCTAssertNil(lookup(shape.replacingOccurrences(of: "connection to gw1", with: "connection to gw2")), "another name")
        XCTAssertNil(lookup("Failed to open HTTPS connection to gw1.example.com\n"), "no lookup line")
        XCTAssertNil(lookup("getaddrinfo failed for host 'gw1.example.com': no\n"), "no second line")
        XCTAssertEqual(StatusNotice.allCases.count, 2)
        XCTAssertFalse(StatusNotice.connectedThroughLastKnownAddress.message.isEmpty)
        // The tunnel run of a gateway gets its address too (`resolve`): it never looks the gateway up again.
        XCTAssertEqual(
            try OpenConnectAuthResult.checkDestination(
                host: "gw1.example.com", port: 443, connectURL: "https://gw1.example.com/", resolve: "gw1.example.com:192.0.2.20",
                fingerprint: Out.pin, pins: [], client: true
            ).resolveAddress, "192.0.2.20")
    }

    private typealias Out = OpenConnectOutput
}

// MARK: - The command line

extension AnyConnectCLITests {
    /// `passtunnel diagnose` shows the address and how long ago a connection by the name confirmed it; its JSON has
    /// `last_known_address` with `confirmed_at`. Nothing is contacted.
    func testDiagnoseShowsTheLastKnownServerAddress() async throws {
        let p = try makeProfile("Acme Known")
        LastKnownAddress.save(
            "192.0.2.10", for: p, destination: ProfileDestination.of(p, store: store), store: store, at: Date().addingTimeInterval(-7200))
        let human = try await run(
            .diagnose(checkClock: false, json: false), macOS: OperatingSystemVersion(majorVersion: 15, minorVersion: 4, patchVersion: 0))
        XCTAssertTrue(human.out.contains("Last known server address: 192.0.2.10"), human.out)
        XCTAssertTrue(human.out.contains("(confirmed "), human.out)
        let json = try await run(
            .diagnose(checkClock: false, json: true), macOS: OperatingSystemVersion(majorVersion: 15, minorVersion: 4, patchVersion: 0))
        let profiles = try XCTUnwrap(json.json?["profiles"] as? [[String: Any]])
        let known = try XCTUnwrap(profiles.first { $0["id"] as? String == p.id }?["last_known_address"] as? [String: Any])
        XCTAssertEqual(known["address"] as? String, "192.0.2.10")
        XCTAssertNotNil(known["confirmed_at"] as? String)
    }
}
