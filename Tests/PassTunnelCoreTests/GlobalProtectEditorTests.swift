import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelVPNConfig

/// The Mac app's Palo Alto GlobalProtect editor and views (#233), as far as they are Core's: the server address and the
/// gateway typed into the editor (`GlobalProtectEditing`), the portal's gateways offered after a failure for want of one
/// (`GatewayChoice`), the confirmation of "Trust This Gateway…" (`GatewayTrust`), and the statuses of the new failures
/// (`DisplayStatus`).
final class GlobalProtectEditorTests: XCTestCase {
    typealias E = GlobalProtectEditing
    static let pin = "pin-sha256:B9S1MyM7eI6e0MBVCfgWo0zkSVpzyFfkmueG8/HAbiY="
    static let otherPin = "pin-sha256:E86EpKhiszwwyqu937GB+mox53WHxoGiVhwY7ZXxrwQ="

    static func profile(skipPortal: Bool = false, serverCert: String = "", gatewayServerCert: String = "") -> Profile {
        var p = Profile(id: "corp", name: "Corp", type: .globalprotect)
        p.host = "vpn.example.com"
        p.port = 443
        p.skipPortal = skipPortal
        p.serverCert = serverCert
        p.gatewayServerCert = gatewayServerCert
        return p
    }

    // MARK: the server address

    func testPastingAnAddressSetsHostAndPort() {
        var p = Profile(id: "corp", name: "Corp", type: .globalprotect)
        E.applyServer("  HTTPS://VPN.Example.com:8443/ \n", to: &p)
        XCTAssertEqual([p.host, String(p.port)], ["vpn.example.com", "8443"])
        XCTAssertEqual(E.serverText(host: p.host, port: p.port), "https://vpn.example.com:8443")
        E.applyServer("https://[2001:db8::1]", to: &p)
        XCTAssertEqual([p.host, String(p.port)], ["2001:db8::1", "443"])
        XCTAssertEqual(E.serverText(host: p.host, port: p.port), "https://[2001:db8::1]")
        // A path (pasted from a browser) is no address: the fields stay; clearing the field clears them.
        E.applyServer("https://vpn.example.com/global-protect/login.esp", to: &p)
        XCTAssertEqual(p.host, "2001:db8::1")
        E.applyServer(" ", to: &p)
        XCTAssertEqual([p.host, String(p.port)], ["", "443"])
        // The stored spelling of the same host is kept: nothing to save.
        p.host = "VPN.Example.com"
        E.applyServer(E.serverText(host: p.host, port: p.port), to: &p)
        XCTAssertEqual(p.host, "VPN.Example.com")
    }

    func testServerProblems() {
        let cases: [(String, AnyConnectEditing.ServerProblem?)] = [
            ("vpn.example.com", nil), ("https://vpn.example.com:4443", nil), ("https://vpn.example.com/", nil), ("[::1]", nil),
            ("", .empty), ("  ", .empty),
            ("https://vpn.example.com/global-protect/login.esp", .path), ("https://vpn.example.com/ssl-vpn", .path),
            ("https://vpn.example.com/a b", .path),
            ("http://vpn.example.com", .scheme), ("https://alice@vpn.example.com", .userInfo),
            ("https://vpn.example.com/?a=b", .queryOrFragment), ("https://vpn.example.com/%41", .percentEscape),
            ("https://vpn.example.com:0", .port), ("https://vpn example.com", .host)
        ]
        for (text, expected) in cases {
            XCTAssertEqual(E.serverProblem(text), expected, text)
            XCTAssertEqual(E.serverProblem(text) == nil, GlobalProtectServer.parse(text.trimmingCharacters(in: .whitespaces)) != nil, text)
        }
        XCTAssertFalse(AnyConnectEditing.ServerProblem.path.message.isEmpty)
    }

    /// No message repeats what was typed.
    func testMessagesNeverEchoTheInput() {
        let secret = "Hunter2Secret"
        for text in ["https://vpn.example.com/\(secret)", "https://\(secret)@vpn.example.com", secret + " " + secret] {
            XCTAssertFalse(E.serverProblem(text)?.message.contains(secret) ?? true, text)
        }
        XCTAssertFalse(E.gatewayProblem("=" + secret)?.contains(secret) ?? true)
        XCTAssertFalse(E.usernameProblem("=" + secret)?.contains(secret) ?? true)
    }

    func testGatewayAndUserName() {
        XCTAssertNil(E.gatewayProblem(""))
        XCTAssertNil(E.gatewayProblem("  US East  "))
        XCTAssertEqual(E.normalizedGateway("  US East \n"), "US East")
        XCTAssertNotNil(E.gatewayProblem("=US East"))
        XCTAssertNotNil(E.gatewayProblem("US\nEast"))
        XCTAssertNotNil(E.gatewayProblem(String(repeating: "x", count: 256)))
        XCTAssertNil(E.usernameProblem(""))
        XCTAssertNil(E.usernameProblem("alice"))
        XCTAssertNotNil(E.usernameProblem("=alice"))
    }

    /// A gateway pin without a portal pin: openconnect then accepts only the pinned keys at the portal too.
    func testOnlyAGatewayKeyIsPointedOut() {
        XCTAssertTrue(E.pinsGatewayOnly(Self.profile(gatewayServerCert: Self.pin)))
        XCTAssertFalse(E.pinsGatewayOnly(Self.profile(serverCert: Self.otherPin, gatewayServerCert: Self.pin)))
        XCTAssertFalse(E.pinsGatewayOnly(Self.profile()))
        XCTAssertFalse(E.pinsGatewayOnly(Self.profile(skipPortal: true, gatewayServerCert: Self.pin)))
        var any = Self.profile(gatewayServerCert: Self.pin)
        any.type = .anyconnect
        XCTAssertFalse(E.pinsGatewayOnly(any))
    }

    // MARK: the portal's gateways

    func testTheGatewayListIsBoundToItsPortal() throws {
        var p = Self.profile()
        let choice = try XCTUnwrap(GatewayChoice(p, labels: ["US East", "EU West", "APAC"]))
        XCTAssertEqual(choice.portal, "vpn.example.com:443")
        XCTAssertEqual(choice.options(for: p), ["US East", "EU West", "APAC"])
        XCTAssertTrue(choice.allows("EU West", for: p))
        XCTAssertFalse(choice.allows("Moon", for: p), "only the portal's labels")
        // The gateway is no part of the portal: changing it keeps the list.
        p.gateway = "EU West"
        XCTAssertTrue(choice.matches(p))
        // Another host (its case aside), port, or skipping the portal: none offered.
        var other = p
        other.host = "VPN.EXAMPLE.COM"
        XCTAssertTrue(choice.matches(other))
        other.host = "vpn2.example.com"
        XCTAssertEqual(choice.options(for: other), [])
        other = p
        other.port = 8443
        XCTAssertFalse(choice.matches(other))
        other = p
        other.skipPortal = true
        XCTAssertFalse(choice.allows("US East", for: other))
        other = p
        other.id = "other"
        XCTAssertFalse(choice.matches(other))
        // Only for a GlobalProtect profile that signs in through the portal.
        XCTAssertNil(GatewayChoice(Self.profile(skipPortal: true), labels: ["A"]))
        var any = Self.profile()
        any.type = .anyconnect
        XCTAssertNil(GatewayChoice(any, labels: ["A"]))
    }

    /// The labels are the portal's text: only those the profile's `gateway` takes are offered, each once, at most 32.
    func testTheLabelsAreBoundedAndValidated() throws {
        let p = Self.profile()
        let labels = ["US East", "=bad", " padded", "Ä", String(repeating: "x", count: 65), "US East", "EU\u{7}", "APAC"]
        XCTAssertEqual(try XCTUnwrap(GatewayChoice(p, labels: labels)).labels, ["US East", "APAC"])
        XCTAssertEqual(try XCTUnwrap(GatewayChoice(p, labels: nil)).labels, [], "unreadable: none, the failure still counts")
        let many = (0..<40).map { "G\($0)" }
        XCTAssertEqual(try XCTUnwrap(GatewayChoice(p, labels: many)).labels.count, 32)
    }

    // MARK: Trust This Gateway

    func testTheGatewayKeyWaitsForThePortalKey() throws {
        let p = Self.profile()
        let offer = try XCTUnwrap(ServerTrustOffer(p, pin: Self.pin, gateway: "gw1.example.com:443"))
        var trust = try XCTUnwrap(GatewayTrust(offer))
        XCTAssertTrue(trust.needsPortalKey)
        XCTAssertEqual(trust.portalKey, .reading)
        XCTAssertEqual(trust.portal, "vpn.example.com:443")
        XCTAssertFalse(trust.canTrust, "not before the portal's key is shown")
        XCTAssertNil(trust.portalPin)

        // A failed read: still nothing to trust; Retry reads again.
        trust.portalKeyFailed("No answer", for: offer)
        XCTAssertEqual(trust.portalKey, .failed("No answer"))
        XCTAssertFalse(trust.canTrust)
        XCTAssertFalse(trust.portalKeyRead(Self.otherPin, for: offer), "not while failed")
        trust.retry()
        XCTAssertEqual(trust.portalKey, .reading)

        // An answer for another offer (the profile changed meanwhile) is not taken; one that is no pin fails.
        var changed = p
        changed.port = 8443
        let otherOffer = try XCTUnwrap(ServerTrustOffer(changed, pin: Self.pin, gateway: "gw1.example.com:443"))
        XCTAssertFalse(trust.portalKeyRead(Self.otherPin, for: otherOffer))
        XCTAssertEqual(trust.portalKey, .reading)
        var bad = trust
        XCTAssertFalse(bad.portalKeyRead("pin-sha256:short", for: offer))
        XCTAssertFalse(bad.canTrust)

        XCTAssertTrue(trust.portalKeyRead(" " + Self.otherPin + " ", for: offer))
        XCTAssertEqual(trust.portalKey, .read(Self.otherPin))
        XCTAssertTrue(trust.canTrust)
        XCTAssertEqual(trust.portalPin, Self.otherPin)
        XCTAssertFalse(trust.portalKeyRead(Self.pin, for: offer), "read once")
    }

    func testAPinnedPortalNeedsNoRead() throws {
        let offer = try XCTUnwrap(ServerTrustOffer(Self.profile(serverCert: Self.otherPin), pin: Self.pin, gateway: "gw1.example.com:443"))
        let trust = try XCTUnwrap(GatewayTrust(offer))
        XCTAssertFalse(trust.needsPortalKey)
        XCTAssertEqual(trust.portalKey, .notNeeded)
        XCTAssertTrue(trust.canTrust)
        XCTAssertNil(trust.portalPin)
        // The portal's own key is "Trust This Server…", not this confirmation.
        XCTAssertNil(GatewayTrust(try XCTUnwrap(ServerTrustOffer(Self.profile(), pin: Self.pin))))
    }

    // MARK: statuses

    func testTheNewFailuresHaveTheirStatus() {
        func status(_ failure: ConnectionFailure) -> DisplayStatus {
            DisplayStatus(DisplayStatus.Facts(Self.profile(), state: .disconnected, lastError: "x", failure: failure))
        }
        let at = Date(timeIntervalSince1970: 1_800_000_000)
        XCTAssertEqual(status(ConnectionFailure(kind: .ssoRequired, at: at)), .failed(.ssoRequired))
        var list = ConnectionFailure(kind: .configuration, at: at, credentialsSent: true)
        XCTAssertEqual(status(list), .failed(.message("x")))
        list.detail = .gatewayRequired
        XCTAssertEqual(status(list), .failed(.gatewayRequired), "labels unreadable: the typed detail says it")
        list.detail = nil
        list.gateways = ["US East"]
        XCTAssertEqual(status(list), .failed(.gatewayRequired))
        var notGP = ConnectionFailure(kind: .configuration, at: at)
        notGP.detail = .notGlobalProtectServer
        XCTAssertEqual(status(notGP), .failed(.notGlobalProtectServer))
        // The reason's text decides nothing: the words alone are another configuration failure.
        XCTAssertEqual(
            status(ConnectionFailure(kind: .configuration, at: at, reason: VPNLog.notGlobalProtectServer)), .failed(.message("x")))
        var key = ConnectionFailure(kind: .configuration, at: at, credentialsSent: true)
        key.serverCert = Self.pin
        key.detail = .gatewayRequired
        XCTAssertEqual(status(key), .failed(.serverNotTrusted), "a key first")

        for s in [DisplayStatus.failed(.ssoRequired), .failed(.gatewayRequired), .failed(.notGlobalProtectServer)] {
            XCTAssertFalse(s.summary(at: at).isEmpty)
            XCTAssertFalse(s.line(at: at).isEmpty)
            XCTAssertEqual(s.action, .tryAgain)
        }
        XCTAssertEqual(DisplayStatus.failed(.notGlobalProtectServer).line(at: at), VPNLog.notGlobalProtectServer)
    }

    /// The detail is the app's: `status --json` and the MCP tools report the failure exactly as before.
    func testTheDetailIsNotInTheJSON() throws {
        let at = Date(timeIntervalSince1970: 1_800_000_000)
        var failure = ConnectionFailure(kind: .configuration, at: at, reason: "r", credentialsSent: true)
        failure.gateways = ["US East"]
        let before = try JSONCoding.encoder().encode(failure)
        failure.detail = .gatewayRequired
        XCTAssertEqual(try JSONCoding.encoder().encode(failure), before)
        let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: before) as? [String: Any])
        XCTAssertFalse(json.keys.contains { $0.lowercased().contains("detail") })
        let decoded = try JSONCoding.decoder().decode(ConnectionFailure.self, from: before)
        XCTAssertNil(decoded.detail)
        XCTAssertEqual(decoded.gateways, ["US East"])
    }

    func testOnlyGlobalProtectIsExperimental() {
        XCTAssertEqual(VPNType.allCases.filter(\.isExperimental), [.globalprotect])
    }
}

extension ConnectionManagerTests {
    /// After a portal listed three gateways and the profile named none, the manager offers them for the profile's
    /// `gateway` (`gatewayChoice`), the status says so, and choosing one writes only that field, while the profile
    /// still names that portal.
    func testGlobalProtectGatewayChoiceAfterTheFailure() async throws {
        let p = try makeGlobalProtectProfile(gateway: "")
        let fake = FakeGlobalProtect(
            clock: clock,
            script: [
                .stderr(GP.portalPrelogin + GP.portalTLS + GP.portalConfig + GP.threeGateways),
                .stderr("GATEWAY: [US East|EU West|APAC]:***\nUser input required in non-interactive mode\n" + GP.failed)
            ],
            status: 1)
        let r = try await globalProtectFailure(fake, profile: p)
        XCTAssertEqual(r.error as? PTError, .invalidField("gateway"))
        XCTAssertEqual(r.failure.detail, .gatewayRequired)
        let choice = try XCTUnwrap(r.manager.gatewayChoice(p.id))
        XCTAssertEqual(choice.labels, ["US East", "EU West", "APAC"])
        XCTAssertEqual(choice.portal, "vpn.example.com:8443")
        let stored = try store.get(p.id)
        XCTAssertEqual(DisplayStatus(DisplayStatus.Facts(stored, in: r.manager)), .failed(.gatewayRequired))
        XCTAssertNil(r.manager.failedGateway(p.id))

        // Not a label of the portal's: refused, nothing written.
        XCTAssertThrowsError(try r.manager.chooseGateway(choice, label: "Moon")) { XCTAssertEqual($0 as? ServerTrustOffer.Stale, .init()) }
        let saved = try r.manager.chooseGateway(choice, label: "EU West")
        var expected = stored
        expected.gateway = "EU West"
        XCTAssertEqual(saved, expected, "only the gateway changed")
        XCTAssertNoThrow(try saved.checkGlobalProtectFields())

        // Another portal since: no list, and choosing is refused.
        try store.update(p.id) { $0.host = "vpn2.example.com" }
        XCTAssertNil(r.manager.gatewayChoice(p.id))
        XCTAssertThrowsError(try r.manager.chooseGateway(choice, label: "APAC"))
        XCTAssertEqual(try store.get(p.id).gateway, "EU West")
    }

    /// A server that is neither a GlobalProtect portal nor a gateway: the sign-in types it, so its status and card hold
    /// in any language. The failure's reason and error are replaced with their Turkish translations from the catalog, as
    /// the app shows them with Turkish active; the status still says "not a GlobalProtect server".
    func testGlobalProtectNotAServerInTurkish() async throws {
        let stderr =
            GP.portalPrelogin + GP.portalTLS + "POST https://vpn.example.com:8443/ssl-vpn/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Mac\n"
            + "Server is neither a GlobalProtect portal nor a gateway.\n" + GP.failed
        let r = try await globalProtectFailure(FakeGlobalProtect(clock: clock, script: [.stderr(stderr)], status: 1))
        XCTAssertEqual(r.error as? PTError, .invalidField("host"))
        XCTAssertEqual(r.failure.detail, .notGlobalProtectServer)
        XCTAssertFalse(r.failure.credentialsSent)
        XCTAssertNil(r.manager.gatewayChoice(r.profile.id))
        XCTAssertEqual(DisplayStatus(DisplayStatus.Facts(r.profile, in: r.manager)), .failed(.notGlobalProtectServer))

        let catalog = try LocalizationTests.loadCatalog()
        func turkish(_ key: String) throws -> String { try XCTUnwrap(catalog.values[key]?["tr"]?.first, key) }
        var failure = r.failure
        failure.reason = try turkish("This server is not a GlobalProtect portal or gateway")
        XCTAssertNotEqual(failure.reason, VPNLog.notGlobalProtectServer)
        let error = try turkish("The value of “%@” is not valid.").replacingOccurrences(of: "%@", with: "host")
        let status = DisplayStatus(DisplayStatus.Facts(r.profile, state: .disconnected, lastError: error, failure: failure))
        XCTAssertEqual(status, .failed(.notGlobalProtectServer), "the card shows with Turkish active")
        XCTAssertEqual(status.action, .tryAgain)

        // The gateway list too: typed by the sign-in, whatever the labels or the language.
        var list = ConnectionFailure(kind: .configuration, at: t0, credentialsSent: true)
        list.detail = .gatewayRequired
        XCTAssertEqual(
            DisplayStatus(DisplayStatus.Facts(r.profile, state: .disconnected, lastError: error, failure: list)), .failed(.gatewayRequired))
    }

    /// The gateway's key: the card knows which gateway; the confirmation saves the gateway's key only with the portal's
    /// key read for the same offer.
    func testGlobalProtectTrustThisGatewayFlow() async throws {
        let p = try makeGlobalProtectProfile(serverCert: "", gatewayServerCert: "")
        let stderr =
            GP.portalPrelogin + GP.portalTLS + GP.portalConfig + GP.oneGateway + GP.gatewayLogin
            + "Connected to 192.0.2.20:443\nSSL negotiation with gw1.example.com\nServer certificate verify failed: signer not found\n\n"
            + "Certificate from VPN server \"gw1.example.com\" failed verification.\nReason: signer not found\n"
            + "To trust this server in future, perhaps add this to your command line:\n    --servercert \(GP.otherPin)\n"
            + "SSL connection failure: Error in the certificate.\nFailed to open HTTPS connection to gw1.example.com\n" + GP.failed
        let r = try await globalProtectFailure(FakeGlobalProtect(clock: clock, script: [.stderr(stderr)], status: 1), profile: p)
        XCTAssertEqual(r.manager.failedGateway(p.id), "gw1.example.com:443")
        XCTAssertNil(r.manager.gatewayChoice(p.id))
        XCTAssertEqual(DisplayStatus(DisplayStatus.Facts(try store.get(p.id), in: r.manager)), .failed(.serverNotTrusted))

        let offer = try XCTUnwrap(r.manager.serverTrustOffer(p.id))
        var trust = try XCTUnwrap(GatewayTrust(offer))
        XCTAssertFalse(trust.canTrust)
        XCTAssertThrowsError(try r.manager.trustServer(offer, portalPin: trust.portalPin)) {
            XCTAssertEqual($0 as? ServerTrustOffer.PortalPinRequired, .init())
        }
        XCTAssertEqual(try store.get(p.id).gatewayServerCert, "", "nothing saved without the portal's key")
        XCTAssertTrue(trust.portalKeyRead(GP.portalPin, for: offer))
        let saved = try r.manager.trustServer(offer, portalPin: trust.portalPin)
        XCTAssertEqual([saved.serverCert, saved.gatewayServerCert], [GP.portalPin, GP.otherPin])
        XCTAssertNil(r.manager.serverTrustOffer(p.id))
        XCTAssertEqual(r.manager.failedGateway(p.id), "gw1.example.com:443", "the card still says which gateway")
    }
}
