import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit
@testable import PassTunnelVPNConfig

/// The Mac app's Cisco AnyConnect editor and views (#186), as far as they are Core's: the server address pasted into
/// the editor, the group, user name and pin checks (`AnyConnectEditing`), the status of a profile this Mac cannot
/// connect (below macOS 15.4, `DisplayStatus.unavailable`) and of the AnyConnect failures, and "Trust this server"
/// (`ServerTrustOffer`, `ConnectionManager.trustServer`).
final class AnyConnectEditorTests: XCTestCase {
    typealias E = AnyConnectEditing
    static let pin = "pin-sha256:B9S1MyM7eI6e0MBVCfgWo0zkSVpzyFfkmueG8/HAbiY="
    static let otherPin = "pin-sha256:E86EpKhiszwwyqu937GB+mox53WHxoGiVhwY7ZXxrwQ="

    // MARK: the server address

    func testPastingAnAddressSetsHostPortAndGroup() {
        var p = Profile(id: "corp", name: "Corp", type: .anyconnect)
        E.applyServer("  HTTPS://VPN.Example.com:8443/engineering \n", to: &p)
        XCTAssertEqual([p.host, String(p.port), p.usergroup], ["vpn.example.com", "8443", "engineering"])
        XCTAssertEqual(E.serverText(host: p.host, port: p.port, usergroup: p.usergroup), "https://vpn.example.com:8443/engineering")

        E.applyServer("vpn.example.com", to: &p)
        XCTAssertEqual([p.host, String(p.port), p.usergroup], ["vpn.example.com", "443", ""])
        XCTAssertEqual(E.serverText(host: p.host, port: p.port, usergroup: p.usergroup), "https://vpn.example.com")

        E.applyServer("https://[2001:db8::1]:10443/staff/eu", to: &p)
        XCTAssertEqual([p.host, String(p.port), p.usergroup], ["2001:db8::1", "10443", "staff/eu"])
        XCTAssertEqual(E.serverText(host: p.host, port: p.port, usergroup: p.usergroup), "https://[2001:db8::1]:10443/staff/eu")

        // Something that is no address leaves the fields as they were; clearing the field clears them.
        E.applyServer("https://vpn.example.com:99999", to: &p)
        XCTAssertEqual(p.host, "2001:db8::1")
        E.applyServer("   ", to: &p)
        XCTAssertEqual([p.host, String(p.port), p.usergroup], ["", "443", ""])
        XCTAssertEqual(E.serverText(host: "", port: 443, usergroup: "x"), "")
    }

    /// A host stored with capitals (by hand or the CLI) is the same server: pasting it again changes nothing to save.
    func testTheStoredSpellingOfTheSameHostIsKept() {
        var p = Profile(id: "corp", name: "Corp", type: .anyconnect)
        p.host = "VPN.Example.com"
        let text = E.serverText(host: p.host, port: p.port, usergroup: p.usergroup)
        XCTAssertEqual(text, "https://VPN.Example.com")
        XCTAssertNil(E.serverProblem(text))
        E.applyServer(text, to: &p)
        XCTAssertEqual(p.host, "VPN.Example.com")
    }

    func testServerProblems() {
        let cases: [(String, E.ServerProblem?)] = [
            ("https://vpn.example.com", nil), ("vpn.example.com:8443/engineering", nil), ("https://[::1]", nil),
            ("", .empty), ("  \n", .empty),
            ("http://vpn.example.com", .scheme), ("ftp://vpn.example.com", .scheme),
            ("https://alice@vpn.example.com", .userInfo), ("https://alice:hunter2@vpn.example.com/x", .userInfo),
            ("https://vpn.example.com/?token=abc", .queryOrFragment), ("https://vpn.example.com#", .queryOrFragment),
            ("https://vpn.example.com/a%20b", .percentEscape),
            ("https://vpn.example.com:0", .port), ("https://vpn.example.com:65536", .port), ("https://vpn.example.com:08443", .port),
            ("https://vpn.example.com:", .port), ("https://[::1]:x", .port),
            ("https://vpn.example.com/../etc", .group), ("https://vpn.example.com/a b", .group),
            ("https://vpn example.com", .host), ("https://2001:db8::1", .host), ("https://[fe80::1%25en0]", .percentEscape),
            ("https://[::1", .host), ("https://-bad-.example.com", .host)
        ]
        for (text, expected) in cases {
            XCTAssertEqual(E.serverProblem(text), expected, text)
            // What `parse` takes is exactly what has no problem.
            XCTAssertEqual(E.serverProblem(text) == nil, AnyConnectServer.parse(text) != nil, text)
        }
    }

    /// No message repeats what was typed: a password pasted into the wrong field shows up nowhere else.
    func testMessagesNeverEchoTheInput() {
        let secret = "Hunter2Secret"
        let inputs = [
            "https://\(secret)@vpn.example.com", "https://vpn.example.com/?\(secret)", "http://\(secret)",
            "https://vpn.example.com:\(secret)", "https://vpn.example.com/\(secret) x", secret + " " + secret
        ]
        for text in inputs {
            let problem = try? XCTUnwrap(E.serverProblem(text), text)
            XCTAssertFalse(problem?.message.contains(secret) ?? true, text)
        }
        for message in [E.groupProblem("=\(secret)"), E.pinProblem(secret), E.usernameProblem("=\(secret)")] {
            XCTAssertNotNil(message)
            XCTAssertFalse(message?.contains(secret) ?? true)
        }
        XCTAssertEqual(E.ServerProblem.port.message, "The port must be between 1 and 65535.")
    }

    // MARK: group, user name and pin

    func testGroup() {
        XCTAssertEqual(E.normalizedGroup("  Employees \n"), "Employees")
        XCTAssertNil(E.groupProblem(""))
        XCTAssertNil(E.groupProblem(" Employees "), "the blanks are dropped on save")
        XCTAssertNotNil(E.groupProblem("=Employees"))
        XCTAssertNotNil(E.groupProblem("Emp\u{7}loyees"))
        XCTAssertNotNil(E.groupProblem(String(repeating: "g", count: 256)))
        XCTAssertNil(E.groupProblem(String(repeating: "g", count: 255)))
    }

    func testUserName() {
        XCTAssertNil(E.usernameProblem(""), "asked each time")
        XCTAssertNil(E.usernameProblem("alice"))
        XCTAssertNotNil(E.usernameProblem("=alice"))
        XCTAssertNotNil(E.usernameProblem("al\tice"))
        XCTAssertNotNil(E.usernameProblem(String(repeating: "a", count: 256)))
    }

    func testPinNormalization() {
        let pin = Self.pin
        XCTAssertEqual(E.normalizedPin(""), "")
        XCTAssertEqual(E.normalizedPin("  \n"), "")
        XCTAssertEqual(E.normalizedPin(pin), pin)
        XCTAssertEqual(E.normalizedPin("  PIN-SHA256:" + pin.dropFirst("pin-sha256:".count) + "\n"), pin)
        XCTAssertNil(E.pinProblem(""))
        XCTAssertNil(E.pinProblem(" " + pin.uppercased().prefix(11) + pin.dropFirst(11)))
        // The base64 is case-sensitive: its spelling is kept, and a wrong one is refused, never "fixed".
        XCTAssertNotNil(E.pinProblem("pin-sha256:" + pin.dropFirst(11).lowercased()))
        for bad in ["sha256:abcd", "pin-sha256:", String(pin.dropLast()), pin + "=", String(repeating: "ab", count: 32)] {
            XCTAssertNotNil(E.pinProblem(bad), bad)
            XCTAssertEqual(E.normalizedPin(bad), bad, "kept as typed, for the error to point at")
        }
        // What the editor saves passes the profile's own check.
        var p = Profile(id: "corp", name: "Corp", type: .anyconnect)
        p.host = "vpn.example.com"
        p.serverCert = E.normalizedPin("  PIN-sha256:" + pin.dropFirst(11))
        XCTAssertNoThrow(try p.checkAnyConnectFields())
    }

    // MARK: below macOS 15.4

    static let oldMac = OperatingSystemVersion(majorVersion: 14, minorVersion: 7, patchVersion: 6)
    static let newMac = OperatingSystemVersion(majorVersion: 15, minorVersion: 4, patchVersion: 0)

    func testBelowMacOS154TheProfileIsListedDisabledWithTheNote() {
        var p = Profile(id: "corp", name: "Corp", type: .anyconnect)
        p.otpMode = .totp
        let refusal = ConnectionManager.connectRefusal(.anyconnect, macOS: Self.oldMac)
        let status = DisplayStatus(DisplayStatus.Facts(p, state: .disconnected, refusal: refusal))
        XCTAssertEqual(
            status, .unavailable(note: "Requires macOS 15.4 or later", reason: "Cisco AnyConnect requires macOS 15.4 or later."))
        XCTAssertFalse(status.allowsAction, "Connect is shown disabled")
        XCTAssertEqual(status.action, .connect)
        XCTAssertEqual(status.summary(at: Date()), "Requires macOS 15.4 or later")
        XCTAssertEqual(status.line(at: Date()), "Cisco AnyConnect requires macOS 15.4 or later.")
        // It wins over an earlier failure and a protected profile's "Touch ID to connect".
        p.requireAuth = .always
        XCTAssertEqual(
            DisplayStatus(DisplayStatus.Facts(p, state: .disconnected, lastError: "x", refusal: refusal)).summary(at: Date()),
            "Requires macOS 15.4 or later")
        // On 15.4, and for the other types, nothing changes.
        XCTAssertNil(ConnectionManager.connectRefusal(.anyconnect, macOS: Self.newMac))
        XCTAssertEqual(DisplayStatus(DisplayStatus.Facts(p, state: .disconnected)), .protected)
        for type in [VPNType.openvpn, .forti] { XCTAssertNil(ConnectionManager.connectRefusal(type, macOS: Self.oldMac)) }
        XCTAssertTrue(DisplayStatus.off.allowsAction)
    }

    // MARK: failures

    func testCertificateAndHostScanFailures() {
        let p = Profile(id: "corp", name: "Corp", type: .anyconnect)
        var cert = ConnectionFailure(kind: .configuration, at: Date(), reason: "signer not found")
        cert.serverCert = Self.pin
        let message = PTError.serverCertificateRejected(reason: "signer not found", pin: Self.pin, log: "").localizedDescription
        let status = DisplayStatus(DisplayStatus.Facts(p, state: .disconnected, lastError: message, failure: cert))
        XCTAssertEqual(status, .failed(.serverNotTrusted))
        XCTAssertEqual(status.summary(at: Date()), "Server not trusted")
        XCTAssertEqual(status.line(at: Date()), "The server’s certificate is not trusted")
        XCTAssertEqual(status.action, .tryAgain)
        // Another configuration failure without a key stays the error's own words.
        let other = ConnectionFailure(kind: .configuration, at: Date())
        XCTAssertEqual(DisplayStatus(DisplayStatus.Facts(p, state: .disconnected, lastError: "x", failure: other)), .failed(.message("x")))

        let scan = ConnectionFailure(kind: .hostScanRequired, at: Date())
        let scanned = DisplayStatus(DisplayStatus.Facts(p, state: .disconnected, lastError: "x", failure: scan))
        XCTAssertEqual(scanned, .failed(.hostScanRequired))
        XCTAssertEqual(scanned.summary(at: Date()), "Host scan required")
        XCTAssertEqual(scanned.line(at: Date()), "The server requires a host scan")
    }

    // MARK: the trust offer

    func testTheOfferHoldsTheServerAndTheKey() throws {
        var p = Profile(id: "corp", name: "Corp", type: .anyconnect)
        p.host = " vpn.example.com "
        p.port = 8443
        p.usergroup = "engineering"
        let offer = try XCTUnwrap(ServerTrustOffer(p, pin: "  " + Self.pin + "\n"))
        XCTAssertEqual(offer.pin, Self.pin)
        XCTAssertEqual(offer.replacing, "")
        XCTAssertEqual(offer.server, "vpn.example.com:8443/engineering")
        XCTAssertTrue(offer.matches(p))

        // Not an offer: another type, no pin or not a full one, or the key the profile already trusts.
        XCTAssertNil(ServerTrustOffer(Profile(id: "f", name: "F", type: .forti), pin: Self.pin))
        XCTAssertNil(ServerTrustOffer(p, pin: nil))
        XCTAssertNil(ServerTrustOffer(p, pin: "pin-sha256:abc"))
        p.serverCert = Self.pin
        XCTAssertNil(ServerTrustOffer(p, pin: Self.pin))
        // Another key than the pinned one: the offer replaces it, and says which.
        let replacing = try XCTUnwrap(ServerTrustOffer(p, pin: Self.otherPin))
        XCTAssertEqual(replacing.replacing, Self.pin)

        // Only while the profile names the same server with the same pin.
        var changed = p
        changed.host = "VPN.EXAMPLE.COM"
        XCTAssertTrue(replacing.matches(changed), "the same host")
        for edit: (inout Profile) -> Void in [
            { $0.host = "vpn2.example.com" }, { $0.port = 443 }, { $0.usergroup = "" }, { $0.serverCert = "" },
            { $0.serverCert = Self.otherPin }, { $0.id = "other" }
        ] {
            var q = p
            edit(&q)
            XCTAssertFalse(replacing.matches(q))
        }
    }
}

// MARK: - "Trust this server" against the manager

extension ConnectionManagerTests {
    /// The manager's macOS (`systemVersion`) decides whether a Cisco AnyConnect profile is shown disabled.
    func testTheManagersMacOSDecidesTheAnyConnectStatus() {
        let m = makeManager()
        var p = Profile(id: "corp", name: "Corp", type: .anyconnect)
        p.host = "vpn.example.com"
        m.systemVersion = AnyConnectEditorTests.oldMac
        XCTAssertEqual(DisplayStatus(DisplayStatus.Facts(p, in: m)).summary(at: Date()), "Requires macOS 15.4 or later")
        m.systemVersion = AnyConnectEditorTests.newMac
        XCTAssertEqual(DisplayStatus(DisplayStatus.Facts(p, in: m)), .off)
        m.systemVersion = nil  // Linux: the distribution's openconnect is checked when connecting
        XCTAssertEqual(DisplayStatus(DisplayStatus.Facts(p, in: m)), .off)
    }

    /// openconnect did not trust the certificate and printed the key's pin: the manager offers it for the server the
    /// sign-in went to; trusting it writes only `server_cert`, and the next sign-in pins that key.
    func testTrustThisServerKeepsThePinAfterTheFailure() async throws {
        let r = try await signInFailure(Out.output(status: 1, stderr: Out.untrusted), pin: "")
        let id = r.profile.id
        let offer = try XCTUnwrap(r.manager.serverTrustOffer(id))
        XCTAssertEqual(offer.pin, Out.otherPin)
        XCTAssertEqual(offer.replacing, "")
        XCTAssertEqual(offer.server, "vpn.example.com:8443/engineering")

        let before = try store.get(id)
        let saved = try r.manager.trustServer(offer)
        XCTAssertEqual(saved.serverCert, Out.otherPin)
        var expected = before
        expected.serverCert = Out.otherPin
        XCTAssertEqual(try store.get(id), expected, "nothing else changed")
        XCTAssertNil(r.manager.serverTrustOffer(id), "taken")
        XCTAssertNoThrow(try store.get(id).checkAnyConnectFields())
        XCTAssertNotNil(r.manager.failures[id], "the failure stays until the next connect")
    }

    /// The pinned key no longer matches: the offer says which key it replaces.
    func testTrustTheNewKeyReplacesThePin() async throws {
        let r = try await signInFailure(Out.output(status: 1, stderr: Out.pinMismatch))
        let offer = try XCTUnwrap(r.manager.serverTrustOffer(r.profile.id))
        XCTAssertEqual(offer.pin, Out.otherPin)
        XCTAssertEqual(offer.replacing, Out.pin)
        XCTAssertEqual(try r.manager.trustServer(offer).serverCert, Out.otherPin)
    }

    /// The profile's server changed after the failure (the editor or the CLI): the key is not offered for the new
    /// server, and an offer still held is refused without writing anything.
    func testNoTrustForAServerThatChangedSince() async throws {
        let r = try await signInFailure(Out.output(status: 1, stderr: Out.untrusted), pin: "")
        let id = r.profile.id
        let offer = try XCTUnwrap(r.manager.serverTrustOffer(id))
        try store.update(id) { $0.host = "vpn2.example.com" }
        XCTAssertNil(r.manager.serverTrustOffer(id))
        XCTAssertThrowsError(try r.manager.trustServer(offer)) { XCTAssertEqual($0 as? ServerTrustOffer.Stale, ServerTrustOffer.Stale()) }
        XCTAssertEqual(try store.get(id).serverCert, "")
        try store.update(id) { $0.host = "vpn.example.com" }
        XCTAssertNotNil(r.manager.serverTrustOffer(id), "the same server again")
        // A pin set meanwhile (by hand) is not overwritten either.
        try store.update(id) { $0.serverCert = Out.pin }
        XCTAssertNil(r.manager.serverTrustOffer(id))
        XCTAssertThrowsError(try r.manager.trustServer(offer))
        XCTAssertEqual(try store.get(id).serverCert, Out.pin)
    }

    /// Other failures make no offer, and the next connect ends it.
    func testOnlyACertificateFailureOffersAKey() async throws {
        for stderr in [Out.refused, Out.hostScan, Out.rejected] {
            let r = try await signInFailure(Out.output(status: 1, stderr: stderr))
            XCTAssertNil(r.manager.serverTrustOffer(r.profile.id))
        }
        let r = try await signInFailure(Out.output(status: 1, stderr: Out.untrusted), pin: "")
        XCTAssertNotNil(r.manager.serverTrustOffer(r.profile.id))
        let fake = FakeOpenConnect()
        fake.results = [Out.output(status: 1, stderr: Out.refused)]
        r.manager.toolRunner = fake
        _ = try? await r.manager.connect(r.profile.id)
        XCTAssertNil(r.manager.serverTrustOffer(r.profile.id))
    }
}
