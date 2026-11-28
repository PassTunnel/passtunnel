import Foundation
import XCTest

@testable import PassTunnelCLI
@testable import PassTunnelCore
@testable import PassTunnelKit

private let macOS154 = OperatingSystemVersion(majorVersion: 15, minorVersion: 4, patchVersion: 0)
private let secret = "JBSWY3DPEHPK3PXP"

/// Code-only profiles (`VPNType.code`): no VPN, only the one-time code of a TOTP secret. They are stored with
/// their type's settings, edited with the keys they have, shared, listed, and refused before anything when
/// connecting, while their code is shown and printed like any other profile's.
final class CodeOnlyProfileTests: CoreTestCase {
    // MARK: model

    @MainActor
    func testTheType() throws {
        XCTAssertEqual(VPNType(rawValue: "code"), .code)
        XCTAssertEqual(VPNType.allCases.filter(\.isCodeOnly), [.code])
        XCTAssertEqual(VPNType.connectable, [.openvpn, .forti, .anyconnect, .globalprotect], "a code-only profile never connects")
        XCTAssertFalse(VPNType.code.isConnectable)
        XCTAssertEqual(ShareFile.version(for: .code), 2, "older readers refuse the type instead of misreading it")
        XCTAssertEqual(CLIRunner.typeName(.code), "Code only")
    }

    func testANewProfileHasOnlyItsCode() throws {
        let p = try store.create(name: "GitHub", type: .code)
        XCTAssertEqual(p.type, .code)
        XCTAssertEqual(p.otpMode, .totp)
        XCTAssertEqual(p.passwordMode, .none)
        XCTAssertEqual(p.needs, [], "nothing to ask")
        XCTAssertTrue(p.usesStoredSecrets, "its TOTP secret")
        XCTAssertEqual(try store.get(p.id), p)
    }

    /// Whatever it is given (a hand-edited file, an older editor), a code-only profile is saved without a password,
    /// a user name or anything that connects; "before connecting" becomes off, "always" stays.
    func testSaveKeepsTheTypesSettings() throws {
        var p = try store.create(name: "GitHub", type: .code)
        p.username = "alice"
        p.passwordMode = .keychain
        p.otpMode = .ask
        p.autoReconnect = true
        p.connectAtLogin = true
        p.sessionLimitMin = 60
        p.healthHost = "10.0.0.5"
        p.requireAuth = .connect
        try store.save(p)
        let stored = try store.get(p.id)
        XCTAssertEqual(stored.username, "")
        XCTAssertEqual(stored.passwordMode, .none)
        XCTAssertEqual(stored.otpMode, .totp)
        XCTAssertFalse(stored.autoReconnect)
        XCTAssertFalse(stored.connectAtLogin)
        XCTAssertEqual(stored.sessionLimitMin, 0)
        XCTAssertEqual(stored.healthHost, "")
        XCTAssertEqual(stored.requireAuth, .off)

        let updated = try store.update(p.id) {
            $0.requireAuth = .always; $0.passwordMode = .ask
        }
        XCTAssertEqual(updated.requireAuth, .always)
        XCTAssertEqual(updated.passwordMode, .none, "what update returns is what was saved")
        XCTAssertEqual(try store.get(p.id), updated)
    }

    /// Other types are not touched by it.
    func testOtherTypesKeepTheirSettings() throws {
        var p = try store.create(name: "Lab", type: .forti)
        p.username = "alice"
        p.requireAuth = .connect
        p.autoReconnect = true
        try store.save(p)
        let stored = try store.get(p.id)
        XCTAssertEqual(stored.username, "alice")
        XCTAssertEqual(stored.requireAuth, .connect)
        XCTAssertTrue(stored.autoReconnect)
        XCTAssertEqual(stored.passwordMode, .keychain)
    }

    // MARK: fields

    func testOnlyItsKeysCanBeSet() throws {
        var p = try store.create(name: "GitHub", type: .code)
        XCTAssertEqual(
            ProfileFields.keys(for: .code),
            ["name", "badge", "icon", "badge_style", "pinned", "order", "digits", "period", "algorithm", "require_auth"])
        try ProfileFields.set(&p, key: "digits", value: "8")
        try ProfileFields.set(&p, key: "totp.period", value: "60")
        try ProfileFields.set(&p, key: "algorithm", value: "SHA-256")
        try ProfileFields.set(&p, key: "require_auth", value: "always")
        try ProfileFields.set(&p, key: "require_auth", value: "off")
        XCTAssertEqual(p.totp, TOTPParams(digits: 8, period: 60, algorithm: .sha256))
        for key in [
            "username", "password_mode", "otp_mode", "otp_delivery", "otp_template", "session_limit_min", "auto_reconnect",
            "connect_at_login", "health_host", "host", "port", "trusted_cert", "server_cert", "gateway", "set_dns"
        ] {
            XCTAssertThrowsError(try ProfileFields.set(&p, key: key, value: "1"), key) {
                XCTAssertEqual($0 as? PTError, .wrongProfileType(p.id), key)
            }
        }
        XCTAssertThrowsError(try ProfileFields.set(&p, key: "require_auth", value: "connect")) {
            XCTAssertEqual($0 as? PTError, .invalidField("require_auth"), "nothing to confirm before connecting")
        }
    }

    // MARK: share files

    func testItIsSharedAndImportedWithoutItsSecret() throws {
        var p = try store.create(name: "GitHub", type: .code)
        p.totp = TOTPParams(digits: 8, period: 30, algorithm: .sha1)
        try store.save(p)
        try Secrets.set(p.id, .totp, secret)
        let file = home.appendingPathComponent("github.passtunnel")
        try store.exportShare(p.id, to: file)
        let text = String(decoding: try Data(contentsOf: file), as: UTF8.self)
        XCTAssertFalse(text.contains(secret), "never the secret")
        XCTAssertEqual(try ShareFile.read(from: file).passtunnelProfile, 2)

        let imported = try store.importShare(file, name: nil)
        XCTAssertNotEqual(imported.id, p.id)
        XCTAssertEqual(imported.type, .code)
        XCTAssertEqual(imported.totp.digits, 8)
        XCTAssertEqual(imported.otpMode, .totp)
        XCTAssertEqual(imported.passwordMode, .none)
        XCTAssertFalse(Secrets.has(imported.id, .totp))
    }

    // MARK: connecting

    func testItIsRefusedAsCodeOnly() throws {
        let p = try store.create(name: "GitHub", type: .code)
        for macOS: OperatingSystemVersion? in [macOS154, nil] {
            XCTAssertNil(ConnectionManager.connectRefusal(.code, macOS: macOS), "its code is shown as any other profile's")
            XCTAssertThrowsError(try ConnectionManager.checkConnectable(p, macOS: macOS)) {
                XCTAssertEqual($0 as? PTError, .codeOnlyProfile(p.id))
            }
        }
        let error = PTError.codeOnlyProfile(p.id)
        XCTAssertEqual(AutomationErrorCode.of(error), .invalidArgument)
        XCTAssertEqual(error.localizedDescription, "Profile “\(p.id)” only shows a one-time code. It has no VPN to connect.")
        XCTAssertNil(error.unavailableNote, "not a type this system lacks")
    }

    func testDestinationAndClaimsAreEmpty() throws {
        let p = try store.create(name: "GitHub", type: .code)
        XCTAssertEqual(ProfileDestination.of(p, store: store).host, "")
        XCTAssertTrue(ProfileNetwork.claims(for: p, store: store, live: true, tunnelRoutes: { _ in [] }).isEmpty)
        XCTAssertNil(ProfileNetwork.observedOptions(p, store: store, tunnelRoutes: { _ in [] }))
    }

    // MARK: status

    func testItShowsAsCodeOnly() throws {
        let p = try store.create(name: "GitHub", type: .code)
        let status = DisplayStatus(DisplayStatus.Facts(p, state: .disconnected, lastError: "old", droppedUnseen: true))
        XCTAssertEqual(status, .codeOnly)
        XCTAssertFalse(status.allowsAction, "no Connect")
        XCTAssertEqual(status.summary(at: Date()), "Code only")
        XCTAssertEqual(status.line(at: Date()), "Code only · no VPN to connect")
        // Other profiles are as before.
        let forti = try store.create(name: "Lab", type: .forti)
        XCTAssertEqual(DisplayStatus(DisplayStatus.Facts(forti, state: .disconnected)), .off)
    }
}

extension ConnectionManagerTests {
    /// Nothing is asked, read, run or sent for a code-only profile: it has no VPN.
    func testCodeOnlyIsRefusedBeforeAnything() async throws {
        var p = try store.create(name: "GitHub", type: .code)
        p.requireAuth = .always
        try store.save(p)
        p = try store.get(p.id)
        try Secrets.set(p.id, .totp, totpSecret)
        let m = makeManager()
        let requestsBefore = helper.requests.count
        let attempts: [() async throws -> Void] = [
            { try await m.connect(p.id) },
            { try await m.connect(p.id, followOnly: true) },
            { try await m.connect(p.id, interactive: false) },
            { _ = try await m.checkCanStart(p.id) },
            { try await m.toggle(p.id) }
        ]
        for (n, attempt) in attempts.enumerated() {
            do {
                try await attempt()
                XCTFail("attempt \(n) went ahead")
            } catch {
                XCTAssertEqual(error as? PTError, .codeOnlyProfile(p.id), "attempt \(n)")
            }
        }
        XCTAssertEqual(authenticator.calls, 0, "no Touch ID")
        XCTAssertFalse(m.vault.isUnlocked(p.id, .totp))
        XCTAssertEqual(helper.requests.count, requestsBefore, "the helper was not asked anything")
        XCTAssertEqual(m.state(p.id), .disconnected)
    }
}

extension AnyConnectCLITests {
    /// `add --type code`, `code`, `list`, `show` and `connect` of a code-only profile.
    func testCodeOnlyInTheCommand() async throws {
        XCTAssertEqual(try CLICommand.parse(["add", "GitHub", "--type", "code"]), .add(name: "GitHub", type: .code))
        XCTAssertThrowsError(try CLICommand.parse(["add", "GitHub", "--type", "code", "--server", "https://vpn.example.com"])) {
            XCTAssertEqual(($0 as? CLIUsageError)?.command, "add")
        }
        XCTAssertThrowsError(try CLICommand.parse(["add", "GitHub", "--type", "authenticator"])) {
            XCTAssertTrue(($0 as? CLIUsageError)?.message.contains("globalprotect or code") == true)
        }

        let added = try await run(.add(name: "GitHub", type: .code), macOS: macOS154)
        XCTAssertEqual(added.code, 0, added.err)
        XCTAssertTrue(added.err.contains("passtunnel secret github totp"), added.err)
        let p = try store.get("github")
        XCTAssertEqual(p.type, .code)
        try Secrets.set(p.id, .totp, secret)

        let code = try await run(.code(id: p.id, copy: false, json: true), macOS: macOS154)
        XCTAssertEqual(code.code, 0, code.err)
        let printed = try XCTUnwrap(code.json?["code"] as? String)
        XCTAssertEqual(printed.count, 6)
        XCTAssertTrue(printed.allSatisfy(\.isNumber))

        let list = try await run(.list(json: true, quiet: false), macOS: macOS154)
        let entry = try XCTUnwrap(list.jsonArray?.first { $0["id"] as? String == p.id })
        XCTAssertEqual(entry["type"] as? String, "code")
        XCTAssertNil(entry["connect_refusal"], "its code works: nothing to refuse")

        let show = try await run(.show(id: p.id, json: false), macOS: macOS154)
        XCTAssertEqual(show.code, 0, show.err)
        XCTAssertFalse(show.out.contains("password"), show.out)
        XCTAssertTrue(show.out.contains("totp_secret"), show.out)

        let connect = try await run(.connect(id: p.id), macOS: macOS154)
        XCTAssertEqual(connect.code, AutomationExit.usage)
        XCTAssertTrue(connect.err.contains("only shows a one-time code"), connect.err)
    }
}
