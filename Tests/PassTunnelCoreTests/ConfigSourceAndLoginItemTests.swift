import Foundation
import XCTest
@testable import PassTunnelCore
@testable import PassTunnelKit

final class ConfigSourceTests: CoreTestCase {
    func testImportOVPNRecordsSourceNameAndTime() throws {
        let before = Date().addingTimeInterval(-1)
        let url = try write("client\nremote vpn.example.com 1194\n", name: "acme.ovpn")
        let p = try store.importOVPN(url, name: "Acme")
        XCTAssertEqual(p.configSourceName, "acme.ovpn")
        let at = try XCTUnwrap(p.configImportedAt)
        XCTAssertGreaterThanOrEqual(at, before.addingTimeInterval(-1))
        XCTAssertLessThanOrEqual(at, Date())
        XCTAssertEqual(try store.get(p.id), p)
    }

    func testSetOVPNUpdatesSourceAndKeepsOtherFields() throws {
        var p = try store.create(name: "Acme", type: .openvpn)
        p.username = "alice"
        try store.save(p)
        XCTAssertNil(try store.get(p.id).configSourceName)
        let when = Date(timeIntervalSince1970: 1_790_000_000.75)
        let saved = try store.setOVPN(p.id, from: try write("client\nremote vpn.example.com\n", name: "new.ovpn"), now: when)
        XCTAssertEqual(saved.configSourceName, "new.ovpn")
        XCTAssertEqual(saved.configImportedAt, Date(timeIntervalSince1970: 1_790_000_000))
        XCTAssertEqual(saved.username, "alice")
        XCTAssertEqual(try store.get(p.id), saved)
        let json = try String(contentsOf: store.dir(p.id).appendingPathComponent("profile.json"))
        XCTAssertTrue(json.contains(#""config_source_name" : "new.ovpn""#), json)
        XCTAssertTrue(json.contains(#""config_imported_at" : "2026-09-21T"#), json)
    }

    func testDecodingIsTolerant() throws {
        func decode(_ extra: String) throws -> Profile {
            try JSONCoding.decode(Profile.self, from: Data(#"{"id":"acme","name":"Acme","type":"openvpn"\#(extra)}"#.utf8))
        }
        let legacy = try decode("")
        XCTAssertNil(legacy.configSourceName)
        XCTAssertNil(legacy.configImportedAt)
        let iso = try decode(#","config_source_name":"acme.ovpn","config_imported_at":"2026-10-03T08:00:00Z""#)
        XCTAssertEqual(iso.configSourceName, "acme.ovpn")
        XCTAssertEqual(iso.configImportedAt, Date(timeIntervalSince1970: 1_791_014_400))
        let numeric = try decode(#","config_imported_at":1791014400"#)
        XCTAssertEqual(numeric.configImportedAt, Date(timeIntervalSince1970: 1_791_014_400))
        let junk = try decode(#","config_source_name":42,"config_imported_at":"yesterday""#)
        XCTAssertNil(junk.configSourceName)
        XCTAssertNil(junk.configImportedAt)
        XCTAssertNil(try decode(#","config_source_name":"""#).configSourceName)
        // Not written when unknown, so older profiles stay unchanged on disk.
        let text = String(decoding: try JSONCoding.encode(legacy), as: UTF8.self)
        XCTAssertFalse(text.contains("config_source_name"))
        XCTAssertFalse(text.contains("config_imported_at"))
    }

    func testShareKeepsSourceNameButNotImportTime() throws {
        let p = try store.importOVPN(try write("client\nremote vpn.example.com\n", name: "acme.ovpn"), name: "Acme")
        let shareURL = home.appendingPathComponent("acme.passtunnel")
        try store.exportShare(p.id, to: shareURL)
        let text = try String(contentsOf: shareURL)
        XCTAssertTrue(text.contains("config_source_name"))
        XCTAssertFalse(text.contains("config_imported_at"))
        let q = try store.importShare(shareURL, name: "Copy")
        XCTAssertEqual(q.configSourceName, "acme.ovpn")
        XCTAssertNotNil(q.configImportedAt)
    }
}

#if os(macOS)
final class LoginItemTests: XCTestCase {
    private func openEvent(property: OSType?) -> NSAppleEventDescriptor {
        let event = NSAppleEventDescriptor(eventClass: AEEventClass(kCoreEventClass), eventID: AEEventID(kAEOpenApplication),
                                           targetDescriptor: nil, returnID: AEReturnID(kAutoGenerateReturnID),
                                           transactionID: AETransactionID(kAnyTransactionID))
        if let property {
            event.setParam(NSAppleEventDescriptor(enumCode: property), forKeyword: AEKeyword(keyAEPropData))
        }
        return event
    }

    func testLoginLaunchEvent() {
        XCTAssertTrue(LoginItem.isBackgroundLaunch(arguments: ["PassTunnel"],
                                                   launchEvent: openEvent(property: OSType(keyAELaunchedAsLogInItem))))
        XCTAssertFalse(LoginItem.isBackgroundLaunch(arguments: ["PassTunnel"], launchEvent: openEvent(property: nil)))
        XCTAssertFalse(LoginItem.isBackgroundLaunch(arguments: ["PassTunnel"],
                                                    launchEvent: openEvent(property: OSType(keyAELaunchedAsServiceItem))))
        XCTAssertFalse(LoginItem.isBackgroundLaunch(arguments: ["PassTunnel"], launchEvent: nil))
    }

    func testBackgroundArgument() {
        XCTAssertTrue(LoginItem.isBackgroundLaunch(arguments: ["PassTunnel", "--background"], launchEvent: nil))
        // argv[0] is never treated as the flag.
        XCTAssertFalse(LoginItem.isBackgroundLaunch(arguments: ["--background"], launchEvent: nil))
    }

    func testUnavailableOutsideAppBundle() {
        // The test runner is not an .app, so the status never reaches SMAppService.
        XCTAssertFalse(LoginItem.isAvailable)
        XCTAssertEqual(LoginItem.status, .unavailable)
    }
}
#endif
