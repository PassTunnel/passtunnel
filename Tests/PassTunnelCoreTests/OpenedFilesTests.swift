import Foundation
import XCTest

@testable import PassTunnelCore
@testable import PassTunnelKit

/// Files opened from Finder, AirDrop or `open`, and the type declarations in the app's Info.plist.
final class OpenedFilesTests: CoreTestCase {
    func testOneShareFileIsImported() {
        let url = URL(fileURLWithPath: "/tmp/acme.passtunnel")
        XCTAssertEqual(OpenedFiles.route([url]), .importShare(url))
        let upper = URL(fileURLWithPath: "/tmp/Acme.PASSTUNNEL")
        XCTAssertEqual(OpenedFiles.route([upper]), .importShare(upper))
    }

    /// OpenVPN configurations go to the import review of the main window.
    func testOpenVPNConfigurationsAreRoutedToTheirImport() {
        for name in ["acme.ovpn", "Acme.OVPN", "acme.conf"] {
            let url = URL(fileURLWithPath: "/tmp/\(name)")
            XCTAssertEqual(OpenedFiles.route([url]), .importOVPN(url), name)
        }
        XCTAssertEqual(
            OpenedFiles.route([URL(string: "https://vpn.example.com/acme.ovpn")!]),
            .unsupported("https://vpn.example.com/acme.ovpn"))
    }

    func testOtherFilesAreRejected() {
        XCTAssertNil(OpenedFiles.route([]))
        XCTAssertEqual(OpenedFiles.route([URL(fileURLWithPath: "/tmp/acme.ovpn.txt")]), .unsupported("acme.ovpn.txt"))
        XCTAssertEqual(
            OpenedFiles.route([URL(fileURLWithPath: "/tmp/acme.passtunnel.json")]),
            .unsupported("acme.passtunnel.json"))
        XCTAssertEqual(OpenedFiles.route([URL(fileURLWithPath: "/tmp/passtunnel")]), .unsupported("passtunnel"))
        let web = URL(string: "https://vpn.example.com/acme.passtunnel")!
        XCTAssertEqual(OpenedFiles.route([web]), .unsupported(web.absoluteString))
    }

    /// Like the File → Import Shared Profile panel: one file; several import nothing.
    func testSeveralFilesImportNothing() {
        let a = URL(fileURLWithPath: "/tmp/a.passtunnel"), b = URL(fileURLWithPath: "/tmp/b.passtunnel")
        XCTAssertEqual(OpenedFiles.route([a, b]), .tooMany(2))
        XCTAssertEqual(OpenedFiles.route([a, URL(fileURLWithPath: "/tmp/c.ovpn")]), .tooMany(2))
    }

    /// An opened file goes through `ProfileStore.importShare`, with all its checks (hosts included).
    func testOpenedFileIsValidatedLikeAnImport() throws {
        let bad = try write(
            #"{"passtunnel_profile":1,"profile":{"name":"Acme","type":"forti","host":"vpn.example.com\u0000"}}"#,
            name: "bad.passtunnel")
        guard case .importShare(let url)? = OpenedFiles.route([bad]) else { return XCTFail("not routed to the import") }
        assertThrows(.invalidField("host")) { _ = try store.importShare(url, name: nil) }
        XCTAssertTrue(store.list().isEmpty)

        let good = try write(
            #"{"passtunnel_profile":1,"profile":{"name":"Acme","type":"forti","host":"vpn.example.com"}}"#,
            name: "good.passtunnel")
        guard case .importShare(let url)? = OpenedFiles.route([good]) else { return XCTFail("not routed to the import") }
        XCTAssertEqual(try store.importShare(url, name: nil).host, "vpn.example.com")
    }

    /// Opened share files go to the same import as File → Import Shared Profile, configurations to the review.
    func testAppUsesTheSharedImportAndTheReview() throws {
        let root = LocalizationTests.root.appendingPathComponent("Sources/PassTunnel")
        let delegate = try String(contentsOf: root.appendingPathComponent("App/AppDelegate.swift"), encoding: .utf8)
        XCTAssertTrue(delegate.contains("func application(_ application: NSApplication, open urls: [URL])"))
        let actions = try String(contentsOf: root.appendingPathComponent("Editor/ImportActions.swift"), encoding: .utf8)
        XCTAssertTrue(
            actions.contains("case .importShare(let url):\n            AppDelegate.shared?.showMainWindow()\n            importShared(at: url)"))
        // An opened configuration goes through the review, like File → Import .ovpn….
        XCTAssertTrue(actions.contains("case .importOVPN(let url):\n            importOVPN(at: url)"))
        XCTAssertTrue(actions.contains("guard let model = AppModel.shared else { return }\n        review(url, in: model)"))
    }

    // MARK: Info.plist

    static func infoPlist() throws -> [String: Any] {
        let data = try Data(contentsOf: LocalizationTests.root.appendingPathComponent("Resources/Info.plist"))
        return try XCTUnwrap(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
    }

    func testInfoPlistExportsTheShareFileType() throws {
        let plist = try Self.infoPlist()
        let exported = try XCTUnwrap(plist["UTExportedTypeDeclarations"] as? [[String: Any]])
        XCTAssertEqual(exported.count, 1)
        let type = try XCTUnwrap(exported.first)
        XCTAssertEqual(type["UTTypeIdentifier"] as? String, ShareFile.typeIdentifier)
        XCTAssertEqual(type["UTTypeConformsTo"] as? [String], ["public.json"])
        XCTAssertFalse((type["UTTypeDescription"] as? String ?? "").isEmpty)
        let tags = try XCTUnwrap(type["UTTypeTagSpecification"] as? [String: Any])
        XCTAssertEqual(tags["public.filename-extension"] as? [String], [ShareFile.fileExtension])
    }

    static let ovpnTypeIdentifier = "com.furkanprlk.passtunnel.ovpn"

    /// The app's documents, by their one content type.
    static func documentTypes() throws -> [String: [String: Any]] {
        let documents = try XCTUnwrap(try infoPlist()["CFBundleDocumentTypes"] as? [[String: Any]])
        var byType: [String: [String: Any]] = [:]
        for document in documents {
            let types = try XCTUnwrap(document["LSItemContentTypes"] as? [String])
            XCTAssertEqual(types.count, 1)
            XCTAssertNil(document["CFBundleTypeExtensions"], "claimed by content type only")
            XCTAssertNil(document["NSDocumentClass"], "the app imports files; it has no document class")
            XCTAssertEqual(document["CFBundleTypeRole"] as? String, "Viewer", "the app imports files, never edits them")
            byType[types[0]] = document
        }
        XCTAssertEqual(byType.count, documents.count)
        return byType
    }

    func testInfoPlistOpensShareFilesAsTheirOwner() throws {
        let documents = try Self.documentTypes()
        XCTAssertEqual(Set(documents.keys), [ShareFile.typeIdentifier, Self.ovpnTypeIdentifier])
        XCTAssertEqual(documents[ShareFile.typeIdentifier]?["LSHandlerRank"] as? String, "Owner")
    }

    /// `.ovpn` is not PassTunnel's format: an imported type (another app's exported one wins), opened as an
    /// alternate handler, so PassTunnel is in Open With and can be made the default without taking over from an
    /// installed VPN client.
    func testInfoPlistOpensOpenVPNConfigurationsAsAnAlternate() throws {
        let imported = try XCTUnwrap(try Self.infoPlist()["UTImportedTypeDeclarations"] as? [[String: Any]])
        XCTAssertEqual(imported.count, 1)
        let type = try XCTUnwrap(imported.first)
        XCTAssertEqual(type["UTTypeIdentifier"] as? String, Self.ovpnTypeIdentifier)
        XCTAssertEqual(type["UTTypeConformsTo"] as? [String], ["public.data"])
        XCTAssertFalse((type["UTTypeDescription"] as? String ?? "").isEmpty)
        let tags = try XCTUnwrap(type["UTTypeTagSpecification"] as? [String: Any])
        XCTAssertEqual(tags["public.filename-extension"] as? [String], ["ovpn"])
        XCTAssertEqual(try Self.documentTypes()[Self.ovpnTypeIdentifier]?["LSHandlerRank"] as? String, "Alternate")
    }

    /// `.conf` is used by many programs: no type declares it and no document claims it, so other `.conf` files keep
    /// their kind and their app. An OpenVPN `.conf` still opens with Open With, File → Import .ovpn… or a drop.
    func testInfoPlistLeavesConfFilesAlone() throws {
        let plist = try Self.infoPlist()
        for key in ["UTExportedTypeDeclarations", "UTImportedTypeDeclarations"] {
            for type in plist[key] as? [[String: Any]] ?? [] {
                let tags = type["UTTypeTagSpecification"] as? [String: Any]
                XCTAssertFalse((tags?["public.filename-extension"] as? [String] ?? []).contains("conf"), key)
            }
        }
        XCTAssertFalse(try Self.documentTypes().keys.contains { $0.contains("conf") })
    }

    /// A share file is what the type says it is: JSON.
    func testShareFilesAreJSON() throws {
        let p = try store.create(name: "Acme", type: .forti)
        let out = home.appendingPathComponent("acme.\(ShareFile.fileExtension)")
        try store.exportShare(p.id, to: out)
        XCTAssertNotNil(try JSONSerialization.jsonObject(with: Data(contentsOf: out)) as? [String: Any])
    }
}
