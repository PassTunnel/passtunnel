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

    func testOtherFilesAreRejected() {
        XCTAssertNil(OpenedFiles.route([]))
        XCTAssertEqual(OpenedFiles.route([URL(fileURLWithPath: "/tmp/acme.ovpn")]), .unsupported("acme.ovpn"))
        XCTAssertEqual(OpenedFiles.route([URL(fileURLWithPath: "/tmp/acme.passtunnel.json")]),
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
        let bad = try write(#"{"passtunnel_profile":1,"profile":{"name":"Acme","type":"forti","host":"vpn.example.com\u0000"}}"#,
                            name: "bad.passtunnel")
        guard case .importShare(let url)? = OpenedFiles.route([bad]) else { return XCTFail("not routed to the import") }
        assertThrows(.invalidField("host")) { _ = try store.importShare(url, name: nil) }
        XCTAssertTrue(store.list().isEmpty)

        let good = try write(#"{"passtunnel_profile":1,"profile":{"name":"Acme","type":"forti","host":"vpn.example.com"}}"#,
                             name: "good.passtunnel")
        guard case .importShare(let url)? = OpenedFiles.route([good]) else { return XCTFail("not routed to the import") }
        XCTAssertEqual(try store.importShare(url, name: nil).host, "vpn.example.com")
    }

    /// The app hands opened files to the same import as File → Import Shared Profile.
    func testAppUsesTheSharedImport() throws {
        let root = LocalizationTests.root.appendingPathComponent("Sources/PassTunnel")
        let delegate = try String(contentsOf: root.appendingPathComponent("App/AppDelegate.swift"), encoding: .utf8)
        XCTAssertTrue(delegate.contains("func application(_ application: NSApplication, open urls: [URL])"))
        let actions = try String(contentsOf: root.appendingPathComponent("Editor/ImportActions.swift"), encoding: .utf8)
        XCTAssertTrue(actions.contains("case .importShare(let url):\n            AppDelegate.shared?.showMainWindow()\n            importShared(at: url)"))
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

    func testInfoPlistOpensShareFilesAsViewer() throws {
        let plist = try Self.infoPlist()
        let documents = try XCTUnwrap(plist["CFBundleDocumentTypes"] as? [[String: Any]])
        XCTAssertEqual(documents.count, 1)
        let document = try XCTUnwrap(documents.first)
        XCTAssertEqual(document["LSItemContentTypes"] as? [String], [ShareFile.typeIdentifier])
        XCTAssertEqual(document["CFBundleTypeRole"] as? String, "Viewer")
        XCTAssertEqual(document["LSHandlerRank"] as? String, "Owner")
        XCTAssertNil(document["NSDocumentClass"], "the app imports share files; it has no document class")
    }

    /// A share file is what the type says it is: JSON.
    func testShareFilesAreJSON() throws {
        let p = try store.create(name: "Acme", type: .forti)
        let out = home.appendingPathComponent("acme.\(ShareFile.fileExtension)")
        try store.exportShare(p.id, to: out)
        XCTAssertNotNil(try JSONSerialization.jsonObject(with: Data(contentsOf: out)) as? [String: Any])
    }
}
