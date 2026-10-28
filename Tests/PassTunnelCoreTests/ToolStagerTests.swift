// macOS only, like ToolStager.
#if os(macOS)
import Darwin
import XCTest
@testable import PassTunnelShared

/// The helper runs the tools from a root-owned copy with their libraries (`ToolStager`). Uses a fake
/// bundle of ad-hoc signed programs with the tools' file names and load paths, never the VPN tools.
final class ToolStagerTests: XCTestCase {
    var base: URL!
    var contents: String { base.appendingPathComponent("Acme.app/Contents").path }
    var runRoot: String { base.appendingPathComponent("run").path }
    let buildID = String(repeating: "ab", count: 32)
    static let libraries = ["libacme.1.dylib", "libbase.1.dylib"]

    override func setUpWithError() throws {
        base = FileManager.default.temporaryDirectory.appendingPathComponent("pt-stage-\(UUID().uuidString)")
        try FileManager.default.createDirectory(atPath: contents + "/Resources/bin", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: contents + "/Frameworks/Sparkle.framework", withIntermediateDirectories: true)
        let fixture = try Self.fixture()
        for tool in HelperCore.Tool.allCases {
            try FileManager.default.copyItem(atPath: fixture + "/" + tool.rawValue, toPath: contents + "/Resources/bin/" + tool.rawValue)
        }
        for lib in Self.libraries {
            try FileManager.default.copyItem(atPath: fixture + "/" + lib, toPath: contents + "/Frameworks/" + lib)
        }
        try "#!/bin/sh\n".write(toFile: contents + "/Resources/bin/dns-updown", atomically: true, encoding: .utf8)
    }

    override func tearDownWithError() throws {
        // Staged directories are read-only; make them removable again.
        _ = run("/bin/chmod", ["-R", "u+w", base.path])
        try? FileManager.default.removeItem(at: base)
    }

    // MARK: - Fixture

    static var builtFixture: String?

    override class func tearDown() {
        if let builtFixture { try? FileManager.default.removeItem(atPath: builtFixture) }
        builtFixture = nil
        super.tearDown()
    }

    /// `openvpn`, `openfortivpn` and `openconnect` print where their library and its dependency were loaded from:
    /// `libacme` by `@executable_path/../../Frameworks`, `libbase` by `@loader_path`, as bundle-tools.sh
    /// writes them. Built once per run.
    static func fixture() throws -> String {
        if let builtFixture { return builtFixture }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("pt-stage-fixture-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let dl = "#include <dlfcn.h>\n"
        try (dl + "const char *base_path(void) { Dl_info i; dladdr((void *)base_path, &i); return i.dli_fname; }\n")
            .write(toFile: dir + "/base.c", atomically: true, encoding: .utf8)
        try
            (dl + "const char *base_path(void);\nconst char *acme_path(void) { Dl_info i; dladdr((void *)acme_path, &i); return i.dli_fname; }\n"
            + "const char *acme_base(void) { return base_path(); }\n")
            .write(toFile: dir + "/acme.c", atomically: true, encoding: .utf8)
        try
            "#include <stdio.h>\nconst char *acme_path(void); const char *acme_base(void);\nint main(void) { printf(\"%s\\n%s\\n\", acme_path(), acme_base()); return 0; }\n"
            .write(toFile: dir + "/tool.c", atomically: true, encoding: .utf8)
        let steps: [[String]] = [
            ["clang", "-dynamiclib", "-o", dir + "/libbase.1.dylib", dir + "/base.c", "-install_name", "@loader_path/libbase.1.dylib"],
            [
                "clang", "-dynamiclib", "-o", dir + "/libacme.1.dylib", dir + "/acme.c", dir + "/libbase.1.dylib",
                "-install_name", "@executable_path/../../Frameworks/libacme.1.dylib"
            ],
            ["clang", "-o", dir + "/openvpn", dir + "/tool.c", dir + "/libacme.1.dylib"],
            ["clang", "-o", dir + "/openfortivpn", dir + "/tool.c", dir + "/libacme.1.dylib"],
            ["clang", "-o", dir + "/openconnect", dir + "/tool.c", dir + "/libacme.1.dylib"]
        ]
        for step in steps where run("/usr/bin/xcrun", step) != 0 { throw XCTSkip("no C compiler available") }
        for name in ["openvpn", "openfortivpn", "openconnect", "libacme.1.dylib", "libbase.1.dylib"] {
            let id = "com.example.acme." + name.replacingOccurrences(of: ".1.dylib", with: "")
            guard run("/usr/bin/codesign", ["-f", "-s", "-", "-i", id, dir + "/" + name]) == 0 else {
                throw XCTSkip("codesign not available")
            }
        }
        builtFixture = dir
        return dir
    }

    @discardableResult
    func run(_ executable: String, _ args: [String], output: UnsafeMutablePointer<String>? = nil) -> Int32 {
        Self.run(executable, args, output: output)
    }

    @discardableResult
    static func run(_ executable: String, _ args: [String], output: UnsafeMutablePointer<String>? = nil) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = output == nil ? FileHandle.nullDevice : pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return -1 }
        if let output { output.pointee = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self) }
        p.waitUntilExit()
        return p.terminationStatus
    }

    static let toolRequirement: (HelperCore.Tool) -> String = { "identifier \"com.example.acme.\($0.rawValue)\"" }
    static let libraryRequirement = "identifier \"com.example.acme.libacme\" or identifier \"com.example.acme.libbase\""

    func stager(id: String? = nil, toolPins: [String: Set<String>] = [:], libraryPins: [String: Set<String>] = [:]) -> ToolStager {
        ToolStager(
            bundleContents: contents, runRoot: runRoot, buildID: id ?? buildID, toolPins: toolPins,
            libraryPins: libraryPins, toolRequirement: Self.toolRequirement, libraryRequirement: Self.libraryRequirement)
    }

    /// The pins build-app.sh would generate for the fake bundle.
    func pins() throws -> (tools: [String: Set<String>], libraries: [String: Set<String>]) {
        var tools: [String: Set<String>] = [:], libs: [String: Set<String>] = [:]
        for tool in HelperCore.Tool.allCases {
            tools[tool.rawValue] = [
                try CodeSignature.verify(
                    path: contents + "/Resources/bin/" + tool.rawValue,
                    requirement: Self.toolRequirement(tool))
            ]
        }
        tools["dns-updown"] = []
        for lib in Self.libraries {
            libs[lib] = [try CodeSignature.verify(path: contents + "/Frameworks/" + lib, requirement: Self.libraryRequirement)]
        }
        return (tools, libs)
    }

    func mode(_ path: String) -> mode_t {
        var st = stat()
        return lstat(path, &st) == 0 ? st.st_mode & 0o7777 : 0
    }

    func entries(_ path: String) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: path)) ?? []).sorted()
    }

    /// Flips a byte in the first page (hashed by the signature), keeping the file's mode.
    func corrupt(_ path: String) throws {
        let saved = mode(path)
        _ = chmod(path, 0o644)
        var data = try Data(contentsOf: URL(fileURLWithPath: path))
        let i = min(0x800, data.count / 4)
        data[i] ^= 0xff
        try data.write(to: URL(fileURLWithPath: path))
        _ = chmod(path, saved)
    }

    // MARK: - Tests

    func testStagesToolsAndLibrariesWithTheBundleLayout() throws {
        let p = try pins()
        let staged = try stager(toolPins: p.tools, libraryPins: p.libraries).stage()
        let realRoot = try XCTUnwrap(HelperCore.realPath(runRoot))
        XCTAssertEqual(staged.directory, realRoot + "/tools/" + buildID, "symlinks resolved, as proc_pidpath reports it")
        XCTAssertEqual(staged.executable(.openvpn), staged.directory + "/Resources/bin/openvpn")

        XCTAssertEqual(entries(staged.directory), ["Frameworks", "Resources"])
        XCTAssertEqual(
            entries(staged.directory + "/Resources/bin"), ["openconnect", "openfortivpn", "openvpn"], "dns-updown is copied per session")
        XCTAssertEqual(entries(staged.directory + "/Frameworks"), Self.libraries, "no Sparkle, nothing else")
        for dir in [
            realRoot + "/tools", staged.directory, staged.directory + "/Resources",
            staged.directory + "/Resources/bin", staged.directory + "/Frameworks"
        ] {
            XCTAssertEqual(mode(dir), 0o755, dir)
        }
        for tool in HelperCore.Tool.allCases {
            XCTAssertEqual(mode(staged.executable(tool)), 0o555)
            XCTAssertTrue(
                FileManager.default.contentsEqual(
                    atPath: staged.executable(tool),
                    andPath: contents + "/Resources/bin/" + tool.rawValue))
        }
        for lib in Self.libraries { XCTAssertEqual(mode(staged.directory + "/Frameworks/" + lib), 0o444) }

        // The staged tool loads the staged libraries, never the bundle's.
        var out = ""
        XCTAssertEqual(run(staged.executable(.openvpn), [], output: &out), 0)
        let loaded = out.split(separator: "\n").map { HelperCore.realPath(String($0)) }
        XCTAssertEqual(loaded, [staged.directory + "/Frameworks/libacme.1.dylib", staged.directory + "/Frameworks/libbase.1.dylib"])

        // Unpinned (swift build): every dylib in Frameworks.
        HelperCore.removeEntry(base.appendingPathComponent("run").path)
        let unpinned = try stager().stage()
        XCTAssertEqual(entries(unpinned.directory + "/Frameworks"), Self.libraries)
    }

    func testStagedCopyIsReusedAndOtherBuildsAreRemoved() throws {
        let first = try stager().stage()
        let inode = try FileManager.default.attributesOfItem(atPath: first.executable(.openvpn))[.systemFileNumber] as? Int
        XCTAssertEqual(try stager().stage(), first)
        XCTAssertEqual(
            try FileManager.default.attributesOfItem(atPath: first.executable(.openvpn))[.systemFileNumber] as? Int,
            inode, "a valid copy is not copied again")

        let other = String(repeating: "cd", count: 32), third = String(repeating: "ef", count: 32)
        _ = try stager(id: other).stage()
        _ = try stager(id: third).stage()
        let tools = (first.directory as NSString).deletingLastPathComponent
        XCTAssertEqual(entries(tools), [third], "other builds' copies are removed")

        // …unless a tool still runs from one.
        let s = stager(id: other)
        _ = try s.stage(inUse: [third])
        XCTAssertEqual(entries(tools), [other, third].sorted())
        XCTAssertEqual(s.buildDirectory(ofExecutable: tools + "/" + third + "/Resources/bin/openvpn"), third)
        XCTAssertNil(s.buildDirectory(ofExecutable: contents + "/Resources/bin/openvpn"))
    }

    func testModifiedOrIncompleteCopyIsStagedAgain() throws {
        let p = try pins()
        let s = stager(toolPins: p.tools, libraryPins: p.libraries)
        let staged = try s.stage()
        let lib = staged.directory + "/Frameworks/libacme.1.dylib"
        let source = contents + "/Frameworks/libacme.1.dylib"

        try corrupt(lib)
        XCTAssertEqual(try s.stage(), staged)
        XCTAssertTrue(FileManager.default.contentsEqual(atPath: lib, andPath: source))
        XCTAssertEqual(mode(lib), 0o444)

        XCTAssertEqual(unlink(lib), 0)
        XCTAssertEqual(try s.stage(), staged)
        XCTAssertTrue(FileManager.default.contentsEqual(atPath: lib, andPath: source))

        _ = chmod(staged.directory + "/Frameworks", 0o777)
        XCTAssertEqual(try s.stage(), staged)
        XCTAssertEqual(mode(staged.directory + "/Frameworks"), 0o755, "writable by others: staged again")

        try Data("x".utf8).write(to: URL(fileURLWithPath: staged.directory + "/Frameworks/libextra.dylib"))
        XCTAssertEqual(try s.stage(), staged)
        XCTAssertEqual(entries(staged.directory + "/Frameworks"), Self.libraries, "unexpected files: staged again")
    }

    func testSymlinkedSourceIsRefused() throws {
        let p = try pins()
        let fixture = try Self.fixture()
        for (path, target) in [
            (contents + "/Frameworks/libbase.1.dylib", fixture + "/libbase.1.dylib"),
            (contents + "/Resources/bin/openvpn", fixture + "/openvpn")
        ] {
            let saved = base.appendingPathComponent("saved").path
            try FileManager.default.moveItem(atPath: path, toPath: saved)
            try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: target)
            for s in [stager(toolPins: p.tools, libraryPins: p.libraries), stager()] {
                XCTAssertThrowsError(try s.stage()) {
                    XCTAssertEqual($0 as? HelperCore.Failure, .symlinkNotAllowed(path), "\($0)")
                }
                XCTAssertEqual(entries(runRoot + "/tools"), [], "nothing staged, no partial copy left")
            }
            try FileManager.default.removeItem(atPath: path)
            try FileManager.default.moveItem(atPath: saved, toPath: path)
        }
        XCTAssertNoThrow(try stager(toolPins: p.tools, libraryPins: p.libraries).stage())
    }

    func testTamperedSourceIsRefused() throws {
        let p = try pins()
        let s = stager(toolPins: p.tools, libraryPins: p.libraries)
        try corrupt(contents + "/Frameworks/libbase.1.dylib")
        XCTAssertThrowsError(try s.stage()) { XCTAssertNotNil($0 as? CodeSignature.Failure, "\($0)") }
        XCTAssertEqual(entries(runRoot + "/tools"), [])
        // Unpinned too: the signature itself no longer matches.
        XCTAssertThrowsError(try stager().stage()) { XCTAssertNotNil($0 as? CodeSignature.Failure, "\($0)") }
    }

    func testLibraryPinsAreEnforced() throws {
        let p = try pins()
        var wrong = p.libraries
        wrong["libbase.1.dylib"] = ["0000000000000000000000000000000000000000"]
        let cdhash = try XCTUnwrap(p.libraries["libbase.1.dylib"]?.first)
        XCTAssertThrowsError(try stager(toolPins: p.tools, libraryPins: wrong).stage()) {
            XCTAssertEqual($0 as? PinnedTools.Mismatch, PinnedTools.Mismatch(tool: "libbase.1.dylib", cdhash: cdhash))
        }
        XCTAssertEqual(entries(runRoot + "/tools"), [])

        // Another signed build of the library (same identifier, passes the requirement) is refused.
        let fixture = try Self.fixture()
        let other = base.appendingPathComponent("libbase.1.dylib").path
        try FileManager.default.copyItem(atPath: fixture + "/libbase.1.dylib", toPath: other)
        XCTAssertEqual(
            run(
                "/usr/bin/codesign",
                [
                    "-f", "-s", "-", "-i", "com.example.acme.libbase",
                    "--options", "runtime", other
                ]), 0)
        try FileManager.default.removeItem(atPath: contents + "/Frameworks/libbase.1.dylib")
        try FileManager.default.copyItem(atPath: other, toPath: contents + "/Frameworks/libbase.1.dylib")
        XCTAssertThrowsError(try stager(toolPins: p.tools, libraryPins: p.libraries).stage()) {
            XCTAssertEqual(($0 as? PinnedTools.Mismatch)?.tool, "libbase.1.dylib", "\($0)")
        }

        // A pinned build stages only pinned libraries; one missing from the bundle is an error.
        var extra = p.libraries
        extra["libmissing.1.dylib"] = ["1111111111111111111111111111111111111111"]
        XCTAssertThrowsError(try stager(toolPins: p.tools, libraryPins: extra).stage()) {
            XCTAssertEqual(
                $0 as? HelperCore.Failure,
                .system("open \(self.contents)/Frameworks/libmissing.1.dylib", ENOENT), "\($0)")
        }
        // A tool pin mismatch as well.
        var tools = p.tools
        tools["openfortivpn"] = ["2222222222222222222222222222222222222222"]
        XCTAssertThrowsError(try stager(toolPins: tools, libraryPins: p.libraries).stage()) {
            XCTAssertEqual(($0 as? PinnedTools.Mismatch)?.tool, "openfortivpn", "\($0)")
        }
    }

    /// openconnect is staged and checked like the others although nothing runs it yet: a pinned build
    /// refuses another build of it, and a bundle without it (an older layout) is not staged.
    func testOpenconnectIsStagedAndPinned() throws {
        let p = try pins()
        XCTAssertNotNil(p.tools["openconnect"])
        let staged = try stager(toolPins: p.tools, libraryPins: p.libraries).stage()
        XCTAssertEqual(staged.executable(.openconnect), staged.directory + "/Resources/bin/openconnect")
        XCTAssertEqual(mode(staged.executable(.openconnect)), 0o555)

        var tools = p.tools
        tools["openconnect"] = ["3333333333333333333333333333333333333333"]
        XCTAssertThrowsError(try stager(id: String(repeating: "cd", count: 32), toolPins: tools, libraryPins: p.libraries).stage()) {
            XCTAssertEqual(($0 as? PinnedTools.Mismatch)?.tool, "openconnect", "\($0)")
        }
        tools["openconnect"] = nil
        XCTAssertThrowsError(try stager(id: String(repeating: "ce", count: 32), toolPins: tools, libraryPins: p.libraries).stage()) {
            XCTAssertEqual(($0 as? PinnedTools.Mismatch)?.tool, "openconnect", "a pinned build without its pin refuses it: \($0)")
        }

        try FileManager.default.removeItem(atPath: contents + "/Resources/bin/openconnect")
        XCTAssertThrowsError(try stager(id: String(repeating: "cf", count: 32)).stage()) {
            XCTAssertEqual(
                $0 as? HelperCore.Failure,
                .system("open \(self.contents)/Resources/bin/openconnect", ENOENT), "\($0)")
        }
    }

    func testBuildIDMustBeHex() {
        for id in ["", "unknown", "../" + buildID, String(repeating: "A", count: 64), String(repeating: "a", count: 65)] {
            XCTAssertThrowsError(try stager(id: id).stage(), id)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: runRoot + "/tools"))
    }
}
#endif
