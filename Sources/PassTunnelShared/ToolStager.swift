// macOS only: stages the app bundle's tools (fcopyfile, code signatures).
#if os(macOS)
import Foundation

/// Copies the bundled tools and their libraries out of the app bundle into a root-owned directory
/// before the helper runs them.
///
/// The app bundle is writable by the user who installed it, and whoever can write it can also rename
/// it. A tool checked in the bundle would still load its libraries from there after it was resumed
/// (`@executable_path/../../Frameworks/…`), and those are only Team-ID-checked by library validation.
/// The staged copy has the bundle's layout (`Resources/bin/<tool>`, `Frameworks/<lib>.dylib`), so the
/// tools' load paths resolve to the staged libraries only. Every file is copied by descriptor, never
/// followed through a link, and checked as copied (requirement and `PinnedTools` cdhash): a file
/// swapped in the bundle meanwhile yields a copy that is refused.
///
/// Location: `<runRoot>/tools/<build ID>` (`/var/run/passtunnel/tools/…`). The run root is already
/// root-owned and checked by the helper, and macOS empties `/var/run` when the Mac starts, so a copy
/// lives no longer than needed and nothing is left behind once PassTunnel is removed. Copying the few
/// megabytes again on the first connection after a restart is cheap.
public struct ToolStager {
    /// The app's `Contents` directory (holds `Resources/bin` and `Frameworks`).
    public var bundleContents: String
    /// Root-owned run root (`PT.helperRunRoot`); copies go to `<runRoot>/tools/<buildID>`.
    public var runRoot: String
    /// The helper build (hex SHA-256 of its executable): every build stages its own copy.
    public var buildID: String
    /// Tool pins (file name in `Resources/bin` → cdhashes); empty: nothing pinned.
    public var toolPins: [String: Set<String>]
    /// Library pins (file name in `Frameworks` → cdhashes); consulted when `toolPins` is not empty.
    public var libraryPins: [String: Set<String>]
    public var toolRequirement: (HelperCore.Tool) -> String
    public var libraryRequirement: String
    /// Validates a file's static signature against a requirement and returns its cdhash (replaced in tests).
    var validate: (_ path: String, _ requirement: String) throws -> String

    public static let toolsDirName = "tools"
    /// Staged directories (root:wheel, 0755): readable, writable only by root.
    public static let dirMode: mode_t = 0o755
    public static let toolMode: mode_t = 0o555
    public static let libraryMode: mode_t = 0o444
    static let maxFileBytes: off_t = 256 << 20

    public init(
        bundleContents: String, runRoot: String = PT.helperRunRoot, buildID: String,
        toolPins: [String: Set<String>] = PinnedTools.cdhashes,
        libraryPins: [String: Set<String>] = PinnedTools.libraryCDHashes,
        toolRequirement: @escaping (HelperCore.Tool) -> String = { PT.toolRequirement(identifier: $0.signingIdentifier) },
        libraryRequirement: String = PT.teamRequirement
    ) {
        self.init(
            bundleContents: bundleContents, runRoot: runRoot, buildID: buildID, toolPins: toolPins,
            libraryPins: libraryPins, toolRequirement: toolRequirement, libraryRequirement: libraryRequirement,
            validate: { try CodeSignature.verify(path: $0, requirement: $1) })
    }

    init(
        bundleContents: String, runRoot: String, buildID: String, toolPins: [String: Set<String>],
        libraryPins: [String: Set<String>], toolRequirement: @escaping (HelperCore.Tool) -> String,
        libraryRequirement: String, validate: @escaping (_ path: String, _ requirement: String) throws -> String
    ) {
        self.bundleContents = bundleContents
        self.runRoot = runRoot
        self.buildID = buildID
        self.toolPins = toolPins
        self.libraryPins = libraryPins
        self.toolRequirement = toolRequirement
        self.libraryRequirement = libraryRequirement
        self.validate = validate
    }

    /// A checked staged copy.
    public struct Staged: Equatable {
        /// `<runRoot>/tools/<buildID>` with symlinks resolved (as `proc_pidpath` reports the tools).
        public let directory: String
        public func executable(_ tool: HelperCore.Tool) -> String { directory + "/Resources/bin/" + tool.rawValue }
    }

    /// Build ID check: it becomes a path component.
    static func isValidBuildID(_ id: String) -> Bool {
        (16...64).contains(id.utf8.count) && id.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }

    /// Libraries to stage: the pinned ones in a pinned build, else every `*.dylib` entry in the bundle's
    /// `Frameworks` (all of them are the tools' dependencies; Sparkle is a framework directory). A
    /// symlink is listed too, and refused by the copy.
    func libraryNames() -> [String] {
        if !toolPins.isEmpty { return libraryPins.keys.sorted() }
        let dir = bundleContents + "/Frameworks"
        let names = (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []
        return names.filter { name in
            var st = stat()
            return name.hasSuffix(".dylib") && ProfileDirectory.isPlainName(name)
                && lstat(dir + "/" + name, &st) == 0 && (st.st_mode & S_IFMT) != S_IFDIR
        }.sorted()
    }

    /// Returns the staged copy for this build, staging it first when it is missing or fails the check.
    /// Copies of other builds are removed, except the directories named in `inUse` (tools still
    /// running from them; removing their files would break adopting them after a helper restart).
    public func stage(inUse: Set<String> = []) throws -> Staged {
        guard Self.isValidBuildID(buildID) else { throw HelperCore.Failure.invalidText("helper build ID") }
        try HelperCore.ensureRootOwnedDir(runRoot)
        guard let realRoot = HelperCore.realPath(runRoot) else { throw HelperCore.Failure.system("resolve \(runRoot)", errno) }
        let toolsRoot = realRoot + "/" + Self.toolsDirName
        try HelperCore.ensureRootOwnedDir(toolsRoot, mode: Self.dirMode)
        let dir = toolsRoot + "/" + buildID
        let libraries = libraryNames()

        if (try? check(dir, libraries: libraries)) == nil {
            HelperCore.removeEntry(dir)
            let partial = toolsRoot + "/." + buildID + ".partial"
            HelperCore.removeEntry(partial)
            do {
                try copy(into: partial, libraries: libraries)
                try check(partial, libraries: libraries)
                guard rename(partial, dir) == 0 else { throw HelperCore.Failure.system("rename \(partial)", errno) }
            } catch {
                HelperCore.removeEntry(partial)
                throw error
            }
        }
        for entry in (try? FileManager.default.contentsOfDirectory(atPath: toolsRoot)) ?? []
        where entry != buildID && !inUse.contains(entry) {
            HelperCore.removeEntry(toolsRoot + "/" + entry)
        }
        return Staged(directory: dir)
    }

    /// The build directory name of a staged executable path (for `stage(inUse:)`), nil for any other path.
    public func buildDirectory(ofExecutable path: String) -> String? {
        guard let realRoot = HelperCore.realPath(runRoot) else { return nil }
        let prefix = realRoot + "/" + Self.toolsDirName + "/"
        guard path.hasPrefix(prefix) else { return nil }
        return path.dropFirst(prefix.count).split(separator: "/").first.map(String.init)
    }

    // MARK: - Copy

    func copy(into dir: String, libraries: [String]) throws {
        for sub in ["", "/Resources", "/Resources/bin", "/Frameworks"] {
            guard mkdir(dir + sub, 0o700) == 0 else { throw HelperCore.Failure.system("mkdir \(dir + sub)", errno) }
        }
        for tool in HelperCore.Tool.allCases {
            try Self.copyFile(
                bundleContents + "/Resources/bin/" + tool.rawValue,
                to: dir + "/Resources/bin/" + tool.rawValue, mode: Self.toolMode)
        }
        for lib in libraries {
            guard ProfileDirectory.isPlainName(lib) else { throw HelperCore.Failure.notARegularFile(lib) }
            try Self.copyFile(bundleContents + "/Frameworks/" + lib, to: dir + "/Frameworks/" + lib, mode: Self.libraryMode)
        }
        for sub in ["/Frameworks", "/Resources/bin", "/Resources", ""] {
            try Self.restrict(dir + sub, mode: Self.dirMode)
        }
    }

    /// Copies the data of a regular file (never through a symlink) into a new file.
    static func copyFile(_ src: String, to dst: String, mode: mode_t) throws {
        let sfd = open(src, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard sfd >= 0 else {
            if errno == ELOOP { throw HelperCore.Failure.symlinkNotAllowed(src) }
            throw HelperCore.Failure.system("open \(src)", errno)
        }
        defer { close(sfd) }
        var st = stat()
        guard fstat(sfd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { throw HelperCore.Failure.notARegularFile(src) }
        guard st.st_size <= maxFileBytes else { throw HelperCore.Failure.fileTooLarge(src) }
        let dfd = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard dfd >= 0 else { throw HelperCore.Failure.system("create \(dst)", errno) }
        defer { close(dfd) }
        // Data only: Mach-O signatures are embedded; no extended attributes (quarantine) come along.
        guard fcopyfile(sfd, dfd, nil, copyfile_flags_t(COPYFILE_DATA)) == 0 else {
            throw HelperCore.Failure.system("copy \(src)", errno)
        }
        if geteuid() == 0, fchown(dfd, 0, 0) != 0 { throw HelperCore.Failure.system("chown \(dst)", errno) }
        guard fchmod(dfd, mode) == 0 else { throw HelperCore.Failure.system("chmod \(dst)", errno) }
    }

    static func restrict(_ dir: String, mode: mode_t) throws {
        if geteuid() == 0, lchown(dir, 0, 0) != 0 { throw HelperCore.Failure.system("chown \(dir)", errno) }
        guard lchmod(dir, mode) == 0 else { throw HelperCore.Failure.system("chmod \(dir)", errno) }
    }

    // MARK: - Check

    /// Throws unless `dir` holds exactly the expected files, owned by us and not writable by anyone
    /// else, each with an accepted signature and cdhash.
    func check(_ dir: String, libraries: [String]) throws {
        try Self.checkEntry(dir, type: S_IFDIR, mode: Self.dirMode)
        try Self.checkEntries(dir, ["Frameworks", "Resources"])
        try Self.checkEntry(dir + "/Resources", type: S_IFDIR, mode: Self.dirMode)
        try Self.checkEntries(dir + "/Resources", ["bin"])
        try Self.checkEntry(dir + "/Resources/bin", type: S_IFDIR, mode: Self.dirMode)
        try Self.checkEntries(dir + "/Resources/bin", HelperCore.Tool.allCases.map(\.rawValue))
        try Self.checkEntry(dir + "/Frameworks", type: S_IFDIR, mode: Self.dirMode)
        try Self.checkEntries(dir + "/Frameworks", libraries)
        let pinned = !toolPins.isEmpty
        for tool in HelperCore.Tool.allCases {
            let path = dir + "/Resources/bin/" + tool.rawValue
            try Self.checkEntry(path, type: S_IFREG, mode: Self.toolMode)
            let cdhash = try validate(path, toolRequirement(tool))
            try PinnedTools.check(tool.rawValue, cdhash: cdhash, allowed: PinnedTools.allowed(tool.rawValue, pins: toolPins))
        }
        for lib in libraries {
            let path = dir + "/Frameworks/" + lib
            try Self.checkEntry(path, type: S_IFREG, mode: Self.libraryMode)
            let cdhash = try validate(path, libraryRequirement)
            try PinnedTools.check(lib, cdhash: cdhash, allowed: pinned ? libraryPins[lib] ?? [] : nil)
        }
    }

    static func checkEntry(_ path: String, type: mode_t, mode: mode_t) throws {
        var st = stat()
        guard lstat(path, &st) == 0 else { throw HelperCore.Failure.system("stat \(path)", errno) }
        if (st.st_mode & S_IFMT) == S_IFLNK { throw HelperCore.Failure.symlinkNotAllowed(path) }
        guard (st.st_mode & S_IFMT) == type else {
            throw type == S_IFDIR ? HelperCore.Failure.notADirectory(path) : HelperCore.Failure.notARegularFile(path)
        }
        guard st.st_uid == geteuid() else { throw HelperCore.Failure.wrongOwner(path: path, expected: geteuid(), actual: st.st_uid) }
        guard type == S_IFDIR || st.st_nlink == 1 else { throw HelperCore.Failure.multipleLinks(path) }
        guard st.st_mode & 0o7777 == mode else { throw HelperCore.Failure.insecurePermissions(path) }
    }

    static func checkEntries(_ dir: String, _ expected: [String]) throws {
        let names = try FileManager.default.contentsOfDirectory(atPath: dir)
        guard Set(names) == Set(expected), names.count == expected.count else {
            throw HelperCore.Failure.notARegularFile(dir + "/" + (Set(names).symmetricDifference(expected).sorted().first ?? ""))
        }
    }
}
#endif
