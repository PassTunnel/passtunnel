import Foundation
import PassTunnelVPNConfig

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto  // swift-crypto: the same API, outside Apple platforms
#endif

/// Validation and file preparation done by the privileged helper before it launches a tool.
/// Everything here works without root so it can be unit-tested with injected paths and uids;
/// launching and code-signature checks live in the helper target.
public struct HelperCore {
    public enum Failure: Error, Equatable, LocalizedError, CustomStringConvertible {
        case invalidProfileID(String)
        case unknownUser(uid_t)
        case notAbsolute(String)
        case outsideProfilesRoot(String)
        case wrongDirectoryName(String)
        case wrongOwner(path: String, expected: uid_t, actual: uid_t)
        case notADirectory(String)
        case notARegularFile(String)
        case insecurePermissions(String)
        case symlinkNotAllowed(String)
        case multipleLinks(String)
        case fileTooLarge(String)
        case invalidLogPath(String)
        case invalidText(String)
        case invalidCredential(String)
        case socketPathTooLong(String)
        case notASocket(String)
        case configChanged
        /// The config names a network device that is there already (`interfaceExists`).
        case deviceExists(String)
        /// A line-based file for a root process failed the final check (`checkLines`).
        case unsafeFile(String)
        /// The tool needs a later macOS than this one (`Tool.minimumMacOS`; "15.4"): the VPN type's name ("Cisco
        /// AnyConnect", "Palo Alto GlobalProtect") and that version.
        case requiresNewerMacOS(String, String)
        case system(String, Int32)

        public var description: String {
            switch self {
            case .invalidProfileID(let id): return "Invalid profile ID “\(id)”."
            case .unknownUser(let uid): return "Unknown user \(uid)."
            case .notAbsolute(let p): return "Path must be absolute: \(p)"
            case .outsideProfilesRoot(let p): return "Profile directory is not inside the PassTunnel profiles folder: \(p)"
            case .wrongDirectoryName(let p): return "Profile directory name does not match the profile ID: \(p)"
            case .wrongOwner(let p, let e, let a): return "\(p) is owned by uid \(a), expected \(e)."
            case .notADirectory(let p): return "Not a directory: \(p)"
            case .notARegularFile(let p): return "Not a regular file: \(p)"
            case .insecurePermissions(let p): return "Insecure permissions on \(p)"
            case .symlinkNotAllowed(let p): return "Symbolic links are not allowed: \(p)"
            case .multipleLinks(let p): return "Hard-linked files are not allowed: \(p)"
            case .fileTooLarge(let p): return "File is too large: \(p)"
            case .invalidLogPath(let p): return "The log file must be a .log file directly inside the profile directory: \(p)"
            case .invalidText(let p): return "File is not valid UTF-8 text: \(p)"
            case .invalidCredential(let f): return "Invalid \(f): it must be a single line."
            case .socketPathTooLong(let p): return "The management socket path is too long (use a shorter profile ID): \(p)"
            case .notASocket(let p): return "Refusing to replace \(p): it is not a socket."
            case .configChanged:
                return "\(HelperCore.configFileName) changed after PassTunnel checked it. Connect again to confirm the new settings."
            case .deviceExists(let name):
                return "The network device \(name) already exists, and PassTunnel only connects through a device "
                    + "it creates. Use “dev tun” or “dev tap” so that the system picks a free name, or a name no "
                    + "device has."
            case .unsafeFile(let name): return "Refusing to write \(name): its contents failed the final check."
            case .requiresNewerMacOS(let vpn, let version): return "\(vpn) requires macOS \(version) or later."
            case .system(let what, let err): return "\(what): \(String(cString: strerror(err)))"
            }
        }
        public var errorDescription: String? { description }

        /// `HelperResponse.ErrorCode` the app gets with this failure.
        public var code: String? {
            self == .configChanged ? HelperResponse.ErrorCode.configChanged : nil
        }
    }

    /// The VPN tools bundled in `Contents/Resources/bin`, which `ToolStager` stages and checks.
    public enum Tool: String, CaseIterable {
        case openvpn, openfortivpn, openconnect

        /// The VPN type the tool connects, for messages.
        public var displayName: String {
            switch self {
            case .openvpn: return "OpenVPN"
            case .openfortivpn: return "FortiGate SSL VPN"
            case .openconnect: return "Cisco AnyConnect"
            }
        }

        public var signingIdentifier: String {
            switch self {
            case .openvpn: return PT.openvpnIdentifier
            case .openfortivpn: return PT.openfortivpnIdentifier
            case .openconnect: return PT.openconnectIdentifier
            }
        }

        /// The macOS the tool needs when it is later than the app's own minimum (nil: the app's). Homebrew's
        /// libopenconnect imports `strchrnul`, which macOS has from 15.4: dyld stops openconnect at launch
        /// on anything older. Must match `TOOL_MINIMUMS` in scripts/check-tool-symbols.sh, which holds the
        /// tool and the libraries only it loads to that version.
        public var minimumMacOS: OperatingSystemVersion? {
            switch self {
            case .openvpn, .openfortivpn: return nil
            case .openconnect: return OperatingSystemVersion(majorVersion: 15, minorVersion: 4, patchVersion: 0)
            }
        }

        /// Whether the tool starts on macOS `version` (`minimumMacOS`).
        public func runs(on version: OperatingSystemVersion) -> Bool {
            guard let minimum = minimumMacOS else { return true }
            return (version.majorVersion, version.minorVersion, version.patchVersion)
                >= (minimum.majorVersion, minimum.minorVersion, minimum.patchVersion)
        }

        /// "15.4", "15.4.1".
        public static func versionText(_ version: OperatingSystemVersion) -> String {
            "\(version.majorVersion).\(version.minorVersion)" + (version.patchVersion == 0 ? "" : ".\(version.patchVersion)")
        }
    }

    /// Everything the helper needs to spawn a tool. The caller owns `logFD` and must close it.
    public struct LaunchPlan {
        public let profileID: String
        public let ownerUID: uid_t
        public let tool: Tool
        public let arguments: [String]
        /// `<runRoot>/<uid>/<profileID>`: root-owned, holds the tool's config, auth file and socket.
        public let runDir: String
        public let sessionDir: SessionDirectory
        public let logFD: Int32
        /// Copy of the bundled DNS script inside `runDir`; its signature must be checked before launch.
        /// OpenVPN runs it through the wrapper `dnsHookName` next to it. On Linux the link to the daemon's
        /// own executable that OpenVPN runs as its DNS hook.
        public let dnsUpdownPath: String?
        /// The validated profile directory.
        public let profileDir: ProfileDirectory
        /// Full path of the OpenVPN management socket inside `runDir` (OpenVPN only).
        public let mgmtSocket: String?
        /// Literal values the tool's output must never write to the log (openconnect: the session cookie). When
        /// set, the output goes through a pipe and `MaskingCopier` (`OutputMask`) instead of straight into the log.
        public var maskedSecrets: [String]? = nil
    }

    public static let configFileName = "config.ovpn"
    public static let maxConfigBytes = 1 << 20
    /// sun_path is 104 bytes on macOS and 108 on Linux, including the terminating NUL.
    #if os(Linux)
    public static let maxSocketPathBytes = 107
    #else
    public static let maxSocketPathBytes = 103
    #endif
    /// Run root, per-user and per-session directories: root-owned, searchable but not listable.
    public static let runDirMode: mode_t = 0o711
    /// The system's CA bundle (`FortiConfig.systemCAFile`, which openfortivpn's config names too).
    public static let systemCAFile = FortiConfig.systemCAFile
    /// Inside root-owned `/var/empty`, and never created.
    public static let missingDirectory = "/var/empty/passtunnel-none"
    #if os(Linux)
    /// The tools' only environment. The distribution's tools use the distribution's OpenSSL, whose
    /// configuration (system-wide crypto policies, the CA store) applies unchanged.
    public static let fixedEnvironment = ["PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"]
    #else
    /// The tools' only environment. The OpenSSL variables keep the bundled libcrypto from loading a
    /// config file, providers or engines from its compiled-in (Homebrew) prefix, and point its default
    /// trust store at the system's CA bundle.
    public static let fixedEnvironment = [
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C",
        "OPENSSL_CONF=/dev/null",
        "OPENSSL_MODULES=\(missingDirectory)",
        "OPENSSL_ENGINES=\(missingDirectory)",
        "SSL_CERT_FILE=\(systemCAFile)",
        "SSL_CERT_DIR=/var/empty"
    ]
    #endif

    public var runRoot: String
    public var dnsUpdownSource: String?
    /// Whether the OpenVPN that will run knows `--dns-updown` (2.7 and later, as the Mac's bundled
    /// build). OpenVPN 2.6, which Linux distributions ship, does not: its DNS hook runs as
    /// `--route-up` and `--down` instead (`openVPNArguments`), and without a hook it gets no DNS option.
    public var openVPNHasDNSUpdown = true
    #if os(Linux)
    /// The daemon's own executable (resolved and checked), which OpenVPN runs as its DNS hook through
    /// the link `dnsHookName` in the session directory (docs/LINUX.md, "DNS"), and openconnect as its
    /// `script` through the link `vpn-hook` (`vpnHookPath`). Nil: no DNS hook, and no Cisco AnyConnect.
    public var dnsHook: String?
    #endif
    /// The DNS hook's name in the session directory: on Linux the link to the daemon, also the hook's
    /// `argv[0]` (OpenVPN 2.7's `--dns-updown` runs a path without arguments, so `passtunneld dns-hook`
    /// cannot be spelled there); on the Mac the wrapper around the script (`dnsHookText`).
    public static let dnsHookName = "dns-hook"
    /// The CA bundle openfortivpn's config names (`ca-file`): the Mac's system bundle; the Linux daemon
    /// sets the distribution's, checked, before every start.
    public var caFile = HelperCore.systemCAFile
    /// Whether openfortivpn and pppd change DNS themselves when the profile asks for the VPN's DNS
    /// (`set-dns`, `pppd-use-peerdns`), as on the Mac. The Linux daemon applies DNS itself and turns
    /// this off.
    public var fortiHandlesDNS = true
    /// Whether a Palo Alto GlobalProtect root configuration gets `disable-ipv6`: on Linux for an openconnect older
    /// than 9.20 (docs/LINUX.md, "Palo Alto GlobalProtect"), which the daemon decides from the version of the tool
    /// it checked, never from the request (`ToolSpec.openConnectDisablesIPv6`, set by passtunneld before every
    /// start). Off on the Mac (9.21) and for Cisco AnyConnect, which never gets it.
    public var openConnectDisableIPv6 = false
    /// Whether the kernel has a network device of that name; nil: not checked (the Mac). The Linux daemon
    /// sets it: there a `dev` with a name of its own could attach OpenVPN to a persistent device created
    /// earlier, which its owner can still open (`namedDevices`). Throws when it cannot tell.
    public var interfaceExists: ((String) throws -> Bool)?
    public var homeDirectory: (uid_t) -> String?
    public var userName: (uid_t) -> String?
    /// The macOS a tool would run on, for `Tool.minimumMacOS` (replaced in tests). Nil: not checked (Linux,
    /// where `minimumMacOS` does not apply).
    #if os(macOS)
    public var systemVersion: OperatingSystemVersion? = ProcessInfo.processInfo.operatingSystemVersion
    #else
    public var systemVersion: OperatingSystemVersion?
    #endif

    public init(
        runRoot: String = PT.helperRunRoot, dnsUpdownSource: String? = nil,
        homeDirectory: @escaping (uid_t) -> String? = HelperCore.passwdHome,
        userName: @escaping (uid_t) -> String? = HelperCore.passwdName
    ) {
        self.runRoot = runRoot
        self.dnsUpdownSource = dnsUpdownSource
        self.homeDirectory = homeDirectory
        self.userName = userName
    }

    public static func passwdHome(_ uid: uid_t) -> String? {
        passwdField(uid) { $0.pw_dir }
    }

    public static func passwdName(_ uid: uid_t) -> String? {
        passwdField(uid) { $0.pw_name }
    }

    private static func passwdField(_ uid: uid_t, _ field: (passwd) -> UnsafeMutablePointer<CChar>?) -> String? {
        var pwd = passwd()
        var result: UnsafeMutablePointer<passwd>?
        var buf = [CChar](repeating: 0, count: 16384)
        guard getpwuid_r(uid, &pwd, &buf, buf.count, &result) == 0, result != nil, let value = field(pwd) else {
            return nil
        }
        return String(cString: value)
    }

    /// Slug-like IDs only (ASCII letters, digits, `-`, `_`, `.`; no leading `.`/`-`, no trailing `.`):
    /// they become a path component under the run root.
    public static func isValidProfileID(_ id: String) -> Bool {
        guard (1...64).contains(id.utf8.count), let first = id.unicodeScalars.first, first != ".", first != "-",
            id.unicodeScalars.last != "."
        else {
            return false
        }
        return id.unicodeScalars.allSatisfy { c in
            switch c {
            case "a"..."z", "A"..."Z", "0"..."9", "-", "_", ".": return true
            default: return false
            }
        }
    }

    // MARK: - Profile directory

    /// `<realpath(home)>/Library/Application Support/PassTunnel/profiles` for that user.
    public func profilesRoot(for uid: uid_t) throws -> String {
        guard let home = homeDirectory(uid), home.hasPrefix("/") else { throw Failure.unknownUser(uid) }
        guard let realHome = Self.realPath(home) else { throw Failure.unknownUser(uid) }
        return (realHome as NSString).appendingPathComponent(PT.profilesSubpath)
    }

    /// Opens `path` as the profile directory of `profileID` for user `uid`. The resolved path must be
    /// exactly `<profilesRoot>/<profileID>` with no symlinks below the home directory, the directory
    /// must be owned by `uid` and not group- or world-writable (on macOS the group is usually
    /// `staff`, i.e. every local user).
    public func openProfileDir(_ path: String, profileID: String, uid: uid_t) throws -> ProfileDirectory {
        guard Self.isValidProfileID(profileID) else { throw Failure.invalidProfileID(profileID) }
        guard path.hasPrefix("/") else { throw Failure.notAbsolute(path) }
        // realpath() would stop at a NUL and resolve only what comes before it.
        guard !Self.containsNUL(path) else { throw Failure.outsideProfilesRoot(path) }
        let root = try profilesRoot(for: uid)
        guard let resolved = Self.realPath(path) else { throw Failure.outsideProfilesRoot(path) }
        guard resolved.hasPrefix(root + "/") else { throw Failure.outsideProfilesRoot(path) }
        guard resolved == root + "/" + profileID else { throw Failure.wrongDirectoryName(path) }

        let fd = open(resolved, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else {
            if errno == ELOOP { throw Failure.symlinkNotAllowed(resolved) }
            if errno == ENOTDIR { throw Failure.notADirectory(resolved) }
            throw Failure.system("open \(resolved)", errno)
        }
        var st = stat()
        guard fstat(fd, &st) == 0 else { let e = errno; close(fd); throw Failure.system("stat \(resolved)", e) }
        guard (st.st_mode & S_IFMT) == S_IFDIR else { close(fd); throw Failure.notADirectory(resolved) }
        guard st.st_uid == uid else {
            close(fd)
            throw Failure.wrongOwner(path: resolved, expected: uid, actual: st.st_uid)
        }
        guard st.st_mode & (S_IWGRP | S_IWOTH) == 0 else { close(fd); throw Failure.insecurePermissions(resolved) }
        // Re-check the path of what was actually opened (a component may have been swapped meanwhile).
        guard let opened = Self.path(of: fd), opened == resolved else {
            close(fd)
            throw Failure.outsideProfilesRoot(path)
        }
        return ProfileDirectory(fd: fd, path: resolved, uid: uid, gid: st.st_gid)
    }

    /// The log file name, if `logPath` is a `.log` file directly inside the profile directory.
    public func logFileName(_ logPath: String, in dir: ProfileDirectory) throws -> String {
        guard logPath.hasPrefix("/"), !Self.containsNUL(logPath) else { throw Failure.invalidLogPath(logPath) }
        let name = (logPath as NSString).lastPathComponent
        let parent = (logPath as NSString).deletingLastPathComponent
        guard ProfileDirectory.isPlainName(name), name.hasSuffix(".log"), name.count > 4,
            let realParent = Self.realPath(parent), realParent == dir.path
        else {
            throw Failure.invalidLogPath(logPath)
        }
        return name
    }

    // MARK: - Launch preparation

    public func prepareOpenVPN(_ s: OpenVPNStart, uid: uid_t) throws -> LaunchPlan {
        guard let clientUser = userName(uid), !clientUser.isEmpty else { throw Failure.unknownUser(uid) }
        let username = s.username ?? ""
        let secret = s.secret ?? ""
        try Self.checkCredential(username, field: "username", maxBytes: 512)
        try Self.checkCredential(secret, field: "password", maxBytes: 4096)

        let dir = try openProfileDir(s.profileDir, profileID: s.profileID, uid: uid)
        let logName = try logFileName(s.logPath, in: dir)
        let data = try dir.readFile(Self.configFileName, maxBytes: Self.maxConfigBytes)
        // The app checked (and the user confirmed) one exact file; run nothing else.
        if let expected = s.configSHA256, Self.sha256Hex(data) != expected.lowercased() { throw Failure.configChanged }
        guard let text = String(data: data, encoding: .utf8) else { throw Failure.invalidText(Self.configFileName) }
        let sanitized = try OVPNSanitizer.sanitize(text)
        if let interfaceExists {
            for name in Self.namedDevices(sanitized) where try interfaceExists(name) { throw Failure.deviceExists(name) }
        }
        let socketPath = PT.mgmtSocketPath(uid: uid, profileID: s.profileID, runRoot: runRoot)
        guard socketPath.utf8.count <= Self.maxSocketPathBytes else { throw Failure.socketPathTooLong(socketPath) }

        let session = try makeRunDir(profileID: s.profileID, uid: uid)
        let runDir = session.path
        do {
            let configPath = runDir + "/" + Self.configFileName
            // The sanitizer refuses NUL lines; checked again on what is actually written.
            guard !Self.containsNUL(sanitized) else { throw Failure.unsafeFile(Self.configFileName) }
            try Self.writeNewFile(configPath, Data(sanitized.utf8), mode: 0o600)
            var authPath: String?
            if !username.isEmpty {
                authPath = runDir + "/auth"
                let auth = Self.authFileText(username: username, secret: secret)
                try Self.checkLines(auth, count: 2, file: "auth")
                try Self.writeNewFile(authPath!, Data(auth.utf8), mode: 0o600)
            }
            #if os(Linux)
            let dnsPath = try linkDNSHook(in: runDir)
            let hookPath = dnsPath
            #else
            let dnsPath = try stageDNSScript(in: runDir)
            let hookPath = try dnsPath.map { _ in try writeDNSHook(in: runDir) }
            #endif
            let args = Self.openVPNArguments(
                configPath: configPath, mgmtSocket: socketPath, clientUser: clientUser,
                authFile: authPath, dnsUpdown: hookPath,
                verbosity: Self.openVPNVerbosity(sanitized),
                tlsVersionMin: OVPNSanitizer.tlsVersionFloor(of: sanitized),
                hasDNSUpdown: openVPNHasDNSUpdown)
            let logFD = try dir.createLogFile(logName)
            return LaunchPlan(
                profileID: s.profileID, ownerUID: uid, tool: .openvpn, arguments: args,
                runDir: runDir, sessionDir: session, logFD: logFD, dnsUpdownPath: dnsPath,
                profileDir: dir, mgmtSocket: socketPath)
        } catch {
            removeRunDir(profileID: s.profileID, uid: uid)
            throw error
        }
    }

    public func prepareForti(_ s: FortiStart, uid: uid_t) throws -> LaunchPlan {
        let text = try FortiConfig(s).render(caFile: caFile, handlesDNS: fortiHandlesDNS)
        let dir = try openProfileDir(s.profileDir, profileID: s.profileID, uid: uid)
        let logName = try logFileName(s.logPath, in: dir)
        let session = try makeRunDir(profileID: s.profileID, uid: uid)
        let runDir = session.path
        do {
            let configPath = runDir + "/openfortivpn.conf"
            try Self.writeNewFile(configPath, Data(text.utf8), mode: 0o600)
            let logFD = try dir.createLogFile(logName)
            return LaunchPlan(
                profileID: s.profileID, ownerUID: uid, tool: .openfortivpn,
                arguments: Self.fortiArguments(configPath: configPath),
                runDir: runDir, sessionDir: session, logFD: logFD, dnsUpdownPath: nil,
                profileDir: dir, mgmtSocket: nil)
        } catch {
            removeRunDir(profileID: s.profileID, uid: uid)
            throw error
        }
    }

    /// Fixed OpenVPN flags. They follow `--config`, so they override anything left in the file; only
    /// `--pull-filter` and `--server-poll-timeout` come before it. Pull filters are tried in the order
    /// OpenVPN reads them, the command line up to `--config`, then the file, and the first that matches a
    /// pushed option decides, so the file's own `pull-filter` lines cannot accept what these ignore
    /// (`ignoredPushPrefixes`). `--server-poll-timeout` is a default: OpenVPN copies the options in force
    /// where a `<connection>` block is read into it, so the blocks get it too, and a config that sets its
    /// own value (a slow proxy) keeps it. With it, a server that does not answer is given up on after
    /// `serverPollTimeout` seconds (OpenVPN 2.6 and 2.7: the TCP connect, then the first packet from the
    /// server, over UDP and TCP) instead of 120. `--remap-usr1 SIGTERM` turns OpenVPN's restart after a
    /// failed try into an exit, so each run tries once; `ConnectionManager` tries again.
    /// Management is a unix socket that OpenVPN only serves to `clientUser` (peer credentials check).
    /// The DNS hook is always explicit: OpenVPN's compiled-in default points into the build machine's
    /// Homebrew prefix, which must never be executed as root. `verbosity` comes from `openVPNVerbosity`.
    /// Without `hasDNSUpdown` (OpenVPN 2.6, which rejects the option) and without a hook, scripts stay
    /// limited to OpenVPN's built-in commands and nothing changes DNS. A hook on OpenVPN 2.6 (only the
    /// Linux daemon's) runs as `--route-up`, whose failure OpenVPN logs without exiting, as 2.7 does for
    /// `--dns-updown`, and as `--down` before the device closes (`--down-pre`).
    /// `--tls-version-min` (`tlsVersionMin`, from `OVPNSanitizer.tlsVersionFloor(of:)`: 1.2, or the config's
    /// own 1.3) holds the TLS floor even for a spelling the sanitizer missed: OpenVPN reads the command line
    /// and the file in order and the last `tls-version-min` wins, so this one, after `--config`, does.
    public static func openVPNArguments(
        configPath: String, mgmtSocket: String, clientUser: String,
        authFile: String?, dnsUpdown: String?, verbosity: Int = defaultVerbosity,
        tlsVersionMin: [String] = [OVPNSanitizer.minimumTLSVersion],
        hasDNSUpdown: Bool = true
    ) -> [String] {
        var args = ignoredPushPrefixes.flatMap { ["--pull-filter", "ignore", $0] }
        args +=
            [
                "--server-poll-timeout", String(serverPollTimeout),
                "--config", configPath,
                "--verb", String(min(max(0, verbosity), maxVerbosity)),
                "--management", mgmtSocket, "unix",
                "--management-client-user", clientUser,
                "--auth-nocache",
                "--remap-usr1", "SIGTERM",
                "--connect-retry-max", "3",
                "--tls-version-min"
            ] + tlsVersionMin
        if let authFile { args += ["--auth-user-pass", authFile] }
        if let dnsUpdown, hasDNSUpdown {
            args += ["--script-security", "2", "--dns-updown", dnsUpdown]
        } else if let dnsUpdown {
            args += ["--script-security", "2", "--route-up", dnsUpdown, "--down", dnsUpdown, "--down-pre"]
        } else if hasDNSUpdown {
            args += ["--script-security", "1", "--dns-updown", "disable"]
        } else {
            args += ["--script-security", "1"]
        }
        return args
    }

    /// Pushed options OpenVPN drops (`--pull-filter ignore`, which compares the start of the option as the
    /// server sent it, after leading whitespace). `verb`: the server must not raise the capped log level
    /// (`maxVerbosity`). OpenVPN reads a pushed option as a config line, so `"verb"` and `'verb'` are
    /// `verb` too, and so is a line that starts with an escaped space (`\ verb`). No option a client needs
    /// starts with a backslash.
    public static let ignoredPushPrefixes = ["verb", "\"verb", "'verb", "\\"]

    /// The names OpenVPN on Linux gives the kernel for the config's devices (`OVPNSanitizer.deviceNames`):
    /// all but exactly `tun` and `tap`, for which the kernel (or, with data channel offload, OpenVPN)
    /// picks a name no device has; cut to `maxInterfaceNameBytes`, as OpenVPN cuts them. A device of such
    /// a name that exists already is attached to, and a persistent one stays open to its owner.
    public static func namedDevices(_ config: String) -> [String] {
        var names: [String] = []
        for name in OVPNSanitizer.deviceNames(of: config) where name != "tun" && name != "tap" {
            let cut = String(decoding: name.utf8.prefix(maxInterfaceNameBytes), as: UTF8.self)
            if !names.contains(cut) { names.append(cut) }
        }
        return names
    }

    /// `IFNAMSIZ` - 1.
    public static let maxInterfaceNameBytes = 15

    /// Seconds OpenVPN waits for a server to answer (`--server-poll-timeout`) unless the config says.
    public static let serverPollTimeout = 10

    /// OpenVPN's `verb` when a config sets none. From `verb 5` on it logs every packet (R/W marks),
    /// from 7 data-channel keys and from 9 packet contents; the log is readable by the user and by
    /// `get_logs`, so the level is capped.
    public static let defaultVerbosity = 3
    public static let maxVerbosity = 4

    /// The config's `verb` (the last one wins), capped at `maxVerbosity`.
    public static func openVPNVerbosity(_ config: String) -> Int {
        min(OVPNSanitizer.verbosity(of: config) ?? defaultVerbosity, maxVerbosity)
    }

    /// Always pass `-c`: without it openfortivpn reads a default config from the Homebrew prefix.
    public static func fortiArguments(configPath: String) -> [String] {
        ["-c", configPath]
    }

    /// Lowercase hex SHA-256, as `OpenVPNStart.configSHA256` carries it.
    public static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// OpenVPN's `--auth-user-pass` file: the user name, then the password, one per line.
    static func authFileText(username: String, secret: String) -> String { username + "\n" + secret + "\n" }

    /// Defense in depth for a line-based file a root process reads: `text` must be exactly `count`
    /// lines, each ending in "\n", with no NUL and no CR. Throws `Failure.unsafeFile(file)` otherwise.
    public static func checkLines(_ text: String, count: Int, file: String) throws {
        let bytes = Array(text.utf8)
        guard !bytes.contains(0), !bytes.contains(0x0D), bytes.last == 0x0A,
            bytes.lazy.filter({ $0 == 0x0A }).count == count
        else { throw Failure.unsafeFile(file) }
    }

    /// A path for a C call: anything after a NUL would be silently ignored there.
    static func containsNUL(_ s: String) -> Bool { s.utf8.contains(0) }

    static func checkCredential(_ s: String, field: String, maxBytes: Int) throws {
        guard s.utf8.count <= maxBytes,
            !s.unicodeScalars.contains(where: { $0 == "\n" || $0 == "\r" || $0.value == 0 })
        else {
            throw Failure.invalidCredential(field)
        }
    }

    // MARK: - Run directory (root-owned)

    /// `<runRoot>/<uid>`.
    public func userRunDir(uid: uid_t) -> String { runRoot + "/\(uid)" }

    /// Creates a fresh session directory `<runRoot>/<uid>/<profileID>` (root-owned, 0711), replacing
    /// a stale one. Users can reach files inside by name but cannot list, rename or replace them, so
    /// the management socket can be handed to the user without a race.
    public func makeRunDir(profileID: String, uid: uid_t) throws -> SessionDirectory {
        guard Self.isValidProfileID(profileID) else { throw Failure.invalidProfileID(profileID) }
        try Self.ensureRootOwnedDir(runRoot)
        try Self.ensureRootOwnedDir(userRunDir(uid: uid))
        let dir = PT.sessionDir(uid: uid, profileID: profileID, runRoot: runRoot)
        removeRunDir(profileID: profileID, uid: uid)
        guard mkdir(dir, 0o700) == 0 else { throw Failure.system("mkdir \(dir)", errno) }
        guard chmod(dir, Self.runDirMode) == 0 else { throw Failure.system("chmod \(dir)", errno) }
        return try openRunDir(profileID: profileID, uid: uid)
    }

    /// Opens an existing session directory after checking it is a real directory we own.
    public func openRunDir(profileID: String, uid: uid_t) throws -> SessionDirectory {
        guard Self.isValidProfileID(profileID) else { throw Failure.invalidProfileID(profileID) }
        let dir = PT.sessionDir(uid: uid, profileID: profileID, runRoot: runRoot)
        let fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else {
            if errno == ELOOP { throw Failure.symlinkNotAllowed(dir) }
            throw Failure.system("open \(dir)", errno)
        }
        var st = stat()
        guard fstat(fd, &st) == 0 else { let e = errno; close(fd); throw Failure.system("stat \(dir)", e) }
        guard (st.st_mode & S_IFMT) == S_IFDIR else { close(fd); throw Failure.notADirectory(dir) }
        guard st.st_uid == geteuid() else {
            close(fd)
            throw Failure.wrongOwner(path: dir, expected: geteuid(), actual: st.st_uid)
        }
        return SessionDirectory(fd: fd, path: dir, ownerUID: uid)
    }

    public func removeRunDir(profileID: String, uid: uid_t) {
        guard Self.isValidProfileID(profileID) else { return }
        Self.removeEntry(PT.sessionDir(uid: uid, profileID: profileID, runRoot: runRoot))
    }

    /// Removes a directory tree, or just the link if `path` is a symlink.
    public static func removeEntry(_ path: String) {
        var st = stat()
        guard lstat(path, &st) == 0 else { return }
        if (st.st_mode & S_IFMT) == S_IFLNK { unlink(path); return }
        try? FileManager.default.removeItem(atPath: path)
    }

    /// `path` must be a real directory owned by us with mode exactly `mode`; created if missing.
    public static func ensureRootOwnedDir(_ path: String, mode: mode_t = runDirMode) throws {
        var st = stat()
        if lstat(path, &st) != 0 {
            guard errno == ENOENT else { throw Failure.system("stat \(path)", errno) }
            guard mkdir(path, 0o700) == 0 || errno == EEXIST else { throw Failure.system("mkdir \(path)", errno) }
            guard lstat(path, &st) == 0 else { throw Failure.system("stat \(path)", errno) }
        }
        guard (st.st_mode & S_IFMT) != S_IFLNK else { throw Failure.symlinkNotAllowed(path) }
        guard (st.st_mode & S_IFMT) == S_IFDIR else { throw Failure.notADirectory(path) }
        guard st.st_uid == geteuid() else { throw Failure.wrongOwner(path: path, expected: geteuid(), actual: st.st_uid) }
        if st.st_mode & 0o7777 != mode, chmod(path, mode) != 0 {
            throw Failure.system("chmod \(path)", errno)
        }
    }

    #if os(Linux)
    /// Links the daemon's own executable into the (root-owned) run directory as `dnsHookName`, the path
    /// OpenVPN runs as its DNS hook. Returns nil without a hook.
    func linkDNSHook(in runDir: String) throws -> String? {
        guard let target = dnsHook else { return nil }
        guard target.hasPrefix("/"), !Self.containsNUL(target) else { throw Failure.notAbsolute(target) }
        let path = runDir + "/" + Self.dnsHookName
        guard symlink(target, path) == 0 else { throw Failure.system("link \(path)", errno) }
        return path
    }
    #endif

    /// Copies the bundled DNS script (with its extended-attribute signature) into the run directory.
    /// Returns nil when no script is bundled. macOS only (`fcopyfile`): elsewhere a script fails to stage,
    /// and the Linux daemon is its own hook (`linkDNSHook`).
    func stageDNSScript(in runDir: String) throws -> String? {
        guard let src = dnsUpdownSource else { return nil }
        let sfd = open(src, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard sfd >= 0 else {
            if errno == ENOENT { return nil }
            throw Failure.system("open \(src)", errno)
        }
        defer { close(sfd) }
        var st = stat()
        guard fstat(sfd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { throw Failure.notARegularFile(src) }
        guard st.st_size <= 1 << 20 else { throw Failure.fileTooLarge(src) }
        let dst = runDir + "/dns-updown"
        let dfd = open(dst, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o700)
        guard dfd >= 0 else { throw Failure.system("create \(dst)", errno) }
        defer { close(dfd) }
        #if os(macOS)
        guard fcopyfile(sfd, dfd, nil, copyfile_flags_t(COPYFILE_DATA | COPYFILE_XATTR)) == 0 else {
            throw Failure.system("copy \(src)", errno)
        }
        _ = fchmod(dfd, 0o700)
        return dst
        #else
        throw Failure.system("copy \(src)", ENOTSUP)
        #endif
    }

    // MARK: - Log size

    /// Size above which a running tool's log is trimmed, how much of its end is kept, and how much of
    /// its start (version, tunnel device, pushed options, route and DNS set-up).
    public static let maxLogBytes = 5 << 20
    public static let keptLogBytes = 1 << 20
    public static let keptLogHeadBytes = 64 << 10

    /// Keeps the log behind `fd` (opened with `O_APPEND`, readable) under `maxBytes`: when it is
    /// larger, everything between its first `headBytes` and its last `keepBytes` (both cut at line
    /// boundaries) is replaced by a marker line. The tool keeps appending through its own descriptor;
    /// lines it writes during the few microseconds of the cut can be lost. Returns true when it trimmed.
    @discardableResult
    public static func capLog(
        fd: Int32, maxBytes: Int = maxLogBytes, keepBytes: Int = keptLogBytes,
        headBytes: Int = keptLogHeadBytes
    ) -> Bool {
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_size > maxBytes,
            headBytes + keepBytes < st.st_size
        else { return false }
        let size = Int(st.st_size)
        var head = [UInt8](repeating: 0, count: headBytes)
        let h = headBytes > 0 ? pread(fd, &head, headBytes, 0) : 0
        guard h >= 0 else { return false }
        let headEnd = head[0..<h].lastIndex(of: 0x0A).map { $0 + 1 } ?? 0
        var tail = [UInt8](repeating: 0, count: keepBytes)
        let n = pread(fd, &tail, keepBytes, off_t(size - keepBytes))
        guard n > 0 else { return false }
        var kept = tail[0..<n]
        if let nl = kept.firstIndex(of: 0x0A) { kept = kept[(nl + 1)...] }
        guard ftruncate(fd, off_t(headEnd)) == 0 else { return false }
        let marker = "[log trimmed by the helper at \(maxBytes >> 20) MB; lines in between removed]\n"
        let data = Array(marker.utf8) + Array(kept)
        _ = data.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        return true
    }

    // MARK: - File helpers

    /// Writes a new file (never follows or replaces an existing entry).
    public static func writeNewFile(_ path: String, _ data: Data, mode: mode_t) throws {
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        guard fd >= 0 else { throw Failure.system("create \(path)", errno) }
        defer { close(fd) }
        _ = fchmod(fd, mode)
        try data.withUnsafeBytes { buf in
            var off = 0
            while off < buf.count {
                let n = write(fd, buf.baseAddress! + off, buf.count - off)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw Failure.system("write \(path)", errno)
                }
                off += n
            }
        }
    }

    public static func realPath(_ path: String) -> String? {
        guard let p = realpath(path, nil) else { return nil }
        defer { free(p) }
        return String(cString: p)
    }

    /// What `fd` refers to: `F_GETPATH` on the Mac, the `/proc/self/fd` link on Linux (which ends in
    /// " (deleted)" for a removed entry, so that never matches). Nil elsewhere, where `openProfileDir`
    /// therefore refuses every directory.
    static func path(of fd: Int32) -> String? {
        #if os(macOS)
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(fd, F_GETPATH, &buf) != -1 else { return nil }
        return String(cString: buf)
        #elseif os(Linux)
        var buf = [CChar](repeating: 0, count: 4097)
        let n = readlink("/proc/self/fd/\(fd)", &buf, buf.count - 1)
        guard n > 0, n < buf.count - 1 else { return nil }
        buf[n] = 0
        return String(cString: buf)
        #else
        return nil
        #endif
    }
}

/// An open, validated profile directory. Files are accessed relative to the descriptor so the
/// directory cannot be swapped between validation and use.
public final class ProfileDirectory {
    public let fd: Int32
    public let path: String
    public let uid: uid_t
    public let gid: gid_t

    init(fd: Int32, path: String, uid: uid_t, gid: gid_t) {
        self.fd = fd
        self.path = path
        self.uid = uid
        self.gid = gid
    }

    deinit { close(fd) }

    static func isPlainName(_ name: String) -> Bool {
        !name.isEmpty && name != "." && name != ".." && !name.utf8.contains(UInt8(ascii: "/"))
            && !name.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7F })
    }

    /// Reads a regular, single-link file owned by the user and writable only by them. Symlinks,
    /// FIFOs and directories are refused.
    public func readFile(_ name: String, maxBytes: Int) throws -> Data {
        guard Self.isPlainName(name) else { throw HelperCore.Failure.notARegularFile(name) }
        let full = path + "/" + name
        let f = openat(fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard f >= 0 else {
            if errno == ELOOP { throw HelperCore.Failure.symlinkNotAllowed(full) }
            throw HelperCore.Failure.system("open \(full)", errno)
        }
        defer { close(f) }
        var st = stat()
        guard fstat(f, &st) == 0 else { throw HelperCore.Failure.system("stat \(full)", errno) }
        guard (st.st_mode & S_IFMT) == S_IFREG else { throw HelperCore.Failure.notARegularFile(full) }
        guard st.st_uid == uid else { throw HelperCore.Failure.wrongOwner(path: full, expected: uid, actual: st.st_uid) }
        guard st.st_nlink == 1 else { throw HelperCore.Failure.multipleLinks(full) }
        guard st.st_mode & (S_IWGRP | S_IWOTH) == 0 else { throw HelperCore.Failure.insecurePermissions(full) }
        guard st.st_size <= maxBytes else { throw HelperCore.Failure.fileTooLarge(full) }

        var data = Data()
        var buf = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = read(f, &buf, buf.count)
            if n < 0 {
                if errno == EINTR { continue }
                throw HelperCore.Failure.system("read \(full)", errno)
            }
            if n == 0 { break }
            data.append(buf, count: n)
            if data.count > maxBytes { throw HelperCore.Failure.fileTooLarge(full) }
        }
        return data
    }

    /// Replaces `name` with a fresh file owned by the user (0600) and returns an appending descriptor
    /// (also readable, for `HelperCore.capLog`). Whatever was there before (symlink, hard link) is
    /// unlinked, never followed or truncated, so every session starts with an empty log.
    public func createLogFile(_ name: String) throws -> Int32 {
        guard Self.isPlainName(name) else { throw HelperCore.Failure.invalidLogPath(name) }
        let full = path + "/" + name
        if unlinkat(fd, name, 0) != 0, errno != ENOENT {
            throw HelperCore.Failure.system("remove \(full)", errno)
        }
        let f = openat(fd, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_APPEND | O_CLOEXEC, 0o600)
        guard f >= 0 else { throw HelperCore.Failure.system("create \(full)", errno) }
        if fchown(f, uid, gid) != 0, geteuid() == 0 {
            let e = errno
            close(f)
            throw HelperCore.Failure.system("chown \(full)", e)
        }
        _ = fchmod(f, 0o600)
        return f
    }
}

/// An open session directory `<runRoot>/<uid>/<profileID>` (root-owned). Socket operations go
/// through the descriptor and never follow links.
public final class SessionDirectory {
    public let fd: Int32
    public let path: String
    /// The user the session belongs to.
    public let ownerUID: uid_t

    init(fd: Int32, path: String, ownerUID: uid_t) {
        self.fd = fd
        self.path = path
        self.ownerUID = ownerUID
    }

    deinit { close(fd) }

    /// Removes a stale socket. Missing is fine; a symlink or any other file type is refused.
    public func removeSocket(_ name: String) throws {
        guard ProfileDirectory.isPlainName(name) else { throw HelperCore.Failure.notASocket(name) }
        let full = path + "/" + name
        var st = stat()
        if fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return }
            throw HelperCore.Failure.system("stat \(full)", errno)
        }
        if (st.st_mode & S_IFMT) == S_IFLNK { throw HelperCore.Failure.symlinkNotAllowed(full) }
        guard (st.st_mode & S_IFMT) == S_IFSOCK else { throw HelperCore.Failure.notASocket(full) }
        if unlinkat(fd, name, 0) != 0, errno != ENOENT { throw HelperCore.Failure.system("remove \(full)", errno) }
    }

    /// Hands a socket created by root to the session's user (0600). False unless `name` is a socket
    /// that ends up owned by the user with mode 0600. Race-free because only root can change entries
    /// in this directory; the checks still never follow a link.
    @discardableResult
    public func restrictSocket(_ name: String) -> Bool {
        guard ProfileDirectory.isPlainName(name) else { return false }
        var st = stat()
        guard fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0, (st.st_mode & S_IFMT) == S_IFSOCK else { return false }
        #if os(Linux)
        // The mode first, while root owns the socket: changing the mode of another user's file needs
        // CAP_FOWNER, which the daemon's capability bounding set leaves out. glibc carries out
        // AT_SYMLINK_NOFOLLOW through fchmodat2 or /proc; where neither works, the entry was just seen
        // to be a socket in a directory only root can change, so following it is no risk.
        if st.st_mode & 0o777 != 0o600, fchmodat(fd, name, 0o600, AT_SYMLINK_NOFOLLOW) != 0 {
            _ = fchmodat(fd, name, 0o600, 0)
        }
        if st.st_uid != ownerUID { _ = fchownat(fd, name, ownerUID, gid_t.max, AT_SYMLINK_NOFOLLOW) }
        #else
        if st.st_uid != ownerUID { _ = fchownat(fd, name, ownerUID, gid_t.max, AT_SYMLINK_NOFOLLOW) }
        _ = fchmodat(fd, name, 0o600, AT_SYMLINK_NOFOLLOW)
        #endif
        guard fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 else { return false }
        return (st.st_mode & S_IFMT) == S_IFSOCK && st.st_uid == ownerUID && st.st_mode & 0o777 == 0o600
    }
}
