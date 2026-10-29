import Foundation

// The distribution's tools on Linux (docs/LINUX.md, "Daemon security rules"): where each may be, the
// version it needs, and the checks a path passes before root runs it. Pure apart from `lstat` and
// `realpath`, so the daemon and the `passtunnel` command (Cisco AnyConnect's sign-in) share them, and the
// tests run on every platform.

/// A file root may execute: every component of its real path owned by root and not writable by group
/// or others, none a symbolic link, and the file itself a regular file. Then only root could have
/// replaced it, before or after the check. Used for the VPN tools and for the daemon's own executable.
public enum TrustedPath {
    public enum Failure: Error, Equatable, CustomStringConvertible {
        case missing(String)
        case notAbsolute(String)
        case symlink(String)
        case wrongOwner(String, uid_t)
        case writableByOthers(String)
        case notADirectory(String)
        case notARegularFile(String)

        public var description: String {
            switch self {
            case .missing(let p): return "\(p) does not exist."
            case .notAbsolute(let p): return "\(p) is not an absolute path."
            case .symlink(let p): return "\(p) is a symbolic link."
            case .wrongOwner(let p, let uid): return "\(p) is owned by uid \(uid), not by root."
            case .writableByOthers(let p): return "\(p) is writable by its group or by others."
            case .notADirectory(let p): return "\(p) is not a directory."
            case .notARegularFile(let p): return "\(p) is not a regular file."
            }
        }
    }

    /// Checks `path`, which must already be resolved (`realpath`). `owner` is root except in tests,
    /// which also start at a `base` of their own instead of `/`.
    public static func check(_ path: String, owner: uid_t = 0, base: String = "/") throws {
        guard path.hasPrefix("/"), !path.utf8.contains(0) else { throw Failure.notAbsolute(path) }
        var current = ""
        var components = ["/"]
        for part in path.split(separator: "/", omittingEmptySubsequences: true) {
            current += "/" + part
            components.append(current)
        }
        if base != "/" {
            let root = base.hasSuffix("/") ? String(base.dropLast()) : base
            components = components.filter { $0 == root || $0.hasPrefix(root + "/") }
            guard !components.isEmpty else { throw Failure.notAbsolute(path) }
        }
        for (index, component) in components.enumerated() {
            var st = stat()
            guard lstat(component, &st) == 0 else { throw Failure.missing(component) }
            let type = st.st_mode & S_IFMT
            if type == S_IFLNK { throw Failure.symlink(component) }
            guard st.st_uid == owner else { throw Failure.wrongOwner(component, st.st_uid) }
            guard st.st_mode & (S_IWGRP | S_IWOTH) == 0 else { throw Failure.writableByOthers(component) }
            if index == components.count - 1 {
                guard type == S_IFREG else { throw Failure.notARegularFile(component) }
            } else {
                guard type == S_IFDIR else { throw Failure.notADirectory(component) }
            }
        }
    }
}

/// A tool version, compared numerically (`2.6.10` > `2.6.9`). Pre-release suffixes (`2.7_rc2`) count
/// as the release they lead to. `twoDigitMinor` is how the version is written, not part of its value:
/// openconnect numbers its releases `9.01`, `9.12`, `8.20`.
public struct ToolVersion: Comparable, CustomStringConvertible, Sendable {
    public let major: Int
    public let minor: Int
    public let patch: Int
    /// Written `9.01` (openconnect's form) rather than `9.1.0`.
    public let twoDigitMinor: Bool

    public init(_ major: Int, _ minor: Int, _ patch: Int = 0, twoDigitMinor: Bool = false) {
        self.major = major
        self.minor = minor
        self.patch = patch
        self.twoDigitMinor = twoDigitMinor
    }

    /// The leading `major.minor[.patch]` of `text` (`2.6.9`, `2.7_rc2`, `1.21.0-dirty`).
    public init?(parsing text: Substring, twoDigitMinor: Bool = false) {
        var numbers: [Int] = []
        var digits = ""
        for c in text {
            if c.isASCII, c.isNumber {
                digits.append(c)
                guard digits.count <= 6 else { return nil }
            } else if c == ".", !digits.isEmpty, numbers.count < 2 {
                numbers.append(Int(digits)!)
                digits = ""
            } else {
                break
            }
        }
        if !digits.isEmpty { numbers.append(Int(digits)!) }
        guard numbers.count >= 2 else { return nil }
        self.init(numbers[0], numbers[1], numbers.count > 2 ? numbers[2] : 0, twoDigitMinor: twoDigitMinor)
    }

    public static func == (a: ToolVersion, b: ToolVersion) -> Bool {
        (a.major, a.minor, a.patch) == (b.major, b.minor, b.patch)
    }

    public static func < (a: ToolVersion, b: ToolVersion) -> Bool {
        (a.major, a.minor, a.patch) < (b.major, b.minor, b.patch)
    }

    /// `2.6.9`; openconnect's `9.12` (`9.12.1` with a patch level).
    public var description: String {
        guard twoDigitMinor else { return "\(major).\(minor).\(patch)" }
        return short + (patch > 0 ? ".\(patch)" : "")
    }

    /// `2.6`; openconnect's `9.01`.
    public var short: String {
        twoDigitMinor ? "\(major)." + (minor < 10 ? "0\(minor)" : "\(minor)") : "\(major).\(minor)"
    }
}

/// A distribution tool the daemon runs: where it may be, which version it needs and how its version
/// is read. pppd is not run by the daemon but by openfortivpn (from the path compiled into it), so it
/// is checked the same way before every FortiGate start.
public struct ToolSpec {
    public let name: String
    /// Fixed paths; the first that exists is used.
    public let candidates: [String]
    public let minimum: ToolVersion
    public let package: String
    public let versionArguments: [String]
    public let parseVersion: (String) -> ToolVersion?

    public static let openvpn = ToolSpec(
        name: "OpenVPN", candidates: ["/usr/sbin/openvpn", "/usr/bin/openvpn"], minimum: ToolVersion(2, 6, 0),
        package: "openvpn", versionArguments: ["--version"], parseVersion: ToolSpec.openVPNVersion)

    public static let openfortivpn = ToolSpec(
        name: "openfortivpn", candidates: ["/usr/bin/openfortivpn"], minimum: ToolVersion(1, 21, 0),
        package: "openfortivpn", versionArguments: ["--version"], parseVersion: ToolSpec.firstVersion)

    public static let pppd = ToolSpec(
        name: "pppd", candidates: ["/usr/sbin/pppd"], minimum: ToolVersion(2, 4, 7),
        package: "ppp", versionArguments: ["--version"], parseVersion: ToolSpec.firstVersion)

    /// Cisco AnyConnect's tool (docs/LINUX.md, "Cisco AnyConnect"): the distribution's, never bundled, 9.01 or
    /// later (owner decision, #2: Debian 12 and EPEL 9 ship 9.01; Ubuntu 22.04's 8.20 is not supported). The
    /// daemon runs it as root for the tunnel; `passtunnel` runs it as the user for the sign-in.
    public static let openconnect = ToolSpec(
        name: "openconnect", candidates: ["/usr/sbin/openconnect", "/usr/bin/openconnect"],
        minimum: ToolVersion(9, 1, twoDigitMinor: true), package: "openconnect", versionArguments: ["--version"],
        parseVersion: ToolSpec.openConnectVersion)

    public init(
        name: String, candidates: [String], minimum: ToolVersion, package: String, versionArguments: [String],
        parseVersion: @escaping (String) -> ToolVersion?
    ) {
        self.name = name
        self.candidates = candidates
        self.minimum = minimum
        self.package = package
        self.versionArguments = versionArguments
        self.parseVersion = parseVersion
    }

    /// The version on the first line of `openvpn --version`: "OpenVPN 2.6.9 x86_64-pc-linux-gnu […]".
    public static func openVPNVersion(_ output: String) -> ToolVersion? {
        for line in output.split(separator: "\n", omittingEmptySubsequences: true) {
            let words = line.split(separator: " ", omittingEmptySubsequences: true)
            if words.count >= 2, words[0] == "OpenVPN" { return ToolVersion(parsing: words[1]) }
        }
        return nil
    }

    /// The first word that is a version: `openfortivpn --version` prints "1.21.0" (or "v1.22.1-3-g…"
    /// from a git build), `pppd --version` "pppd version 2.4.9".
    public static func firstVersion(_ output: String) -> ToolVersion? {
        for line in output.split(separator: "\n", omittingEmptySubsequences: true) {
            for word in line.split(separator: " ", omittingEmptySubsequences: true) {
                let text = word.hasPrefix("v") ? word.dropFirst() : word
                if text.first?.isNumber == true, let version = ToolVersion(parsing: text) { return version }
            }
        }
        return nil
    }
}

extension ToolSpec {
    /// `openconnect --version`'s first line: "OpenConnect version v9.12" (a distribution build may add
    /// "-3", a git build "-12-gabcdef"), then the library and its features.
    public static func openConnectVersion(_ output: String) -> ToolVersion? {
        for line in output.split(separator: "\n", omittingEmptySubsequences: true) {
            let words = line.split(separator: " ", omittingEmptySubsequences: true)
            guard words.count >= 3, words[0] == "OpenConnect", words[1] == "version" else { continue }
            let text = words[2].hasPrefix("v") ? words[2].dropFirst() : words[2]
            return ToolVersion(parsing: text, twoDigitMinor: true)
        }
        return nil
    }

    /// The option that keeps openconnect from offering the server a sign-in in a browser (9.10 and later).
    public static let noExternalAuthOption = "--no-external-auth"
    /// What `openconnect --help` is run with to tell which options it has.
    public static let helpArguments = ["--help"]

    /// Whether `openconnect --help` lists `--no-external-auth` (as an option of its own, not inside another
    /// word): the sign-in renders `no-external-auth` only then (docs/LINUX.md, "Cisco AnyConnect").
    public static func openConnectHasNoExternalAuth(help: String) -> Bool {
        help.split(whereSeparator: { $0 == "\n" || $0 == " " || $0 == "\t" || $0 == "," || $0 == "=" || $0 == "[" })
            .contains { $0 == noExternalAuthOption }
    }
}

/// A checked tool: its real path and version.
public struct ResolvedTool: Equatable, Sendable {
    public let path: String
    public let version: ToolVersion

    public init(path: String, version: ToolVersion) {
        self.path = path
        self.version = version
    }
}

public enum ToolFailure: Error, Equatable, CustomStringConvertible {
    case notInstalled(name: String, candidates: [String], package: String, minimum: ToolVersion)
    case untrusted(name: String, path: String, reason: String)
    case unknownVersion(name: String, path: String)
    case tooOld(name: String, version: ToolVersion, minimum: ToolVersion, package: String)
    case noCABundle(candidates: [String])
    case untrustedCABundle(path: String, reason: String)

    public var description: String {
        switch self {
        case .notInstalled(let name, let candidates, let package, let minimum):
            return "\(name) is not installed (none of \(candidates.joined(separator: ", ")) exists). "
                + "Install the distribution's \(package) package, version \(minimum.short) or later."
        case .untrusted(let name, let path, let reason):
            return "Refusing to run \(name) from \(path): \(reason)"
        case .unknownVersion(let name, let path):
            return "Could not tell the version of \(name) at \(path)."
        case .tooOld(let name, let version, let minimum, let package):
            return "\(name) \(version) is too old: PassTunnel needs \(minimum) or later. Update the \(package) package."
        case .noCABundle(let candidates):
            return "No CA bundle to verify the gateway with (none of \(candidates.joined(separator: ", ")) exists). "
                + "Install the distribution's ca-certificates package."
        case .untrustedCABundle(let path, let reason):
            return "Refusing to use the CA bundle \(path): \(reason)"
        }
    }
}

/// Finding and checking the distribution's tools and CA bundle, as the daemon does before every start
/// (`SystemTools`) and `passtunnel` before Cisco AnyConnect's sign-in.
public enum DistributionTools {
    /// Where distributions keep the CA bundle (Debian and Ubuntu, Fedora and RHEL, others); the first
    /// that exists is used (docs/LINUX.md).
    public static let caBundles = [
        "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem"
    ]

    /// The first existing candidate of `spec`, resolved with `realpath` once, then that real path checked
    /// (`TrustedPath`, owned by `owner` from `base` on) and its version read from what `versionOutput` gives
    /// for it (the tool run with `spec.versionArguments`; nil when it could not be run).
    public static func resolve(
        _ spec: ToolSpec, owner: uid_t = 0, base: String = "/", versionOutput: (String, [String]) -> String?
    ) throws -> ResolvedTool {
        guard let candidate = spec.candidates.first(where: { access($0, F_OK) == 0 }) else {
            throw ToolFailure.notInstalled(name: spec.name, candidates: spec.candidates, package: spec.package, minimum: spec.minimum)
        }
        guard let real = HelperCore.realPath(candidate) else {
            throw ToolFailure.untrusted(name: spec.name, path: candidate, reason: "its path cannot be resolved.")
        }
        do {
            try TrustedPath.check(real, owner: owner, base: base)
        } catch {
            throw ToolFailure.untrusted(name: spec.name, path: real, reason: String(describing: error))
        }
        guard let output = versionOutput(real, spec.versionArguments), let version = spec.parseVersion(output) else {
            throw ToolFailure.unknownVersion(name: spec.name, path: real)
        }
        guard version >= spec.minimum else {
            throw ToolFailure.tooOld(name: spec.name, version: version, minimum: spec.minimum, package: spec.package)
        }
        return ResolvedTool(path: real, version: version)
    }

    /// The first existing CA bundle of `candidates`, resolved, then checked as a tool is: only root can have
    /// changed what a tool verifies the server with.
    public static func caBundle(candidates: [String] = caBundles, owner: uid_t = 0, base: String = "/") throws -> String {
        guard let candidate = candidates.first(where: { access($0, F_OK) == 0 }) else {
            throw ToolFailure.noCABundle(candidates: candidates)
        }
        guard let real = HelperCore.realPath(candidate) else {
            throw ToolFailure.untrustedCABundle(path: candidate, reason: "its path cannot be resolved.")
        }
        do {
            try TrustedPath.check(real, owner: owner, base: base)
        } catch {
            throw ToolFailure.untrustedCABundle(path: real, reason: String(describing: error))
        }
        return real
    }
}
