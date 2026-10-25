import Foundation
import PassTunnelVPNConfig

/// Which of the lines the helper's sanitizer refuses an import leaves out instead of refusing the file.
///
/// `OVPNSanitizer`, the helper's check at every connect, is not changed by any of this. A line is skipped
/// by turning it into a comment (`# PassTunnel skipped: …`) in the configuration PassTunnel stores, so a
/// line that came back would be refused at connect time as before. Only lines whose whole effect PassTunnel
/// replaces or does not need are skipped (`skippable`, `skippableManaged`). Everything else the sanitizer
/// refuses blocks the file: directives with a role in checking the server or the sign-in, ones that load
/// code or read files outside the configuration, server-only directives and server or standalone modes,
/// malformed lines and blocks, and any name not listed here. SECURITY.md ("Importing an OpenVPN configuration") has the table.
public enum OVPNSkipRules {
    /// Why a line can be left out. The raw values are stable (`passtunnel import --json`).
    public enum Reason: String, CaseIterable, Hashable, Sendable {
        /// Runs a program (`up`, `down`, `route-up`, …).
        case program
        /// `script-security` above 1 (or unreadable): OpenVPN's default level, 1, applies.
        case scriptSecurity = "script_security"
        /// A DNS script: PassTunnel's own hook sets DNS from what the server sends.
        case dns
        /// How OpenVPN runs as a process, or a file it would write as root.
        case process
        /// OpenVPN's own log file.
        case logging
        /// OpenVPN's management interface.
        case management
        /// A variable for scripts (`setenv` of anything but client metadata).
        case environment

        /// Why leaving the line out is safe, for people.
        public var message: String {
            switch self {
            case .program:
                return String(localized: "Runs a program. PassTunnel never runs scripts from a profile.")
            case .scriptSecurity:
                return String(localized: "Allows scripts. PassTunnel never runs scripts from a profile.")
            case .dns:
                return String(localized: "A DNS script. PassTunnel sets DNS from what the server sends.")
            case .process:
                return String(localized: "Changes how OpenVPN runs or writes a file as root. PassTunnel runs the connection itself.")
            case .logging:
                return String(localized: "A log file. PassTunnel keeps the connection’s log itself.")
            case .management:
                return String(localized: "OpenVPN’s management interface. PassTunnel sets it up itself.")
            case .environment:
                return String(localized: "A variable for scripts. PassTunnel runs none.")
            }
        }
    }

    /// A line left out.
    public struct Skipped: Hashable, Sendable {
        /// 1-based, in the text given (`OVPNImportReport`: in the file as the user wrote it).
        public var line: Int
        /// The directive as the sanitizer names it: "up", "setenv BASH_ENV".
        public var directive: String
        /// The line as written, trimmed, safe to show (`displayText`).
        public var text: String
        public var reason: Reason

        public init(line: Int, directive: String, text: String, reason: Reason) {
            self.line = line
            self.directive = directive
            self.text = text
            self.reason = reason
        }
    }

    /// A line that refuses the file.
    public struct Blocking: Hashable, Sendable, CustomStringConvertible {
        public var line: Int
        /// As the sanitizer names it: "plugin", "<config>", "(line)".
        public var directive: String
        public var text: String
        /// In English, as the sanitizer gives it ("not allowed", "references an external file; …").
        public var reason: String

        public init(line: Int, directive: String, text: String, reason: String) {
            self.line = line
            self.directive = directive
            self.text = text
            self.reason = reason
        }

        /// "line 3: plugin (not allowed)", as `PTError.ovpnNotAllowed` lists it.
        public var description: String { "line \(line): \(directive) (\(reason))" }
    }

    public struct Result: Equatable, Sendable {
        /// The text with every skipped line turned into a comment; all other lines byte for byte. When
        /// `blocking` is empty, `OVPNSanitizer.sanitize` accepts it.
        public var text: String
        public var skipped: [Skipped]
        public var blocking: [Blocking]
    }

    /// What a skipped line becomes, followed by its `displayText`.
    public static let marker = "# PassTunnel skipped: "

    // The sanitizer's reasons the rules below rely on. A line refused for any other reason blocks, so a
    // new rule in the sanitizer can only make the import stricter.
    static let notAllowed = "not allowed"
    static let managedByPassTunnel = "managed by PassTunnel"
    static let scriptSecurityReasons: Set<String> = ["level above 1 allows scripts", "invalid level"]
    static let setenvReason = "only client metadata variables may be set"

    /// Directives the sanitizer refuses as "not allowed" whose whole effect PassTunnel replaces or does
    /// not need. Every other "not allowed" directive blocks:
    /// - checking the server or the sign-in: `tls-verify`, `auth-user-pass-verify`, `tls-crypt-v2-verify`;
    /// - loading code: `plugin`, `engine`, `providers`, `pkcs11-providers`, `show-pkcs11-ids`;
    /// - reading files outside the configuration: `config`, `capath`, `dev-node`, `replay-persist` (also
    ///   replay protection across restarts), `client-config-dir`, `ifconfig-pool-persist`;
    /// - server-only (the file is not a client configuration): `learn-address`, `client-connect`,
    ///   `client-disconnect`, `client-crresponse`, `port-share`, and the server modes `server`,
    ///   `server-ipv6`, `server-bridge`, `tls-server`, `inetd` (and `mode` other than `p2p`, refused with
    ///   its own reason);
    /// - standalone modes, which do something else instead of connecting: `genkey`, `mktun`, `rmtun`,
    ///   `help`, `version`, `test-crypto`, the `show-…` listings, `allow-nonadmin`;
    /// - a file or a process setting no client needs: `memstats`, `setcon`, `win-sys`, `service`,
    ///   `msg-channel` (and a `dev` name that is not a device type, refused with its own reason).
    static let skippable: [String: Reason] = [
        // Programs OpenVPN runs as root at points of the connection. The helper never runs a program a
        // profile names: DNS is set by its own pinned hook (`--dns-updown` on its command line) from what
        // the server sends, routes and addresses by OpenVPN itself.
        "up": .program,
        "down": .program,
        "route-up": .program,
        "route-pre-down": .program,
        "ipchange": .program,
        // The `ip` program for addresses and routes (Linux builds): without it OpenVPN uses its own.
        "iproute": .program,
        // A DNS script, `disable` or `force`: the helper passes its own `--dns-updown` after the config.
        "dns-updown": .dns,
        // How OpenVPN runs as a process. The helper starts it in the foreground, supervises and stops it,
        // and keeps it root so that it can undo its routes and DNS when the connection ends; nothing it
        // reads depends on the working directory, since every file must be inline.
        "daemon": .process,
        "cd": .process,
        "chroot": .process,
        "user": .process,
        "group": .process,
        // Files OpenVPN would write as root. The helper tracks the process itself; nothing in PassTunnel
        // reads a status file or temporary files. `tls-export-cert` only feeds a `tls-verify` script, and
        // `tls-verify` blocks the file.
        "writepid": .process,
        "status": .process,
        "tmp-dir": .process,
        "tls-export-cert": .process,
    ]

    /// The `log*` and `management*` directives (refused as "managed by PassTunnel") that can be left out:
    /// the helper keeps the log (OpenVPN's output goes to the profile's `vpn.log`) and sets up the
    /// management interface itself (`--management` on its socket, `--management-client-user`). Blocking:
    /// `management-external-key` and `management-external-cert` (the key or certificate would come from
    /// another program: the profile could not sign in), `management-client-auth` (server-only), and any
    /// other name in these families.
    static let skippableManaged: [String: Reason] = [
        "log": .logging,
        "log-append": .logging,
        "management": .management,
        "management-client": .management,
        "management-client-user": .management,
        "management-client-group": .management,
        "management-hold": .management,
        "management-query-passwords": .management,
        "management-query-proxy": .management,
        "management-query-remote": .management,
        "management-forget-disconnect": .management,
        "management-signal": .management,
        "management-up-down": .management,
        "management-log-cache": .management,
    ]

    /// Clearer words for lines that block although the sanitizer says PassTunnel manages the family.
    static let blockingReasons: [String: String] = [
        "management-external-key": "the private key would come from another program",
        "management-external-cert": "the certificate would come from another program",
    ]

    /// Why `violation` can be skipped; nil when it blocks.
    public static func skipReason(_ violation: OVPNSanitizer.Violation) -> Reason? {
        let name = violation.directive
        if name.hasPrefix("setenv ") { return violation.reason == setenvReason ? .environment : nil }
        if name == "script-security" { return scriptSecurityReasons.contains(violation.reason) ? .scriptSecurity : nil }
        switch violation.reason {
        case notAllowed: return skippable[name]
        case managedByPassTunnel: return skippableManaged[name]
        default: return nil
        }
    }

    /// Classifies every line `OVPNSanitizer.sanitize` refuses in `text` and comments out the ones that can
    /// be skipped. A line is skipped only when everything the sanitizer reports on it can be.
    public static func apply(_ text: String) -> Result {
        let violations = sanitizerViolations(text)
        guard !violations.isEmpty else { return Result(text: text, skipped: [], blocking: []) }
        var lines = OVPNInliner.lines(text)
        var byLine: [Int: [OVPNSanitizer.Violation]] = [:]
        for v in violations { byLine[v.line, default: []].append(v) }

        var skipped: [Skipped] = []
        var blocking: [Blocking] = []
        for number in byLine.keys.sorted() {
            let found = byLine[number] ?? []
            let original = lines.indices.contains(number - 1) ? lines[number - 1] : ""
            let shown = displayText(original, firstLine: number == 1)
            let reasons = found.compactMap(skipReason)
            if reasons.count == found.count, let reason = reasons.first, lines.indices.contains(number - 1) {
                skipped.append(Skipped(line: number, directive: found[0].directive, text: shown, reason: reason))
                lines[number - 1] = commentLine(for: original, firstLine: number == 1)
            } else {
                blocking += found.map { blockingEntry($0, text: shown) }
            }
        }
        let out = lines.joined(separator: "\n")
        if blocking.isEmpty {
            // Commenting out directive lines changes no other line's meaning, so this never finds anything;
            // it makes "no blocking lines" mean "the sanitizer accepts the text" whatever happens above.
            let outLines = OVPNInliner.lines(out)
            blocking = sanitizerViolations(out).map { v in
                blockingEntry(v, text: displayText(outLines.indices.contains(v.line - 1) ? outLines[v.line - 1] : "",
                                                   firstLine: v.line == 1))
            }
        }
        return Result(text: out, skipped: skipped, blocking: blocking)
    }

    static func sanitizerViolations(_ text: String) -> [OVPNSanitizer.Violation] {
        do {
            _ = try OVPNSanitizer.sanitize(text)
            return []
        } catch let failure as OVPNSanitizer.Failure {
            return failure.violations
        } catch {
            return [OVPNSanitizer.Violation(line: 1, directive: "(line)", reason: "\(error)")]
        }
    }

    /// A line that blocks, with the sanitizer's reason; "managed by PassTunnel" would read as if the line
    /// were taken care of, so those say why they block or "not allowed".
    static func blockingEntry(_ v: OVPNSanitizer.Violation, text: String) -> Blocking {
        let reason = blockingReasons[v.directive] ?? (v.reason == managedByPassTunnel ? notAllowed : v.reason)
        return Blocking(line: v.line, directive: v.directive, text: text, reason: reason)
    }

    /// The comment a skipped line becomes: at most `OVPNSanitizer.maxLineBytes` bytes, so OpenVPN reads it
    /// as one line, and starting with `#`, so it is a comment wherever it is (also in a `<connection>`).
    static func commentLine(for line: String, firstLine: Bool) -> String {
        marker + displayText(line, firstLine: firstLine, maxBytes: OVPNSanitizer.maxLineBytes - marker.utf8.count)
    }

    /// `line` trimmed, cut to `maxBytes` of UTF-8 (ending in "…" when cut), with characters that could
    /// garble a terminal or a label shown as "�": control characters (tabs and other whitespace as a space),
    /// line and paragraph separators and bidirectional formatting.
    public static func displayText(_ line: String, firstLine: Bool = false,
                                   maxBytes: Int = OVPNSanitizer.maxLineBytes - marker.utf8.count) -> String {
        var line = Substring(line)
        if firstLine, line.hasPrefix("\u{FEFF}") { line = line.dropFirst() }
        let trimmed = String(line).trimmingCharacters(in: .whitespacesAndNewlines)
        var scalars = String.UnicodeScalarView()
        for s in trimmed.unicodeScalars {
            switch s.value {
            case 0x09, 0x0A, 0x0B, 0x0C, 0x0D: scalars.append(" ")
            case 0x2028, 0x2029, 0x200E, 0x200F, 0x202A...0x202E, 0x2066...0x2069, 0xFEFF:
                scalars.append("\u{FFFD}")
            default:
                scalars.append(s.properties.generalCategory == .control ? "\u{FFFD}" : s)
            }
        }
        let shown = String(scalars)
        guard shown.utf8.count > maxBytes else { return shown }
        let ellipsis = "…"
        var cut = String.UnicodeScalarView()
        var bytes = 0
        for s in shown.unicodeScalars {
            let size = String(s).utf8.count
            if bytes + size > maxBytes - ellipsis.utf8.count { break }
            cut.append(s)
            bytes += size
        }
        return String(cut) + ellipsis
    }
}
