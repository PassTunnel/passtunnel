import Foundation

/// The Mac's DNS hook: OpenVPN's own `dns-updown` script (bundled, signed and pinned, never changed) run
/// through a short wrapper the helper writes next to the script's copy in the session directory
/// (docs/ARCHITECTURE.md, "DNS script (macOS)").
extension HelperCore {
    /// The only search path the script gets. OpenVPN runs its DNS hook with nothing but its DNS variables
    /// in the environment, and bash then falls back to its compiled-in path, which starts with
    /// `/usr/gnu/bin:/usr/local/bin` and ends with `.`; the script runs `grep`, `cut`, `xargs`, `sed` and
    /// `sleep` by name.
    public static let dnsScriptSearchPath = "/usr/bin:/bin:/usr/sbin:/sbin"

    /// Written by the wrapper before the script's dns-up runs: the variables OpenVPN passed, one
    /// `name=value` per line. It stays until the helper has checked, once the tool has ended, that the Mac
    /// has its DNS back (`OpenVPNDNS.settle`).
    public static let dnsRecordName = "dns-up.env"

    /// Written by the wrapper after the script's dns-up: `status=<its exit status>` and `service=<the primary
    /// service>`, the service only when the primary service was the same right before and right after the
    /// script (the script reads it in between). With the record, the session's evidence of what it set where.
    public static let dnsResultName = "dns-up.result"

    /// Written by the wrapper once the script's dns-down has run (whatever it did; a dns-up removes it).
    public static let dnsDownMarkName = "dns-down.ran"

    /// Written by the helper right before it runs a dns-down OpenVPN skipped: it is never run twice, also when
    /// the helper is killed while it runs.
    public static let dnsDownTriedName = "dns-down.helper"

    /// Where the session's log is, for what the helper says about its DNS once it no longer holds the log open
    /// (`DNSOwner`).
    public static let dnsOwnerName = "dns-owner"

    /// Larger records are refused (OpenVPN passes at most a few dozen short values).
    static let maxDNSRecordBytes = 64 << 10

    /// A session directory holds the record of its own session, and the one of the profile's last session when a
    /// start came while that one waited for another session (`OpenVPNDNSKeeper`, `parked`).
    public enum DNSSlot: CaseIterable, Sendable {
        case current, carried

        public var recordName: String { self == .current ? HelperCore.dnsRecordName : "dns-carried.env" }
        public var resultName: String { self == .current ? HelperCore.dnsResultName : "dns-carried.result" }
    }

    /// Every file a session directory keeps while its DNS is not settled (`keepOnlyDNSRecord`).
    public static var dnsKeptNames: Set<String> {
        Set(DNSSlot.allCases.flatMap { [$0.recordName, $0.resultName] } + [dnsDownMarkName, dnsDownTriedName, dnsOwnerName])
    }

    /// The wrapper (`dnsHookName`, 0700), OpenVPN's `--dns-updown`. It fixes `PATH`, keeps the record and the
    /// result of a dns-up, marks a dns-down that ran, and hands the script's exit status back to OpenVPN.
    /// `${!dns_@}` lists the names of the set `dns_*` variables. `primary` reads the primary service as the script
    /// does (`primary_dns_key`, from `State:/Network/Global/IPv4`), but only an ID of letters, digits and `-`.
    public static let dnsHookText = """
        #!/bin/bash
        # Written by the PassTunnel helper. Runs OpenVPN's dns-updown with a fixed PATH and records the
        # variables of a dns-up, its result and the service it changed, so that the helper can run the
        # dns-down OpenVPN skipped and check that the Mac has its DNS back once the session has ended.
        PATH=\(dnsScriptSearchPath)
        export PATH
        umask 077
        dir=${0%/*}
        record="$dir/\(dnsRecordName)"
        result="$dir/\(dnsResultName)"
        primary() {
            echo "show State:/Network/Global/IPv4" | /usr/sbin/scutil \\
                | /usr/bin/sed -n 's/^ *PrimaryService : \\([A-Za-z0-9-]\\{1,64\\}\\)$/\\1/p' | /usr/bin/head -n 1
        }
        if [ "$script_type" = dns-up ]; then
            /bin/rm -f "$dir/\(dnsDownMarkName)" "$result"
            for name in dev ${!dns_@}; do
                printf '%s=%s\\n' "$name" "${!name}"
            done > "$record.new" && /bin/mv -f "$record.new" "$record"
            before=$(primary)
            /bin/bash "$dir/dns-updown"
            status=$?
            after=$(primary)
            service=
            [ "$before" = "$after" ] && service=$before
            printf 'status=%s\\nservice=%s\\n' "$status" "$service" > "$result.new" && /bin/mv -f "$result.new" "$result"
            exit $status
        fi
        /bin/bash "$dir/dns-updown"
        status=$?
        : > "$dir/\(dnsDownMarkName)"
        exit $status

        """

    /// Writes the wrapper into `runDir` and returns its path.
    func writeDNSHook(in runDir: String) throws -> String {
        let path = runDir + "/" + Self.dnsHookName
        try Self.writeNewFile(path, Data(Self.dnsHookText.utf8), mode: 0o700)
        return path
    }

    /// The environment for the script's dns-down after a dns-up that recorded `record`: `PATH`,
    /// `script_type=dns-down` and the recorded variables. Nil unless every line is a variable OpenVPN 2.7
    /// sets for the hook (`dev` and the `dns_*` names of `setenv_dns_options`), with a value made of what
    /// OpenVPN itself lets through (`validate_domain`'s characters, plus `:` for IPv6 addresses), and
    /// unless `dev` and a server address are among them.
    public static func dnsDownEnvironment(record: String) -> [String]? {
        guard let lines = dnsRecordLines(record) else { return nil }
        return ["PATH=" + dnsScriptSearchPath, "script_type=dns-down"] + lines
    }

    /// The recorded variables by name, checked as `dnsDownEnvironment` checks them.
    public static func dnsVariables(record: String) -> [String: String]? {
        guard let lines = dnsRecordLines(record) else { return nil }
        var out: [String: String] = [:]
        for line in lines {
            let eq = line.firstIndex(of: "=")!
            out[String(line[..<eq])] = String(line[line.index(after: eq)...])
        }
        return out
    }

    /// The record's lines, nil unless they pass `dnsDownEnvironment`'s checks.
    static func dnsRecordLines(_ record: String) -> [String]? {
        var lines = record.components(separatedBy: "\n")
        guard lines.last == "" else { return nil }
        lines.removeLast()
        var names = Set<String>()
        for line in lines {
            guard let eq = line.firstIndex(of: "=") else { return nil }
            let name = String(line[..<eq]), value = line[line.index(after: eq)...]
            guard isDNSVariableName(name), names.insert(name).inserted,
                !value.isEmpty, value.utf8.count <= 255,
                value.unicodeScalars.allSatisfy(isDNSValueScalar)
            else { return nil }
        }
        guard names.contains("dev"), names.contains(where: { $0.hasPrefix("dns_server_") && $0.contains("_address_") }) else {
            return nil
        }
        return lines
    }

    /// The dns-up's result as the wrapper writes it: exactly `status=<0-255>` and `service=<ID or nothing>`, each on
    /// a line; nil for anything else.
    public static func dnsResult(_ text: String) -> (status: Int32, service: String?)? {
        let lines = text.components(separatedBy: "\n")
        guard lines.count == 3, lines[2] == "", lines[0].hasPrefix("status="), lines[1].hasPrefix("service=") else { return nil }
        let statusText = lines[0].dropFirst("status=".count)
        guard (1...3).contains(statusText.count), statusText.allSatisfy({ $0.isASCII && $0.isNumber }), let status = Int32(statusText),
            status <= 255
        else { return nil }
        let service = String(lines[1].dropFirst("service=".count))
        guard service.isEmpty || OpenVPNDNS.isServiceID(service) else { return nil }
        return (status, service.isEmpty ? nil : service)
    }

    /// `dev`, `dns_search_domain_<i>`, `dns_server_<n>_address_<m>`, `…_port_<m>`, `…_resolve_domain_<m>`,
    /// `…_dnssec`, `…_transport` or `…_sni`.
    static func isDNSVariableName(_ name: String) -> Bool {
        if name == "dev" { return true }
        func isIndex(_ s: Substring) -> Bool { !s.isEmpty && s.count <= 4 && s.allSatisfy { $0.isASCII && $0.isNumber } }
        if name.hasPrefix("dns_search_domain_") { return isIndex(name.dropFirst("dns_search_domain_".count)) }
        guard name.hasPrefix("dns_server_") else { return false }
        let rest = name.dropFirst("dns_server_".count)
        guard let sep = rest.firstIndex(of: "_"), isIndex(rest[..<sep]) else { return false }
        let field = rest[rest.index(after: sep)...]
        if ["dnssec", "transport", "sni"].contains(field) { return true }
        for prefix in ["address_", "port_", "resolve_domain_"] where field.hasPrefix(prefix) {
            return isIndex(field.dropFirst(prefix.count))
        }
        return false
    }

    /// ASCII letters, digits, `.`, `-`, `_`, `:`, or any non-ASCII character.
    static func isDNSValueScalar(_ c: Unicode.Scalar) -> Bool {
        switch c {
        case "a"..."z", "A"..."Z", "0"..."9", ".", "-", "_", ":": return true
        default: return c.value >= 0x80
        }
    }

    /// The dns-down still owed for the session in `runDir`: nil when there is no record, when a dns-down ran after
    /// it (`dnsDownMarkName`) or the helper ran or tried one already (`dnsDownTriedName`), else
    /// `dnsDownEnvironment` of it. Throws as `readSessionFile` does.
    public static func pendingDNSDown(runDir: String) throws -> [String]? {
        guard !dnsDownRan(runDir: runDir), !isRegularFile(runDir + "/" + dnsDownTriedName),
            let text = try readSessionFile(runDir: runDir, name: dnsRecordName)
        else { return nil }
        guard let environment = dnsDownEnvironment(record: text) else { throw Failure.unsafeFile(dnsRecordName) }
        return environment
    }

    /// What the session in `runDir` recorded in `slot`: nil when there is no record; the result when the wrapper
    /// wrote one (none: its dns-up has not finished, or an older wrapper ran it). Throws for a file that is not
    /// sound (`readSessionFile`), a record `dnsVariables` refuses, one without a `dev` the keys can name, or a
    /// result `dnsResult` refuses.
    public static func dnsRecord(runDir: String, slot: DNSSlot = .current) throws -> OpenVPNDNSRecord? {
        guard let text = try readSessionFile(runDir: runDir, name: slot.recordName) else { return nil }
        guard let variables = dnsVariables(record: text), let session = OpenVPNDNSSession(variables: variables) else {
            throw Failure.unsafeFile(slot.recordName)
        }
        var record = OpenVPNDNSRecord(session: session)
        if let resultText = try readSessionFile(runDir: runDir, name: slot.resultName) {
            guard let result = dnsResult(resultText) else { throw Failure.unsafeFile(slot.resultName) }
            record.status = result.status
            record.service = result.service
        }
        return record
    }

    /// Whether the dns-down after the last dns-up has run: the wrapper's mark is a regular file.
    public static func dnsDownRan(runDir: String) -> Bool {
        isRegularFile(runDir + "/" + dnsDownMarkName)
    }

    /// Marks, right before the helper runs a dns-down OpenVPN skipped, that it did: it is never run again.
    public static func markDNSDownTried(runDir: String) {
        let fd = open(runDir + "/" + dnsDownTriedName, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        if fd >= 0 { close(fd) }
    }

    public static func isRegularFile(_ path: String) -> Bool {
        var st = stat()
        return lstat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFREG
    }

    /// Removes everything in a session directory but its DNS records, results, marks and owner
    /// (`dnsKeptNames`): what a check of the Mac's DNS that could not finish leaves for the next try (the
    /// configuration, the auth file, the socket, the state and the scripts go now).
    public static func keepOnlyDNSRecord(runDir: String) {
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: runDir)) ?? []
        let kept = dnsKeptNames
        for entry in entries where !kept.contains(entry) {
            removeEntry(runDir + "/" + entry)
        }
    }

    /// Removes a slot's record and result.
    public static func removeDNSSlot(runDir: String, _ slot: DNSSlot) {
        unlink(runDir + "/" + slot.recordName)
        unlink(runDir + "/" + slot.resultName)
    }

    /// The texts of a slot's record and result, as they are (`readSessionFile`'s checks), to carry them into
    /// another session directory (`writeCarriedDNSRecord`).
    public static func dnsRecordTexts(runDir: String, slot: DNSSlot) throws -> (record: String, result: String?)? {
        guard let record = try readSessionFile(runDir: runDir, name: slot.recordName) else { return nil }
        return (record, try readSessionFile(runDir: runDir, name: slot.resultName))
    }

    /// Writes a record carried over a start into the new session directory's `carried` slot; refused unless the
    /// texts pass the checks they would be read with.
    public static func writeCarriedDNSRecord(runDir: String, record: String, result: String?) throws {
        guard let variables = dnsVariables(record: record), OpenVPNDNSSession(variables: variables) != nil else {
            throw Failure.unsafeFile(DNSSlot.carried.recordName)
        }
        if let result, dnsResult(result) == nil { throw Failure.unsafeFile(DNSSlot.carried.resultName) }
        try writeNewFile(runDir + "/" + DNSSlot.carried.recordName, Data(record.utf8), mode: 0o600)
        if let result { try writeNewFile(runDir + "/" + DNSSlot.carried.resultName, Data(result.utf8), mode: 0o600) }
    }

    // MARK: The session's log

    /// The profile directory and the log name of an OpenVPN session (`dnsOwnerName`, one per line), as the start
    /// checked them: the helper appends to that log what it did about the session's DNS once the session's own
    /// descriptor is gone (`appendToLog`, which checks both again).
    public struct DNSOwner: Equatable, Sendable {
        public var profileDir: String
        public var logName: String

        public init(profileDir: String, logName: String) {
            self.profileDir = profileDir
            self.logName = logName
        }
    }

    public static func writeDNSOwner(runDir: String, _ owner: DNSOwner) throws {
        let text = owner.profileDir + "\n" + owner.logName + "\n"
        try checkLines(text, count: 2, file: dnsOwnerName)
        try writeNewFile(runDir + "/" + dnsOwnerName, Data(text.utf8), mode: 0o600)
    }

    /// The owner file's contents; nil when there is none or it is not sound.
    public static func dnsOwner(runDir: String) -> DNSOwner? {
        guard let text = try? readSessionFile(runDir: runDir, name: dnsOwnerName) else { return nil }
        let lines = text.components(separatedBy: "\n")
        guard lines.count == 3, lines[2] == "", lines[0].hasPrefix("/"), !containsNUL(text), ProfileDirectory.isPlainName(lines[1])
        else { return nil }
        return DNSOwner(profileDir: lines[0], logName: lines[1])
    }

    /// Appends `text` to the log `owner` names, as user `uid`'s file in the profile directory of `profileID`: the
    /// directory checked as a start checks it (`openProfileDir`), the log a `.log` name, opened relative to it
    /// without following a link, a regular, single-link file of that user. False when any of that fails.
    @discardableResult
    public func appendToLog(_ text: String, owner: DNSOwner, profileID: String, uid: uid_t) -> Bool {
        guard owner.logName.hasSuffix(".log"), ProfileDirectory.isPlainName(owner.logName),
            let dir = try? openProfileDir(owner.profileDir, profileID: profileID, uid: uid)
        else { return false }
        let fd = openat(dir.fd, owner.logName, O_WRONLY | O_APPEND | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == uid, st.st_nlink == 1 else { return false }
        let bytes = Array(text.utf8)
        return bytes.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) } == bytes.count
    }

    /// A file of the session directory: nil when there is none. It must be a regular, single-link file we own,
    /// writable by nobody else, at most `maxDNSRecordBytes` of UTF-8; anything else throws.
    static func readSessionFile(runDir: String, name: String) throws -> String? {
        let path = runDir + "/" + name
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            if errno == ENOENT { return nil }
            if errno == ELOOP { throw Failure.symlinkNotAllowed(path) }
            throw Failure.system("open \(path)", errno)
        }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0 else { throw Failure.system("stat \(path)", errno) }
        guard (st.st_mode & S_IFMT) == S_IFREG else { throw Failure.notARegularFile(path) }
        guard st.st_uid == geteuid() else { throw Failure.wrongOwner(path: path, expected: geteuid(), actual: st.st_uid) }
        guard st.st_nlink == 1 else { throw Failure.multipleLinks(path) }
        guard st.st_mode & (S_IWGRP | S_IWOTH) == 0 else { throw Failure.insecurePermissions(path) }
        guard st.st_size <= maxDNSRecordBytes else { throw Failure.fileTooLarge(path) }
        var bytes = [UInt8](repeating: 0, count: maxDNSRecordBytes + 1)
        var count = 0
        while count < bytes.count {
            let n = bytes.withUnsafeMutableBytes { read(fd, $0.baseAddress! + count, $0.count - count) }
            if n < 0 {
                if errno == EINTR { continue }
                throw Failure.system("read \(path)", errno)
            }
            if n == 0 { break }
            count += n
        }
        guard count <= maxDNSRecordBytes else { throw Failure.fileTooLarge(path) }
        guard let text = String(bytes: bytes[..<count], encoding: .utf8) else { throw Failure.unsafeFile(name) }
        return text
    }
}
