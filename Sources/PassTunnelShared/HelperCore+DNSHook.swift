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
    /// `name=value` per line. The wrapper removes it after a dns-down. One left behind when the tool has
    /// exited is a dns-down OpenVPN never ran (`pendingDNSDown`).
    public static let dnsRecordName = "dns-up.env"

    /// Larger records are refused (OpenVPN passes at most a few dozen short values).
    static let maxDNSRecordBytes = 64 << 10

    /// The wrapper (`dnsHookName`, 0700), OpenVPN's `--dns-updown`. It fixes `PATH`, keeps the record and
    /// hands the script's exit status back to OpenVPN. `${!dns_@}` lists the names of the set `dns_*`
    /// variables.
    public static let dnsHookText = """
        #!/bin/bash
        # Written by the PassTunnel helper. Runs OpenVPN's dns-updown with a fixed PATH and records the
        # variables of a dns-up, so that the helper can run the dns-down OpenVPN skipped.
        PATH=\(dnsScriptSearchPath)
        export PATH
        umask 077
        dir=${0%/*}
        record="$dir/\(dnsRecordName)"
        if [ "$script_type" = dns-up ]; then
            for name in dev ${!dns_@}; do
                printf '%s=%s\\n' "$name" "${!name}"
            done > "$record.new" && /bin/mv -f "$record.new" "$record"
            exec /bin/bash "$dir/dns-updown"
        fi
        /bin/bash "$dir/dns-updown"
        status=$?
        /bin/rm -f "$record"
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
        return ["PATH=" + dnsScriptSearchPath, "script_type=dns-down"] + lines
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

    /// The dns-down still owed for the session in `runDir`: nil when there is no record, else
    /// `dnsDownEnvironment` of it. The record must be a regular, single-link file we own; anything else,
    /// or a record `dnsDownEnvironment` refuses, throws.
    public static func pendingDNSDown(runDir: String) throws -> [String]? {
        let path = runDir + "/" + dnsRecordName
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
        guard let text = String(bytes: bytes[..<count], encoding: .utf8),
            let environment = dnsDownEnvironment(record: text)
        else { throw Failure.unsafeFile(dnsRecordName) }
        return environment
    }
}
