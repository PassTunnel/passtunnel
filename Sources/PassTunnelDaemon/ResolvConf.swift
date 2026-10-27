import Foundation

/// The file backend's text: /etc/resolv.conf with a marked block at the top that names the tunnel's
/// servers and search domains, and the file's own `nameserver` lines (and `search` and `domain` lines,
/// when the tunnel brings domains) disabled by a mark of the same interface, so that nothing leaks past
/// the tunnel. A resolv.conf cannot route names, so every name is resolved through the tunnel here.
/// `DNSApplier` makes it from the baseline (the file without PassTunnel) for the newest session; taking
/// every block and mark out again gives back the baseline, whatever else changed in the file
/// meanwhile. Works on bytes: the file is not necessarily UTF-8, and is restored exactly.
enum ResolvConf {
    static func begin(_ interface: String) -> [UInt8] {
        Array("# PassTunnel \(interface) begin: DNS of the VPN, removed when it disconnects".utf8)
    }

    static func end(_ interface: String) -> [UInt8] { Array("# PassTunnel \(interface) end".utf8) }

    /// Put before each line the block replaces.
    static func mark(_ interface: String) -> [UInt8] { Array("#PassTunnel \(interface)# ".utf8) }

    /// `previous` with the block of `settings` at the top and its resolver lines disabled.
    static func apply(_ settings: DNSSettings, interface: String, to previous: [UInt8]) -> [UInt8] {
        var block = [begin(interface)]
        for server in settings.servers.prefix(DNSApplier.maxNameservers) { block.append(Array("nameserver \(server)".utf8)) }
        let replacesSearch = !settings.searchDomains.isEmpty
        if replacesSearch { block.append(Array(("search " + settings.searchDomains.joined(separator: " ")).utf8)) }
        block.append(end(interface))
        let mark = mark(interface)
        let rest = lines(previous).map { line in
            isKeyword(line, "nameserver") || (replacesSearch && (isKeyword(line, "search") || isKeyword(line, "domain")))
                ? mark + line : line
        }
        return joined(block + rest)
    }

    /// `text` without any PassTunnel block (of whatever interface: one a crash left behind too) and with
    /// every line a mark disabled enabled again; nil when none of it is there.
    static func stripAll(_ text: [UInt8]) -> [UInt8]? {
        let all = lines(text)
        var kept: [[UInt8]] = []
        var changed = false
        var i = 0
        while i < all.count {
            if let interface = blockInterface(all[i]), let close = all[(i + 1)...].firstIndex(of: end(interface)) {
                i = close + 1
                changed = true
                continue
            }
            if let line = unmarked(all[i]) {
                kept.append(line)
                changed = true
            } else {
                kept.append(all[i])
            }
            i += 1
        }
        return changed ? joined(kept) : nil
    }

    /// The interface whose block `line` begins, if it begins one.
    static func blockInterface(_ line: [UInt8]) -> String? {
        let prefix = Array("# PassTunnel ".utf8), suffix = Array(" begin: DNS of the VPN, removed when it disconnects".utf8)
        guard line.count > prefix.count + suffix.count, line.starts(with: prefix), line.suffix(suffix.count).elementsEqual(suffix),
            let name = interfaceName(line[prefix.count..<(line.count - suffix.count)])
        else { return nil }
        return name
    }

    /// The line a mark (`#PassTunnel <interface># `) disabled; nil when it has none.
    static func unmarked(_ line: [UInt8]) -> [UInt8]? {
        let prefix = Array("#PassTunnel ".utf8)
        guard line.starts(with: prefix), let close = line[prefix.count...].firstIndex(of: 0x23),  // "#"
            let name = interfaceName(line[prefix.count..<close])
        else { return nil }
        let mark = mark(name)
        return line.starts(with: mark) ? Array(line.dropFirst(mark.count)) : nil
    }

    private static func interfaceName(_ bytes: ArraySlice<UInt8>) -> String? {
        guard bytes.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else { return nil }
        return try? DNSSettings.interface(String(decoding: bytes, as: UTF8.self))
    }

    /// glibc reads a keyword only at the very start of a line, followed by a space or a tab.
    static func isKeyword(_ line: [UInt8], _ keyword: String) -> Bool {
        let k = Array(keyword.utf8)
        return line.count > k.count && line.starts(with: k) && (line[k.count] == 0x20 || line[k.count] == 0x09)
    }

    /// The lines of `text`, the last one empty when it ends in a newline: `joined` gives `text` back.
    static func lines(_ text: [UInt8]) -> [[UInt8]] {
        text.split(separator: 0x0A, omittingEmptySubsequences: false).map(Array.init)
    }

    static func joined(_ lines: [[UInt8]]) -> [UInt8] {
        Array(lines.joined(separator: [0x0A]))
    }
}
