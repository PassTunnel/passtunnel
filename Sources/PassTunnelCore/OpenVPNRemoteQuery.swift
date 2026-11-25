import Foundation
import PassTunnelKit
import PassTunnelShared

/// OpenVPN's question before each try of a run started with `--management-query-remote` (`OpenVPNStart.queryRemote`,
/// #298): `>REMOTE:vpn.example.com,1194,udp`, the server it is about to connect to. It waits for the answer
/// (`OpenVPNRemoteAnswer`) and asks the client that connects next when none is connected: the question stays pending
/// (OpenVPN shows it to every client right after its banner) until one answers.
public struct OpenVPNRemoteQuery: Equatable, Sendable {
    public static let prefix = ">REMOTE:"

    /// The `remote` host as the config has it.
    public var host: String
    public var port: String
    public var proto: String

    public init(host: String, port: String, proto: String) {
        self.host = host
        self.port = port
        self.proto = proto
    }

    /// `>REMOTE:host,port,proto`; nil for any other line, and for one OpenVPN cut short (it writes the question into
    /// a 256-byte buffer). A host has no comma (an IPv6 address has colons).
    public init?(line: String) {
        guard line.hasPrefix(Self.prefix) else { return nil }
        let fields = line.dropFirst(Self.prefix.count).split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard fields.count == 3, !fields[0].isEmpty else { return nil }
        self.init(host: fields[0], port: fields[1], proto: fields[2])
    }

    /// The command that answers `line` when it is OpenVPN's question: `answer(query)`, or `remote ACCEPT` for a
    /// question that cannot be read (OpenVPN waits for any answer, so none is ever left unanswered); nil for any
    /// other line.
    public static func answer(to line: String, with answer: (OpenVPNRemoteQuery) -> String) -> String? {
        guard line.hasPrefix(prefix) else { return nil }
        return OpenVPNRemoteQuery(line: line).map(answer) ?? OpenVPNRemoteAnswer.accept
    }
}

/// How every management client of PassTunnel answers OpenVPN's `>REMOTE:` question (`OpenVPNRemoteQuery`): the app's
/// held connection (`PersistentManagementQuerier`) and the one-shot connections of the command line, the MCP server
/// and the app before it holds one (`ManagementSocket`). Whichever of them OpenVPN asks, the answer is the same, as it
/// comes from the profile's files and not from the process that started the run:
/// - `remote MOD <address> <port>` when the profile has a last known address for exactly the host asked about
///   (`LastKnownAddress.read`: an OpenVPN profile whose config fits, `OVPNAnalyzer.knownAddressFit`, for the
///   config and host as they are now), with the port OpenVPN asked about, a number; and only once that answer is
///   recorded in the profile's `Record` file, which the connecting process reads to know what its run was told;
/// - `remote ACCEPT` otherwise: OpenVPN connects as it would without the question.
/// Only a run the app started for a try at the last known address asks (`ConnectionManager`), so `MOD` never
/// changes a run by the name. The profile is the one whose session directory holds the socket
/// (`PT.mgmtSocketPath`: `<run root>/<uid>/<profile id>/mgmt.sock`).
public final class OpenVPNRemoteAnswer: @unchecked Sendable {
    public static let accept = "remote ACCEPT"

    /// `profiles/<id>/.remote-answer`: the last `remote MOD` given to the profile's OpenVPN (0600). The connecting
    /// process removes it before it starts a run that asks, and reads it once that run ended or connected.
    public static let recordFile = ".remote-answer"

    struct Record: Codable, Equatable {
        var address: String
        var port: Int
    }

    public let store: ProfileStore

    public init(store: ProfileStore) { self.store = store }

    /// The command that answers `query` on the management socket `socketPath`.
    public func command(for query: OpenVPNRemoteQuery, socketPath: String) -> String {
        let id = URL(fileURLWithPath: socketPath).deletingLastPathComponent().lastPathComponent
        guard Slug.isValid(id), let p = try? store.get(id), p.type == .openvpn else { return Self.accept }
        let entry = LastKnownAddress.read(p, destination: ProfileDestination.of(p, store: store), store: store)
        let command = Self.command(for: query, entry: entry)
        guard command != Self.accept, let entry, let port = Int(query.port) else { return command }
        // `MOD` only once the profile's directory says so; without the record it is not given.
        do {
            try JSONCoding.write(Record(address: entry.address, port: port), to: Self.recordURL(id, store: store), mode: 0o600)
        } catch {
            return Self.accept
        }
        return command
    }

    /// `remote MOD <address> <port>` for the entry's host, `remote ACCEPT` for anything else (another host, no entry,
    /// a port that is no number).
    static func command(for query: OpenVPNRemoteQuery, entry: LastKnownAddress.Entry?) -> String {
        guard let entry, query.host.lowercased() == entry.host, let port = Int(query.port), String(port) == query.port,
            (1...65535).contains(port), IPAddress(entry.address) != nil
        else { return accept }
        return "remote MOD \(entry.address) \(port)"
    }

    static func recordURL(_ id: String, store: ProfileStore) -> URL { store.dir(id).appendingPathComponent(recordFile) }

    /// The address a `remote MOD` gave the profile's OpenVPN since `clearRecord`; nil when none was given.
    static func recordedAddress(_ id: String, store: ProfileStore) -> String? {
        guard let data = ProfileNetwork.readOwned(recordURL(id, store: store)),
            let record = try? JSONCoding.decode(Record.self, from: data, name: recordFile)
        else { return nil }
        return record.address
    }

    static func clearRecord(_ id: String, store: ProfileStore) {
        try? FileManager.default.removeItem(at: recordURL(id, store: store))
    }
}
