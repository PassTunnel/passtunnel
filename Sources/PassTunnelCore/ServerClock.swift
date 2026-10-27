import Foundation
import PassTunnelKit
import PassTunnelVPNConfig

#if canImport(Network)
import Network
import Security
#endif

/// Measures how far this computer's clock is off (`ClockOffset`), to tell a wrong clock from a wrong
/// password when a server rejects a sign-in. Two sources, and no others (docs/APP.md, the privacy page):
/// - `gateway`: the FortiGate gateway the VPN signs in to. `ConnectionManager` asks it automatically, only
///   after it rejected a sign-in: one `HEAD /` over TLS, trusted exactly as openfortivpn trusts it, and
///   its `Date` header. Nothing else is sent: no credentials, no cookies.
/// - `timeServer`: SNTP to Apple's time server (`time.apple.com`, which macOS itself uses), on Linux to
///   the NTP server the system is configured with; only when the user asks (the app's Check button,
///   `passtunnel diagnose --check-clock`, MCP `diagnose` with `check_clock`).
/// OpenVPN servers tell no reliable time, so their profiles get only the second.
public protocol ClockChecking: Sendable {
    /// One request to the gateway; `trustedCert`: the profile's certificate digest (64 hex), if any.
    func gateway(host: String, port: Int, trustedCert: String?, timeout: TimeInterval) async throws -> ClockOffset
    /// One SNTP query to the time server.
    func timeServer(timeout: TimeInterval) async throws -> ClockOffset
}

public struct ServerClock: ClockChecking {
    public enum Failure: Error, Equatable, LocalizedError {
        case invalidHost
        case invalidPort
        /// Not on this platform (the gateway check needs the Network framework).
        case unavailable
        /// Linux: no NTP server is configured.
        case noTimeServer
        case timedOut
        /// The gateway's certificate is neither trusted by the system nor the profile's trusted certificate.
        case untrusted
        case connectionFailed(String)
        /// The gateway answered without a usable `Date` header.
        case noDate
        /// The answer was not HTTP (gateway).
        case invalidReply

        public var errorDescription: String? {
            switch self {
            case .invalidHost: return String(localized: "The gateway address is not valid.")
            case .invalidPort: return String(localized: "The port must be between 1 and 65535.")
            case .unavailable: return String(localized: "Checking the clock with the gateway is not available on this system.")
            case .noTimeServer: return String(localized: "No time server is set up on this system.")
            case .timedOut: return String(localized: "The server did not answer in time.")
            case .untrusted: return String(localized: "The gateway’s certificate is not trusted, so its time was not read.")
            case .connectionFailed(let reason): return String(localized: "Could not reach the server: \(reason)")
            case .noDate: return String(localized: "The gateway’s answer did not include its time.")
            case .invalidReply: return String(localized: "The server’s answer was not understood.")
            }
        }
    }

    /// The whole gateway check, from connecting to the answer.
    public static let gatewayTimeout: TimeInterval = 5
    /// The time server's answer (and looking up its address).
    public static let timeServerTimeout: TimeInterval = 5
    /// The most of the gateway's answer that is read: its head only.
    static let maxResponseHead = 16 * 1024

    public init() {}

    // MARK: gateway

    /// The request, and all of it: no cookies, no credentials, `Connection: close`.
    static func headRequest(host: String, port: Int) -> String {
        "HEAD / HTTP/1.1\r\nHost: \(hostHeader(host, port: port))\r\nUser-Agent: PassTunnel\r\nAccept: */*\r\n"
            + "Connection: close\r\n\r\n"
    }

    /// "vpn.example.com", "vpn.example.com:10443", "[2001:db8::1]:10443" (an IPv6 zone is left out).
    static func hostHeader(_ host: String, port: Int) -> String {
        var name = host
        if name.contains(":") { name = "[" + String(name.split(separator: "%", maxSplits: 1)[0]) + "]" }
        return port == 443 ? name : "\(name):\(port)"
    }

    /// The offset from the gateway's answer (`head`: its bytes so far), or why there is none.
    static func gatewayResult(head: Data, sent: Date, received: Date, host: String) -> Result<ClockOffset, Failure> {
        let text = String(decoding: head, as: UTF8.self)
        guard text.hasPrefix("HTTP/1.") else { return .failure(.invalidReply) }
        guard let date = ClockOffset.dateHeader(inResponse: text) else { return .failure(.noDate) }
        let offset = ClockOffset.offset(serverTime: date, resolution: 1, sent: sent, received: received)
        return .success(ClockOffset(offset: offset, source: .gateway, server: host, checkedAt: received))
    }

    #if canImport(Network)
    /// The TLS handshake accepts the gateway's certificate when its SHA-256 is `trustedCert` or the
    /// system trusts it for `host` (without fetching anything for that, as openfortivpn's OpenSSL does
    /// not), the same rule openfortivpn applies; otherwise nothing is sent. Then the request, and the
    /// response head is read until its blank line, the end of the connection or `timeout`.
    public func gateway(host: String, port: Int, trustedCert: String?, timeout: TimeInterval) async throws -> ClockOffset {
        let h = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard FortiConfig.isValidHost(h) else { throw Failure.invalidHost }
        guard (1...65535).contains(port), let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
            throw Failure.invalidPort
        }
        let pin = trustedCert.flatMap(TLSFingerprint.normalize)
        let queue = DispatchQueue(label: "passtunnel.gateway-clock")
        let exchange = GatewayExchange()
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(
            tls.securityProtocolOptions,
            { _, trust, complete in
                let ref = sec_trust_copy_ref(trust).takeRetainedValue()
                if let pin, let leaf = (SecTrustCopyCertificateChain(ref) as? [SecCertificate])?.first,
                    TLSFingerprint.sha256Hex(SecCertificateCopyData(leaf) as Data) == pin
                {
                    complete(true)
                    return
                }
                SecTrustSetNetworkFetchAllowed(ref, false)
                SecTrustEvaluateAsyncWithError(ref, queue) { _, trusted, _ in
                    if !trusted { exchange.untrusted = true }
                    complete(trusted)
                }
            }, queue)
        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = max(1, Int(timeout.rounded(.up)))
        let connection = NWConnection(host: NWEndpoint.Host(h), port: nwPort, using: NWParameters(tls: tls, tcp: tcp))
        let request = Data(Self.headRequest(host: h, port: port).utf8)

        func receive(sent: Date) {
            connection.receive(minimumIncompleteLength: 1, maximumLength: Self.maxResponseHead) { data, _, isComplete, error in
                if let data { exchange.head.append(data) }
                let ended = exchange.head.range(of: Data("\r\n\r\n".utf8))
                guard ended != nil || isComplete || error != nil || exchange.head.count >= Self.maxResponseHead else {
                    return receive(sent: sent)
                }
                let head = ended.map { exchange.head[..<$0.lowerBound] } ?? exchange.head
                if head.isEmpty, let error {
                    return exchange.finish(connection, .failure(Failure.connectionFailed(error.localizedDescription)))
                }
                exchange.finish(
                    connection,
                    Self.gatewayResult(head: head, sent: sent, received: Date(), host: h)
                        .mapError { $0 as Error })
            }
        }

        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<ClockOffset, Error>) in
                exchange.continuation = continuation
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        let sent = Date()
                        connection.send(
                            content: request,
                            completion: .contentProcessed { error in
                                if let error {
                                    exchange.finish(connection, .failure(Failure.connectionFailed(error.localizedDescription)))
                                }
                            })
                        receive(sent: sent)
                    case .failed(let error), .waiting(let error):
                        exchange.finish(
                            connection,
                            .failure(
                                exchange.untrusted
                                    ? Failure.untrusted
                                    : Failure.connectionFailed(error.localizedDescription)))
                    case .cancelled:
                        exchange.finish(connection, .failure(Failure.timedOut))
                    default:
                        break
                    }
                }
                connection.start(queue: queue)
                queue.asyncAfter(deadline: .now() + timeout) {
                    exchange.finish(connection, .failure(Failure.timedOut))
                }
            }
        } onCancel: {
            queue.async { exchange.finish(connection, .failure(Failure.timedOut)) }
        }
    }

    /// Single-use state of one gateway check; all access happens on its serial queue.
    private final class GatewayExchange: @unchecked Sendable {
        var continuation: CheckedContinuation<ClockOffset, Error>?
        var untrusted = false
        var head = Data()

        func finish(_ connection: NWConnection, _ result: Result<ClockOffset, Error>) {
            guard let c = continuation else { return }
            continuation = nil
            connection.stateUpdateHandler = nil
            connection.cancel()
            c.resume(with: result)
        }
    }
    #else
    /// Linux: Foundation there cannot pin a certificate by its digest, as the VPN does, so the gateway
    /// is not asked (docs/LINUX.md).
    public func gateway(host: String, port: Int, trustedCert: String?, timeout: TimeInterval) async throws -> ClockOffset {
        throw Failure.unavailable
    }
    #endif

    // MARK: time server

    public func timeServer(timeout: TimeInterval) async throws -> ClockOffset {
        guard let host = Self.timeServerHost() else { throw Failure.noTimeServer }
        return try await SNTP.query(host: host, timeout: timeout)
    }

    /// Apple platforms: Apple's time server, the one macOS uses. Linux: the first server the system's
    /// time service is configured with (systemd-timesyncd, chrony or ntpd); nil when none is.
    public static func timeServerHost(
        read: (String) -> String? = { try? String(contentsOfFile: $0, encoding: .utf8) },
        list: (String) -> [String] = { (try? FileManager.default.contentsOfDirectory(atPath: $0)) ?? [] }
    )
        -> String?
    {
        #if os(Linux)
        return configuredTimeServer(read: read, list: list)
        #else
        return "time.apple.com"
        #endif
    }

    static let timesyncdConfig = "/etc/systemd/timesyncd.conf"
    static let timesyncdDropIns = "/etc/systemd/timesyncd.conf.d"
    static let ntpConfigs = ["/etc/chrony/chrony.conf", "/etc/chrony.conf", "/etc/ntpsec/ntp.conf", "/etc/ntp.conf"]

    /// systemd-timesyncd's `NTP=` (its drop-ins after the main file, as systemd reads them), else the
    /// first `server` or `pool` of chrony's or ntpd's configuration. Names only from the files; the
    /// servers a service has built in or learned from DHCP are not known here.
    static func configuredTimeServer(read: (String) -> String?, list: (String) -> [String]) -> String? {
        let dropIns = list(timesyncdDropIns).filter { $0.hasSuffix(".conf") }.sorted().map { timesyncdDropIns + "/" + $0 }
        let timesyncd = ([timesyncdConfig] + dropIns).compactMap(read)
        if let server = timesyncdServer(timesyncd) { return server }
        for path in ntpConfigs {
            if let text = read(path), let server = ntpConfServer(text) { return server }
        }
        return nil
    }

    /// The first server of the last `NTP=` in `[Time]` (an empty one clears the earlier ones), else of
    /// `FallbackNTP=`, across the files in the order given.
    static func timesyncdServer(_ files: [String]) -> String? {
        var ntp: [String] = []
        var fallback: [String] = []
        for text in files {
            var inTime = false
            for raw in text.split(whereSeparator: \.isNewline) {
                let line = raw.trimmingCharacters(in: .whitespaces)
                if line.hasPrefix("#") || line.hasPrefix(";") || line.isEmpty { continue }
                if line.hasPrefix("[") { inTime = line == "[Time]"; continue }
                guard inTime, let eq = line.firstIndex(of: "=") else { continue }
                let key = line[..<eq].trimmingCharacters(in: .whitespaces)
                let servers = line[line.index(after: eq)...].split(whereSeparator: \.isWhitespace).map(String.init)
                if key == "NTP" { ntp = servers } else if key == "FallbackNTP" { fallback = servers }
            }
        }
        return (ntp + fallback).first(where: FortiConfig.isValidHost)
    }

    /// The host of the first `server` or `pool` line of a chrony or ntpd configuration; ntpd's
    /// reference clocks (127.127.x.x) are not servers.
    static func ntpConfServer(_ text: String) -> String? {
        for raw in text.split(whereSeparator: \.isNewline) {
            let words = raw.split(whereSeparator: \.isWhitespace)
            guard words.count >= 2, words[0] == "server" || words[0] == "pool" else { continue }
            let host = String(words[1])
            if host.hasPrefix("127.127.") || !FortiConfig.isValidHost(host) { continue }
            return host
        }
        return nil
    }
}

extension ClockOffset {
    /// The measurement in a sentence for the CLI ("Your clock is 48 s behind the gateway’s, …").
    public var sentence: String {
        let seconds = Int(offsetSeconds.magnitude)
        let server = self.server ?? ""
        switch (source, isWrong, isBehind) {
        case (.gateway, true, true):
            return String(
                localized:
                    "Your clock is \(seconds) s behind the gateway’s, so one-time codes made from it are likely refused. Fix the clock, then try again."
            )
        case (.gateway, true, false):
            return String(
                localized:
                    "Your clock is \(seconds) s ahead of the gateway’s, so one-time codes made from it are likely refused. Fix the clock, then try again."
            )
        case (.gateway, false, _):
            return String(localized: "Your clock matches the gateway’s, \(seconds) s apart.")
        case (.timeServer, true, true):
            return String(
                localized:
                    "Your clock is \(seconds) s behind the time server \(server), so one-time codes made from it are likely refused. Fix the clock, then try again."
            )
        case (.timeServer, true, false):
            return String(
                localized:
                    "Your clock is \(seconds) s ahead of the time server \(server), so one-time codes made from it are likely refused. Fix the clock, then try again."
            )
        case (.timeServer, false, _):
            return String(localized: "Your clock matches the time server \(server), \(seconds) s apart.")
        }
    }
}
