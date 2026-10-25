import Foundation
#if canImport(Glibc)
import Glibc
#endif
import PassTunnelKit

/// A minimal SNTP client (RFC 4330, NTP version 4 packets): one request, one valid reply. The request
/// carries nothing but a random number where the client's time would go, so the server learns
/// nothing about this computer's clock; the reply must echo it (its origin timestamp), or it is
/// ignored, like any reply that is not a synchronized server's answer.
enum SNTP {
    static let port: UInt16 = 123
    static let packetSize = 48
    /// Seconds from 1900-01-01, where NTP time starts, to 1970-01-01.
    static let ntpToUnix: TimeInterval = 2_208_988_800

    /// LI 0, version 4, mode 3 (client); `nonce` as the transmit timestamp.
    static func request(nonce: UInt64) -> [UInt8] {
        var packet = [UInt8](repeating: 0, count: packetSize)
        packet[0] = 0x23
        for i in 0..<8 { packet[40 + i] = UInt8(truncatingIfNeeded: nonce >> (56 - 8 * i)) }
        return packet
    }

    /// The server's receive and transmit times (seconds since 1970) from a reply.
    struct Reply: Equatable {
        var received: TimeInterval
        var transmitted: TimeInterval
    }

    /// A reply to the request with `nonce`, or nil: shorter than a packet, not version 3 or 4, not from
    /// a server (mode 4), unsynchronized (leap indicator 3, stratum 0, a "kiss-o'-death", or 16 and up),
    /// another origin timestamp, a missing time, or one that left before it arrived.
    static func parse(_ bytes: [UInt8], nonce: UInt64) -> Reply? {
        guard bytes.count >= packetSize else { return nil }
        let leap = bytes[0] >> 6, version = (bytes[0] >> 3) & 0x7, mode = bytes[0] & 0x7
        guard leap != 3, version == 3 || version == 4, mode == 4, (1...15).contains(bytes[1]) else { return nil }
        guard timestamp(bytes, at: 24) == nonce else { return nil }
        let received = timestamp(bytes, at: 32), transmitted = timestamp(bytes, at: 40)
        guard received != 0, transmitted != 0 else { return nil }
        let reply = Reply(received: unixSeconds(received), transmitted: unixSeconds(transmitted))
        return reply.transmitted >= reply.received ? reply : nil
    }

    private static func timestamp(_ bytes: [UInt8], at offset: Int) -> UInt64 {
        (0..<8).reduce(UInt64(0)) { $0 << 8 | UInt64(bytes[offset + $1]) }
    }

    /// An NTP timestamp as seconds since 1970. The 32-bit seconds wrap on 2036-02-07; as RFC 4330 §3
    /// says, a value with the top bit clear is taken to be after that.
    static func unixSeconds(_ ts: UInt64) -> TimeInterval {
        let seconds = ts >> 32
        let fraction = TimeInterval(ts & 0xFFFF_FFFF) / 4_294_967_296
        let era: TimeInterval = seconds & 0x8000_0000 != 0 ? 0 : 4_294_967_296
        return TimeInterval(seconds) + era - ntpToUnix + fraction
    }

    /// The server's time minus this computer's: ((T2 − T1) + (T3 − T4)) / 2, with T1 and T4 when the
    /// request left and the reply arrived here.
    static func offset(sent: Date, reply: Reply, received: Date) -> TimeInterval {
        ((reply.received - sent.timeIntervalSince1970) + (reply.transmitted - received.timeIntervalSince1970)) / 2
    }

    /// Asks `host` (`port`: tests only), off the calling thread; gives up after `timeout`, also when
    /// looking up the address takes longer.
    static func query(host: String, port: UInt16 = port, timeout: TimeInterval) async throws -> ClockOffset {
        let once = Once<ClockOffset>()
        return try await withCheckedThrowingContinuation { continuation in
            once.continuation = continuation
            DispatchQueue.global(qos: .userInitiated).async {
                once.resume(Result { try querySync(host: host, port: port, timeout: timeout) })
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout + 0.5) {
                once.resume(.failure(ServerClock.Failure.timedOut))
            }
        }
    }

    /// Resumes its continuation once; later results are dropped.
    private final class Once<T>: @unchecked Sendable {
        private let lock = NSLock()
        var continuation: CheckedContinuation<T, Error>?

        func resume(_ result: Result<T, Error>) {
            lock.lock()
            let c = continuation
            continuation = nil
            lock.unlock()
            c?.resume(with: result)
        }
    }

    /// Blocking: sends one request to the first of `host`'s addresses that takes it, then waits for
    /// a valid reply until `timeout`, ignoring any other datagram.
    static func querySync(host: String, port: UInt16 = port, timeout: TimeInterval) throws -> ClockOffset {
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = POSIXSocket.datagram
        hints.ai_protocol = Int32(IPPROTO_UDP)
        var list: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(host, String(port), &hints, &list)
        guard rc == 0, let first = list else {
            throw ServerClock.Failure.connectionFailed(String(cString: gai_strerror(rc)))
        }
        defer { freeaddrinfo(list) }

        var nonce: UInt64 = 0
        while nonce == 0 { nonce = UInt64.random(in: 1...UInt64.max) }
        let packet = request(nonce: nonce)
        var fd: Int32 = -1
        var sent = Date()
        var lastError: Int32 = 0
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let entry = cursor, fd < 0 {
            cursor = entry.pointee.ai_next
            let s = socket(entry.pointee.ai_family, entry.pointee.ai_socktype, entry.pointee.ai_protocol)
            guard s >= 0 else { lastError = errno; continue }
            // Connected, so the system passes on only datagrams from this address.
            if POSIXSocket.connect(s, entry.pointee.ai_addr, entry.pointee.ai_addrlen) == 0 {
                sent = Date()
                if packet.withUnsafeBytes({ send(s, $0.baseAddress, $0.count, 0) }) == packet.count {
                    fd = s
                    break
                }
            }
            lastError = errno
            POSIXSocket.close(s)
        }
        guard fd >= 0 else { throw ServerClock.Failure.connectionFailed(String(cString: strerror(lastError))) }
        defer { POSIXSocket.close(fd) }

        var buffer = [UInt8](repeating: 0, count: 512)
        while true {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw ServerClock.Failure.timedOut }
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&pfd, 1, Int32(max(1, (remaining * 1000).rounded(.up)))) > 0 else { continue }
            let n = buffer.withUnsafeMutableBytes { recv(fd, $0.baseAddress, $0.count, 0) }
            let received = Date()
            if n < 0 {
                // An ICMP "port unreachable" for the request: nothing listens there.
                if errno == ECONNREFUSED { throw ServerClock.Failure.connectionFailed(String(cString: strerror(errno))) }
                continue
            }
            guard let reply = parse(Array(buffer[0..<n]), nonce: nonce) else { continue }
            return ClockOffset(offset: offset(sent: sent, reply: reply, received: received), source: .timeServer,
                               server: host, checkedAt: received)
        }
    }
}
