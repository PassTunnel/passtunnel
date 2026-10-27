import Foundation

#if canImport(Glibc)
import Glibc
#endif

/// The socket calls whose spelling differs between Darwin and Linux: `SOCK_STREAM` and `SOCK_DGRAM`
/// (enums on Glibc), SIGPIPE (a socket option on Darwin, a flag on every send on Linux) and `sun_len` (Darwin
/// only). Also used by the tests' fake servers.
enum POSIXSocket {
    /// `SOCK_STREAM` as `socket()` and `addrinfo` take it.
    static var stream: Int32 {
        #if canImport(Glibc)
        Int32(SOCK_STREAM.rawValue)
        #else
        SOCK_STREAM
        #endif
    }

    /// `SOCK_DGRAM`, the same way.
    static var datagram: Int32 {
        #if canImport(Glibc)
        Int32(SOCK_DGRAM.rawValue)
        #else
        SOCK_DGRAM
        #endif
    }

    /// Writes to `fd` never raise SIGPIPE. Darwin: `SO_NOSIGPIPE`. Linux has no such option; `write`
    /// below passes `MSG_NOSIGNAL` instead.
    static func noSigPipe(_ fd: Int32) {
        #if canImport(Darwin)
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        #endif
    }

    /// `write(2)` on a socket, without SIGPIPE when the peer has gone (with `noSigPipe` on Darwin).
    static func write(_ fd: Int32, _ bytes: UnsafeRawPointer?, _ count: Int) -> Int {
        #if canImport(Darwin)
        Darwin.write(fd, bytes, count)
        #else
        Glibc.send(fd, bytes, count, Int32(MSG_NOSIGNAL))
        #endif
    }

    static func connect(_ fd: Int32, _ address: UnsafePointer<sockaddr>, _ length: socklen_t) -> Int32 {
        #if canImport(Darwin)
        Darwin.connect(fd, address, length)
        #else
        Glibc.connect(fd, address, length)
        #endif
    }

    static func close(_ fd: Int32) {
        #if canImport(Darwin)
        _ = Darwin.close(fd)
        #else
        _ = Glibc.close(fd)
        #endif
    }

    /// Ends both directions; a reader blocked on `fd` sees end of file.
    static func shutdown(_ fd: Int32) {
        #if canImport(Darwin)
        _ = Darwin.shutdown(fd, SHUT_RDWR)
        #else
        _ = Glibc.shutdown(fd, Int32(SHUT_RDWR))
        #endif
    }

    /// The unix-domain address of `path`; nil when it does not fit `sun_path` with its terminating NUL
    /// (104 bytes on macOS, 108 on Linux).
    static func unixAddress(_ path: String) -> sockaddr_un? {
        var address = sockaddr_un()
        guard path.utf8.count < MemoryLayout.size(ofValue: address.sun_path) else { return nil }
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.copyBytes(from: path.utf8)
            raw[path.utf8.count] = 0
        }
        #if canImport(Darwin)
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        #endif
        return address
    }
}
