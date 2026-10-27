import Foundation
import XCTest

@testable import PassTunnelCore

#if canImport(Glibc)
import Glibc
#endif

/// Points the secret items of the code under test at `service`. The Linux tests keep the items in
/// memory (`PASSTUNNEL_SECRET_STORE=memory`), never in a real keyring or credential store; the Mac's use
/// the Keychain under that service.
func useTestSecrets(service: String) {
    setenv("PASSTUNNEL_KEYCHAIN_SERVICE", service, 1)
    #if !canImport(Security)
    setenv("PASSTUNNEL_SECRET_STORE", MemorySecretStore.name, 1)
    #endif
}

/// The socket calls of the tests' fake servers that are spelled differently on Darwin and Glibc (and
/// clash with the names of some tests' own helpers).
enum TestSocket {
    static func bind(_ fd: Int32, _ address: UnsafePointer<sockaddr>, _ length: socklen_t) -> Int32 {
        #if canImport(Darwin)
        Darwin.bind(fd, address, length)
        #else
        Glibc.bind(fd, address, length)
        #endif
    }

    static func listen(_ fd: Int32, _ backlog: Int32) -> Int32 {
        #if canImport(Darwin)
        Darwin.listen(fd, backlog)
        #else
        Glibc.listen(fd, backlog)
        #endif
    }

    /// A unix-domain socket listening at `path` (-1 when it cannot be made).
    static func listenUnix(_ path: String, backlog: Int32) -> Int32 {
        guard var address = POSIXSocket.unixAddress(path) else { return -1 }
        let fd = socket(AF_UNIX, POSIXSocket.stream, 0)
        guard fd >= 0 else { return -1 }
        _ = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        _ = listen(fd, backlog)
        return fd
    }
}
