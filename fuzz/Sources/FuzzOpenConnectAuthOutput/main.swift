import Foundation
import FuzzSupport
import PassTunnelVPNConfig

// Fuzzes the parser of what `openconnect --authenticate` prints (`OpenConnectAuthResult`) and the check
// of where the sign-in ended, then the root file built from it. The output comes from a run that talked
// to the server, so every value is the server's to choose. Properties: whatever the parser accepts is
// exactly openconnect's five lines (printing the result again gives the same bytes); the description
// never depends on the cookie; the helper's check agrees with the client's; and when the destination
// check passes for the profile the output names, the root file renders, and openconnect would read back
// that cookie, that key and that address. The harness never crashes or hangs on any bytes. The same output
// is also parsed as Palo Alto GlobalProtect's (`checkGlobalProtect`).
@_cdecl("LLVMFuzzerTestOneInput")
func LLVMFuzzerTestOneInput(_ data: UnsafePointer<UInt8>?, _ size: Int) -> CInt {
    let bytes = [UInt8](fuzzData(data, size))
    checkGlobalProtect(bytes)
    guard let result = try? OpenConnectAuthResult.parse(bytes) else { return 0 }

    let printed = Array(result.output.utf8)
    precondition(bytes == printed || (result.resolve.isEmpty && bytes == printed + [0x0A]), "parsed output does not print back the same")
    precondition(result.cookie.utf8.count <= OpenConnectConfig.maxCookieBytes && !result.cookie.isEmpty)
    // The tunnel run's option: the value under its name, or the STRAP form unchanged; always one root accepts.
    precondition(OpenConnectCookie.isValidTunnelOption(result.tunnelCookie), "the tunnel cookie is not one root accepts")
    precondition(
        result.tunnelCookie == result.cookie ? result.cookie.hasPrefix("openconnect_strapkey=") : result.tunnelCookie == "webvpn=" + result.cookie,
        "the tunnel cookie is not the printed one under its name")
    precondition(OpenConnectPin.isValid(result.fingerprint))
    let other = try! OpenConnectAuthResult(
        cookie: "xxxxxxxx", host: result.host, connectURL: result.connectURL, fingerprint: result.fingerprint, resolve: result.resolve)
    precondition(result.description == other.description, "the description depends on the cookie")

    // The profile the output claims: `https://<host>[:<port>]/`.
    let url = result.connectURL
    guard url.hasPrefix("https://"), url.hasSuffix("/") else { return 0 }
    var authority = String(url.dropFirst("https://".count).dropLast())
    var port = 443
    if let colon = authority.lastIndex(of: ":"), !authority.hasSuffix("]"), let p = Int(authority[authority.index(after: colon)...]) {
        port = p
        authority = String(authority[..<colon])
    }
    let host = authority.hasPrefix("[") && authority.hasSuffix("]") ? String(authority.dropFirst().dropLast()) : authority

    for pin in ["", result.fingerprint] {
        guard let config = try? result.tunnelConfig(host: host, port: port, profileServerCert: pin, scriptPath: "/x/vpn-hook", tlsOnly: false)
        else { continue }
        precondition(url.lowercased().hasPrefix("https://"), "accepted a connect URL that is not https")
        // The helper's check, on the fields the client sends it, accepts the same and builds the same file.
        let helper = try? OpenConnectAuthResult.tunnelConfig(
            host: host, port: port, connectURL: url, resolve: config.resolveAddress == nil ? nil : result.resolve, cookie: result.tunnelCookie,
            serverCert: result.fingerprint, profileServerCert: pin, scriptPath: "/x/vpn-hook", tlsOnly: false)
        precondition(helper == config, "the helper's check disagrees with the client's")
        guard let text = try? config.render() else { preconditionFailure("a checked sign-in did not render") }
        let table = OpenConnectOptions.all.map { (name: $0.name, takesValue: $0.takesValue) }
        guard let read = readLikeOpenConnect(Array(text.utf8), table: table) else { preconditionFailure("openconnect would refuse the file") }
        let values = Dictionary(read.map { ($0.option, $0.value) }, uniquingKeysWith: { a, _ in a })
        precondition(values["cookie"] == Array(result.tunnelCookie.utf8), "cookie not recovered")
        precondition(values["servercert"] == Array(result.fingerprint.utf8), "the root run does not trust the key the sign-in accepted")
        if let address = config.resolveAddress {
            precondition(values["resolve"] == Array("\(host.lowercased()):\(address)".utf8), "resolve not recovered")
            let bracketed = address.contains(":") ? "[\(address)]" : address
            precondition(result.host == bracketed, "HOST is not the resolved address")
        } else {
            precondition(values["resolve"] == nil, "resolve for an IP-address host")
        }
    }
    return 0
}

/// GlobalProtect: the cookie is taken unchanged, and the sign-in may end on another server than the profile's
/// (the portal's gateway). Properties: the result prints back the same; the tunnel cookie is the printed one and
/// one root accepts; the description never depends on the cookie; for the server the output names (as the
/// profile's, with and without skipping the portal) and for a portal on another host, the destination is
/// `CONNECT_URL`'s server, the helper's check on the fields the client sends agrees, and the root file renders
/// and reads back that server, cookie, key and address.
func checkGlobalProtect(_ bytes: [UInt8]) {
    guard let result = try? OpenConnectAuthResult.parse(bytes, protocol: .gp) else { return }
    let printed = Array(result.output.utf8)
    precondition(bytes == printed || (result.resolve.isEmpty && bytes == printed + [0x0A]), "parsed output does not print back the same")
    precondition(result.protocol == .gp && result.tunnelCookie == result.cookie, "the GlobalProtect cookie is not taken unchanged")
    precondition(GlobalProtectCookie.isValidTunnelOption(result.tunnelCookie), "the tunnel cookie is not one root accepts")
    precondition(GlobalProtectCookie.secrets(result.cookie).count == 2, "the bearer secret is not masked on its own")
    let other = try! OpenConnectAuthResult(
        protocol: .gp, cookie: "authcookie=xxxxxxxx&user=x&computer=", host: result.host, connectURL: result.connectURL,
        fingerprint: result.fingerprint, resolve: result.resolve)
    precondition(result.description == other.description, "the description depends on the cookie")

    let url = result.connectURL
    guard url.hasPrefix("https://"), url.hasSuffix("/") else { return }
    var authority = String(url.dropFirst("https://".count).dropLast())
    var port = 443
    if let colon = authority.lastIndex(of: ":"), !authority.hasSuffix("]"), let p = Int(authority[authority.index(after: colon)...]) {
        port = p
        authority = String(authority[..<colon])
    }
    let host = authority.hasPrefix("[") && authority.hasSuffix("]") ? String(authority.dropFirst().dropLast()) : authority

    let table = OpenConnectOptions.all.map { (name: $0.name, takesValue: $0.takesValue) }
    let profiles: [(host: String, port: Int, skipPortal: Bool)] = [(host, port, false), (host, port, true), ("vpn.example.com", 443, false)]
    for profile in profiles {
        for (pin, gatewayPin) in [("", ""), (result.fingerprint, ""), ("", result.fingerprint)] {
            guard
                let destination = try? result.checkDestination(
                    host: profile.host, port: profile.port, skipPortal: profile.skipPortal, profileServerCert: pin,
                    profileGatewayServerCert: gatewayPin)
            else { continue }
            precondition(url.lowercased().hasPrefix("https://"), "accepted a connect URL that is not https")
            guard
                let config = try? result.tunnelConfig(
                    host: profile.host, port: profile.port, skipPortal: profile.skipPortal, profileServerCert: pin,
                    profileGatewayServerCert: gatewayPin, scriptPath: "/x/vpn-hook", tlsOnly: false, disableIPv6: true)
            else { preconditionFailure("a checked GlobalProtect sign-in has no root config") }
            precondition(config.host == destination.host && config.port == destination.port, "the tunnel does not go to the destination")
            let helper = try? OpenConnectAuthResult.tunnelConfig(
                protocol: .gp, host: destination.host, port: destination.port, connectURL: url,
                resolve: destination.resolveAddress == nil ? nil : result.resolve, cookie: result.tunnelCookie, serverCert: result.fingerprint,
                profileServerCert: pin, profileGatewayServerCert: gatewayPin, scriptPath: "/x/vpn-hook", tlsOnly: false, disableIPv6: true)
            precondition(helper == config, "the helper's check disagrees with the client's")
            guard let text = try? config.render() else { preconditionFailure("a checked GlobalProtect sign-in did not render") }
            guard let read = readLikeOpenConnect(Array(text.utf8), table: table) else { preconditionFailure("openconnect would refuse the file") }
            let values = Dictionary(read.map { ($0.option, $0.value) }, uniquingKeysWith: { a, _ in a })
            precondition(values["protocol"] == Array("gp".utf8))
            precondition(values["cookie"] == Array(result.cookie.utf8), "cookie not recovered")
            precondition(values["servercert"] == Array(result.fingerprint.utf8), "the root run does not trust the key the sign-in accepted")
            precondition(read.last?.option == "disable-ipv6")
            // The server is CONNECT_URL's, as openconnect would connect to it.
            let h = destination.host.contains(":") ? "[\(destination.host)]" : destination.host
            let server = "https://\(h)\(destination.port == 443 ? "" : ":\(destination.port)")/"
            precondition(url.lowercased() == server, "the destination is not CONNECT_URL's server")
            precondition(values["server"] == Array(server.utf8), "server not recovered")
            if let address = destination.resolveAddress {
                precondition(values["resolve"] == Array("\(destination.host):\(address)".utf8), "resolve not recovered")
                precondition(result.host == (address.contains(":") ? "[\(address)]" : address), "HOST is not the resolved address")
            } else {
                precondition(values["resolve"] == nil, "resolve for an IP-address host")
            }
            // Skipping the portal allows only the profile's own server.
            if profile.skipPortal { precondition(destination.port == profile.port) }
        }
    }
}

runFuzzer(LLVMFuzzerTestOneInput)
