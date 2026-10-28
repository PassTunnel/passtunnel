import Foundation
import FuzzSupport
import PassTunnelVPNConfig

// Fuzzes the parser of what `openconnect --authenticate` prints (`OpenConnectAuthResult`) and the check
// of where the sign-in ended, then the root file built from it. The output comes from a run that talked
// to the server, so every value is the server's to choose. Properties: whatever the parser accepts is
// exactly openconnect's five lines (printing the result again gives the same bytes); the description
// never depends on the cookie; and when the destination check passes for the profile the output names,
// the root file renders, and openconnect would read back that cookie, that key and that address. The
// harness never crashes or hangs on any bytes.
@_cdecl("LLVMFuzzerTestOneInput")
func LLVMFuzzerTestOneInput(_ data: UnsafePointer<UInt8>?, _ size: Int) -> CInt {
    let bytes = [UInt8](fuzzData(data, size))
    guard let result = try? OpenConnectAuthResult.parse(bytes) else { return 0 }

    let printed = Array(result.output.utf8)
    precondition(bytes == printed || (result.resolve.isEmpty && bytes == printed + [0x0A]), "parsed output does not print back the same")
    precondition(result.cookie.utf8.count <= OpenConnectConfig.maxCookieBytes && !result.cookie.isEmpty)
    precondition(OpenConnectPin.isValid(result.fingerprint))
    let other = try! OpenConnectAuthResult(
        cookie: "x", host: result.host, connectURL: result.connectURL, fingerprint: result.fingerprint, resolve: result.resolve)
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
        guard let config = try? result.tunnelConfig(host: host, port: port, serverCert: pin, scriptPath: "/x/vpn-hook", tlsOnly: false)
        else { continue }
        precondition(url.lowercased().hasPrefix("https://"), "accepted a connect URL that is not https")
        guard let text = try? config.render() else { preconditionFailure("a checked sign-in did not render") }
        let table = OpenConnectOptions.all.map { (name: $0.name, takesValue: $0.takesValue) }
        guard let read = readLikeOpenConnect(Array(text.utf8), table: table) else { preconditionFailure("openconnect would refuse the file") }
        let values = Dictionary(read.map { ($0.option, $0.value) }, uniquingKeysWith: { a, _ in a })
        precondition(values["cookie"] == Array(result.cookie.utf8), "cookie not recovered")
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

runFuzzer(LLVMFuzzerTestOneInput)
