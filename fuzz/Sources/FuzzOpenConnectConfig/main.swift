import Foundation
import FuzzSupport
import PassTunnelVPNConfig

// Fuzzes the two openconnect config files PassTunnel renders: the root tunnel run's (`OpenConnectConfig`)
// and the user's sign-in run's (`OpenConnectAuthConfig`), for Cisco AnyConnect and for Palo Alto GlobalProtect
// (its own cookie shape, path, gateway label, two pins and `disable-ipv6`, never in an AnyConnect file).
// openconnect reads them as `option value` lines
// with no quoting, so the danger is a field that smuggles in a line break, a second option, or a value
// openconnect would read differently (blanks or `=` it skips, a NUL it stops at). Property: whatever
// either renderer agrees to write, read back the way openconnect 9.21 reads it (`readLikeOpenConnect`),
// is exactly the expected options in order, with each field recovered byte for byte. Anything that
// cannot be represented must be refused, not emitted, and anything the validators accept must pass the
// final check. The harness never crashes or hangs on any bytes.
@_cdecl("LLVMFuzzerTestOneInput")
func LLVMFuzzerTestOneInput(_ data: UnsafePointer<UInt8>?, _ size: Int) -> CInt {
    // Fields split on 0x1F (Unit Separator), each decoded as (lossy) UTF-8, as in FuzzFortiConfig.
    let parts = fuzzData(data, size).split(separator: 0x1F, maxSplits: 12, omittingEmptySubsequences: false)
    func field(_ i: Int) -> String { i < parts.count ? String(decoding: parts[i], as: UTF8.self) : "" }

    let host = field(0)
    let port = Int(field(1)) ?? 443
    let usergroup = field(2)
    let username = field(3)
    let authgroup = field(4)
    let serverCert = field(5)
    let cookie = field(6)
    let resolveAddress = field(7).isEmpty ? nil : field(7)
    let scriptPath = field(8)
    let flags = field(9)
    let caFile = field(10).isEmpty ? OpenConnectConfig.systemCAFile : field(10)
    // GlobalProtect's own fields; flags `s` (skip the portal) and `6` (disable-ipv6).
    let gateway = field(11)
    let gatewayServerCert = field(12)
    let disableIPv6 = flags.contains("6")

    let table = OpenConnectOptions.all.map { (name: $0.name, takesValue: $0.takesValue) }
    func expectedURL(path: String) -> [UInt8] {
        let lower = host.lowercased()
        let h = lower.contains(":") ? "[\(lower)]" : lower
        return Array("https://\(h)\(port == 443 ? "" : ":\(port)")/\(path)".utf8)
    }

    // The root run's file.
    let root = OpenConnectConfig(
        host: host, port: port, cookie: cookie, serverCert: serverCert, resolveAddress: resolveAddress, scriptPath: scriptPath,
        tlsOnly: flags.contains("t"))
    // The final check is as strict as the validators, never stricter: whatever validates must render.
    if (try? root.validate()) != nil { precondition((try? root.render()) != nil, "a valid root config failed its final check") }
    if let text = try? root.render() {
        guard let read = readLikeOpenConnect(Array(text.utf8), table: table) else { preconditionFailure("openconnect would refuse the root file") }
        var expected = ["protocol", "server", "cookie", "servercert"]
        if resolveAddress != nil { expected.append("resolve") }
        expected += ["script", "non-inter", "reconnect-timeout"]
        if root.tlsOnly { expected.append("no-dtls") }
        precondition(read.map(\.option) == expected, "root file has options \(read.map(\.option)), expected \(expected)")
        let values = Dictionary(read.map { ($0.option, $0.value) }, uniquingKeysWith: { a, _ in a })
        precondition(values["protocol"] == Array("anyconnect".utf8))
        precondition(values["server"] == expectedURL(path: ""), "server not recovered")
        precondition(values["cookie"] == Array(cookie.utf8), "cookie not recovered")
        precondition(values["servercert"] == Array(serverCert.utf8), "servercert not recovered")
        precondition(values["script"] == Array(scriptPath.utf8), "script not recovered")
        precondition(values["reconnect-timeout"] == Array("60".utf8))
        if let resolveAddress, let resolve = values["resolve"] ?? nil {
            // openconnect splits it at the first ':' into the host to override and the address.
            let colon = resolve.firstIndex(of: UInt8(ascii: ":"))!
            precondition(Array(resolve[..<colon]) == Array(host.lowercased().utf8), "resolve does not name the server's host")
            precondition(Array(resolve[(colon + 1)...]) == Array(resolveAddress.utf8), "resolve address not recovered")
        }
        precondition(!scriptPath.utf8.contains { " ;|&$`'\"\\<>()*?[]{}~#!\n".utf8.contains($0) }, "a shell character in script")
    }

    // The sign-in run's file.
    let auth = OpenConnectAuthConfig(
        host: host, port: port, usergroup: usergroup, username: username, authgroup: authgroup, serverCert: serverCert)
    let noExternalAuth = flags.contains("n")
    if (try? auth.validate()) != nil, (try? auth.render(noExternalAuth: noExternalAuth)) == nil {
        preconditionFailure("a valid sign-in config failed its final check")
    }
    if let text = try? auth.render(caFile: caFile, noExternalAuth: noExternalAuth) {
        guard let read = readLikeOpenConnect(Array(text.utf8), table: table) else { preconditionFailure("openconnect would refuse the sign-in file") }
        var expected = ["protocol", "server", "user"]
        if !authgroup.isEmpty { expected.append("authgroup") }
        expected += serverCert.isEmpty ? ["no-system-trust", "cafile"] : ["servercert"]
        expected += ["non-inter", "passwd-on-stdin"]
        if noExternalAuth { expected.append("no-external-auth") }
        precondition(read.map(\.option) == expected, "sign-in file has options \(read.map(\.option)), expected \(expected)")
        let values = Dictionary(read.map { ($0.option, $0.value) }, uniquingKeysWith: { a, _ in a })
        precondition(values["server"] == expectedURL(path: usergroup), "server not recovered")
        precondition(values["user"] == Array(username.utf8), "user name not recovered")
        if !authgroup.isEmpty { precondition(values["authgroup"] == Array(authgroup.utf8), "group not recovered") }
        if serverCert.isEmpty {
            precondition(values["cafile"] == Array(caFile.utf8), "cafile not recovered")
        } else {
            precondition(values["servercert"] == Array(serverCert.utf8), "servercert not recovered")
        }
        // The group path holds nothing a URL would read as a query, fragment, user info or port.
        precondition(!usergroup.utf8.contains { "?#@:% \\".utf8.contains($0) } && !usergroup.hasPrefix("/") && !usergroup.contains(".."))
    }

    // Cisco AnyConnect files never take GlobalProtect's options.
    var acIPv6 = root
    acIPv6.disableIPv6 = true
    precondition((try? acIPv6.render()) == nil, "a Cisco AnyConnect root file rendered disable-ipv6")
    precondition((try? auth.render(noExternalAuth: noExternalAuth, disableIPv6: true)) == nil, "a Cisco AnyConnect sign-in rendered disable-ipv6")
    if !gateway.isEmpty || !gatewayServerCert.isEmpty || flags.contains("s") {
        let acWithGP = OpenConnectAuthConfig(
            host: host, port: port, usergroup: usergroup, username: username, authgroup: authgroup, serverCert: serverCert,
            skipPortal: flags.contains("s"), gateway: gateway, gatewayServerCert: gatewayServerCert)
        precondition((try? acWithGP.render(noExternalAuth: noExternalAuth)) == nil, "a Cisco AnyConnect sign-in took GlobalProtect's fields")
    }

    // The GlobalProtect root file: the same fields, its own cookie shape, and disable-ipv6.
    let gpRoot = OpenConnectConfig(
        protocol: .gp, host: host, port: port, cookie: cookie, serverCert: serverCert, resolveAddress: resolveAddress,
        scriptPath: scriptPath, tlsOnly: flags.contains("t"), disableIPv6: disableIPv6)
    if (try? gpRoot.validate()) != nil { precondition((try? gpRoot.render()) != nil, "a valid GlobalProtect root config failed its final check") }
    if let text = try? gpRoot.render() {
        guard let read = readLikeOpenConnect(Array(text.utf8), table: table) else {
            preconditionFailure("openconnect would refuse the GlobalProtect root file")
        }
        var expected = ["protocol", "server", "cookie", "servercert"]
        if resolveAddress != nil { expected.append("resolve") }
        expected += ["script", "non-inter", "reconnect-timeout"]
        if gpRoot.tlsOnly { expected.append("no-dtls") }
        if disableIPv6 { expected.append("disable-ipv6") }
        precondition(read.map(\.option) == expected, "GlobalProtect root file has options \(read.map(\.option)), expected \(expected)")
        let values = Dictionary(read.map { ($0.option, $0.value) }, uniquingKeysWith: { a, _ in a })
        precondition(values["protocol"] == Array("gp".utf8))
        precondition(values["server"] == expectedURL(path: ""), "server not recovered")
        precondition(values["cookie"] == Array(cookie.utf8), "cookie not recovered")
        precondition(values["servercert"] == Array(serverCert.utf8), "servercert not recovered")
        precondition(values["script"] == Array(scriptPath.utf8), "script not recovered")
        // The tunnel run takes the cookie unchanged: nothing in it could split it, or end the line.
        precondition(GlobalProtectCookie.isValidTunnelOption(cookie) && !cookie.utf8.contains { " \t;'\"\\\n\r".utf8.contains($0) })
        precondition(GlobalProtectCookie.secrets(cookie).count == 2, "the bearer secret is not masked on its own")
    }

    // The GlobalProtect sign-in file: the path from skip-portal, the gateway as authgroup, a line per pin.
    let gpAuth = OpenConnectAuthConfig(
        protocol: .gp, host: host, port: port, usergroup: usergroup, username: username, authgroup: authgroup, serverCert: serverCert,
        skipPortal: flags.contains("s"), gateway: gateway, gatewayServerCert: gatewayServerCert)
    if (try? gpAuth.validate()) != nil, (try? gpAuth.render(noExternalAuth: noExternalAuth, disableIPv6: disableIPv6)) == nil {
        preconditionFailure("a valid GlobalProtect sign-in config failed its final check")
    }
    if let text = try? gpAuth.render(caFile: caFile, noExternalAuth: noExternalAuth, disableIPv6: disableIPv6) {
        precondition(usergroup.isEmpty && authgroup.isEmpty, "a GlobalProtect sign-in took a user group or group")
        guard let read = readLikeOpenConnect(Array(text.utf8), table: table) else {
            preconditionFailure("openconnect would refuse the GlobalProtect sign-in file")
        }
        let pins = [serverCert, gatewayServerCert].filter { !$0.isEmpty }
        var expected = ["protocol", "server", "user"]
        if !gateway.isEmpty { expected.append("authgroup") }
        expected += pins.isEmpty ? ["no-system-trust", "cafile"] : pins.map { _ in "servercert" }
        expected += ["non-inter", "passwd-on-stdin"]
        if noExternalAuth { expected.append("no-external-auth") }
        if disableIPv6 { expected.append("disable-ipv6") }
        precondition(read.map(\.option) == expected, "GlobalProtect sign-in file has options \(read.map(\.option)), expected \(expected)")
        let values = Dictionary(read.map { ($0.option, $0.value) }, uniquingKeysWith: { a, _ in a })
        precondition(values["protocol"] == Array("gp".utf8))
        precondition(values["server"] == expectedURL(path: flags.contains("s") ? "gateway" : ""), "server not recovered")
        precondition(values["user"] == Array(username.utf8), "user name not recovered")
        if !gateway.isEmpty { precondition(values["authgroup"] == Array(gateway.utf8), "gateway not recovered") }
        precondition(read.filter { $0.option == "servercert" }.map(\.value) == pins.map { Array($0.utf8) }, "pins not recovered")
        if pins.isEmpty { precondition(values["cafile"] == Array(caFile.utf8), "cafile not recovered") }
    }

    // The stored pin form is a fixed point of normalization.
    if let pin = OpenConnectPin.normalize(serverCert) {
        precondition(OpenConnectPin.isValid(pin) && OpenConnectPin.normalize(pin) == pin && pin.utf8.count == OpenConnectPin.length)
    }
    return 0
}

runFuzzer(LLVMFuzzerTestOneInput)
