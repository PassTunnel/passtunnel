import Foundation
import PassTunnelVPNConfig

extension OpenConnectProtocol {
    /// The VPN type's name, for messages.
    public var displayName: String {
        switch self {
        case .anyconnect: return "Cisco AnyConnect"
        case .gp: return "Palo Alto GlobalProtect"
        }
    }
}

/// The helper's side of a Cisco AnyConnect or Palo Alto GlobalProtect session (docs/ARCHITECTURE.md, "Helper
/// protocol 4" and "Helper protocol 5"): the request checked again by its protocol's rules,
/// `<run>/openconnect.conf` rendered from it, the hook's `policy`, the arguments and the environment openconnect
/// runs with.
extension HelperCore {
    public static let openConnectConfigName = "openconnect.conf"

    /// Why a start is refused while the network of the profile's last openconnect session could not be restored
    /// yet: `typeName` is the profile's type as the start request names it ("Palo Alto GlobalProtect"), nil for one
    /// that does not say.
    public static func stillRestoringMessage(typeName: String?) -> String {
        let session = typeName.map { "last \($0) session" } ?? "last session"
        return "The network settings of this profile's \(session) are still being restored. Try again shortly."
    }

    /// Only the config file: everything else is in it (`OpenConnectConfig`), and argv is visible to every
    /// local user.
    public static func openConnectArguments(configPath: String) -> [String] { ["--config=" + configPath] }

    /// What openconnect gets on top of `fixedEnvironment`. On the Mac: GnuTLS reads no system priority file
    /// (openconnect sets this itself, but only in `main`, after the libraries' initializers ran) and
    /// p11-kit no file of the user's (`~/.config/pkcs11`); the bundled libraries' compiled-in Homebrew
    /// paths are overwritten at build time (docs/ARCHITECTURE.md, "Fixed environment"). On Linux the
    /// distribution's GnuTLS keeps its system-wide crypto policy.
    #if os(Linux)
    public static let openConnectEnvironment = ["P11_KIT_NO_USER_CONFIG=1"]
    #else
    public static let openConnectEnvironment = ["GNUTLS_SYSTEM_PRIORITY_FILE=/dev/null", "P11_KIT_NO_USER_CONFIG=1"]
    #endif

    /// The complete environment `tool` runs with: built here from fixed values, never taken from the
    /// helper's own environment, so no proxy (`https_proxy`), key log (`SSLKEYLOGFILE`), debug
    /// (`GNUTLS_DEBUG_LEVEL`) or token (`TPM_INTERFACE_TYPE`) variable can reach a tool.
    public static func environment(for tool: Tool) -> [String] {
        switch tool {
        case .openvpn, .openfortivpn: return fixedEnvironment
        case .openconnect: return fixedEnvironment + openConnectEnvironment
        }
    }

    /// Throws `Failure.requiresNewerMacOS`, with the VPN type's name, when openconnect cannot start on this macOS
    /// (`Tool.minimumMacOS`: dyld would stop it at launch).
    public func checkOpenConnectRuns(_ protocol: OpenConnectProtocol) throws {
        guard let version = systemVersion, !Tool.openconnect.runs(on: version), let minimum = Tool.openconnect.minimumMacOS
        else { return }
        throw Failure.requiresNewerMacOS(`protocol`.displayName, Tool.versionText(minimum))
    }

    /// The root configuration for request `s`, built only by `OpenConnectAuthResult.tunnelConfig(protocol:…)`,
    /// which checks the request's fields as the client checked the sign-in, by the request's protocol:
    /// `connectURL` exactly `https://<host>[:<port>]/` for the request's host and port (for GlobalProtect the
    /// gateway's), `resolve` as `<host>:<IP literal>` for a host name and absent for an IP address, `serverCert` a
    /// full pin equal to `profileServerCert` or `profileGatewayServerCert` when either is set, the cookie's shape
    /// (`OpenConnectCookie`'s, or `GlobalProtectCookie`'s), and `scriptPath`. The profile ID, the user group (Cisco
    /// AnyConnect: unused, but part of the profile the client checked; GlobalProtect: empty) and the two profile
    /// pins (each empty or full; the gateway's empty for Cisco AnyConnect) are checked here first. `disableIPv6`
    /// renders `disable-ipv6` for GlobalProtect only (`openConnectDisableIPv6`). Errors name fields, never values.
    public static func openConnectConfig(_ s: OpenConnectStart, scriptPath: String, disableIPv6: Bool = false) throws
        -> OpenConnectConfig
    {
        typealias E = OpenConnectConfig.ValidationError
        guard isValidProfileID(s.profileID) else { throw Failure.invalidProfileID(s.profileID) }
        switch s.protocol {
        case .anyconnect:
            guard s.usergroup.isEmpty || OpenConnectAuthConfig.isValidUsergroup(s.usergroup) else {
                throw E.invalidValue(
                    field: "user group",
                    reason: "not 1–\(OpenConnectAuthConfig.maxUsergroupBytes) bytes of letters, digits and - _ . ~ / without .. or a leading /")
            }
            guard s.profileGatewayServerCert.isEmpty else {
                throw E.invalidValue(field: "gateway server certificate", reason: "used only for Palo Alto GlobalProtect")
            }
        case .gp:
            // The path decides portal or gateway and could name a SAML cookie field: never part of this type.
            guard s.usergroup.isEmpty else { throw E.invalidValue(field: "user group", reason: "used only for Cisco AnyConnect") }
        }
        guard s.profileServerCert.isEmpty || OpenConnectPin.isValid(s.profileServerCert) else { throw E.invalidServerCert }
        guard s.profileGatewayServerCert.isEmpty || OpenConnectPin.isValid(s.profileGatewayServerCert) else {
            throw E.invalidServerCert
        }
        return try OpenConnectAuthResult.tunnelConfig(
            protocol: s.protocol, host: s.host, port: s.port, connectURL: s.connectURL, resolve: s.resolve, cookie: s.cookie,
            serverCert: s.serverCert, profileServerCert: s.profileServerCert, profileGatewayServerCert: s.profileGatewayServerCert,
            scriptPath: scriptPath, tlsOnly: s.tlsOnly, disableIPv6: s.protocol == .gp && disableIPv6)
    }

    /// Lines of the rendered file for request `s`, counted from the request rather than the renderer:
    /// the header and seven options, `resolve` for a host name, `no-dtls` for TLS only, and `disable-ipv6` for
    /// GlobalProtect when `disableIPv6` (the daemon's decision, never the request's).
    static func openConnectLineCount(_ s: OpenConnectStart, disableIPv6: Bool = false) -> Int {
        8 + (s.resolve == nil ? 0 : 1) + (s.tlsOnly ? 1 : 0) + (s.protocol == .gp && disableIPv6 ? 1 : 0)
    }

    /// The literal secrets of request `s`'s cookie for the output masker, by its protocol: for Cisco AnyConnect the
    /// whole option, its `webvpn` value and a STRAP key (`OpenConnectCookie.secrets`), for GlobalProtect the whole
    /// cookie and its `authcookie` value (`GlobalProtectCookie.secrets`).
    static func openConnectSecrets(_ s: OpenConnectStart) -> [String] {
        switch s.protocol {
        case .anyconnect: return OpenConnectCookie.secrets(s.cookie)
        case .gp: return GlobalProtectCookie.secrets(s.cookie)
        }
    }

    /// A well-formed hook path for checking a request before anything is staged; the file gets the staged
    /// hook's path (`hookPath`).
    static let hookPathForChecks = "/var/empty/" + VPNHook.name

    /// Prepares a Cisco AnyConnect or Palo Alto GlobalProtect session by the request's protocol, in this order,
    /// and stops at the first failure:
    /// 1. openconnect runs on this macOS (`checkOpenConnectRuns`, the message naming the protocol's VPN type),
    ///    before anything is read, staged or written;
    /// 2. every field of the request (`openConnectConfig`), before anything is read, staged or written;
    /// 3. the profile directory and the log path (`openProfileDir`, `logFileName`);
    /// 4. `hookPath()`: stages the tools and returns the staged hook's path (`ToolStager`);
    /// 5. the configuration built again with that path, rendered, and the text checked once more against
    ///    the protocol and the line count the request implies (`OpenConnectConfig.checkRendered`);
    /// 6. a fresh session directory with `openconnect.conf` and `policy` (0600, owned by the helper), and the
    ///    log, replaced, in the profile directory.
    /// A failure after the session directory was made removes it, and with it the cookie. The output masker gets
    /// the protocol's cookie secrets (`openConnectSecrets`).
    public func prepareOpenConnect(_ s: OpenConnectStart, uid: uid_t, hookPath: () throws -> String) throws -> LaunchPlan {
        try checkOpenConnectRuns(s.protocol)
        let disableIPv6 = s.protocol == .gp && openConnectDisableIPv6
        _ = try Self.openConnectConfig(s, scriptPath: Self.hookPathForChecks, disableIPv6: disableIPv6)
        let dir = try openProfileDir(s.profileDir, profileID: s.profileID, uid: uid)
        let logName = try logFileName(s.logPath, in: dir)
        let config = try Self.openConnectConfig(s, scriptPath: try hookPath(), disableIPv6: disableIPv6)
        let text = try config.render()
        // `checkRendered` applies the rules of the file's own protocol line: it must be the request's.
        guard text.hasPrefix(OpenConnectConfig.header + "\nprotocol \(s.protocol.rawValue)\n") else {
            throw OpenConnectConfig.ValidationError.unsafeOutput("protocol is not the request's")
        }
        try OpenConnectConfig.checkRendered(text, lineCount: Self.openConnectLineCount(s, disableIPv6: disableIPv6))
        let policy = try OpenConnectPolicy(uid: uid, profileID: s.profileID, setRoutes: s.setRoutes, setDNS: s.setDNS).text()

        let session = try makeRunDir(profileID: s.profileID, uid: uid)
        let runDir = session.path
        do {
            let configPath = runDir + "/" + Self.openConnectConfigName
            // The cookie: this buffer is overwritten once written (best effort; `text` and the request are
            // Swift strings, which cannot be erased).
            var bytes = Data(text.utf8)
            defer { Self.wipe(&bytes) }
            try Self.writeNewFile(configPath, bytes, mode: 0o600)
            try Self.writeNewFile(runDir + "/" + OpenConnectPolicy.fileName, Data(policy.utf8), mode: 0o600)
            #if os(Linux)
            // passtunneld: the `script` the configuration names, a link to the daemon's own executable.
            try linkVPNHook(in: runDir)
            #endif
            let logFD = try dir.createLogFile(logName)
            // A server can make openconnect print what it chooses (the CONNECT status line, say), so its output
            // goes through the masker, which removes the cookie (whole, and its `webvpn` value and a STRAP key, or
            // its `authcookie` value, alone) before it reaches the user's log.
            return LaunchPlan(
                profileID: s.profileID, ownerUID: uid, tool: .openconnect,
                arguments: Self.openConnectArguments(configPath: configPath),
                runDir: runDir, sessionDir: session, logFD: logFD, dnsUpdownPath: nil,
                profileDir: dir, mgmtSocket: nil, maskedSecrets: Self.openConnectSecrets(s))
        } catch {
            removeRunDir(profileID: s.profileID, uid: uid)
            throw error
        }
    }

    #if os(Linux)
    /// passtunneld's `script` for a session: `<run>/<uid>/<id>/vpn-hook`, which `prepareOpenConnect` makes a
    /// link to the daemon's own executable (`dnsHook`, resolved and checked), as `dns-hook` is for OpenVPN
    /// (docs/LINUX.md, "Cisco AnyConnect"). A path of the run root, digits, the profile ID and `/`: safe for
    /// openconnect's `/bin/sh -c`. Throws without a daemon executable to link to.
    public func vpnHookPath(profileID: String, uid: uid_t) throws -> String {
        guard dnsHook != nil else { throw Failure.system("link \(VPNHook.name)", ENOENT) }
        return PT.sessionDir(uid: uid, profileID: profileID, runRoot: runRoot) + "/" + VPNHook.name
    }

    /// Links the daemon's own executable into the (root-owned) session directory as `vpn-hook`.
    func linkVPNHook(in runDir: String) throws {
        guard let target = dnsHook, target.hasPrefix("/"), !Self.containsNUL(target) else {
            throw Failure.system("link \(VPNHook.name)", ENOENT)
        }
        let path = runDir + "/" + VPNHook.name
        guard symlink(target, path) == 0 else { throw Failure.system("link \(path)", errno) }
    }
    #endif

    /// Overwrites `data` with zeros.
    static func wipe(_ data: inout Data) {
        _ = data.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
    }
}

// MARK: - Tunnel status

extension HelperCore {
    /// The state of an openconnect session's network as its hook recorded it (the root-owned `network`
    /// record, `OpenConnectJournal`), for the `status` reply: what the client decides "connected" and
    /// "failed" by. The session log is not: a server can make openconnect print text of its choosing into it.
    /// `.unknown` when the record cannot be read right now (the hook is appending to it).
    public static func tunnelStatus(runDir: String) -> TunnelStatus {
        let record: OpenConnectRecord?
        do {
            record = try OpenConnectJournal.read(OpenConnectJournal.path(runDir: runDir))
        } catch {
            return TunnelStatus(state: .unknown)
        }
        guard let record else { return TunnelStatus(state: .settingUp) }
        switch record.status {
        case nil: return TunnelStatus(state: .settingUp, interface: record.interface)
        case .up?: return TunnelStatus(state: .up, interface: record.interface)
        case .reconnecting?: return TunnelStatus(state: .reconnecting, interface: record.interface)
        case .failed(let reason)?: return TunnelStatus(state: .failed, reason: VPNHook.oneLine(reason), interface: record.interface)
        }
    }
}
