import Foundation
import PassTunnelVPNConfig

/// The helper's side of a Cisco AnyConnect session (docs/ARCHITECTURE.md, "Helper protocol 4"): the
/// request checked again, `<run>/openconnect.conf` rendered from it, the hook's `policy`, the arguments
/// and the environment openconnect runs with.
extension HelperCore {
    public static let openConnectConfigName = "openconnect.conf"

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

    /// Throws `Failure.requiresNewerMacOS` when openconnect cannot start on this macOS
    /// (`Tool.minimumMacOS`: dyld would stop it at launch).
    public func checkOpenConnectRuns() throws {
        guard let version = systemVersion, !Tool.openconnect.runs(on: version), let minimum = Tool.openconnect.minimumMacOS
        else { return }
        throw Failure.requiresNewerMacOS(.openconnect, Tool.versionText(minimum))
    }

    /// The root configuration for request `s`, built only by `OpenConnectAuthResult.tunnelConfig`, which
    /// checks the request's fields as the client checked the sign-in: `connectURL` exactly
    /// `https://<host>[:<port>]/` for the request's host and port, `resolve` as `<host>:<IP literal>` for a
    /// host name and absent for an IP address, `serverCert` a full pin equal to `profileServerCert` when
    /// that is set, the cookie's length and characters, and `scriptPath`. The profile ID, the user group
    /// (unused, but part of the profile the client checked) and `profileServerCert` are checked here first.
    /// Errors name fields, never values.
    public static func openConnectConfig(_ s: OpenConnectStart, scriptPath: String) throws -> OpenConnectConfig {
        guard isValidProfileID(s.profileID) else { throw Failure.invalidProfileID(s.profileID) }
        guard s.usergroup.isEmpty || OpenConnectAuthConfig.isValidUsergroup(s.usergroup) else {
            throw OpenConnectConfig.ValidationError.invalidValue(
                field: "user group",
                reason: "not 1–\(OpenConnectAuthConfig.maxUsergroupBytes) bytes of letters, digits and - _ . ~ / without .. or a leading /")
        }
        guard s.profileServerCert.isEmpty || OpenConnectPin.isValid(s.profileServerCert) else {
            throw OpenConnectConfig.ValidationError.invalidServerCert
        }
        return try OpenConnectAuthResult.tunnelConfig(
            host: s.host, port: s.port, connectURL: s.connectURL, resolve: s.resolve, cookie: s.cookie,
            serverCert: s.serverCert, profileServerCert: s.profileServerCert, scriptPath: scriptPath, tlsOnly: s.tlsOnly)
    }

    /// Lines of the rendered file for request `s`, counted from the request rather than the renderer:
    /// the header and seven options, `resolve` for a host name, `no-dtls` for TLS only.
    static func openConnectLineCount(_ s: OpenConnectStart) -> Int {
        8 + (s.resolve == nil ? 0 : 1) + (s.tlsOnly ? 1 : 0)
    }

    /// A well-formed hook path for checking a request before anything is staged; the file gets the staged
    /// hook's path (`hookPath`).
    static let hookPathForChecks = "/var/empty/" + VPNHook.name

    /// Prepares a Cisco AnyConnect session, in this order, and stops at the first failure:
    /// 1. openconnect runs on this macOS (`checkOpenConnectRuns`), before anything is read, staged or written;
    /// 2. every field of the request (`openConnectConfig`), before anything is read, staged or written;
    /// 3. the profile directory and the log path (`openProfileDir`, `logFileName`);
    /// 4. `hookPath()`: stages the tools and returns the staged hook's path (`ToolStager`);
    /// 5. the configuration built again with that path, rendered, and the text checked once more against
    ///    the line count the request implies (`OpenConnectConfig.checkRendered`);
    /// 6. a fresh session directory with `openconnect.conf` and `policy` (0600, owned by the helper), and the
    ///    log, replaced, in the profile directory.
    /// A failure after the session directory was made removes it, and with it the cookie.
    public func prepareOpenConnect(_ s: OpenConnectStart, uid: uid_t, hookPath: () throws -> String) throws -> LaunchPlan {
        try checkOpenConnectRuns()
        _ = try Self.openConnectConfig(s, scriptPath: Self.hookPathForChecks)
        let dir = try openProfileDir(s.profileDir, profileID: s.profileID, uid: uid)
        let logName = try logFileName(s.logPath, in: dir)
        let config = try Self.openConnectConfig(s, scriptPath: try hookPath())
        let text = try config.render()
        try OpenConnectConfig.checkRendered(text, lineCount: Self.openConnectLineCount(s))
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
            // goes through the masker, which removes the cookie, before it reaches the user's log.
            return LaunchPlan(
                profileID: s.profileID, ownerUID: uid, tool: .openconnect,
                arguments: Self.openConnectArguments(configPath: configPath),
                runDir: runDir, sessionDir: session, logFD: logFD, dnsUpdownPath: nil,
                profileDir: dir, mgmtSocket: nil, maskedSecrets: [s.cookie])
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
