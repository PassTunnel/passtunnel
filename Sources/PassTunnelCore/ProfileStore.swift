import Foundation

/// Profiles on disk: `profiles/<id>/profile.json` (+ `config.ovpn`, `vpn.log`).
/// Stateless and synchronous; every call re-reads the file system and the environment.
public struct ProfileStore {
    public let paths: AppPaths
    static let profileFile = "profile.json"
    static let ovpnFile = "config.ovpn"
    static let logFile = "vpn.log"
    static let maxOVPNSize = 2 * 1024 * 1024

    public init(paths: AppPaths = .default) {
        self.paths = paths
    }

    // MARK: listing

    /// All readable profiles, sorted by (order, name). Damaged entries are skipped.
    public func list() -> [Profile] {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: paths.profilesDir.path) else { return [] }
        let profiles = names.filter(Slug.isValid).compactMap { try? load($0) }
        return profiles.sorted {
            if $0.order != $1.order { return $0.order < $1.order }
            let byName = $0.name.localizedStandardCompare($1.name)
            if byName != .orderedSame { return byName == .orderedAscending }
            return $0.id < $1.id
        }
    }

    public func get(_ id: String) throws -> Profile {
        try checkID(id)
        guard FileManager.default.fileExists(atPath: profileURL(id).path) else { throw PTError.profileNotFound(id) }
        return try load(id)
    }

    public func exists(_ id: String) -> Bool {
        Slug.isValid(id) && FileManager.default.fileExists(atPath: profileURL(id).path)
    }

    // MARK: create / save / delete

    /// New profile with a unique slug id ("acme", "acme-2", …). OpenVPN profiles get the first
    /// management port ≥ `$PASSTUNNEL_MGMT_BASE` (17505) not used by another OpenVPN profile.
    /// Forti profiles default to `.separate` OTP delivery.
    public func create(name: String, type: VPNType) throws -> Profile {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw PTError.emptyName }
        try paths.ensureDirectories()
        return try withLock {
            let existing = list()
            var p = Profile(id: try uniqueID(for: trimmed), name: trimmed, type: type)
            p.order = (existing.map(\.order).max() ?? -1) + 1
            switch type {
            case .openvpn:
                p.otpDelivery = .combined
                p.mgmtPort = try freeMgmtPort(existing)
            case .forti:
                p.otpDelivery = .separate
            }
            try save(p)
            return p
        }
    }

    /// Writes `profile.json` (creating the directory if needed). Validates the editable fields.
    public func save(_ p: Profile) throws {
        try checkID(p.id)
        guard !p.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw PTError.emptyName }
        guard (6...8).contains(p.totp.digits) else { throw PTError.invalidField("totp.digits") }
        guard (1...600).contains(p.totp.period) else { throw PTError.invalidField("totp.period") }
        guard (1...65535).contains(p.port) else { throw PTError.invalidField("port") }
        guard (0...65535).contains(p.mgmtPort) else { throw PTError.invalidField("mgmt_port") }
        guard p.sessionLimitMin >= 0 else { throw PTError.invalidField("session_limit_min") }
        if p.otpDelivery == .combined && p.otpMode != .none {
            try OTPComposer.validate(template: p.otpTemplate)
        }
        try paths.ensureDirectories()
        try FileIO.makeDirectory(dir(p.id))
        try JSONCoding.write(p, to: profileURL(p.id), mode: 0o600)
    }

    /// Removes the profile directory, both Keychain items, and the default if it pointed here.
    public func delete(_ id: String) throws {
        try checkID(id)
        let d = dir(id)
        guard FileManager.default.fileExists(atPath: d.path) else { throw PTError.profileNotFound(id) }
        do { try FileManager.default.removeItem(at: d) } catch { throw PTError.fileError(d.path) }
        for kind in SecretKind.allCases { Secrets.delete(id, kind) }
        var prefs = Preferences.load(paths: paths)
        if prefs.defaultProfile == id {
            prefs.defaultProfile = nil
            try prefs.save(paths: paths)
        }
    }

    // MARK: default profile

    /// The default profile id, if it still exists.
    public var defaultID: String? {
        guard let id = Preferences.load(paths: paths).defaultProfile, exists(id) else { return nil }
        return id
    }

    public func setDefault(_ id: String?) throws {
        if let id {
            try checkID(id)
            guard exists(id) else { throw PTError.profileNotFound(id) }
        }
        var prefs = Preferences.load(paths: paths)
        prefs.defaultProfile = id
        try prefs.save(paths: paths)
    }

    // MARK: files

    public func dir(_ id: String) -> URL { paths.profileDir(id) }
    public func ovpnURL(_ id: String) -> URL { dir(id).appendingPathComponent(Self.ovpnFile) }
    public func logURL(_ id: String) -> URL { dir(id).appendingPathComponent(Self.logFile) }
    func profileURL(_ id: String) -> URL { dir(id).appendingPathComponent(Self.profileFile) }

    /// Copies an .ovpn file into the profile (0600).
    public func setOVPN(_ id: String, from url: URL) throws {
        let p = try get(id)
        guard p.type == .openvpn else { throw PTError.wrongProfileType(id) }
        let data = try FileIO.read(url, maxSize: Self.maxOVPNSize)
        try FileIO.writeAtomically(data, to: ovpnURL(id), mode: 0o600)
    }

    /// Creates an OpenVPN profile from an .ovpn file. Name defaults to the file name.
    public func importOVPN(_ url: URL, name: String?) throws -> Profile {
        let data = try FileIO.read(url, maxSize: Self.maxOVPNSize)
        guard let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) else {
            throw PTError.invalidFile(url.lastPathComponent)
        }
        let a = OVPNAnalyzer.analyze(text)
        let fallback = url.deletingPathExtension().lastPathComponent
        var p = try create(name: Self.pick(name, fallback), type: .openvpn)
        do {
            p.passwordMode = a.passwordMode
            p.otpMode = a.otpMode
            p.otpDelivery = a.otpDelivery
            try FileIO.writeAtomically(data, to: ovpnURL(p.id), mode: 0o600)
            try save(p)
        } catch {
            try? delete(p.id)
            throw error
        }
        return p
    }

    /// Writes a share file (0600). Never includes Keychain secrets.
    public func exportShare(_ id: String, to url: URL) throws {
        let p = try get(id)
        var files: [String: Data] = [:]
        if FileManager.default.fileExists(atPath: ovpnURL(id).path) {
            files[Self.ovpnFile] = try FileIO.read(ovpnURL(id), maxSize: Self.maxOVPNSize)
        }
        try ShareFile(profile: p, files: files).write(to: url)
    }

    /// Creates a profile from a share file. A new id and management port are assigned; only
    /// `ShareFile.knownFiles` are written, under fixed names (never a path taken from the file).
    public func importShare(_ url: URL, name: String?) throws -> Profile {
        let share = try ShareFile.read(from: url)
        let src = share.profile
        var p = try create(name: Self.pick(name, src.name.isEmpty ? url.deletingPathExtension().lastPathComponent : src.name),
                           type: src.type)
        do {
            p.badge = src.badge
            p.icon = src.icon
            p.badgeStyle = src.badgeStyle
            p.passwordMode = src.passwordMode
            p.otpMode = src.otpMode
            p.totp = src.totp
            p.sessionLimitMin = max(0, src.sessionLimitMin)
            p.autoReconnect = src.autoReconnect
            p.healthHost = src.healthHost
            p.otpDelivery = src.otpDelivery
            p.otpTemplate = src.otpTemplate
            p.host = src.host
            p.port = src.port
            p.trustedCert = src.trustedCert
            p.setDNS = src.setDNS
            p.setRoutes = src.setRoutes
            if p.type == .openvpn, let ovpn = share.files[Self.ovpnFile] {
                guard ovpn.count <= Self.maxOVPNSize else { throw PTError.fileTooLarge(Self.ovpnFile) }
                try FileIO.writeAtomically(ovpn, to: ovpnURL(p.id), mode: 0o600)
            }
            try save(p)
        } catch {
            try? delete(p.id)
            throw error
        }
        return p
    }

    // MARK: helpers

    private func load(_ id: String) throws -> Profile {
        var p = try JSONCoding.read(Profile.self, from: profileURL(id))
        p.id = id   // the directory name is authoritative
        if p.name.trimmingCharacters(in: .whitespaces).isEmpty { p.name = id }
        return p
    }

    private func checkID(_ id: String) throws {
        guard Slug.isValid(id) else { throw PTError.invalidProfileID(id) }
    }

    private func uniqueID(for name: String) throws -> String {
        var base = Slug.make(name)
        if base.isEmpty { base = "profile" }
        let fm = FileManager.default
        var candidate = base
        var n = 2
        while fm.fileExists(atPath: dir(candidate).path) {
            candidate = "\(base)-\(n)"
            n += 1
        }
        return candidate
    }

    private func freeMgmtPort(_ existing: [Profile]) throws -> Int {
        let used = Set(existing.filter { $0.type == .openvpn }.map(\.mgmtPort))
        var port = Env.mgmtBase
        while used.contains(port) { port += 1 }
        guard port <= 65535 else { throw PTError.noFreePort }
        return port
    }

    private static func pick(_ name: String?, _ fallback: String) -> String {
        let n = name?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return n.isEmpty ? fallback : n
    }

    /// Serialises create() across processes (app and CLI share the directory).
    private func withLock<T>(_ body: () throws -> T) throws -> T {
        let lockPath = paths.profilesDir.appendingPathComponent(".lock").path
        let fd = open(lockPath, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw PTError.fileError(lockPath) }
        defer { close(fd) }
        flock(fd, LOCK_EX)
        defer { flock(fd, LOCK_UN) }
        return try body()
    }
}
