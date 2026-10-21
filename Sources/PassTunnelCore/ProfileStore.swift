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

    /// New profile with a unique slug id ("acme", "acme-2", …) of at most `Slug.maxIDLength`
    /// characters. Forti profiles default to `.separate` OTP delivery. Keychain items still stored
    /// under the new id (left by a profile removed outside the app, or from before a reinstall) are
    /// deleted first, so the new profile never uses secrets it was not given.
    public func create(name: String, type: VPNType) throws -> Profile {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw PTError.emptyName }
        try paths.ensureDirectories()
        return try withLock {
            let existing = list()
            let id = try uniqueID(for: trimmed)
            try Secrets.deleteAll(id)
            var p = Profile(id: id, name: trimmed, type: type)
            p.order = (existing.map(\.order).max() ?? -1) + 1
            p.otpDelivery = type == .forti ? .separate : .combined
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

    /// Read-modify-write of one profile: re-reads `profile.json`, applies `change` and saves the
    /// result, so fields changed elsewhere (CLI, another window) are kept. Use this instead of saving
    /// a copy that may have been read earlier. Returns the saved profile.
    @discardableResult
    public func update(_ id: String, _ change: (inout Profile) throws -> Void) throws -> Profile {
        _ = try get(id)
        return try withLock {
            var p = try get(id)
            try change(&p)
            p.id = id
            try save(p)
            return p
        }
    }

    /// Removes the profile directory, both Keychain items, and the default if it pointed here.
    /// Locked like `update`, so an update running in another process cannot write the profile back.
    public func delete(_ id: String) throws {
        try checkID(id)
        let d = dir(id)
        guard FileManager.default.fileExists(atPath: d.path) else { throw PTError.profileNotFound(id) }
        try withLock {
            guard FileManager.default.fileExists(atPath: d.path) else { throw PTError.profileNotFound(id) }
            do { try FileManager.default.removeItem(at: d) } catch { throw PTError.fileError(d.path) }
        }
        for kind in SecretKind.allCases { Secrets.delete(id, kind) }
        Secrets.deleteProtectionKey(id)
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

    /// Replaces the profile's config (0600) with a self-contained copy of `url`: referenced files
    /// (ca, cert, key, tls-auth, …) are inlined and the result must pass `OVPNSanitizer`. An inline
    /// `<auth-user-pass>` block is not stored (the editor offers its contents for the Keychain).
    /// Records the source file name and import time in the profile and returns the saved profile.
    @discardableResult
    public func setOVPN(_ id: String, from url: URL, now: Date = Date()) throws -> Profile {
        var p = try get(id)
        guard p.type == .openvpn else { throw PTError.wrongProfileType(id) }
        let text = try preparedOVPN(url).text
        try FileIO.writeAtomically(Data(text.utf8), to: ovpnURL(id), mode: 0o600)
        p.configSourceName = url.lastPathComponent
        p.configImportedAt = Self.wholeSeconds(now)
        try save(p)
        return p
    }

    /// Creates an OpenVPN profile from an .ovpn file (made self-contained and checked as in `setOVPN`;
    /// nothing is created if that fails). Name defaults to the file name. A user name and password in
    /// an inline `<auth-user-pass>` block move to the profile and the Keychain; the stored config
    /// keeps a bare `auth-user-pass`.
    public func importOVPN(_ url: URL, name: String?) throws -> Profile {
        let prepared = try preparedOVPN(url)
        let text = prepared.text
        let a = OVPNAnalyzer.analyze(text)
        let fallback = url.deletingPathExtension().lastPathComponent
        var p = try create(name: Self.pick(name, fallback), type: .openvpn)
        do {
            p.passwordMode = a.passwordMode
            p.otpMode = a.otpMode
            p.otpDelivery = a.otpDelivery
            p.configSourceName = url.lastPathComponent
            p.configImportedAt = Self.wholeSeconds(Date())
            if let user = prepared.username { p.username = user }
            try FileIO.writeAtomically(Data(text.utf8), to: ovpnURL(p.id), mode: 0o600)
            try save(p)
            // A new profile: `requireAuth` is off, so the plain item is what `SecretVault.store` writes.
            if let password = prepared.password { try Secrets.set(p.id, .password, password) }
        } catch {
            try? delete(p.id)
            throw error
        }
        return p
    }

    /// Writes a share file (0600). Never includes Keychain secrets, nor user names and passwords
    /// embedded in the config (`<auth-user-pass>`, `<http-proxy-user-pass>`); certificates and keys
    /// are kept.
    public func exportShare(_ id: String, to url: URL) throws {
        let p = try get(id)
        var files: [String: Data] = [:]
        if FileManager.default.fileExists(atPath: ovpnURL(id).path) {
            let data = try FileIO.read(ovpnURL(id), maxSize: Self.maxOVPNSize)
            guard let text = String(data: data, encoding: .utf8) else { throw PTError.invalidFile(Self.ovpnFile) }
            files[Self.ovpnFile] = Data(OVPNInliner.strippingCredentials(text).text.utf8)
        }
        try ShareFile(profile: p, files: files).write(to: url)
    }

    /// Creates a profile from a share file. A new id is assigned; only
    /// `ShareFile.knownFiles` are written, under fixed names (never a path taken from the file).
    /// An `<auth-user-pass>` block (someone else's sign-in, from an older export) is dropped.
    public func importShare(_ url: URL, name: String?) throws -> Profile {
        let share = try ShareFile.read(from: url)
        let src = share.profile
        var sharedOVPN: Data?
        if src.type == .openvpn, let ovpn = share.files[Self.ovpnFile] {
            guard ovpn.count <= Self.maxOVPNSize else { throw PTError.fileTooLarge(Self.ovpnFile) }
            guard let text = String(data: ovpn, encoding: .utf8) else { throw PTError.invalidFile(Self.ovpnFile) }
            try OVPNInliner.check(text)   // share files are already self-contained
            sharedOVPN = Data(OVPNInliner.strippingCredentials(text, blocks: [.authUserPass]).text.utf8)
        }
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
            if let ovpn = sharedOVPN {
                try FileIO.writeAtomically(ovpn, to: ovpnURL(p.id), mode: 0o600)
                p.configSourceName = src.configSourceName ?? Self.ovpnFile
                p.configImportedAt = Self.wholeSeconds(Date())
            }
            try save(p)
        } catch {
            try? delete(p.id)
            throw error
        }
        return p
    }

    // MARK: helpers

    /// The config to store, and the user name and password of an inline `<auth-user-pass>` block,
    /// which is never stored with it.
    private func preparedOVPN(_ url: URL) throws -> OVPNInliner.StrippedCredentials {
        let text = try FileIO.readText(url, maxSize: Self.maxOVPNSize)
        let prepared = try OVPNInliner.prepare(text, baseDir: url.deletingLastPathComponent())
        return OVPNInliner.strippingCredentials(prepared, blocks: [.authUserPass])
    }

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
            candidate = Slug.suffixed(base, n)
            n += 1
        }
        return candidate
    }

    /// profile.json stores whole seconds; rounding here keeps saved and returned profiles equal.
    static func wholeSeconds(_ date: Date) -> Date {
        Date(timeIntervalSince1970: date.timeIntervalSince1970.rounded(.down))
    }

    private static func pick(_ name: String?, _ fallback: String) -> String {
        let n = name?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return n.isEmpty ? fallback : n
    }

    /// Serialises create(), update() and delete() across processes (app and CLI share the directory).
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
