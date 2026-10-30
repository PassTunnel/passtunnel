import Foundation

/// Portable profile file:
/// `{"passtunnel_profile": 1, "profile": {…}, "files": {"config.ovpn": "<base64>"}}`.
/// The profile omits the per-user fields (username, last_username, order, mgmt_port, pinned, require_auth,
/// connect_at_login, config_imported_at). Secrets are never included, and neither are the keys of the profile this
/// version does not know (`Profile.unknownKeys`); keys of an imported profile this version does not know are ignored.
///
/// `passtunnel_profile` is the oldest format version that can read the file, not the writer's: a reader
/// refuses a file of a version it does not know. Version 2 added the type `anyconnect`, so a Cisco
/// AnyConnect profile is written as 2 and refused by an older PassTunnel (which would have imported it as
/// OpenVPN before it knew to refuse unknown types); OpenVPN and FortiGate profiles are still written as 1,
/// unchanged, so every older reader takes them.
public struct ShareFile: Codable {
    /// The newest version this one reads.
    public static let currentVersion = 2
    /// File name extension of share files.
    public static let fileExtension = "passtunnel"
    /// The type the Mac app exports in its Info.plist (conforms to `public.json`).
    public static let typeIdentifier = "com.furkanprlk.passtunnel.profile"
    /// The only file names ever written on import; anything else in `files` is ignored.
    public static let knownFiles: Set<String> = ["config.ovpn"]
    static let maxSize = 4 * 1024 * 1024

    public var passtunnelProfile: Int
    public var profile: Profile
    public var files: [String: Data]

    public init(profile: Profile, files: [String: Data] = [:]) {
        self.passtunnelProfile = Self.version(for: profile.type)
        self.profile = profile
        self.files = files
    }

    /// The version a file with a profile of `type` is written as: the first one that has the type.
    public static func version(for type: VPNType) -> Int {
        switch type {
        case .openvpn, .forti: return 1
        case .anyconnect: return 2
        }
    }

    enum CodingKeys: String, CodingKey { case passtunnelProfile, profile, files }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        guard let version = c.lenient(Int.self, .passtunnelProfile), version >= 1,
            version <= Self.currentVersion
        else { throw PTError.unsupportedShareFile }
        passtunnelProfile = version
        // A profile of a type this version does not know is refused as such, never imported as OpenVPN.
        do {
            profile = try c.decode(Profile.self, forKey: .profile)
        } catch let e as PTError {
            throw e
        } catch {
            throw PTError.unsupportedShareFile
        }
        // Not for the profile an import creates or updates: this version cannot check them.
        profile.unknownKeys = UnknownProfileKeys()
        files = c.lenient([String: Data].self, .files) ?? [:]
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        // Never older than the profile's type needs, also when `profile` was replaced after `init`.
        try c.encode(max(passtunnelProfile, Self.version(for: profile.type)), forKey: .passtunnelProfile)
        try c.encode(profile, forKey: .profile)
        try c.encode(files, forKey: .files)
    }

    public func data() throws -> Data {
        var d = try JSONCoding.encode(self, userInfo: [.passTunnelShareExport: true])
        d.append(0x0A)
        return d
    }

    /// Writes the file with 0600 permissions (it may contain certificates and keys).
    public func write(to url: URL) throws {
        try FileIO.writeAtomically(try data(), to: url, mode: 0o600)
    }

    public static func decode(_ data: Data) throws -> ShareFile {
        do {
            return try JSONCoding.decoder().decode(ShareFile.self, from: data)
        } catch let e as PTError {
            throw e
        } catch {
            throw PTError.unsupportedShareFile
        }
    }

    public static func read(from url: URL) throws -> ShareFile {
        try decode(try FileIO.read(url, maxSize: maxSize))
    }
}
