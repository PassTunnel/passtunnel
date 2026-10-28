import Foundation

/// Portable profile file:
/// `{"passtunnel_profile": 1, "profile": {…}, "files": {"config.ovpn": "<base64>"}}`.
/// The profile omits the per-user fields (username, last_username, order, mgmt_port, pinned, require_auth,
/// connect_at_login, config_imported_at). Secrets are never included.
public struct ShareFile: Codable {
    public static let currentVersion = 1
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
        self.passtunnelProfile = Self.currentVersion
        self.profile = profile
        self.files = files
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
        files = c.lenient([String: Data].self, .files) ?? [:]
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(passtunnelProfile, forKey: .passtunnelProfile)
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
