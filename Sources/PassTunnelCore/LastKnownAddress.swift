import Foundation
import PassTunnelKit
import PassTunnelShared

/// The address a profile's server had at its last successful connection, for a connect whose server name
/// cannot be resolved (#292): `profiles/<id>/last-address.json`.
///
/// - **Which types.** Only those whose tool can be handed an address while it still checks the server against
///   its name exactly as strictly (`isSupported`): Cisco AnyConnect and Palo Alto GlobalProtect, whose sign-in
///   takes it as openconnect's `resolve` (`OpenConnectAuthConfig.resolveAddress`; the tunnel run gets the
///   address the sign-in printed, as always). openfortivpn checks the certificate against the host it was given
///   and resolves that same host, so an address would be checked instead of the name; OpenVPN could take one
///   (none of its checks involve the `remote` name), but the helper reads `config.ovpn` itself and cannot be
///   told one. Neither type learns or uses an address.
/// - **What is learned.** The address the sign-in connected to and printed (`RESOLVE`), which the tunnel run
///   then used, kept once the tunnel is up; only for the profile's own host name (a GlobalProtect gateway on
///   another host is not the server whose name a connect looks up first).
/// - **Bound to the destination.** Like `ProfileNetwork`'s file, it holds the `ProfileDestination`
///   fingerprint it was learned for, a hash and not the settings themselves (for OpenVPN those are the whole
///   `config.ovpn`, keys included): a changed host, port, user group or pin makes it stale, and a stale or
///   foreign file is never used. Every successful connection replaces it (the name is always looked up first, so a
///   server that moved is picked up at once); `ProfileStore.save` drops it when the destination changes, `setOVPN`
///   when a configuration is imported, and a connect that would use it drops a stale one.
/// - **This computer only.** It lives beside `network.json` (0600, replaced atomically, read only if it is a
///   regular file of this user with no group or other access) and is never exported: a share file carries the
///   profile and its `config.ovpn`, nothing else of its directory.
public enum LastKnownAddress {
    public static let fileName = "last-address.json"
    static let version = 1

    /// One learned address; in JSON (`diagnose`) `host`, `address`, `learned_at`.
    public struct Entry: Codable, Equatable, Sendable {
        /// The server's name, lowercase, as the profile has it.
        public var host: String
        /// The IP address the last successful connection used.
        public var address: String
        public var learnedAt: Date

        public init(host: String, address: String, learnedAt: Date) {
            self.host = host
            self.address = address
            self.learnedAt = learnedAt
        }
    }

    struct Saved: Codable, Equatable {
        var version: Int
        var destination: String
        var host: String
        var address: String
        var learnedAt: Date
    }

    /// Whether `type` learns and uses the address (see the type's note).
    public static func isSupported(_ type: VPNType) -> Bool { type.usesOpenConnect }

    /// The profile's host as an address is kept for: trimmed and lowercased; nil for an IP address (nothing to
    /// look up) or no host.
    static func hostName(_ p: Profile) -> String? {
        let host = p.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !host.isEmpty, IPAddress(host) == nil else { return nil }
        return host
    }

    static func url(_ id: String, store: ProfileStore) -> URL { store.dir(id).appendingPathComponent(fileName) }

    /// The address known for `p` as it is now: nil unless the type uses it, the file is there and ours
    /// (`ProfileNetwork.readOwned`), sound, and written for the profile's host and `destination`. `droppingStale`
    /// (a connect): a file that is there but not for the profile as it is now is removed, so it never lingers.
    public static func read(_ p: Profile, destination: ProfileDestination, store: ProfileStore, droppingStale: Bool = false) -> Entry? {
        let file = url(p.id, store: store)
        guard isSupported(p.type), let host = hostName(p), let data = ProfileNetwork.readOwned(file),
            let saved = try? JSONCoding.decode(Saved.self, from: data, name: fileName), saved.version == version,
            saved.destination == destination.fingerprint, saved.host == host, IPAddress(saved.address) != nil
        else {
            if droppingStale && FileManager.default.fileExists(atPath: file.path) { forget(p.id, store: store) }
            return nil
        }
        return Entry(host: saved.host, address: saved.address, learnedAt: saved.learnedAt)
    }

    /// Keeps `address` as the one `p`'s server had when it connected now, for `destination`: atomically, 0600.
    /// Nothing for a type that does not use it, an IP-address host or a value that is not an IP address. A
    /// failure is ignored: the file only helps a later connect.
    static func save(_ address: String, for p: Profile, destination: ProfileDestination, store: ProfileStore, at date: Date) {
        guard isSupported(p.type), let host = hostName(p), IPAddress(address) != nil,
            FileManager.default.fileExists(atPath: store.dir(p.id).path)
        else { return }
        let saved = Saved(version: version, destination: destination.fingerprint, host: host, address: address, learnedAt: date)
        try? JSONCoding.write(saved, to: url(p.id, store: store), mode: 0o600)
    }

    /// Forgets the address of profile `id`: a server at it failed the certificate check, or the profile's server
    /// changed.
    static func forget(_ id: String, store: ProfileStore) {
        try? FileManager.default.removeItem(at: url(id, store: store))
    }

    /// `ProfileStore.save`: forgets the address when `new` goes to another destination than `old` (another host,
    /// port, user group, pin, type, or OpenVPN configuration), so an address of the old server is never tried for
    /// the new one. Only reads anything when there is an address to forget.
    static func forgetIfMoved(from old: Profile?, to new: Profile, store: ProfileStore) {
        guard FileManager.default.fileExists(atPath: url(new.id, store: store).path) else { return }
        guard let old, ProfileDestination.of(old, store: store).fingerprint == ProfileDestination.of(new, store: store).fingerprint
        else { return forget(new.id, store: store) }
    }
}
