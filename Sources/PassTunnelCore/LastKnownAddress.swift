import Foundation
import PassTunnelKit
import PassTunnelShared

/// The address a profile's server name had at the last successful connection by that name, for a connect whose
/// server name cannot be resolved (#292, #298): `profiles/<id>/last-address.json`.
///
/// - **Which types.** Only those whose tool can be handed an address while it still checks the server exactly as
///   strictly (`isSupported`, `host(of:store:)`):
///   - Cisco AnyConnect, and Palo Alto GlobalProtect with `skip_portal` (a portal may send the sign-in on to a
///     gateway of another name, which could not be found either, after the code was sent), whose sign-in takes it as
///     openconnect's `resolve` (`OpenConnectAuthConfig.resolveAddress`; the tunnel run gets the address the sign-in
///     printed, as always), checking the certificate against the name or the pin as before;
///   - OpenVPN (#298), whose checks never involve the `remote` name, for a config with exactly one `remote` host name,
///     no `<connection>` blocks, no proxy and an identity of that one server (`OVPNAnalyzer.knownAddressFit`:
///     `verify-x509-name` or `peer-fingerprint`; with only a role such as `remote-cert-tls` another server of the CA
///     would do). The try at the address is a run the helper starts with
///     `--management-query-remote` (`OpenVPNStart.queryRemote`), whose question every management client of the app
///     answers with this file (`OpenVPNRemoteAnswer`).
///   openfortivpn checks the certificate name against whatever host it connects to and always trusts the system CAs
///   too, so it cannot be narrowed to the name or the pin at an address: FortiGate neither learns nor uses one.
/// - **What is learned, and when.** The address the connection by the name really used, kept once it is up, with that
///   time (`confirmedAt`): for openconnect the one the sign-in connected to and printed (`RESOLVE`), which the tunnel
///   run then used; for OpenVPN the server address its management interface reports for the connected state
///   (`ManagementState.remoteIP`). A connection made at the remembered address leaves the entry as it is (its date
///   keeps meaning "last confirmed by a name lookup"); a connection by the name that yields no address to keep
///   forgets the entry.
/// - **Bound to the destination.** Like `ProfileNetwork`'s file, it holds the `ProfileDestination`
///   fingerprint it was learned for, a hash and not the settings themselves (for OpenVPN those are the whole
///   `config.ovpn`, keys included): a changed host, port, user group, pin or configuration makes it stale, and a
///   stale or foreign file is never used. Every successful connection by the name replaces it (the name is always
///   looked up first, so a server that moved is picked up at once); `ProfileStore.save` drops it when the destination
///   changes, `setOVPN` when a configuration is imported, and a connect that would use it drops a stale one.
/// - **This computer only.** It lives beside `network.json` (0600, replaced atomically, read only if it is a
///   regular file of this user with no group or other access) and is never exported: a share file carries the
///   profile and its `config.ovpn`, nothing else of its directory.
public enum LastKnownAddress {
    public static let fileName = "last-address.json"
    static let version = 1

    /// One learned address; in JSON (`diagnose`) `host`, `address`, `confirmed_at`.
    public struct Entry: Codable, Equatable, Sendable {
        /// The server's name, lowercase, as the profile has it.
        public var host: String
        /// The IP address the last successful connection by that name used.
        public var address: String
        /// When that connection came up.
        public var confirmedAt: Date

        public init(host: String, address: String, confirmedAt: Date) {
            self.host = host
            self.address = address
            self.confirmedAt = confirmedAt
        }
    }

    struct Saved: Codable, Equatable {
        var version: Int
        var destination: String
        var host: String
        var address: String
        var confirmedAt: Date
    }

    /// Whether `type` can learn and use the address at all (see the type's note).
    public static func isSupported(_ type: VPNType) -> Bool { type.usesOpenConnect || type == .openvpn }

    /// Whether `p`'s type learns and uses it: a type that can, and for Palo Alto GlobalProtect only with `skip_portal`.
    /// For OpenVPN the configuration decides as well (`host(of:store:)`).
    public static func applies(to p: Profile) -> Bool {
        isSupported(p.type) && (p.type != .globalprotect || p.skipPortal)
    }

    /// The profile's host as an address is kept for: trimmed and lowercased; nil for an IP address (nothing to
    /// look up) or no host. For openconnect's types; OpenVPN's is its config's (`host(of:store:)`).
    static func hostName(_ p: Profile) -> String? {
        hostName(p.host)
    }

    static func hostName(_ text: String) -> String? {
        let host = text.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !host.isEmpty, IPAddress(host) == nil else { return nil }
        return host
    }

    /// The server name `p` learns and uses an address for: nil unless its type does (`applies`); for OpenVPN the one
    /// `remote` of its config as it is now when the config fits (`OVPNAnalyzer.knownAddressFit`) and names a host.
    public static func host(of p: Profile, store: ProfileStore) -> String? {
        guard applies(to: p) else { return nil }
        guard p.type == .openvpn else { return hostName(p) }
        return openVPNServer(p, store: store).flatMap { hostName($0.host) }
    }

    /// The one server of `p`'s config.ovpn when it fits (`OVPNAnalyzer.knownAddressFit`); nil otherwise or unreadable.
    static func openVPNServer(_ p: Profile, store: ProfileStore) -> OVPNAnalyzer.Server? {
        guard let data = try? FileIO.read(store.ovpnURL(p.id), maxSize: ProfileStore.maxOVPNSize),
            case .fits(let server) = OVPNAnalyzer.knownAddressFit(String(decoding: data, as: UTF8.self))
        else { return nil }
        return server
    }

    static func url(_ id: String, store: ProfileStore) -> URL { store.dir(id).appendingPathComponent(fileName) }

    /// The address known for `p` as it is now: nil unless the type uses it, the file is there and ours
    /// (`ProfileNetwork.readOwned`), sound, and written for the profile's host and `destination`. `droppingStale`
    /// (a connect): a file that is there but not for the profile as it is now is removed, so it never lingers.
    public static func read(_ p: Profile, destination: ProfileDestination, store: ProfileStore, droppingStale: Bool = false) -> Entry? {
        let file = url(p.id, store: store)
        guard let host = host(of: p, store: store), let data = ProfileNetwork.readOwned(file),
            let saved = try? JSONCoding.decode(Saved.self, from: data, name: fileName), saved.version == version,
            saved.destination == destination.fingerprint, saved.host == host, IPAddress(saved.address) != nil
        else {
            if droppingStale && FileManager.default.fileExists(atPath: file.path) { forget(p.id, store: store) }
            return nil
        }
        return Entry(host: saved.host, address: saved.address, confirmedAt: saved.confirmedAt)
    }

    /// Keeps `address` as the one `p`'s server had when it connected now, for `destination`: atomically, 0600.
    /// Nothing for a type that does not use it, an IP-address host or a value that is not an IP address. A
    /// failure is ignored: the file only helps a later connect.
    static func save(_ address: String, for p: Profile, destination: ProfileDestination, store: ProfileStore, at date: Date) {
        guard let host = host(of: p, store: store), IPAddress(address) != nil,
            FileManager.default.fileExists(atPath: store.dir(p.id).path)
        else { return }
        let saved = Saved(version: version, destination: destination.fingerprint, host: host, address: address, confirmedAt: date)
        try? JSONCoding.write(saved, to: url(p.id, store: store), mode: 0o600)
    }

    /// Forgets the address of profile `id`: a server at it failed the certificate check, or the profile's server
    /// changed.
    static func forget(_ id: String, store: ProfileStore) {
        try? FileManager.default.removeItem(at: url(id, store: store))
    }

    /// `ProfileStore.save`: forgets the address when `new` goes to another destination than `old` (another host,
    /// port, user group, pin, `skip_portal`, type, or OpenVPN configuration) or no longer uses one (`host(of:store:)`), so
    /// an address of the old server is never tried for the new one. Only reads anything when there is an address to
    /// forget.
    static func forgetIfMoved(from old: Profile?, to new: Profile, store: ProfileStore) {
        guard FileManager.default.fileExists(atPath: url(new.id, store: store).path) else { return }
        guard let old, host(of: new, store: store) != nil,
            ProfileDestination.of(old, store: store).fingerprint == ProfileDestination.of(new, store: store).fingerprint
        else { return forget(new.id, store: store) }
    }
}
