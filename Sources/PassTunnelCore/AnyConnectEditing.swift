import Foundation
import PassTunnelKit
import PassTunnelVPNConfig

/// The Cisco AnyConnect fields of the Mac app's profile editor, kept apart from SwiftUI so they are tested: the
/// server address as users get it (`https://vpn.example.com[:port][/group]`, `AnyConnectServer.parse`), the group,
/// the user name and the server key pin (`OpenConnectPin`). The messages say what is wrong without repeating what
/// was typed, so nothing pasted into a field by mistake (a password, a link with a token) shows up anywhere else.
public enum AnyConnectEditing {
    /// Why a server address is not one `AnyConnectServer.parse` takes.
    public enum ServerProblem: Equatable, Sendable {
        case empty
        /// A scheme other than `https://`.
        case scheme
        /// A user name or password in the address (`alice@`).
        case userInfo
        /// A query or a fragment (`?`, `#`).
        case queryOrFragment
        /// Percent escapes.
        case percentEscape
        case host
        case port
        /// The path after the host (the user group) is not one `OpenConnectAuthConfig.isValidUsergroup` takes.
        case group

        public var message: String {
            switch self {
            case .empty: return String(localized: "Enter the server address, e.g. https://vpn.example.com.")
            case .scheme: return String(localized: "Use an https:// address.")
            case .userInfo: return String(localized: "Leave the user name out of the address and enter it under User name.")
            case .queryOrFragment: return String(localized: "Leave out anything from “?” or “#” on.")
            case .percentEscape: return String(localized: "Type the address without percent escapes (%).")
            case .host: return String(localized: "Enter a host name or IP address, with an IPv6 address in brackets.")
            case .port: return String(localized: "The port must be between 1 and 65535.")
            case .group:
                return String(localized: "The path after the address may use letters, digits, and - _ . ~ / only.")
            }
        }
    }

    /// The address a profile's server is shown as: `https://` and the host (an IPv6 literal in brackets), `:port`
    /// unless 443, and `/usergroup` when there is one. Empty without a host.
    public static func serverText(host: String, port: Int, usergroup: String) -> String {
        let h = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !h.isEmpty else { return "" }
        var text = "https://" + (h.contains(":") ? "[\(h)]" : h)
        if port != 443 { text += ":\(port)" }
        if !usergroup.isEmpty { text += "/" + usergroup }
        return text
    }

    /// The server address typed or pasted into the editor: a valid one sets `p`'s host, port and user group (the
    /// host kept as stored when only the case of its letters differs: the same server, nothing to save); an empty
    /// one clears them. Anything else leaves them as they were (`serverProblem` says why).
    public static func applyServer(_ text: String, to p: inout Profile) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if let server = AnyConnectServer.parse(trimmed) {
            if p.host.lowercased() != server.host { p.host = server.host }
            p.port = server.port
            p.usergroup = server.usergroup
        } else if trimmed.isEmpty {
            p.host = ""
            p.port = 443
            p.usergroup = ""
        }
    }

    /// Why `text` is not a server address (`AnyConnectServer.parse`), or nil when it is one.
    public static func serverProblem(_ text: String) -> ServerProblem? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return .empty }
        if AnyConnectServer.parse(trimmed) != nil { return nil }
        if trimmed.contains("@") { return .userInfo }
        if trimmed.contains("?") || trimmed.contains("#") { return .queryOrFragment }
        if trimmed.contains("%") { return .percentEscape }
        var rest = Substring(trimmed)
        if let schemeEnd = rest.range(of: "://") {
            if rest[..<schemeEnd.lowerBound].lowercased() != "https" { return .scheme }
            rest = rest[schemeEnd.upperBound...]
        }
        let slash = rest.firstIndex(of: "/")
        let authority = rest[..<(slash ?? rest.endIndex)]
        if let slash {
            let path = rest[rest.index(after: slash)...]
            if !path.isEmpty, !OpenConnectAuthConfig.isValidUsergroup(String(path)) { return .group }
        }
        // The port: after the closing bracket of an IPv6 literal, else after the only colon.
        var portText: Substring?
        if authority.hasPrefix("["), let close = authority.firstIndex(of: "]") {
            let after = authority[authority.index(after: close)...]
            if after.hasPrefix(":") { portText = after.dropFirst() }
        } else if authority.filter({ $0 == ":" }).count == 1, let colon = authority.firstIndex(of: ":") {
            portText = authority[authority.index(after: colon)...]
        }
        if let portText, AnyConnectServer.parse("https://vpn.example.com:" + portText) == nil { return .port }
        return .host
    }

    /// The group (`authgroup`) as the editor saves it: blanks around it dropped.
    public static func normalizedGroup(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Why a group is not one the profile takes (`OpenConnectAuthConfig.isValidAuthgroup`), or nil.
    public static func groupProblem(_ text: String) -> String? {
        let group = normalizedGroup(text)
        guard !group.isEmpty, !OpenConnectAuthConfig.isValidAuthgroup(group) else { return nil }
        return String(
            localized: "Enter the group as the server lists it: at most 255 bytes, without line breaks and without “=” at the start.")
    }

    /// Why a user name is not one the profile takes (`Profile.checkUsername`), or nil; empty is asked each time.
    public static func usernameProblem(_ text: String) -> String? {
        guard (try? Profile.checkUsername(text, type: .anyconnect)) == nil else { return nil }
        return String(localized: "A user name can have at most 255 bytes, no control characters and no “=” at the start.")
    }

    /// The pin as the editor saves it: `OpenConnectPin.normalize`'s form, or the text without blanks around it
    /// when it is not a pin (the error says so).
    public static func normalizedPin(_ text: String) -> String {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? "" : OpenConnectPin.normalize(trimmed) ?? trimmed
    }

    /// Why a pin is not one the profile takes (`OpenConnectPin`), or nil; empty verifies the server with the
    /// system's certificate authorities.
    public static func pinProblem(_ text: String) -> String? {
        let pin = normalizedPin(text)
        guard !pin.isEmpty, !OpenConnectPin.isValid(pin) else { return nil }
        return String(localized: "Enter “pin-sha256:” and the key’s fingerprint (44 base64 characters), or leave it empty.")
    }
}

/// "Trust this server" (#186): openconnect did not trust the Cisco AnyConnect server's certificate and printed the
/// pin of its key (`ConnectionFailure.serverCert`); this is the offer to keep that pin in the profile's
/// `server_cert`. It holds the server the sign-in went to, so it is only taken while the profile still names that
/// server with the pin it had then (`matches`), and only after the user confirmed the host and the pin.
///
/// Palo Alto GlobalProtect (docs/ARCHITECTURE.md, "Trust: two keys"): for the portal (or, with `skip_portal`, the
/// only server) the same, writing `server_cert`; for the gateway the portal sent the sign-in to ("Trust This
/// Gateway…", `gateway` set) it writes `gateway_server_cert`. When the profile has no `server_cert` then, a pin for
/// the gateway turns system trust off for the portal too, so the portal's key must be pinned with it
/// (`needsPortalPin`: the front end reads it with `TLSFingerprint.fetchServerKeyPin` and shows it for confirmation;
/// `ConnectionManager.trustServer(_:portalPin:)` writes both).
public struct ServerTrustOffer: Equatable, Sendable {
    public var profileID: String
    /// The profile's type: Cisco AnyConnect or Palo Alto GlobalProtect.
    public var type: VPNType
    /// The profile's host, port and user group (Cisco AnyConnect) when the sign-in failed.
    public var host: String
    public var port: Int
    public var usergroup: String
    /// Palo Alto GlobalProtect: the profile's `skip_portal` when the sign-in failed.
    public var skipPortal: Bool
    /// Palo Alto GlobalProtect: the gateway whose key was not trusted (`host:port`, an IPv6 literal in brackets), as
    /// the redacted sign-in log named it; nil when the key is the profile's own server's.
    public var gateway: String?
    /// The key's pin, normalized (`OpenConnectPin.normalize`).
    public var pin: String
    /// The pin the profile had then: empty when it had none (the system's CAs did not trust the certificate),
    /// else the key the server no longer presents. For a gateway, `gateway_server_cert`.
    public var replacing: String
    /// A gateway's offer: the profile's `server_cert` then (normalized; empty when it had none).
    public var portalPin: String

    /// The offer for `p` (Cisco AnyConnect or Palo Alto GlobalProtect) and the pin openconnect printed; `gateway`
    /// for a GlobalProtect gateway's key. nil when `pin` is not a full pin or the profile already has it.
    public init?(_ p: Profile, pin: String?, gateway: String? = nil) {
        guard p.type == .anyconnect || p.type == .globalprotect, let pin = pin.flatMap(OpenConnectPin.normalize) else { return nil }
        guard gateway == nil || p.type == .globalprotect else { return nil }
        let current = AnyConnectEditing.normalizedPin(gateway == nil ? p.serverCert : p.gatewayServerCert)
        guard current != pin else { return nil }
        profileID = p.id
        type = p.type
        host = p.host.trimmingCharacters(in: .whitespacesAndNewlines)
        port = p.port
        usergroup = p.type == .anyconnect ? p.usergroup : ""
        skipPortal = p.type == .globalprotect && p.skipPortal
        self.gateway = gateway
        self.pin = pin
        replacing = current
        portalPin = gateway == nil ? "" : AnyConnectEditing.normalizedPin(p.serverCert)
    }

    /// "vpn.example.com:8443/engineering": where the key was presented (a gateway's `host:port`).
    public var server: String {
        if let gateway { return gateway }
        return AnyConnectEditing.serverText(host: host, port: port, usergroup: usergroup).replacingOccurrences(of: "https://", with: "")
    }

    /// A gateway's key, and the profile pins no portal key: trusting it needs the portal's pin as well.
    public var needsPortalPin: Bool { gateway != nil && portalPin.isEmpty }

    /// The profile still names the server of the failed sign-in, with the pins it had then.
    public func matches(_ p: Profile) -> Bool {
        guard p.id == profileID, p.type == type,
            p.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == host.lowercased(), p.port == port
        else { return false }
        switch type {
        case .globalprotect:
            guard p.skipPortal == skipPortal else { return false }
            if gateway == nil { return AnyConnectEditing.normalizedPin(p.serverCert) == replacing }
            return AnyConnectEditing.normalizedPin(p.gatewayServerCert) == replacing && AnyConnectEditing.normalizedPin(p.serverCert) == portalPin
        default:
            return p.usergroup == usergroup && AnyConnectEditing.normalizedPin(p.serverCert) == replacing
        }
    }

    /// The profile changed since the sign-in failed: its server or pin is not the one the offer was made for.
    public struct Stale: Error, Equatable, LocalizedError {
        public init() {}

        public var errorDescription: String? {
            String(localized: "The profile’s server settings changed after the sign-in failed. Connect again to check the server.")
        }
    }

    /// A gateway's key was to be trusted without the portal's (`needsPortalPin`), or with a portal pin that is not a
    /// full pin.
    public struct PortalPinRequired: Error, Equatable, LocalizedError {
        public init() {}

        public var errorDescription: String? {
            String(
                localized:
                    "Trusting the gateway’s key turns off the system’s trust for the portal too, so the portal’s key must be trusted with it."
            )
        }
    }
}

extension ConnectionManager {
    /// The offer to trust the key of the server whose certificate the last connect of `id` did not trust
    /// (`ServerTrustOffer`); nil when there is none, or the profile no longer names that server with the pin it
    /// had (the CLI or the editor changed it since).
    public func serverTrustOffer(_ id: String) -> ServerTrustOffer? {
        guard let offer = trustOffers[id], failures[id]?.serverCert != nil, let p = try? store.get(id), offer.matches(p) else {
            return nil
        }
        return offer
    }

    /// Keeps the offer's pin in the profile's `server_cert` (only that field, on the profile as stored now); for a
    /// Palo Alto GlobalProtect gateway's key in `gateway_server_cert`, and, when the offer `needsPortalPin`,
    /// `portalPin` (the portal's key, which the user confirmed too) in `server_cert`. Throws
    /// `ServerTrustOffer.Stale` when the profile no longer matches the offer, `ServerTrustOffer.PortalPinRequired`
    /// without a full portal pin where one is needed, and the store's errors. The caller asks the user first,
    /// showing the server and the pin (and the portal's).
    @discardableResult
    public func trustServer(_ offer: ServerTrustOffer, portalPin: String? = nil) throws -> Profile {
        var portal: String?
        if offer.needsPortalPin {
            guard let pin = portalPin.flatMap(OpenConnectPin.normalize) else { throw ServerTrustOffer.PortalPinRequired() }
            portal = pin
        }
        let saved = try store.update(offer.profileID) { p in
            guard offer.matches(p) else { throw ServerTrustOffer.Stale() }
            if offer.gateway == nil {
                p.serverCert = offer.pin
            } else {
                p.gatewayServerCert = offer.pin
                if let portal { p.serverCert = portal }
            }
        }
        trustOffers[offer.profileID] = nil
        return saved
    }
}

/// "Fetch Fingerprint" in the editor, bound to the server it was asked for: the result of a fetch is kept only when
/// it answers the fetch under way and the profile still names that server, is shown with that server, and is taken
/// only while the profile still names it. Editing the server while a fetch runs ends the fetch; editing it after the
/// result came drops the result. So a key read from one server never goes into a profile that names another.
public struct FingerprintFetch: Equatable {
    /// What a fingerprint is bound to: the type (which hash), the host (trimmed, lowercased), the port and, for Cisco
    /// AnyConnect, the user group.
    public struct Destination: Equatable {
        public var type: VPNType
        public var host: String
        public var port: Int
        public var usergroup: String

        public init(_ p: Profile) {
            type = p.type
            host = p.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            port = p.port
            usergroup = p.type == .anyconnect ? p.usergroup : ""
        }

        /// "vpn.example.com:8443/engineering", "[2001:db8::1]:443": where the fingerprint was read.
        public var server: String {
            let address = OVPNAnalyzer.Endpoint.address(host: host, port: String(port))
            return usergroup.isEmpty ? address : address + "/" + usergroup
        }
    }

    /// The fetch under way, and the server it reads.
    public private(set) var pending: Destination?
    /// The fingerprint read, and the server it was read from, until it is taken or dropped.
    public private(set) var result: (destination: Destination, value: String)?

    public init() {}

    public var isFetching: Bool { pending != nil }

    /// Starts a fetch for `p`'s server (replacing one under way and an earlier result); the caller reads that server.
    @discardableResult
    public mutating func start(for p: Profile) -> Destination {
        let destination = Destination(p)
        pending = destination
        result = nil
        return destination
    }

    /// The answer of the fetch for `destination`, with the profile as it is now. Kept only when that fetch is still
    /// the one under way and `current` still names its server; true when kept.
    @discardableResult
    public mutating func finish(_ value: String, for destination: Destination, current: Profile) -> Bool {
        guard pending == destination else { return false }
        pending = nil
        guard Destination(current) == destination else { return false }
        result = (destination, value)
        return true
    }

    /// The fetch for `destination` failed or was cancelled: it is no longer under way (unless another one replaced it).
    public mutating func fail(for destination: Destination) {
        if pending == destination { pending = nil }
    }

    /// The profile was edited: a fetch or a result for another server than the one it names now is dropped. True when
    /// a fetch under way was ended (the caller cancels its task).
    @discardableResult
    public mutating func profileChanged(_ p: Profile) -> Bool {
        let now = Destination(p)
        if let r = result, r.destination != now { result = nil }
        guard let pending, pending != now else { return false }
        self.pending = nil
        return true
    }

    /// The fingerprint to put into `p`: the result, only while `p` still names the server it was read from.
    public func value(for p: Profile) -> String? {
        guard let result, result.destination == Destination(p) else { return nil }
        return result.value
    }

    /// The result is shown or taken: it is gone either way.
    public mutating func clearResult() { result = nil }

    public static func == (a: FingerprintFetch, b: FingerprintFetch) -> Bool {
        a.pending == b.pending && a.result?.destination == b.result?.destination && a.result?.value == b.result?.value
    }
}

extension ConnectionManager {
    /// The profiles whose secrets the app may read (codes shown, copied or typed, Keychain items kept in line with
    /// "Confirm with Touch ID"): those of a type this system can connect (`connectRefusal`). A Cisco AnyConnect profile
    /// below macOS 15.4 is listed, but nothing of it is read or unlocked.
    public func profilesWithUsableSecrets(_ profiles: [Profile]) -> [Profile] {
        profiles.filter { connectRefusal($0.type) == nil }
    }
}
