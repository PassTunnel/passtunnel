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
public struct ServerTrustOffer: Equatable, Sendable {
    public var profileID: String
    /// The profile's host, port and user group when the sign-in failed.
    public var host: String
    public var port: Int
    public var usergroup: String
    /// The key's pin, normalized (`OpenConnectPin.normalize`).
    public var pin: String
    /// The pin the profile had then: empty when it had none (the system's CAs did not trust the certificate),
    /// else the key the server no longer presents.
    public var replacing: String

    /// The offer for `p` (Cisco AnyConnect) and the pin openconnect printed; nil when `pin` is not a full pin or
    /// the profile already has it.
    public init?(_ p: Profile, pin: String?) {
        guard p.type == .anyconnect, let pin = pin.flatMap(OpenConnectPin.normalize) else { return nil }
        let current = AnyConnectEditing.normalizedPin(p.serverCert)
        guard current != pin else { return nil }
        profileID = p.id
        host = p.host.trimmingCharacters(in: .whitespacesAndNewlines)
        port = p.port
        usergroup = p.usergroup
        self.pin = pin
        replacing = current
    }

    /// "vpn.example.com:8443/engineering": where the key was presented.
    public var server: String {
        AnyConnectEditing.serverText(host: host, port: port, usergroup: usergroup).replacingOccurrences(of: "https://", with: "")
    }

    /// The profile still names the server of the failed sign-in, with the pin it had then.
    public func matches(_ p: Profile) -> Bool {
        p.id == profileID && p.type == .anyconnect
            && p.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == host.lowercased() && p.port == port
            && p.usergroup == usergroup && AnyConnectEditing.normalizedPin(p.serverCert) == replacing
    }

    /// The profile changed since the sign-in failed: its server or pin is not the one the offer was made for.
    public struct Stale: Error, Equatable, LocalizedError {
        public init() {}

        public var errorDescription: String? {
            String(localized: "The profile’s server settings changed after the sign-in failed. Connect again to check the server.")
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

    /// Keeps the offer's pin in the profile's `server_cert` (only that field, on the profile as stored now). Throws
    /// `ServerTrustOffer.Stale` when the profile no longer matches the offer, and the store's errors. The caller
    /// asks the user first, showing the server and the pin.
    @discardableResult
    public func trustServer(_ offer: ServerTrustOffer) throws -> Profile {
        let saved = try store.update(offer.profileID) { p in
            guard offer.matches(p) else { throw ServerTrustOffer.Stale() }
            p.serverCert = offer.pin
        }
        trustOffers[offer.profileID] = nil
        return saved
    }
}
