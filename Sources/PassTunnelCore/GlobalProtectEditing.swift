import Foundation
import PassTunnelKit
import PassTunnelVPNConfig

/// The Palo Alto GlobalProtect fields of the Mac app's profile editor (#233), kept apart from SwiftUI so they are
/// tested: the server address (`[https://]host[:port]`, `GlobalProtectServer.parse`: the portal, or with `skip_portal`
/// the gateway), the gateway's label and the user name. The pins are `AnyConnectEditing`'s (`OpenConnectPin`). As
/// there, no message repeats what was typed.
public enum GlobalProtectEditing {
    /// The address a profile's server is shown as: `https://` and the host (an IPv6 literal in brackets), `:port`
    /// unless 443. Empty without a host.
    public static func serverText(host: String, port: Int) -> String {
        AnyConnectEditing.serverText(host: host, port: port, usergroup: "")
    }

    /// The server address typed or pasted: a valid one sets `p`'s host and port (the host kept as stored when only
    /// the case of its letters differs); an empty one clears them. Anything else leaves them as they were.
    public static func applyServer(_ text: String, to p: inout Profile) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if let server = GlobalProtectServer.parse(trimmed) {
            if p.host.lowercased() != server.host { p.host = server.host }
            p.port = server.port
        } else if trimmed.isEmpty {
            p.host = ""
            p.port = 443
        }
    }

    /// Why `text` is not a GlobalProtect address (`GlobalProtectServer.parse`), or nil when it is one. A path
    /// (`/global-protect/…` pasted from a browser) is `.path`.
    public static func serverProblem(_ text: String) -> AnyConnectEditing.ServerProblem? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return .empty }
        if GlobalProtectServer.parse(trimmed) != nil { return nil }
        if AnyConnectServer.parse(trimmed) != nil { return .path }
        let problem = AnyConnectEditing.serverProblem(trimmed)
        return problem == .group ? .path : problem
    }

    /// The gateway (`gateway`) as the editor saves it: blanks around it dropped.
    public static func normalizedGateway(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Why a gateway is not one the profile takes (`OpenConnectAuthConfig.isValidGateway`), or nil; empty leaves
    /// the choice to a portal with one gateway.
    public static func gatewayProblem(_ text: String) -> String? {
        let gateway = normalizedGateway(text)
        guard !gateway.isEmpty, !OpenConnectAuthConfig.isValidGateway(gateway) else { return nil }
        return String(
            localized: "Enter the gateway as the portal lists it: at most 255 bytes, without line breaks and without “=” at the start.")
    }

    /// Why a user name is not one the profile takes (`Profile.checkUsername`), or nil; empty is asked each time.
    public static func usernameProblem(_ text: String) -> String? {
        guard (try? Profile.checkUsername(text, type: .globalprotect)) == nil else { return nil }
        return String(localized: "A user name can have at most 255 bytes, no control characters and no “=” at the start.")
    }

    /// The profile pins a gateway's key but not the portal's: openconnect then accepts only the pinned keys for every
    /// server of the sign-in, the portal included, so the portal must present the gateway's key. The editor says so.
    public static func pinsGatewayOnly(_ p: Profile) -> Bool {
        p.type == .globalprotect && !p.skipPortal && AnyConnectEditing.normalizedPin(p.serverCert).isEmpty
            && !AnyConnectEditing.normalizedPin(p.gatewayServerCert).isEmpty
    }
}

/// The portal's gateways, offered after a sign-in failed because the portal lists more than one and the profile
/// names none of them (`PTError.invalidField("gateway")`, `ConnectionFailure.gateways`; docs/ARCHITECTURE.md,
/// "Choosing the gateway"). Bound to the portal they came from: offered, and taken, only while the profile still
/// names that portal (`matches`). The labels are the portal's text as Core read it (printable ASCII, 1–64 bytes, at
/// most 32), and only those the profile's `gateway` takes; empty when they could not be read (the log has them).
public struct GatewayChoice: Equatable, Sendable {
    public var profileID: String
    /// The portal the labels came from: the profile's host and port when the sign-in failed.
    public var host: String
    public var port: Int
    /// The profile's gateway then (empty, or a label the portal did not list).
    public var gateway: String
    /// The portal's gateway labels, in its order.
    public var labels: [String]

    /// The choice for `p` (Palo Alto GlobalProtect, signing in through the portal) and the labels of its failure.
    public init?(_ p: Profile, labels: [String]?) {
        guard p.type == .globalprotect, !p.skipPortal else { return nil }
        profileID = p.id
        host = p.host.trimmingCharacters(in: .whitespacesAndNewlines)
        port = p.port
        gateway = p.gateway
        var seen = Set<String>()
        self.labels = (labels ?? []).prefix(VPNLog.maxGatewayLabels).filter {
            $0.utf8.count <= VPNLog.maxGatewayLabelBytes && $0.utf8.allSatisfy({ (0x20...0x7E).contains($0) })
                && OpenConnectAuthConfig.isValidGateway($0) && seen.insert($0).inserted
        }
    }

    /// "vpn.example.com:443": the portal that listed the gateways.
    public var portal: String { OVPNAnalyzer.Endpoint.address(host: host, port: String(port)) }

    /// The profile still names the portal the labels came from, signing in through it.
    public func matches(_ p: Profile) -> Bool {
        p.id == profileID && p.type == .globalprotect && !p.skipPortal
            && p.host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == host.lowercased() && p.port == port
    }

    /// The labels to offer for `p`: none once it names another portal.
    public func options(for p: Profile) -> [String] { matches(p) ? labels : [] }

    /// A label to put into `p`'s `gateway`: one of the portal's, while `p` still names that portal.
    public func allows(_ label: String, for p: Profile) -> Bool { matches(p) && labels.contains(label) }
}

/// "Trust This Gateway…" (docs/ARCHITECTURE.md, "Trust: two keys"): the confirmation of a `ServerTrustOffer` for a
/// Palo Alto GlobalProtect gateway's key. When the profile pins no portal key, a pin for the gateway turns system
/// trust off for the portal too, so the portal's key is read (`TLSFingerprint.fetchServerKeyPin` for the offer's
/// host and port, by the front end) and shown with the gateway's; the two can be trusted only once it has been read
/// for this offer (`canTrust`), and `ConnectionManager.trustServer(_:portalPin:)` refuses the gateway's without it.
public struct GatewayTrust: Equatable, Sendable {
    public enum PortalKey: Equatable, Sendable {
        /// The profile pins the portal's key already.
        case notNeeded
        /// Being read from the portal.
        case reading
        /// Read: the portal's pin (normalized), shown for the user to confirm with the gateway's.
        case read(String)
        /// Could not be read (the message says why); Retry reads it again.
        case failed(String)
    }

    public let offer: ServerTrustOffer
    public private(set) var portalKey: PortalKey

    /// The confirmation of `offer`; nil unless it is for a GlobalProtect gateway's key.
    public init?(_ offer: ServerTrustOffer) {
        guard offer.type == .globalprotect, offer.gateway != nil else { return nil }
        self.offer = offer
        portalKey = offer.needsPortalPin ? .reading : .notNeeded
    }

    /// "vpn.example.com:443": the portal, whose key is read when it is needed.
    public var portal: String { OVPNAnalyzer.Endpoint.address(host: offer.host, port: String(offer.port)) }

    /// The portal's key is to be read: the profile pins none.
    public var needsPortalKey: Bool { offer.needsPortalPin }

    /// The portal's key read for `offer`: kept only while it is being read for this offer, and only a full pin.
    @discardableResult
    public mutating func portalKeyRead(_ pin: String, for offer: ServerTrustOffer) -> Bool {
        guard offer == self.offer, portalKey == .reading else { return false }
        guard let normalized = OpenConnectPin.normalize(pin) else {
            portalKey = .failed(String(localized: "The portal’s key could not be read."))
            return false
        }
        portalKey = .read(normalized)
        return true
    }

    /// Reading the portal's key for `offer` failed.
    public mutating func portalKeyFailed(_ message: String, for offer: ServerTrustOffer) {
        guard offer == self.offer, portalKey == .reading else { return }
        portalKey = .failed(message)
    }

    /// Retry after a failed read: the key is read again.
    public mutating func retry() {
        if case .failed = portalKey { portalKey = .reading }
    }

    /// Both keys can be trusted: the portal's is pinned already or was read for this offer.
    public var canTrust: Bool {
        switch portalKey {
        case .notNeeded, .read: return true
        case .reading, .failed: return false
        }
    }

    /// The portal's pin to save with the gateway's (`ConnectionManager.trustServer(_:portalPin:)`).
    public var portalPin: String? {
        if case .read(let pin) = portalKey { return pin }
        return nil
    }
}

extension ConnectionManager {
    /// The portal's gateways after the last connect of `id` failed for want of one (`GatewayChoice`); nil when there is
    /// none, or the profile no longer names that portal.
    public func gatewayChoice(_ id: String) -> GatewayChoice? {
        guard let choice = gatewayChoices[id], failures[id] != nil, let p = try? store.get(id), choice.matches(p) else { return nil }
        return choice
    }

    /// Puts `label`, one of the portal's gateways, into the profile's `gateway` (only that field, on the profile as
    /// stored now). Throws `ServerTrustOffer.Stale` when the profile no longer names the portal or `label` is not one
    /// of its gateways, and the store's errors.
    @discardableResult
    public func chooseGateway(_ choice: GatewayChoice, label: String) throws -> Profile {
        try store.update(choice.profileID) { p in
            guard choice.allows(label, for: p) else { throw ServerTrustOffer.Stale() }
            p.gateway = label
        }
    }

    /// The gateway (`host:port`, as the redacted sign-in log named it) whose certificate the last connect of `id` did not
    /// trust; nil when the certificate was the profile's own server's or there is no such failure.
    public func failedGateway(_ id: String) -> String? {
        guard failures[id]?.serverCert != nil else { return nil }
        return failedGateways[id]
    }
}
