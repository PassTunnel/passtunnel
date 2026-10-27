import Foundation

/// A stored profile whose `type` this version does not know: written by a newer PassTunnel (a VPN type
/// added later). It is not a `Profile`: reading it as one would show it as OpenVPN and a save would
/// rewrite it without the fields only the newer version knows. It is listed (name, "needs a newer
/// PassTunnel") and can be deleted; nothing else touches it, and its file is never rewritten.
public struct UnsupportedProfile: Identifiable, Equatable {
    public var id: String
    public var name: String
    /// The `type` value as stored, e.g. "anyconnect".
    public var type: String
    public var order: Int

    /// nil unless `data` is a JSON object with a string `type` that is not a `VPNType`. Only name and
    /// order are read besides it; a profile without a type is an old OpenVPN profile, not this.
    public init?(id: String, json data: Data) {
        guard let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
            let type = object["type"] as? String, VPNType(rawValue: type) == nil
        else { return nil }
        self.id = id
        let name = (object["name"] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        self.name = name.isEmpty ? id : name
        self.type = type
        order = object["order"] as? Int ?? 0
    }

    /// The status shown in place of the connection state.
    public static var statusText: String { String(localized: "Needs a newer PassTunnel") }

    public var error: PTError { .unsupportedProfileType(type) }
}
