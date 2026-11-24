// macOS only: the system configuration's dynamic store and the network preferences.
#if os(macOS)
import Foundation
import SystemConfiguration

/// The Mac's DNS as `OpenVPNDNS` sees it (`OpenVPNDNSSystem`): the dynamic store (`SCDynamicStore`) for the
/// services' `Setup:` DNS and the script's `State:` keys, the network preferences (`SCPreferences`, read only)
/// for what a service's DNS is configured as. Reading works for any user (the app's `diagnose`); writing needs
/// root (the helper), and only ever names a key of a checked service ID or `dev`.
public final class MacOpenVPNDNSSystem: OpenVPNDNSSystem {
    let name: String

    /// `name`: how the store and the preferences session are named (the system's logs show it).
    public init(name: String = "PassTunnel") {
        self.name = name
    }

    static let servicePattern = "Setup:/Network/Service/[^/]+/DNS"
    static let backupPattern = "State:/Network/Service/openvpn-[^/]+/DnsBackup"
    static let tunnelPattern = "State:/Network/Service/openvpn-[^/]+/DNS"

    static func serviceKey(_ id: String) -> String { "Setup:/Network/Service/\(id)/DNS" }
    static func backupKey(_ dev: String) -> String { "State:/Network/Service/openvpn-\(dev)/DnsBackup" }
    static func tunnelKey(_ dev: String) -> String { "State:/Network/Service/openvpn-\(dev)/DNS" }

    func store() -> SCDynamicStore? {
        SCDynamicStoreCreate(nil, name as CFString, nil, nil)
    }

    public func serviceDNS() -> [String: DNSEntity]? {
        guard let values = copy(pattern: Self.servicePattern) else { return nil }
        var out: [String: DNSEntity] = [:]
        for (key, value) in values {
            guard let id = Self.part(of: key, prefix: "Setup:/Network/Service/", suffix: "/DNS"), OpenVPNDNS.isServiceID(id) else { continue }
            out[id] = value
        }
        return out
    }

    public func preferencesDNS(service: String) -> OpenVPNDNS.Preferences {
        guard OpenVPNDNS.isServiceID(service), let prefs = SCPreferencesCreate(nil, name as CFString, nil) else { return .unreadable }
        guard SCPreferencesPathGetValue(prefs, "/NetworkServices/\(service)" as CFString) != nil else {
            return SCError() == kSCStatusNoKey ? .none : .unreadable
        }
        guard let value = SCPreferencesPathGetValue(prefs, "/NetworkServices/\(service)/DNS" as CFString) else {
            return SCError() == kSCStatusNoKey ? .none : .unreadable
        }
        return Self.entity(value).map(OpenVPNDNS.Preferences.entity) ?? .unreadable
    }

    public func setServiceDNS(service: String, _ entity: DNSEntity?) -> Bool {
        guard OpenVPNDNS.isServiceID(service), let store = store() else { return false }
        let key = Self.serviceKey(service) as CFString
        guard let entity else { return SCDynamicStoreRemoveValue(store, key) || SCDynamicStoreCopyValue(store, key) == nil }
        return SCDynamicStoreSetValue(store, key, Self.propertyList(.dictionary(entity)))
    }

    public func scriptBackups() -> [String: DNSEntity]? {
        devices(pattern: Self.backupPattern, suffix: "/DnsBackup")
    }

    public func removeScriptBackup(dev: String) -> Bool {
        remove(OpenVPNDNS.isDeviceName(dev) ? Self.backupKey(dev) : nil)
    }

    public func tunnelDNS() -> [String: DNSEntity]? {
        devices(pattern: Self.tunnelPattern, suffix: "/DNS")
    }

    public func removeTunnelDNS(dev: String) -> Bool {
        remove(OpenVPNDNS.isDeviceName(dev) ? Self.tunnelKey(dev) : nil)
    }

    public func interfaceExists(_ name: String) -> Bool {
        if_nametoindex(name) != 0
    }

    public func serviceName(_ service: String) -> String? {
        guard OpenVPNDNS.isServiceID(service), let prefs = SCPreferencesCreate(nil, name as CFString, nil),
            let service = SCNetworkServiceCopy(prefs, service as CFString)
        else { return nil }
        return SCNetworkServiceGetName(service) as String?
    }

    public func primaryService() -> String? {
        guard let store = store(), let value = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString),
            case .string(let id)? = Self.entity(value)?["PrimaryService"], OpenVPNDNS.isServiceID(id)
        else { return nil }
        return id
    }

    public func globalDNSServers() -> [String]? {
        guard let store = store(), let value = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) else { return nil }
        return Self.entity(value)?["ServerAddresses"]?.strings
    }

    // MARK: Store

    /// Every key matching `pattern` with a dictionary value; nil when the store cannot be read (an empty
    /// dictionary is "none there").
    func copy(pattern: String) -> [String: DNSEntity]? {
        guard let store = store(),
            let values = SCDynamicStoreCopyMultiple(store, nil, [pattern] as CFArray) as? [String: Any]
        else { return nil }
        var out: [String: DNSEntity] = [:]
        for (key, value) in values {
            if let entity = Self.entity(value as CFPropertyList) { out[key] = entity }
        }
        return out
    }

    func devices(pattern: String, suffix: String) -> [String: DNSEntity]? {
        guard let values = copy(pattern: pattern) else { return nil }
        var out: [String: DNSEntity] = [:]
        for (key, value) in values {
            guard let dev = Self.part(of: key, prefix: "State:/Network/Service/openvpn-", suffix: suffix), OpenVPNDNS.isDeviceName(dev)
            else { continue }
            out[dev] = value
        }
        return out
    }

    /// Removes `key`; true also when it was not there.
    func remove(_ key: String?) -> Bool {
        guard let key, let store = store() else { return false }
        return SCDynamicStoreRemoveValue(store, key as CFString) || SCDynamicStoreCopyValue(store, key as CFString) == nil
    }

    static func part(of key: String, prefix: String, suffix: String) -> String? {
        guard key.hasPrefix(prefix), key.hasSuffix(suffix), key.count > prefix.count + suffix.count else { return nil }
        return String(key.dropFirst(prefix.count).dropLast(suffix.count))
    }

    // MARK: Property lists

    static func entity(_ value: CFPropertyList) -> DNSEntity? {
        guard case .dictionary(let d)? = plist(value) else { return nil }
        return d
    }

    static func plist(_ value: Any) -> PlistValue? {
        let cf = value as AnyObject
        let type = CFGetTypeID(cf)
        if type == CFStringGetTypeID() { return .string(value as! String) }
        if type == CFBooleanGetTypeID() { return .bool(CFBooleanGetValue((cf as! CFBoolean))) }
        if type == CFNumberGetTypeID() {
            let n = cf as! CFNumber
            if CFNumberIsFloatType(n) { return .real((value as! NSNumber).doubleValue) }
            return .integer((value as! NSNumber).intValue)
        }
        if type == CFDataGetTypeID() { return .data(value as! Data) }
        if type == CFDateGetTypeID() { return .date(value as! Date) }
        if type == CFArrayGetTypeID() {
            var out: [PlistValue] = []
            for item in value as! [Any] {
                guard let v = plist(item) else { return nil }
                out.append(v)
            }
            return .array(out)
        }
        if type == CFDictionaryGetTypeID() {
            guard let d = value as? [String: Any] else { return nil }
            var out: [String: PlistValue] = [:]
            for (k, item) in d {
                guard let v = plist(item) else { return nil }
                out[k] = v
            }
            return .dictionary(out)
        }
        return nil
    }

    static func propertyList(_ value: PlistValue) -> CFPropertyList {
        switch value {
        case .string(let s): return s as NSString
        case .integer(let n): return NSNumber(value: n)
        case .real(let d): return NSNumber(value: d)
        case .bool(let b): return (b ? kCFBooleanTrue : kCFBooleanFalse)!
        case .data(let d): return d as NSData
        case .date(let d): return d as NSDate
        case .array(let items): return items.map(propertyList) as NSArray
        case .dictionary(let d):
            let out = NSMutableDictionary()
            for (k, v) in d { out[k] = propertyList(v) }
            return out
        }
    }
}
#endif
