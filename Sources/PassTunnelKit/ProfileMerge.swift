import Foundation

/// Three-way merge of profile edits: only the fields that differ between the copy an editor started
/// from (`original`) and what it holds now (`edited`) are applied to the stored profile (`current`),
/// so changes made elsewhere meanwhile (CLI, reordering, connecting) survive a Save. Nested objects
/// such as `totp` merge field by field. Works on the encoded form, so new fields are covered too.
/// The keys a newer version added (`Profile.unknownKeys`) are no editor's: the merged profile has the stored
/// profile's, unless the edit changed the type (then none, as for any change of the type).
public enum ProfileMerge {
    /// Encoded keys (dotted for nested ones, e.g. `totp.digits`) that differ between the two.
    public static func changedFields(from original: Profile, to edited: Profile) throws -> [String] {
        var out: [String] = []
        collectChanges(try object(original), try object(edited), prefix: "", into: &out)
        return out.sorted()
    }

    /// `current` with every field changed from `original` to `edited` set to the edited value.
    /// The ID is always the current one, and so are the unknown keys when the type stays the current one.
    public static func merge(original: Profile, edited: Profile, current: Profile) throws -> Profile {
        let merged = mergeObjects(try object(original), try object(edited), try object(current))
        let data = try JSONSerialization.data(withJSONObject: merged)
        var p = try JSONCoding.decode(Profile.self, from: data, name: "profile.json")
        p.id = current.id
        if p.type == current.type { p.unknownKeys = current.unknownKeys }
        return p
    }

    /// The encoded profile without its unknown keys.
    static func object(_ p: Profile) throws -> [String: Any] {
        let data = try JSONCoding.encode(p, userInfo: [.passTunnelOmitUnknownKeys: true])
        guard let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw PTError.invalidFile("profile.json")
        }
        return dict
    }

    private static func mergeObjects(
        _ original: [String: Any], _ edited: [String: Any],
        _ current: [String: Any]
    ) -> [String: Any] {
        var out = current
        for key in Set(original.keys).union(edited.keys) {
            let o = original[key], e = edited[key]
            if let od = o as? [String: Any], let ed = e as? [String: Any], let cd = current[key] as? [String: Any] {
                out[key] = mergeObjects(od, ed, cd)
            } else if !same(o, e) {
                out[key] = e  // nil removes the key (an optional field cleared in the editor)
            }
        }
        return out
    }

    private static func collectChanges(
        _ original: [String: Any], _ edited: [String: Any], prefix: String,
        into out: inout [String]
    ) {
        for key in Set(original.keys).union(edited.keys) {
            let o = original[key], e = edited[key]
            if let od = o as? [String: Any], let ed = e as? [String: Any] {
                collectChanges(od, ed, prefix: prefix + key + ".", into: &out)
            } else if !same(o, e) {
                out.append(prefix + key)
            }
        }
    }

    private static func same(_ a: Any?, _ b: Any?) -> Bool {
        switch (a, b) {
        case (nil, nil): return true
        case let (a?, b?): return isEqual(a, b)
        default: return false
        }
    }

    #if canImport(ObjectiveC)
    private static func isEqual(_ a: Any, _ b: Any) -> Bool { (a as AnyObject).isEqual(b) }
    #else
    /// `isEqual` as on Apple platforms, without Objective-C bridging, for what `JSONSerialization`
    /// returns: strings (compared like NSString, by UTF-16 code unit), NSNumber, NSNull and objects.
    private static func isEqual(_ a: Any, _ b: Any) -> Bool {
        switch (a, b) {
        case let (a as String, b as String):
            return a.utf16.elementsEqual(b.utf16)
        case let (a as [String: Any], b as [String: Any]):
            return a.count == b.count && a.allSatisfy { key, value in b[key].map { isEqual(value, $0) } ?? false }
        case let (a as NSObject, b as NSObject):
            return a.isEqual(b)
        default:
            return false
        }
    }
    #endif
}
