import Foundation

/// The keys of a stored profile that this version does not know: a newer PassTunnel added them to a type this
/// one knows. They are kept as read and written back on every save (`Profile.encode`), so editing the profile here
/// never drops them (#200). Nothing reads or changes them; they belong to the profile's type as read, so changing
/// `Profile.type` drops them, and share files never carry them (this version cannot check them for the profile an
/// import creates). Keys this version knows are never here, also those it writes only for another type
/// (`usergroup` on an OpenVPN profile), and neither are keys inside `totp`: a newer version adds its keys at the
/// top level (docs/ARCHITECTURE.md, "Keys of a newer version").
public struct UnknownProfileKeys: Equatable {
    /// In key order, the order profile.json is written in. A key is as the decoder hands it (after the key
    /// strategy), so the encoder's strategy writes it back as it was read.
    var members: [Member]

    public init() { members = [] }

    public var isEmpty: Bool { members.isEmpty }

    struct Member: Equatable {
        var key: String
        var value: Value
    }

    /// A JSON value, kept apart by kind (booleans never become numbers) and integers exact.
    indirect enum Value: Equatable, Codable {
        case null
        case bool(Bool)
        case integer(Int64)
        case unsigned(UInt64)
        case number(Double)
        case string(String)
        case array([Value])
        case object([Member])

        init(from decoder: Decoder) throws {
            if let object = try? decoder.container(keyedBy: Key.self) {
                self = .object(try UnknownProfileKeys.members(of: object, excluding: []))
            } else if var array = try? decoder.unkeyedContainer() {
                var values: [Value] = []
                while !array.isAtEnd { values.append(try array.decode(Value.self)) }
                self = .array(values)
            } else {
                let c = try decoder.singleValueContainer()
                if c.decodeNil() {
                    self = .null
                } else if let v = try? c.decode(String.self) {
                    self = .string(v)
                } else if let v = try? c.decode(Bool.self) {
                    self = .bool(v)
                } else if let v = try? c.decode(Int64.self) {
                    self = .integer(v)
                } else if let v = try? c.decode(UInt64.self) {
                    self = .unsigned(v)
                } else {
                    self = .number(try c.decode(Double.self))
                }
            }
        }

        func encode(to encoder: Encoder) throws {
            switch self {
            case .object(let members):
                var c = encoder.container(keyedBy: Key.self)
                for m in members { try c.encode(m.value, forKey: Key(m.key)) }
            case .array(let values):
                var c = encoder.unkeyedContainer()
                for v in values { try c.encode(v) }
            case .null:
                var c = encoder.singleValueContainer()
                try c.encodeNil()
            case .bool(let v):
                var c = encoder.singleValueContainer()
                try c.encode(v)
            case .integer(let v):
                var c = encoder.singleValueContainer()
                try c.encode(v)
            case .unsigned(let v):
                var c = encoder.singleValueContainer()
                try c.encode(v)
            case .number(let v):
                var c = encoder.singleValueContainer()
                try c.encode(v)
            case .string(let v):
                var c = encoder.singleValueContainer()
                try c.encode(v)
            }
        }
    }

    /// Any key of an object.
    struct Key: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init(_ key: String) { stringValue = key }
        init(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }

    /// The keys of `object` that are not `known`, with their values, in key order. A value that cannot be
    /// decoded is left out. So is a key that differs from a known key or an earlier one only in case and
    /// underscores: the snake_case strategy could write both under one name, and a file with a key twice
    /// may not be read again.
    static func members(of object: KeyedDecodingContainer<Key>, excluding known: Set<String>) throws -> [Member] {
        var taken = Set(known.map(fold))
        var out: [Member] = []
        for key in object.allKeys.sorted(by: { $0.stringValue < $1.stringValue }) where !known.contains(key.stringValue) {
            guard taken.insert(fold(key.stringValue)).inserted, let value = try? object.decode(Value.self, forKey: key) else {
                continue
            }
            out.append(Member(key: key.stringValue, value: value))
        }
        return out
    }

    /// `key` without case and underscores, the only things the key strategies change.
    private static func fold(_ key: String) -> String { key.lowercased().filter { $0 != "_" } }

    /// The unknown keys of the object `decoder` holds, next to `known` (a profile's coding keys).
    static func decode(from decoder: Decoder, known: Set<String>) throws -> UnknownProfileKeys {
        var keys = UnknownProfileKeys()
        keys.members = try members(of: try decoder.container(keyedBy: Key.self), excluding: known)
        return keys
    }

    /// Writes the keys into the object `encoder` holds.
    func encode(to encoder: Encoder) throws {
        guard !members.isEmpty else { return }
        var c = encoder.container(keyedBy: Key.self)
        for m in members { try c.encode(m.value, forKey: Key(m.key)) }
    }
}
