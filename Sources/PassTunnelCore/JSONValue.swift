import Foundation

/// A JSON value as the MCP server reads it, decoded with `JSONDecoder` on every platform: booleans stay
/// booleans and are never numbers (`JSONSerialization` gives both as `NSNumber`, which only
/// CoreFoundation tells apart, and that is not available outside Apple platforms), and integers keep
/// their exact value.
public enum JSONValue: Equatable, Sendable {
    case null
    case bool(Bool)
    /// A number without a fraction that fits in 64 bits (`1` and `1.0` alike).
    case integer(Int64)
    /// Any other number: with a fraction, or too large for `integer`.
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    /// One JSON text, also a single scalar. Throws when it is not JSON.
    public init(parsing data: Data) throws {
        self = try JSONDecoder().decode(JSONValue.self, from: data)
    }

    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    public var objectValue: [String: JSONValue]? {
        if case .object(let value) = self { return value }
        return nil
    }

    /// The value as `JSONSerialization` writes it, for a reply.
    public var serializable: Any {
        switch self {
        case .null: return NSNull()
        case .bool(let value): return value
        case .integer(let value): return Int(value)
        case .number(let value): return value
        case .string(let value): return value
        case .array(let values): return values.map(\.serializable)
        case .object(let values): return values.mapValues(\.serializable)
        }
    }
}

extension JSONValue: Decodable {
    /// Containers first, so a nested value is decoded once and only a scalar ever goes through a type
    /// that does not fit (each such try costs a thrown error, with the coding path). `JSONDecoder`
    /// refuses a boolean as a number and a number as a boolean on every platform, and a string as
    /// anything else; integers are tried before other numbers, so they stay exact.
    public init(from decoder: Decoder) throws {
        if let object = try? decoder.container(keyedBy: Key.self) {
            var values: [String: JSONValue] = [:]
            for key in object.allKeys { values[key.stringValue] = try object.decode(JSONValue.self, forKey: key) }
            self = .object(values)
        } else if var array = try? decoder.unkeyedContainer() {
            var values: [JSONValue] = []
            while !array.isAtEnd { values.append(try array.decode(JSONValue.self)) }
            self = .array(values)
        } else {
            let container = try decoder.singleValueContainer()
            if container.decodeNil() {
                self = .null
            } else if let value = try? container.decode(String.self) {
                self = .string(value)
            } else if let value = try? container.decode(Bool.self) {
                self = .bool(value)
            } else if let value = try? container.decode(Int64.self) {
                self = .integer(value)
            } else {
                self = .number(try container.decode(Double.self))
            }
        }
    }

    /// Any key of an object.
    private struct Key: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }

        init(stringValue: String) {
            self.stringValue = stringValue
        }

        init?(intValue: Int) {
            return nil
        }
    }
}
