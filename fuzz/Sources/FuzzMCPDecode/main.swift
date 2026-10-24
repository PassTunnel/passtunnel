import Foundation
import FuzzSupport
import PassTunnelCore

// Fuzzes the decoding of one MCP (JSON-RPC 2.0) request line, as `MCPServer.receive` does on
// untrusted stdin: decode the bytes as a `JSONValue` (the server's decoder, which keeps booleans apart
// from numbers on every platform), take the object apart, classify the `id` with the server's own
// validity rule (the part most exposed to odd numbers: booleans, fractions, huge integers) and write a
// valid one back the way a reply does. Property: it never crashes or hangs on any bytes.
@_cdecl("LLVMFuzzerTestOneInput")
func LLVMFuzzerTestOneInput(_ data: UnsafePointer<UInt8>?, _ size: Int) -> CInt {
    let line = fuzzData(data, size)
    guard let json = try? JSONValue(parsing: line), let object = json.objectValue else { return 0 }

    _ = object["jsonrpc"]?.stringValue
    _ = object["method"]?.stringValue
    if let id = object["id"], MCPServer.isValidID(id) {
        _ = MCPServer.key(id)
        _ = try? JSONSerialization.data(withJSONObject: ["id": id.serializable], options: [.sortedKeys])
    }
    if let params = object["params"]?.objectValue {
        _ = params["_meta"]?.objectValue
        _ = params["arguments"]?.objectValue?.mapValues(\.serializable)
    }
    return 0
}

runFuzzer(LLVMFuzzerTestOneInput)
