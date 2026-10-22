import Foundation
import FuzzSupport
import PassTunnelCore

// Fuzzes the decoding of one MCP (JSON-RPC 2.0) request line, as `MCPServer.receive` does on
// untrusted stdin: parse the bytes as a JSON object, then classify the `id` with the server's own
// validity rule (the part most exposed to odd `NSNumber` values: booleans, fractions, huge
// integers). Property: it never crashes or hangs on any bytes.
@_cdecl("LLVMFuzzerTestOneInput")
func LLVMFuzzerTestOneInput(_ data: UnsafePointer<UInt8>?, _ size: Int) -> CInt {
    let line = fuzzData(data, size)
    guard let json = try? JSONSerialization.jsonObject(with: line, options: [.fragmentsAllowed]),
          let object = json as? [String: Any] else { return 0 }

    _ = object["jsonrpc"] as? String
    _ = object["method"] as? String
    if let id = object["id"], MCPServer.isValidID(id) {
        _ = MCPServer.key(id)
    }
    return 0
}

runFuzzer(LLVMFuzzerTestOneInput)
