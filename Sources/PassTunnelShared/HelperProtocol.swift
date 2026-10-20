import Foundation

/// XPC interface of the privileged helper. Payloads are JSON (`HelperRequest` → `HelperResponse`)
/// so the Objective-C surface stays tiny and versionable.
@objc public protocol PassTunnelHelperProtocol {
    func version(reply: @escaping (Int) -> Void)
    func perform(_ request: Data, reply: @escaping (Data) -> Void)
}
