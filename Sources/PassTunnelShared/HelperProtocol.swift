// macOS only: the XPC interface (Objective-C).
#if os(macOS)
import Foundation

/// XPC interface of the privileged helper. Payloads are JSON (`HelperRequest` → `HelperResponse`)
/// so the Objective-C surface stays tiny and versionable.
@objc public protocol PassTunnelHelperProtocol {
    func version(reply: @escaping (Int) -> Void)
    /// Build identity (`HelperBuild`) of the running helper. Protocol 3 and later; ask only after
    /// `version` matched, an older helper does not implement it.
    func build(reply: @escaping (String) -> Void)
    func perform(_ request: Data, reply: @escaping (Data) -> Void)
}
#endif
