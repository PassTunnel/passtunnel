import Foundation
import PassTunnelShared
import os

/// Exported XPC object; one per connection.
final class HelperService: NSObject, PassTunnelHelperProtocol {
    private let supervisor: Supervisor
    private let callerUID: uid_t
    private let buildID: String
    private let buildNumber: Int?

    init(supervisor: Supervisor, callerUID: uid_t, buildID: String, buildNumber: Int?) {
        self.supervisor = supervisor
        self.callerUID = callerUID
        self.buildID = buildID
        self.buildNumber = buildNumber
    }

    func version(reply: @escaping (Int) -> Void) {
        reply(PT.helperProtocolVersion)
    }

    func build(reply: @escaping (String) -> Void) {
        reply(buildID)
    }

    func perform(_ request: Data, reply: @escaping (Data) -> Void) {
        let uid = NSXPCConnection.current()?.effectiveUserIdentifier ?? callerUID
        let send: (HelperResponse) -> Void = { [buildNumber] response in
            var response = response
            response.helperBuild = buildNumber
            reply((try? response.jsonData()) ?? Data(#"{"ok":false,"error":"encoding failed"}"#.utf8))
        }
        let decoded: HelperRequest
        do {
            decoded = try HelperCore.decodeRequest(request)
        } catch {
            return send(.failure(String(describing: error)))
        }
        supervisor.handle(decoded, uid: uid, reply: send)
    }
}

final class ListenerDelegate: NSObject, NSXPCListenerDelegate {
    private let supervisor: Supervisor
    private let buildID: String
    private let buildNumber: Int?
    private let log = Logger(subsystem: PT.helperLabel, category: "xpc")

    init(supervisor: Supervisor, buildID: String, buildNumber: Int?) {
        self.supervisor = supervisor
        self.buildID = buildID
        self.buildNumber = buildNumber
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        // Messages from clients that do not satisfy the requirement invalidate the connection.
        connection.setCodeSigningRequirement(PT.clientRequirement)
        connection.exportedInterface = NSXPCInterface(with: PassTunnelHelperProtocol.self)
        connection.exportedObject = HelperService(
            supervisor: supervisor, callerUID: connection.effectiveUserIdentifier,
            buildID: buildID, buildNumber: buildNumber)
        connection.resume()
        log.info("connection from pid \(connection.processIdentifier), uid \(connection.effectiveUserIdentifier)")
        return true
    }
}
