import Foundation

/// "Copy details" of a failed connect (`ConnectionManager.failureDetails`): plain text in the user's
/// language for their IT team. The profile's name, the server, what went wrong and the tool's words for it,
/// the tries and their times, the network as the system sees it and the app's version; never a password, a
/// code, a user name or a secret. The app puts it on the pasteboard as ordinary text.
public struct FailureDetails: Equatable {
    public var profileName: String
    /// "vpn.example.com:443 (TCP)"; "" when unknown.
    public var server: String
    public var failure: ConnectionFailure
    public var retry: UnreachableRetry?
    public var network: NetworkStatus
    public var app: AppInfo
    /// When the details were taken.
    public var at: Date

    public init(
        profileName: String, server: String, failure: ConnectionFailure, retry: UnreachableRetry? = nil,
        network: NetworkStatus, app: AppInfo, at: Date
    ) {
        self.profileName = profileName
        self.server = server
        self.failure = failure
        self.retry = retry
        self.network = network
        self.app = app
        self.at = at
    }

    public func text(timeZone: TimeZone = .current) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = timeZone
        f.dateFormat = "yyyy-MM-dd HH:mm:ss xxx"
        var lines = ["PassTunnel " + app.version + (app.build.map { " (\($0))" } ?? "")]
        lines.append(String(localized: "Profile: \(profileName)"))
        if !server.isEmpty { lines.append(String(localized: "Server: \(server)")) }
        var result = Self.result(failure.kind)
        if let words = failure.kind == .authRejected ? failure.reply : failure.reason, !words.isEmpty {
            result += " (\(words))"
        }
        lines.append(String(localized: "Result: \(result)"))
        lines.append(
            failure.credentialsSent
                ? String(localized: "Your sign-in reached the server.")
                : String(localized: "Your sign-in was not sent."))
        if failure.codeSent, let left = failure.codeSecondsLeft {
            lines.append(String(localized: "The code was sent with \(left) s left."))
        }
        if let retry {
            lines.append(
                String(
                    localized:
                        "Tries: \(retry.tries), the first at \(f.string(from: retry.firstFailedAt)), the last at \(f.string(from: retry.lastFailedAt))"
                ))
            if let next = retry.nextTryAt {
                lines.append(String(localized: "Next try at \(f.string(from: next))"))
            } else if retry.waitingForNetwork {
                lines.append(String(localized: "Next try when the network is back"))
            }
        } else {
            if let tries = failure.tries, tries > 1 { lines.append(String(localized: "Tries: \(tries)")) }
            lines.append(String(localized: "Failed at \(f.string(from: failure.at))"))
        }
        lines.append(String(localized: "Network: \(network.summary)"))
        return lines.joined(separator: "\n")
    }

    /// What went wrong, in a few words.
    static func result(_ kind: ConnectionFailure.Kind) -> String {
        switch kind {
        case .unreachable: return String(localized: "The server did not answer")
        case .hostNotFound: return String(localized: "The server name was not found")
        case .authRejected: return String(localized: "The server rejected the sign-in")
        case .configuration: return String(localized: "Configuration or certificate refused")
        case .setup: return String(localized: "Network setup failed")
        case .timeout: return String(localized: "Did not connect in time")
        case .cancelled: return String(localized: "Stopped by you")
        case .toolUnsupported: return String(localized: "The VPN tool does not run on this macOS")
        case .failed: return String(localized: "Could not connect")
        }
    }
}
