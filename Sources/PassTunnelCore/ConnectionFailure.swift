import Foundation
import PassTunnelKit

/// Why a connect failed, typed: `ConnectionManager.failures`, the `failure` object of `status --json`, of a
/// failed `connect --json` (`ErrorReport`) and of the MCP tools. Worked out from the error and, once the
/// VPN tool ran, from its log (`VPNLog.verdict`), the same way for OpenVPN and openfortivpn on the Mac and
/// on Linux.
public struct ConnectionFailure: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, CaseIterable, Sendable {
        /// The server refused the sign-in (OpenVPN `AUTH_FAILED`, openfortivpn "Could not authenticate").
        /// Never retried: retrying could lock the account.
        case authRejected = "auth_rejected"
        /// The server's name could not be resolved.
        case hostNotFound = "host_not_found"
        /// The server did not answer: connection refused or timed out, no route, no TLS answer in time.
        case unreachable
        /// The configuration, a key or the server's certificate was refused, or something the profile
        /// needs is missing (password, TOTP secret, configuration file, server address).
        case configuration
        /// The tunnel came up, but its network setup failed (DNS, the routes that take all traffic).
        case setup
        /// The server took the sign-in but the tunnel did not come up in time.
        case timeout
        /// Stopped before it finished (a disconnect, Ctrl-C, a cancelled confirmation).
        case cancelled
        /// Anything else (the helper refused, the tool exited without a reason PassTunnel knows).
        case failed
    }

    public var kind: Kind
    public var at: Date
    /// authRejected: what the server answered ("AUTH_FAILED,Invalid OTP"), when it said anything.
    public var reply: String?
    /// The tool's own words for a network or configuration failure ("Connection refused").
    public var reason: String?
    /// The credentials reached the server: the TLS session with it came up (OpenVPN "Control Channel",
    /// openfortivpn "Connected to gateway"), or it answered the sign-in.
    public var credentialsSent: Bool
    /// A one-time code went to the server with them (so its period is used up).
    public var codeSent: Bool
    /// That code's seconds left when it was handed to the VPN tool ("Sent with 22 s left").
    public var codeSecondsLeft: Int?
    /// unreachable: how many tries the log shows.
    public var tries: Int?

    public init(kind: Kind, at: Date, reply: String? = nil, reason: String? = nil, credentialsSent: Bool = false,
                codeSent: Bool = false, codeSecondsLeft: Int? = nil, tries: Int? = nil) {
        self.kind = kind
        self.at = at
        self.reply = reply
        self.reason = reason
        self.credentialsSent = credentialsSent
        self.codeSent = codeSent
        self.codeSecondsLeft = codeSecondsLeft
        self.tries = tries
    }

    /// What was handed to the VPN tool before the attempt failed.
    public struct Handed: Equatable, Sendable {
        /// A one-time code was among it.
        public var code: Bool
        /// The code's seconds left then (TOTP).
        public var codeSecondsLeft: Int?

        public init(code: Bool, codeSecondsLeft: Int? = nil) {
            self.code = code
            self.codeSecondsLeft = codeSecondsLeft
        }
    }

    /// Why `error` ended a connect. `log`: the VPN tool's log when the attempt got as far as starting it
    /// (nil before, when the log would be an older session's); `handed`: what the tool was given.
    public static func of(_ error: Error, log: String?, handed: Handed?, at: Date) -> ConnectionFailure {
        let sent = log.map(VPNLog.credentialsSent) ?? false
        var f = ConnectionFailure(kind: .failed, at: at, credentialsSent: sent)
        let verdict = log.flatMap(VPNLog.verdict)
        if let verdict {
            f.reason = verdict.reason
            if verdict.kind == .unreachable, let log { f.tries = VPNLog.tries(log) }
        }
        switch error {
        case PTError.authFailed:
            f.kind = .authRejected
            f.reason = nil
            f.reply = log.flatMap(VPNLog.authFailureReply)
            f.credentialsSent = true
        case PTError.serverUnreachable(_, let reason, _):
            f.kind = .unreachable
            f.reason = reason
            f.tries = f.tries ?? log.map(VPNLog.tries)
        case PTError.hostNotFound:
            f.kind = .hostNotFound
        case PTError.setupFailed(let reason, _):
            f.kind = .setup
            f.reason = reason
            f.credentialsSent = true
        case PTError.connectTimeout:
            f.kind = sent ? .timeout : verdict?.kind ?? .timeout
        case PTError.connectFailed:
            f.kind = verdict?.kind ?? .failed
        case PTError.connectCancelled, PTError.userConfirmationCancelled, is CancellationError:
            f.kind = .cancelled
        case PTError.missingConfig, PTError.missingHost, PTError.missingPassword, PTError.missingTOTPSecret,
             PTError.missingCredential, PTError.invalidField, PTError.usernameTooLong, PTError.invalidSecret,
             PTError.invalidFile, PTError.ovpnNotAllowed, PTError.ovpnReferencedFile, PTError.protectedSecretUnreadable:
            f.kind = .configuration
        default:
            f.kind = .failed
        }
        if f.kind == .authRejected { f.tries = nil }
        if f.kind != .unreachable { f.tries = nil }
        f.codeSent = f.credentialsSent && handed?.code == true
        f.codeSecondsLeft = f.codeSent ? handed?.codeSecondsLeft : nil
        return f
    }

    /// The facts behind it, worded for the CLI ("The code was sent with 22 s left."); nil when there
    /// is nothing to add to the error's message.
    public var details: String? {
        var parts: [String] = []
        switch kind {
        case .authRejected:
            if let reply, !reply.isEmpty { parts.append(String(localized: "The server answered: \(reply).")) }
            if codeSent, let left = codeSecondsLeft { parts.append(String(localized: "The code was sent with \(left) s left.")) }
            parts.append(String(localized: "Not retried, to avoid a lockout."))
        case .unreachable, .hostNotFound:
            if let tries, tries > 1 { parts.append(String(localized: "No answer after \(tries) tries.")) }
        case .failed:
            if !credentialsSent { parts.append(String(localized: "Your sign-in was not sent.")) }
        case .configuration, .setup, .timeout, .cancelled:
            break
        }
        return parts.isEmpty ? nil : parts.joined(separator: " ")
    }
}
