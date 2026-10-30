import Foundation
import PassTunnelKit
import PassTunnelShared
import PassTunnelVPNConfig

#if canImport(Glibc)
import Glibc
#endif

/// The answers of a Palo Alto GlobalProtect sign-in, one per line on openconnect's standard input
/// (docs/ARCHITECTURE.md, "The answers, and the second code"), positional like `OpenConnectAnswers`: each line
/// 1–4,095 bytes without LF, CR or NUL.
///
/// - **First part**, written when the run starts: `.separate` → the password, then the code; `.combined` → the
///   composed secret; no code → the password alone.
/// - **Second part**, only with a code from the profile's TOTP secret and without `skip_portal`: the same answers
///   composed with the code of a later TOTP window, written once the run shows the second sign-in (the gateway's
///   prelogin after the portal's configuration) and the first code's window has ended.
public enum GlobalProtectAnswers {
    /// The lines for `password` and `code` as the profile delivers the code (`OTPComposer.compose`).
    public static func lines(password: String, code: String?, delivery: OTPDelivery, template: String) -> [String] {
        let composed = OTPComposer.compose(password: password, otp: code, delivery: delivery, template: template, type: .globalprotect)
        return [composed.secret] + (composed.separateOTP.map { [$0] } ?? [])
    }

    /// Whether the sign-in gets a second part: a code from the profile's TOTP secret, and the portal signed in to.
    public static func hasSecondPart(skipPortal: Bool, totp: Bool) -> Bool { totp && !skipPortal }

    /// When the second part may be written: the end of the TOTP window of the first code (sent at `codeTime`), so
    /// the two codes are of different time steps.
    public static func secondPartNotBefore(codeTime: Date, params: TOTPParams) -> Date {
        let period = TimeInterval(max(1, params.period))
        return Date(timeIntervalSince1970: TimeInterval(TOTP.counter(params: params, at: codeTime) + 1) * period)
    }
}

/// The user's side of connecting a Palo Alto GlobalProtect profile (docs/ARCHITECTURE.md, "Signing in: portal,
/// then gateway"): `openconnect --authenticate` with `protocol gp`, run as the user, signs in to the portal and
/// the gateway it names (or, with `skip_portal`, to the gateway alone) and prints the gateway's session cookie,
/// which alone goes to the helper. Everything of `AnyConnectSignIn` holds (the program, argv, the 0600 file in its
/// own directory, the fixed environment, the limits, the redacted log); this adds:
///
/// - **Standard input in two parts** (`ToolInput`, `GlobalProtectAnswers`): the second part only after the run
///   shows the second sign-in and the first code's window has ended; standard input is closed without it when
///   the run shows that none can follow (`VPNLog.globalProtectSecondPart`).
/// - **The rules of where the sign-in went**: `checkDestination` for the gateway the run ended on, and the
///   two-server rule over the run's requests (`VPNLog.globalProtectRouteIsAllowed`).
/// - **Its failures** (`VPNLog.globalProtectSignInError`): single sign-on, the portal's gateway list, the gateway's
///   key, a server that is not a GlobalProtect one.
///
/// `@unchecked Sendable`: `run` is called once, on a background queue; the runner keeps no state between runs and
/// the second part's closures are called from the runner's thread only.
struct GlobalProtectSignIn: @unchecked Sendable {
    /// The sign-in's time limit without a second part; with one, the profile's TOTP period is added
    /// (`timeout(base:period:)`): the second part may wait for the next window.
    static let defaultTimeout: TimeInterval = AnyConnectSignIn.defaultTimeout

    /// 60 s plus the TOTP period (90 s for 30-second codes) when the sign-in may write a second part.
    static func timeout(base: TimeInterval, secondPartPeriod period: Int?) -> TimeInterval {
        base + TimeInterval(period.map { max(1, $0) } ?? 0)
    }

    /// The fixed text of a sign-in that touched another server than the portal and the gateway it named.
    static let otherServerReason = "The sign-in went to a server other than the profile's and the gateway its portal named."

    var toolPath: String
    var runner: ToolRunning
    var timeout: TimeInterval = defaultTimeout
    var temporaryDirectory: String = NSTemporaryDirectory()
    var caFile: String = OpenConnectConfig.systemCAFile
    var noExternalAuth = true
    /// `disable-ipv6`: a Linux openconnect older than 9.20 (#234); never on the Mac.
    var disableIPv6 = false

    /// The second part of standard input (`GlobalProtectAnswers`).
    ///
    /// `@unchecked Sendable`: its closures are called from the runner's thread only, one at a time.
    struct SecondPart: @unchecked Sendable {
        /// The end of the first code's window: the part is written at this time or later.
        var notBefore: Date
        /// The time now (the manager's clock).
        var now: () -> Date
        /// Makes the answers at `date`, with the code of that time: the lines, and what else of them the log must not
        /// show (the code alone); nil when they cannot be made, which closes standard input instead.
        var answers: (_ date: Date) -> (lines: [String], secrets: [String])?
        /// Records the code of `date` as sent (`.last-otp`), before its answers are handed to the runner, so another
        /// process that connects the profile meanwhile waits for a later window. Called from the runner's thread.
        var record: (_ date: Date) -> Void
    }

    /// How long standard error must have stayed as it is, with openconnect's prompt after the gateway's prelogin, before
    /// the second part is written: openconnect then waits for its answer, and text that only looked like the second
    /// sign-in (the server's, in a message) has been followed by openconnect's next lines.
    static let promptQuietTime: TimeInterval = 1

    /// The second part as it was written.
    final class Written: @unchecked Sendable {
        private let lock = NSLock()
        private var _at: Date?
        private var _secrets: [String] = []

        /// When it was written; nil when it never was.
        var at: Date? {
            lock.lock()
            defer { lock.unlock() }
            return _at
        }

        /// Its lines, to mask in the log.
        var secrets: [String] {
            lock.lock()
            defer { lock.unlock() }
            return _secrets
        }

        func note(_ date: Date, _ secrets: [String]) {
            lock.lock()
            _at = date
            _secrets = secrets
            lock.unlock()
        }
    }

    struct Success {
        var result: OpenConnectAuthResult
        /// The gateway the tunnel goes to (`checkDestination`).
        var destination: OpenConnectAuthResult.Destination
        /// The redacted standard error, for the log.
        var log: String
        /// When the second part was written, nil when it was not.
        var secondPartAt: Date?
    }

    struct Failure: Error {
        var error: Error
        var log: String
        var credentialsSent: Bool
        /// The portal's gateway labels, for `invalidField("gateway")` (`ConnectionFailure.gateways`).
        var gateways: [String]?
        /// A reason for the failure beside the error (`VPNLog.notGlobalProtectServer`).
        var reason: String?
        var secondPartAt: Date?
    }

    /// Runs the sign-in for `config` (`protocol: .gp`) with `answers` (the first part) and `second` on standard
    /// input, and checks where it ended. `secrets`: the answers as text, masked in the log. `server` names the
    /// profile's server in messages. Blocks until the tool has ended: call it off the main thread.
    func run(
        _ config: OpenConnectAuthConfig, answers: [UInt8], second: SecondPart?, secrets: [String], server: String,
        cancellation: ToolCancellation? = nil
    ) -> Result<Success, Failure> {
        let written = Written()
        func failed(_ error: Error, log: String = "", sent: Bool = false, gateways: [String]? = nil, reason: String? = nil)
            -> Result<Success, Failure>
        {
            .failure(Failure(error: error, log: log, credentialsSent: sent, gateways: gateways, reason: reason, secondPartAt: written.at))
        }
        guard config.protocol == .gp else { return failed(PTError.invalidField("type")) }
        let text: String
        do {
            text = try config.render(caFile: caFile, noExternalAuth: noExternalAuth, disableIPv6: disableIPv6)
        } catch {
            return failed(PTError.invalidField(Self.field(of: error)))
        }
        guard FileManager.default.isExecutableFile(atPath: toolPath) else { return failed(PTError.fileError(toolPath)) }

        var template = Array((temporaryDirectory.hasSuffix("/") ? temporaryDirectory : temporaryDirectory + "/").utf8CString)
        template.removeLast()
        template += Array("passtunnel-signin-XXXXXX".utf8CString)
        guard let made = mkdtemp(&template) else { return failed(PTError.fileError(temporaryDirectory)) }
        let directory = String(cString: made)
        let configPath = directory + "/openconnect.conf"
        defer {
            unlink(configPath)
            rmdir(directory)
        }
        do {
            try AnyConnectSignIn.writeNewFile(configPath, Data(text.utf8))
        } catch {
            return failed(error)
        }

        let input = Self.input(answers, second: second, config: config, written: written)
        defer { input.wipeFirst() }
        var output: ToolOutput
        do {
            output = try runner.run(
                toolPath, AnyConnectSignIn.arguments(configPath: configPath), environment: AnyConnectSignIn.environment, input: input,
                timeout: timeout, cancellation: cancellation)
        } catch is ToolCancelled {
            return failed(PTError.connectCancelled)
        } catch let timedOut as ToolTimeout {
            let log = AnyConnectSignIn.log(AnyConnectSignIn.redacted(timedOut.errorOutput, secrets: secrets + written.secrets))
            return failed(PTError.connectTimeout(timedOut.seconds), log: log, sent: true)
        } catch {
            return failed(PTError.fileError(toolPath))
        }
        defer { output.wipe() }

        let stderr = String(decoding: output.errorOutput, as: UTF8.self)
        let sent = output.errorOutputCut || VPNLog.globalProtectCredentialsSent(stderr)
        var stdout = [UInt8](output.output)
        defer { stdout.wipe() }
        let secrets = secrets + written.secrets + AnyConnectSignIn.printedCookieSecrets(stdout) + Self.printedCookieParts(stdout)
        guard output.status == 0 else {
            let redacted = AnyConnectSignIn.redacted(output.errorOutput, secrets: secrets)
            let error = VPNLog.globalProtectSignInError(
                redacted, status: output.status, credentialsSent: sent, gateway: config.gateway, host: config.host, port: config.port,
                server: server)
            var gateways: [String]?
            var reason: String?
            if case .invalidField("gateway") = error { gateways = VPNLog.globalProtectGateways(redacted)?.labels }
            if case .invalidField("host") = error { reason = VPNLog.notGlobalProtectServer }
            return failed(error, log: AnyConnectSignIn.log(redacted), sent: sent, gateways: gateways, reason: reason)
        }
        let result: OpenConnectAuthResult
        do {
            result = try OpenConnectAuthResult.parse(stdout, protocol: .gp)
        } catch {
            let log = AnyConnectSignIn.log(AnyConnectSignIn.redacted(output.errorOutput, secrets: secrets))
            return failed(PTError.signInUnusable(String(describing: error)), log: log, sent: true)
        }
        let log = AnyConnectSignIn.log(AnyConnectSignIn.redacted(output.errorOutput, secrets: secrets + GlobalProtectCookie.secrets(result.cookie)))
        do {
            let destination = try result.checkDestination(
                host: config.host, port: config.port, skipPortal: config.skipPortal, profileServerCert: config.serverCert,
                profileGatewayServerCert: config.gatewayServerCert)
            // Every request of the run, as it came: standard error past what is kept cannot show where it went.
            guard !output.errorOutputCut, VPNLog.globalProtectRouteIsAllowed(stderr, host: config.host, port: config.port, destination: destination)
            else {
                return failed(PTError.signInUnusable(Self.otherServerReason), log: log, sent: true)
            }
            return .success(Success(result: result, destination: destination, log: log, secondPartAt: written.at))
        } catch {
            return failed(PTError.signInUnusable(String(describing: error)), log: log, sent: true)
        }
    }

    /// Standard error's size and when it last changed, for `promptQuietTime`.
    final class Quiet: @unchecked Sendable {
        private var size = -1
        private var since = Date.distantPast

        /// How long standard error has been `size` bytes, at `now`.
        func unchanged(_ size: Int, at now: Date) -> TimeInterval {
            if size != self.size {
                self.size = size
                since = now
            }
            return now.timeIntervalSince(since)
        }
    }

    /// Standard input: `answers` now; with `second`, its answers once the run shows the second sign-in (by
    /// `VPNLog.globalProtectSecondPart`, which also holds the run to the two-server rule so far), openconnect has
    /// waited at its prompt for `promptQuietTime` and the first code's window has ended; standard input is closed after
    /// them, or without them when the run shows none can follow or went elsewhere.
    static func input(_ answers: [UInt8], second: SecondPart?, config: OpenConnectAuthConfig, written: Written) -> ToolInput {
        guard let second else { return ToolInput(answers) }
        let quiet = Quiet()
        return ToolInput(
            answers,
            second: { sink in
                let at = second.now()
                guard let made = second.answers(at), var bytes = try? OpenConnectAnswers.stdin(made.lines) else { return false }
                defer { bytes.wipe() }
                second.record(at)
                written.note(at, made.lines + made.secrets)
                sink.append(contentsOf: bytes)
                return true
            },
            decide: { errorOutput in
                let text = String(decoding: errorOutput, as: UTF8.self)
                switch VPNLog.globalProtectSecondPart(text, gateway: config.gateway, host: config.host, port: config.port) {
                case .pending: return .wait
                case .none: return .close
                case .due:
                    let now = second.now()
                    let waited = quiet.unchanged(errorOutput.count, at: now) >= promptQuietTime
                    return waited && now >= second.notBefore ? .write : .wait
                }
            })
    }

    /// The `authcookie` value of what standard output's `COOKIE='…'` holds, read as `&`-separated arguments without
    /// the parser's rules: a cookie the parser refuses is never used, but the server may have echoed it on standard
    /// error (the whole value is `AnyConnectSignIn.printedCookieSecrets`').
    static func printedCookieParts(_ stdout: [UInt8]) -> [String] {
        AnyConnectSignIn.printedCookieSecrets(stdout).prefix(1).flatMap { cookie -> [String] in
            cookie.split(whereSeparator: { $0 == "&" || $0.isNewline }).compactMap { part in
                guard let eq = part.firstIndex(of: "="), part[..<eq].lowercased() == GlobalProtectCookie.secretKey else { return nil }
                return String(part[part.index(after: eq)...])
            }
        }.filter { !$0.isEmpty }
    }

    /// The profile field a config error is about.
    static func field(of error: Error) -> String {
        switch error as? OpenConnectConfig.ValidationError {
        case .invalidValue(let field, _)?:
            switch field {
            case "gateway": return "gateway"
            case "gateway server certificate": return "gateway_server_cert"
            case "skip portal": return "skip_portal"
            default: return AnyConnectSignIn.field(of: error)
            }
        default:
            let field = AnyConnectSignIn.field(of: error)
            return field == "anyconnect" ? "globalprotect" : field
        }
    }
}
