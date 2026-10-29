import Foundation
import PassTunnelKit
import PassTunnelShared
import PassTunnelVPNConfig

#if canImport(Glibc)
import Glibc
#endif

/// The user's side of connecting a Cisco AnyConnect profile (docs/ARCHITECTURE.md, "Authentication, split
/// from the tunnel"): `openconnect --authenticate`, run as the user, signs in with the password and the code
/// and prints the session cookie, which alone goes to the helper. Root never holds the password or the code,
/// nor parses the server's sign-in forms.
///
/// - **Program:** the app bundle's `openconnect` on the Mac; on Linux the distribution's, from its fixed paths
///   and checked as the daemon checks it (`ToolSpec.openconnect`: `TrustedPath`, 9.01 or later), never from
///   `PATH` (`distributionTool`). With exactly `["--config=<file>", "--authenticate"]`: nothing else in argv,
///   which every local user can read.
/// - **Config file:** rendered and checked by `OpenConnectAuthConfig` (the user name is only here), written
///   0600 into a directory of its own (0700, made for the run in the user's temporary directory) and
///   removed, with the directory, after the run whatever happened.
/// - **Environment:** exactly `HelperCore.environment(for: .openconnect)`, the tunnel run's fixed list
///   (`LC_ALL=C`, `GNUTLS_SYSTEM_PRIORITY_FILE=/dev/null`, `P11_KIT_NO_USER_CONFIG=1`, …), never this
///   process's: no proxy, key log or debug variable reaches it.
/// - **Standard input:** the answers (`OpenConnectAnswers`: the password, then the code; or the composed
///   secret), one per line; the buffers are overwritten after the run.
/// - **Limits:** a deadline (`timeout`; the tool is stopped then), and output kept up to
///   `SystemToolRunner.maxOutput` per stream; standard output is parsed only when it is at most
///   `OpenConnectAuthResult.maxOutputBytes`.
/// - **Output:** standard output, which holds the cookie, is read only by `OpenConnectAuthResult.parse` and
///   overwritten after it; it is never logged. Standard error (openconnect's progress in this mode) is read
///   whole for whether a form was submitted (`VPNLog.openConnectCredentialsSent`; when the run timed out or
///   standard error went past what is kept, the code counts as sent), then passed through `LogRedactor`
///   with the answers and the cookie as literal secrets, and only then cut to `maxLogBytes` for the log.
///
/// `@unchecked Sendable`: `run` is called once, on a background queue; the runner it holds
/// (`SystemToolRunner`, or a test's fake) keeps no state between runs.
struct AnyConnectSignIn: @unchecked Sendable {
    /// The longest a sign-in may take: openconnect follows the server's redirects and forms in this time.
    static let defaultTimeout: TimeInterval = 60
    /// The most of standard error written to the log.
    static let maxLogBytes = 64 * 1024

    var toolPath: String
    var runner: ToolRunning
    var timeout: TimeInterval = defaultTimeout
    /// Where the run's private directory is made (the user's temporary directory).
    var temporaryDirectory: String = NSTemporaryDirectory()
    /// The system CA bundle the server is checked against when the profile has no pin.
    var caFile: String = OpenConnectConfig.systemCAFile
    /// `no-external-auth`: the Mac's bundled openconnect 9.21 has it (9.10 and later).
    var noExternalAuth = true

    /// The tool's arguments: the config file and the mode, nothing else.
    static func arguments(configPath: String) -> [String] { ["--config=" + configPath, "--authenticate"] }

    /// The tool's complete environment (`HelperCore.environment(for: .openconnect)`).
    static var environment: [String: String] {
        var env: [String: String] = [:]
        for item in HelperCore.environment(for: .openconnect) {
            guard let eq = item.firstIndex(of: "=") else { continue }
            env[String(item[..<eq])] = String(item[item.index(after: eq)...])
        }
        return env
    }

    /// The openconnect a sign-in runs, with what the file it reads depends on: the CA bundle the server is
    /// checked against without a pin, and whether the tool knows `no-external-auth`.
    struct Tool: Equatable {
        var path: String
        var caFile: String = OpenConnectConfig.systemCAFile
        var noExternalAuth = true
    }

    /// `distributionTool` (or a test's stand-in) with its runner, run once on a background queue.
    /// `@unchecked Sendable` as `AnyConnectSignIn` is: the runner keeps no state between runs.
    struct Lookup: @unchecked Sendable {
        var locate: (ToolRunning) throws -> Tool
        var runner: ToolRunning

        func run() -> Result<Tool, Error> { Result { try locate(runner) } }
    }

    /// How long `openconnect --version` and `--help` may take.
    static let probeTimeout: TimeInterval = 5

    /// Linux: the distribution's openconnect (docs/LINUX.md, "Cisco AnyConnect"): the first of
    /// `ToolSpec.openconnect`'s fixed paths, resolved and checked (`TrustedPath`) and run for its version, which
    /// must be 9.01 or later; `--help` tells whether it has `no-external-auth` (9.10 and later), which the file
    /// then names; and the distribution's CA bundle, checked as the daemon checks it. Run as the user, before any
    /// code is used: a tool that is missing, untrusted or too old is `PTError.anyConnectToolUnavailable` with the
    /// reason. Elsewhere there is no distribution tool (`PTError.fileError`).
    static func distributionTool(runner: ToolRunning) throws -> Tool {
        #if os(Linux)
        func output(_ path: String, _ arguments: [String]) -> String? {
            guard let run = try? runner.run(path, arguments, environment: environment, input: Data(), timeout: probeTimeout) else {
                return nil
            }
            return String(decoding: run.output + run.errorOutput, as: UTF8.self)
        }
        do {
            let tool = try DistributionTools.resolve(.openconnect, versionOutput: output)
            let help = output(tool.path, ToolSpec.helpArguments) ?? ""
            return Tool(
                path: tool.path, caFile: try DistributionTools.caBundle(),
                noExternalAuth: ToolSpec.openConnectHasNoExternalAuth(help: help))
        } catch let failure as ToolFailure {
            throw PTError.anyConnectToolUnavailable(failure.description)
        }
        #else
        throw PTError.fileError("openconnect")
        #endif
    }

    /// The app bundle's openconnect (`Contents/Resources/bin/openconnect`); nil outside an app bundle and on
    /// Linux.
    static func bundledTool(app: AppInfo = .current) -> String? {
        #if os(macOS)
        guard app.appPath.hasSuffix(".app") else { return nil }
        return app.appPath + "/Contents/Resources/bin/" + HelperCore.Tool.openconnect.rawValue
        #else
        return nil
        #endif
    }

    /// A sign-in that ended with a cookie at the profile's server.
    struct Success {
        var result: OpenConnectAuthResult
        /// `resolve` for the tunnel run: the sign-in's `RESOLVE` for a host name, nil for an IP address.
        var resolve: String?
        /// The redacted standard error, for the log.
        var log: String
    }

    /// A sign-in that did not: why (a `PTError` that names no value of the server's), the log, and whether the
    /// credentials can have left this computer (`VPNLog.openConnectCredentialsSent`; true once the server
    /// handed out a cookie).
    struct Failure: Error {
        var error: Error
        var log: String
        var credentialsSent: Bool
    }

    /// Runs the sign-in for `config` with `answers` on standard input (overwritten by the caller), and checks
    /// that it ended at the profile's server (`OpenConnectAuthResult.checkDestination`). `secrets`: the
    /// answers as text, masked in the log. `server` names the server in messages. Blocks until the tool has
    /// ended: call it off the main thread.
    func run(
        _ config: OpenConnectAuthConfig, answers: [UInt8], secrets: [String], server: String,
        cancellation: ToolCancellation? = nil
    ) -> Result<Success, Failure> {
        func failed(_ error: Error, log: String = "", sent: Bool = false) -> Result<Success, Failure> {
            .failure(Failure(error: error, log: log, credentialsSent: sent))
        }
        let text: String
        do {
            text = try config.render(caFile: caFile, noExternalAuth: noExternalAuth)
        } catch {
            return failed(PTError.invalidField(Self.field(of: error)))
        }
        guard FileManager.default.isExecutableFile(atPath: toolPath) else { return failed(PTError.fileError(toolPath)) }

        // A directory only this user can enter, for the file only this user can read.
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
            try Self.writeNewFile(configPath, Data(text.utf8))
        } catch {
            return failed(error)
        }

        var input = Data(answers)
        defer { input.wipe() }
        var output: ToolOutput
        do {
            output = try runner.run(
                toolPath, Self.arguments(configPath: configPath), environment: Self.environment, input: input,
                timeout: timeout, cancellation: cancellation)
        } catch is ToolCancelled {
            return failed(PTError.connectCancelled)
        } catch let timedOut as ToolTimeout {
            // Stopped part-way: what it did last is not known, so the code counts as sent.
            let log = Self.log(Self.redacted(timedOut.errorOutput, secrets: secrets))
            return failed(PTError.connectTimeout(timedOut.seconds), log: log, sent: true)
        } catch {
            return failed(PTError.fileError(toolPath))
        }
        defer { output.wipe() }

        // Over the whole of standard error as it came, before redaction and the log's limit; output beyond what
        // was kept is evidence missing, so the code counts as sent.
        let sent = output.errorOutputCut || VPNLog.openConnectCredentialsSent(String(decoding: output.errorOutput, as: UTF8.self))
        var stdout = [UInt8](output.output)
        defer { stdout.wipe() }
        // Whatever COOKIE holds, read apart from the parser, so a cookie it refuses is masked too when the server
        // repeats it on standard error.
        let secrets = secrets + Self.printedCookieSecrets(stdout)
        guard output.status == 0 else {
            let text = Self.redacted(output.errorOutput, secrets: secrets)
            let error = VPNLog.openConnectSignInError(
                text, status: output.status, credentialsSent: sent, authgroup: config.authgroup, server: server)
            return failed(error, log: Self.log(text), sent: sent)
        }
        // A cookie was handed out: the credentials reached the server whatever happens next.
        let result: OpenConnectAuthResult
        do {
            result = try OpenConnectAuthResult.parse(stdout)
        } catch {
            // Its description names keys and rules, never a value.
            let log = Self.log(Self.redacted(output.errorOutput, secrets: secrets))
            return failed(PTError.signInUnusable(String(describing: error)), log: log, sent: true)
        }
        // The cookie as printed, under its name, and each part of it (the STRAP key, the `webvpn` value).
        let cookieSecrets = OpenConnectCookie.secrets(result.cookie) + OpenConnectCookie.secrets(result.tunnelCookie)
        let log = Self.log(Self.redacted(output.errorOutput, secrets: secrets + cookieSecrets))
        do {
            let address = try result.checkDestination(host: config.host, port: config.port, profileServerCert: config.serverCert)
            return .success(Success(result: result, resolve: address == nil ? nil : result.resolve, log: log))
        } catch {
            return failed(PTError.signInUnusable(String(describing: error)), log: log, sent: true)
        }
    }

    /// What standard output's `COOKIE='…'` holds, as literal secrets, without the parser's rules: the value up to
    /// its closing quote (or the end), each of its lines, each `;`-separated part (blanks around it dropped) and
    /// what follows a part's first `=` (a cookie's value under any name, a STRAP key). For the log only: a
    /// cookie the parser refuses is never used, but the server may have echoed it.
    static func printedCookieSecrets(_ stdout: [UInt8]) -> [String] {
        let start = Array("COOKIE='".utf8)
        guard let at = stdout.indices.first(where: { stdout[$0...].starts(with: start) && ($0 == 0 || stdout[$0 - 1] == 0x0A) })
        else { return [] }
        let from = at + start.count
        let to = stdout[from...].firstIndex(of: UInt8(ascii: "'")) ?? stdout.endIndex
        let value = String(decoding: stdout[from..<to], as: UTF8.self)
        var out = [value]
        for line in value.split(whereSeparator: \.isNewline) {
            out.append(String(line))
            for part in line.split(separator: ";") {
                let part = part.trimmingCharacters(in: .whitespaces)
                out.append(part)
                if let eq = part.firstIndex(of: "=") { out.append(String(part[part.index(after: eq)...])) }
            }
        }
        return out.filter { !$0.isEmpty }
    }

    /// The whole of standard error, each line (split at LF) through `LogRedactor` with `secrets` as literal
    /// values: before anything is cut, so a secret is never left in part at a cut.
    static func redacted(_ errorOutput: Data, secrets: [String]) -> String {
        let redactor = LogRedactor(secrets: secrets)
        return String(decoding: errorOutput, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: false)
            .map { redactor.redact(String($0)) }.joined(separator: "\n")
    }

    /// Redacted text as the log: complete lines only, at most `maxLogBytes`. What follows the last line break
    /// (a line the tool had not finished, at the end or at the cut) is dropped, never stored.
    static func log(_ redacted: String) -> String {
        var bytes = Array(redacted.utf8.prefix(maxLogBytes))
        bytes = Array(bytes[..<(bytes.lastIndex(of: 0x0A).map { $0 + 1 } ?? 0)])
        return String(decoding: bytes, as: UTF8.self)
    }

    /// The profile field a config error is about.
    static func field(of error: Error) -> String {
        switch error as? OpenConnectConfig.ValidationError {
        case .invalidHost?: return "host"
        case .invalidPort?: return "port"
        case .invalidServerCert?: return "server_cert"
        case .invalidValue(let field, _)?:
            switch field {
            case "user name": return "username"
            case "group": return "authgroup"
            case "user group": return "usergroup"
            default: return field
            }
        default: return "anyconnect"
        }
    }

    /// Creates `path` (it must not exist; never follows a link) with `data`, 0600.
    static func writeNewFile(_ path: String, _ data: Data) throws {
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw PTError.fileError(path) }
        defer { close(fd) }
        guard fchmod(fd, 0o600) == 0 else { throw PTError.fileError(path) }
        let ok = data.withUnsafeBytes { buf -> Bool in
            var offset = 0
            while offset < buf.count {
                let n = write(fd, buf.baseAddress! + offset, buf.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    return false
                }
                offset += n
            }
            return true
        }
        guard ok else { throw PTError.fileError(path) }
    }
}

extension Array where Element == UInt8 {
    /// Overwrites the bytes with zeros (best effort: copies made earlier are not reached).
    mutating func wipe() {
        _ = withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) }
    }
}

/// Secret bytes in one place, so they can be overwritten where they are (an array passed around by value
/// could be copied on write first).
final class SecretBytes: @unchecked Sendable {
    private(set) var bytes: [UInt8]

    init(_ bytes: [UInt8]) { self.bytes = bytes }

    /// Overwrites them with zeros (best effort: copies made earlier, such as the tool's input buffer, are
    /// overwritten by their owners).
    func wipe() { bytes.wipe() }
}
