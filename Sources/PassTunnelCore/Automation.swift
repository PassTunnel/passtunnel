#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto   // swift-crypto: the same API, outside Apple platforms
#endif
import Foundation
import PassTunnelKit
import PassTunnelShared

// The structured layer shared by `passtunnel … --json` and the MCP server (`passtunnel mcp`): result
// objects, stable error codes and exit codes. Both front ends build their output from these types,
// so a script and an assistant see the same objects. None of them carries a secret: no password,
// TOTP secret, code, key or configuration file content.

// MARK: - Exit and error codes

/// Exit codes of the `passtunnel` command (docs/CLI-JSON.md).
public enum AutomationExit {
    public static let ok: Int32 = 0
    public static let error: Int32 = 1
    public static let usage: Int32 = 2
    /// No such profile, or (`status ID`) the profile is not connected.
    public static let notFound: Int32 = 3
    /// A confirmation or input was needed but was cancelled or cannot be given.
    public static let confirmation: Int32 = 4
    /// The helper is not installed, not approved, outdated or not answering.
    public static let helper: Int32 = 5
    public static let connectFailed: Int32 = 6
    public static let timeout: Int32 = 7
    public static let interrupted: Int32 = 130
}

/// Stable, snake_case error codes of `{"error":{"code":…,"message":…}}` and MCP tool errors.
public enum AutomationErrorCode: String, Codable, CaseIterable, Sendable {
    case invalidArgument = "invalid_argument"
    case profileNotFound = "profile_not_found"
    case notConnected = "not_connected"
    case inputRequired = "input_required"
    case cancelled
    case authCancelled = "auth_cancelled"
    case authUnavailable = "auth_unavailable"
    case helperNotInstalled = "helper_not_installed"
    case helperOutdated = "helper_outdated"
    case helperUnavailable = "helper_unavailable"
    case connectFailed = "connect_failed"
    case serverUnreachable = "server_unreachable"
    case hostNotFound = "host_not_found"
    case credentialsRejected = "credentials_rejected"
    case credentialsMissing = "credentials_missing"
    case otherVPNActive = "other_vpn_active"
    case destinationChanged = "destination_changed"
    case timeout
    case configInvalid = "config_invalid"
    case fileError = "file_error"
    case keychainError = "keychain_error"
    case `internal`

    public var exitCode: Int32 {
        switch self {
        case .invalidArgument: return AutomationExit.usage
        case .profileNotFound, .notConnected: return AutomationExit.notFound
        case .inputRequired, .cancelled, .authCancelled, .authUnavailable: return AutomationExit.confirmation
        case .helperNotInstalled, .helperOutdated, .helperUnavailable: return AutomationExit.helper
        case .connectFailed, .serverUnreachable, .hostNotFound, .credentialsRejected, .credentialsMissing, .otherVPNActive,
             .destinationChanged:
            return AutomationExit.connectFailed
        case .timeout: return AutomationExit.timeout
        case .configInvalid, .fileError, .keychainError, .internal: return AutomationExit.error
        }
    }

    /// The code for any error PassTunnel throws.
    public static func of(_ error: Error) -> AutomationErrorCode {
        switch error {
        case let e as AutomationError: return e.code
        case let e as ConnectFailedError: return of(e.error)
        case is CLIUsageError: return .invalidArgument
        case is DestinationChangedError: return .destinationChanged
        case is ProtectionKeyMismatch, is ProtectionKeyUnusable, is SecretStoreUnavailable: return .keychainError
        case is CancellationError: return .cancelled
        case let e as HelperClientError:
            switch e {
            case .notInstalled, .requiresApproval, .notFound: return .helperNotInstalled
            case .versionMismatch, .buildMismatch: return .helperOutdated
            case .unavailable, .timeout, .badResponse: return .helperUnavailable
            }
        case let e as PTError: return of(e)
        default: return .internal
        }
    }

    static func of(_ e: PTError) -> AutomationErrorCode {
        switch e {
        case .profileNotFound: return .profileNotFound
        case .invalidProfileID, .emptyName, .invalidField, .wrongProfileType, .invalidSecret, .invalidOTPAuthURI,
             .hotpNotSupported, .invalidTemplate, .usernameTooLong:
            return .invalidArgument
        case .fileError, .fileTooLarge: return .fileError
        case .invalidFile, .unsupportedShareFile, .ovpnReferencedFile, .ovpnNotAllowed, .missingConfig, .missingHost:
            return .configInvalid
        case .keychain, .protectedSecretUnreadable: return .keychainError
        case .missingPassword, .missingTOTPSecret, .missingCredential: return .credentialsMissing
        case .helperFailed, .connectFailed, .setupFailed, .connectCancelled: return .connectFailed
        case .serverUnreachable: return .serverUnreachable
        case .hostNotFound: return .hostNotFound
        case .authFailed: return .credentialsRejected
        case .connectTimeout: return .timeout
        case .otherVPNActive: return .otherVPNActive
        case .userConfirmationCancelled: return .authCancelled
        case .userConfirmationFailed, .confirmationRequired, .protectionUnavailable: return .authUnavailable
        }
    }
}

/// An error with an explicit code, thrown by the front ends (e.g. `--no-input` refusing to ask).
public struct AutomationError: Error, Equatable, LocalizedError {
    public var code: AutomationErrorCode
    public var message: String

    public init(_ code: AutomationErrorCode, _ message: String) {
        self.code = code
        self.message = message
    }

    public var errorDescription: String? { message }
}

/// A connect that failed, with why (`ConnectionManager.failures`): what `AutomationService.connect` throws,
/// so the error object carries the `failure`. Its code and message are the underlying error's.
public struct ConnectFailedError: Error, LocalizedError {
    public var error: Error
    public var failure: ConnectionFailure

    public init(_ error: Error, failure: ConnectionFailure) {
        self.error = error
        self.failure = failure
    }

    public var errorDescription: String? { error.localizedDescription }

    /// The error itself, without a `ConnectFailedError` around it.
    public static func underlying(_ error: Error) -> Error {
        (error as? ConnectFailedError)?.error ?? error
    }
}

/// `{"code": …, "message": …}`: the object under `"error"` in `--json` output; a failed connect adds
/// `failure`.
public struct ErrorReport: Codable, Equatable {
    public var code: String
    public var message: String
    public var failure: ConnectionFailure?

    public init(code: AutomationErrorCode, message: String, failure: ConnectionFailure? = nil) {
        self.code = code.rawValue
        self.message = message
        self.failure = failure
    }

    public init(_ error: Error) {
        self.init(code: AutomationErrorCode.of(error), message: error.localizedDescription,
                  failure: (error as? ConnectFailedError)?.failure)
    }
}

/// `{"error": {…}}`, printed on stdout by a failing `--json` command.
public struct ErrorEnvelope: Codable, Equatable {
    public var error: ErrorReport
    public init(_ error: Error) { self.error = ErrorReport(error) }
}

// MARK: - Result objects

/// One profile in `list --json` and the `list_profiles` tool.
public struct ProfileSummary: Codable, Equatable {
    public var id: String
    public var name: String
    public var type: String
    public var isDefault: Bool
    public var pinned: Bool
    public var username: String
    public var passwordMode: String
    public var otpMode: String
    public var requireAuth: String
    /// Connecting asks for Touch ID or the Mac password (`require_auth` protects a secret it uses).
    public var protected: Bool
    public var autoReconnect: Bool
    /// Connected when the app opens at login (if it can connect without asking).
    public var connectAtLogin: Bool
    /// disconnected / connecting / connected; only when the caller asked the helper (MCP).
    public var state: String?

    public init(_ p: Profile, isDefault: Bool, state: ConnectionState? = nil) {
        id = p.id
        name = p.name
        type = p.type.rawValue
        self.isDefault = isDefault
        pinned = p.pinned
        username = p.username
        passwordMode = p.passwordMode.rawValue
        otpMode = p.otpMode.rawValue
        requireAuth = p.requireAuth.rawValue
        self.protected = Self.isProtected(p)
        autoReconnect = p.autoReconnect
        connectAtLogin = p.connectAtLogin
        self.state = state.map(ProfileStatus.stateName)
    }

    /// From the settings alone (no Keychain access).
    static func isProtected(_ p: Profile) -> Bool {
        !SecretVault.protectedKinds(p).isDisjoint(with: SecretVault.usedKinds(p))
    }
}

/// The state of one profile: `status --json`, `connect --json`, `disconnect --json` and the
/// `get_status` / `connect` / `disconnect` tools.
public struct ProfileStatus: Codable, Equatable {
    public var id: String
    public var name: String
    public var type: String
    public var state: String
    /// While connecting: the current step, in the user's language.
    public var phase: String?
    public var ip: String?
    public var since: Date?
    public var durationSeconds: Int?
    public var isDefault: Bool
    public var protected: Bool
    public var autoReconnect: Bool
    /// reachable / unreachable, from the health check of the process that asked (empty in a fresh CLI).
    public var health: String?
    /// Why the last attempt failed (this process only).
    public var error: String?
    /// The same, typed: kind, the server's reply, whether the sign-in and a code were sent.
    public var failure: ConnectionFailure?
    public var warning: String?
    /// Connected, but the management interface did not answer: ip and since may be stale.
    public var statusUnavailable: Bool?

    public init(id: String, name: String, type: String, state: String, phase: String? = nil, ip: String? = nil,
                since: Date? = nil, durationSeconds: Int? = nil, isDefault: Bool, protected: Bool = false,
                autoReconnect: Bool = false, health: String? = nil, error: String? = nil, failure: ConnectionFailure? = nil,
                warning: String? = nil, statusUnavailable: Bool? = nil) {
        self.id = id
        self.name = name
        self.type = type
        self.state = state
        self.phase = phase
        self.ip = ip
        self.since = since
        self.durationSeconds = durationSeconds
        self.isDefault = isDefault
        self.protected = protected
        self.autoReconnect = autoReconnect
        self.health = health
        self.error = error
        self.failure = failure
        self.warning = warning
        self.statusUnavailable = statusUnavailable
    }

    static func stateName(_ state: ConnectionState) -> String {
        switch state {
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        }
    }
}

/// The privileged helper: `helper status --json`, part of `get_status` and `diagnose`.
public struct HelperReport: Codable, Equatable {
    /// enabled / requires_approval / not_installed / missing_from_bundle
    public var state: String
    /// Enabled and answered a version request.
    public var responding: Bool
    public var protocolVersion: Int?
    public var expectedProtocolVersion: Int
    /// Another protocol or build than this app ships: `passtunnel helper install` updates it.
    public var outdated: Bool?
    public var error: String?

    public init(state: String, responding: Bool, protocolVersion: Int? = nil,
                expectedProtocolVersion: Int = PT.helperProtocolVersion, outdated: Bool? = nil, error: String? = nil) {
        self.state = state
        self.responding = responding
        self.protocolVersion = protocolVersion
        self.expectedProtocolVersion = expectedProtocolVersion
        self.outdated = outdated
        self.error = error
    }

    /// Enabled, answering and current.
    public var isUsable: Bool { state == "enabled" && responding && outdated != true }

    public static func stateName(_ status: HelperStatus) -> String {
        switch status {
        case .enabled: return "enabled"
        case .requiresApproval: return "requires_approval"
        case .notRegistered: return "not_installed"
        case .notFound: return "missing_from_bundle"
        }
    }
}

/// `get_status`: the helper plus the profiles asked for.
public struct StatusReport: Codable, Equatable {
    public var helper: HelperReport
    public var profiles: [ProfileStatus]
}

/// `list_profiles`.
public struct ProfileList: Codable, Equatable {
    public var profiles: [ProfileSummary]
}

/// `log ID --json` and `get_logs`: the last lines of the profile's VPN log, with anything that looks
/// like a credential replaced by `<redacted>`; with `--activity` / `source: "activity"`, the last events
/// of its activity log, worded, and as objects. Never a code digit.
public struct LogReport: Codable, Equatable {
    public var id: String
    public var lines: [String]
    /// The log has more lines than were returned.
    public var truncated: Bool
    /// "raw": the VPN tool's output; "activity": what PassTunnel did and saw (`ActivityLog`).
    public var source: String
    /// Activity only: the events `lines` word, oldest first.
    public var events: [ActivityEvent]?

    public init(id: String, lines: [String], truncated: Bool, source: String = "raw", events: [ActivityEvent]? = nil) {
        self.id = id
        self.lines = lines
        self.truncated = truncated
        self.source = source
        self.events = events
    }
}

/// `version --json`.
public struct VersionReport: Codable, Equatable {
    public var version: String
    public var build: String?
    public var appPath: String
    public var helperProtocolVersion: Int
}

/// `diagnose`: what an assistant needs to explain why something does not work. No secrets: whether a
/// password or TOTP secret is saved, never its value; config problems by message, never the file.
public struct DiagnoseReport: Codable, Equatable {
    public var version: String
    public var build: String?
    public var appPath: String
    /// Helper installation and updates work only from /Applications.
    public var inApplications: Bool
    public var helper: HelperReport
    public var profiles: [ProfileCheck]
    /// Linux: where passwords and TOTP secrets are kept, and whether that store can be used.
    public var secretStore: SecretStoreReport?
    /// Only when asked for (`--check-clock`, `check_clock`): how far the clock is off by the time server,
    /// or why that could not be measured.
    public var clock: ClockOffset?
    public var clockError: String?
}

public struct ProfileCheck: Codable, Equatable {
    public var id: String
    public var name: String
    public var type: String
    /// Nothing found that would stop a connect (the server can still refuse it).
    public var ok: Bool
    /// The server the credentials go to (OpenVPN: first `remote`, "+N more"); empty when unknown.
    public var server: String
    public var protected: Bool
    public var passwordSaved: Bool?
    public var totpSaved: Bool?
    /// Fields asked on every connect (user name, password, one-time code): not possible unattended.
    public var asksFor: [String]
    public var problems: [ErrorReport]
    /// The last clock measurement for the profile (FortiGate: the gateway's time after a rejected sign-in).
    public var clock: ClockOffset?
}

/// App identity for `version` and `diagnose`.
public struct AppInfo: Equatable {
    public var version: String
    public var build: String?
    public var appPath: String

    public init(version: String, build: String?, appPath: String) {
        self.version = version
        self.build = build
        self.appPath = appPath
    }

    /// From `Bundle.main` ("dev" for a build without an Info.plist). On Linux, which has no Info.plist,
    /// the version compiled in (`BuildVersion`) and the executable's path.
    public static var current: AppInfo {
        #if os(Linux)
        return AppInfo(version: BuildVersion.version, build: BuildVersion.build, appPath: Bundle.main.executablePath ?? "")
        #else
        let info = Bundle.main.infoDictionary
        return AppInfo(version: info?["CFBundleShortVersionString"] as? String ?? "dev",
                       build: info?["CFBundleVersion"] as? String,
                       appPath: Bundle.main.bundleURL.pathExtension == "app" ? Bundle.main.bundlePath
                                                                          : Bundle.main.executablePath ?? "")
        #endif
    }

    public var inApplications: Bool { appPath.hasPrefix("/Applications/") }
}

/// JSON for automation output: the file style (snake_case, sorted keys) with ISO 8601 dates.
public enum AutomationJSON {
    public static func encoder(pretty: Bool = true) -> JSONEncoder {
        let e = JSONCoding.encoder()
        e.dateEncodingStrategy = .iso8601
        if !pretty { e.outputFormatting = [.sortedKeys, .withoutEscapingSlashes] }
        return e
    }

    /// The value as a JSON object (`[String: Any]`, arrays, …) for embedding in a JSON-RPC message.
    public static func object<T: Encodable>(_ value: T) throws -> Any {
        try JSONSerialization.jsonObject(with: encoder(pretty: false).encode(value), options: [.fragmentsAllowed])
    }
}

// MARK: - Helper inspection

/// Reads the helper's state; `SystemHelperInspector` in the app, a fixed report in tests.
public protocol HelperInspecting {
    func report() async -> HelperReport
}

/// `SMAppService` status, then the running helper's protocol and build (5 s timeout per call). On
/// Linux passtunneld (docs/LINUX.md): `not_installed` without its socket, else `enabled`, and from
/// `hello` (5 s) whether it answers and is the installed build.
public struct SystemHelperInspector: HelperInspecting {
    #if os(macOS)
    public init() {}

    public func report() async -> HelperReport {
        let status = HelperInstaller.status
        var r = HelperReport(state: HelperReport.stateName(status), responding: false)
        guard status == .enabled else { return r }
        let client = HelperClient(machServiceName: HelperClient.defaultMachServiceName, timeout: 5)
        defer { client.invalidate() }
        do {
            let v = try await client.version()
            r.responding = true
            r.protocolVersion = v
            r.outdated = v != PT.helperProtocolVersion ? true : (try? await client.isOutdated()) == true
        } catch {
            r.error = error.localizedDescription
        }
        return r
    }
    #else
    public let socketPath: String
    public let timeout: TimeInterval
    /// The build the daemon must report (`HelperBuild.installedDaemon`, worked out only when the
    /// daemon answers); nil: not compared.
    private let expectedBuild: () -> String?

    public init(socketPath: String = PT.daemonSocketPath(), timeout: TimeInterval = 5,
                expectedBuild: @autoclosure @escaping () -> String? = HelperBuild.installedDaemon) {
        self.socketPath = socketPath
        self.timeout = timeout
        self.expectedBuild = expectedBuild
    }

    public func report() async -> HelperReport {
        let client = UnixSocketHelperClient(socketPath: socketPath, timeout: timeout, expectedBuild: nil)
        guard client.isInstalled else { return HelperReport(state: HelperReport.stateName(.notRegistered), responding: false) }
        var r = HelperReport(state: HelperReport.stateName(.enabled), responding: false)
        do {
            let hello = try await client.hello()
            r.responding = true
            r.protocolVersion = hello.protocolVersion
            r.outdated = hello.protocolVersion != PT.helperProtocolVersion
                || !HelperBuild.matches(helper: hello.build, expected: expectedBuild())
        } catch {
            r.error = error.localizedDescription
        }
        return r
    }
    #endif
}

// MARK: - Confirmation without a prompt

/// Wraps an authenticator for `--no-auth-prompt`: creating keys and reading public keys work (no
/// prompt), unlocking fails with `auth_unavailable` instead of showing Touch ID.
public final class PromptlessAuthenticator: UserAuthenticator {
    private let base: UserAuthenticator

    public init(_ base: UserAuthenticator) { self.base = base }

    public var isAvailable: Bool { base.isAvailable }
    public func createKey() throws -> ProtectionKey { try base.createKey() }
    public func publicKey(keyData: Data) throws -> P256.KeyAgreement.PublicKey { try base.publicKey(keyData: keyData) }

    public func unlock(keyData: Data, reason: String) async throws -> UnlockedProtectionKey {
        throw AutomationError(.authUnavailable, String(localized: "This needs your confirmation (Touch ID or your Mac password), but prompts are turned off (--no-auth-prompt)."))
    }
}
