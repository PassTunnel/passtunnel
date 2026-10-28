import Foundation
import PassTunnelKit
import PassTunnelShared
import PassTunnelVPNConfig

/// Builds the automation result objects (`Automation.swift`) and runs the waiting connect and
/// disconnect behind `connect --wait`, `disconnect --wait` and the MCP tools. One instance per CLI
/// command or MCP server; it never caches profiles (every call reads the store).
@MainActor
public final class AutomationService {
    public let store: ProfileStore
    public let manager: ConnectionManager
    public let helperInspector: HelperInspecting
    public let appInfo: AppInfo
    /// The network path for `diagnose`; read once per call, nothing is contacted.
    private let network: () async -> NetworkStatus
    /// `diagnose`: the app's VPN tools run with `--version` (`BundledTools`); nil without them.
    private let tools: (AppInfo) async -> [ToolCheck]?

    /// Most lines `logs` returns, and the longest line it keeps.
    public static let maxLogLines = 500
    static let maxLogLineLength = 2000

    public init(
        store: ProfileStore, manager: ConnectionManager, helperInspector: HelperInspecting = SystemHelperInspector(),
        appInfo: AppInfo = .current, network: @escaping () async -> NetworkStatus = { await NetworkPath.current() },
        tools: @escaping (AppInfo) async -> [ToolCheck]? = { await BundledTools.check(app: $0) }
    ) {
        self.store = store
        self.manager = manager
        self.helperInspector = helperInspector
        self.appInfo = appInfo
        self.network = network
        self.tools = tools
    }

    // MARK: profiles and state

    /// `withState`: asks the helper first and fills in `state`.
    public func summaries(withState: Bool) async -> [ProfileSummary] {
        if withState { await manager.refresh() }
        let def = store.defaultID
        return store.list().map { ProfileSummary($0, isDefault: $0.id == def, state: withState ? manager.state($0.id) : nil) }
            + store.listUnsupported().map { ProfileSummary($0, isDefault: $0.id == def) }
    }

    public func summary(_ p: Profile) -> ProfileSummary {
        ProfileSummary(p, isDefault: store.defaultID == p.id)
    }

    /// The state the manager last saw (no refresh).
    public func status(_ p: Profile, now: Date = Date()) -> ProfileStatus {
        let m = manager
        var s = ProfileStatus(
            id: p.id, name: p.name, type: p.type.rawValue, state: "disconnected",
            isDefault: store.defaultID == p.id, protected: ProfileSummary.isProtected(p),
            autoReconnect: p.autoReconnect, error: m.lastError[p.id],
            failure: m.failures[p.id].map { Self.redacted($0, id: p.id) })
        if !m.state(p.id).isConnected, let retry = m.unreachableRetry(p.id) {
            s.nextTryAt = retry.nextTryAt
            s.tries = retry.tries
        }
        switch m.state(p.id) {
        case .disconnected: break
        case .connecting(let phase): s.state = "connecting"; s.phase = phase
        case let .connected(ip, since):
            s.state = "connected"; s.ip = ip; s.since = since; s.warning = m.warnings[p.id]
            if let since { s.durationSeconds = Self.wholeSeconds(from: since, to: now) }
            if m.statusUnavailable.contains(p.id) { s.statusUnavailable = true }
            switch m.health[p.id] {
            case .reachable?: s.health = "reachable"
            case .unreachable?: s.health = "unreachable"
            case .unknown?, nil: break
            }
        }
        return s
    }

    /// `status(p)` as the result of a connect that went ahead despite `overlaps` (`checkCanStart`):
    /// with the warnings about them.
    public func status(_ p: Profile, overlaps: [ProfileOverlap], now: Date = Date()) -> ProfileStatus {
        var s = status(p, now: now)
        if !overlaps.isEmpty { s.warnings = overlaps.map { ConnectWarning($0, connecting: p.id) } }
        return s
    }

    /// The failure with the server's reply and the tool's reason passed through `LogRedactor`, as the log is.
    static func redacted(_ failure: ConnectionFailure, id: String) -> ConnectionFailure {
        guard failure.reply != nil || failure.reason != nil else { return failure }
        let redactor = LogRedactor(secrets: SecretKind.allCases.compactMap { Secrets.get(id, $0) })
        var f = failure
        f.reply = f.reply.map(redactor.redact)
        f.reason = f.reason.map(redactor.redact)
        return f
    }

    /// Whole seconds from `start` to `end`: 0 when `end` is not later or the difference is not finite,
    /// `Int.max` when it does not fit. Never traps, whatever date a state file or reply carried.
    static func wholeSeconds(from start: Date, to end: Date) -> Int {
        let seconds = end.timeIntervalSince(start)
        guard seconds.isFinite, seconds > 0 else { return 0 }
        return seconds < Double(Int.max) ? Int(seconds) : Int.max
    }

    /// Refreshes, then the helper and every profile (or the one asked for).
    public func statusReport(id: String?) async throws -> StatusReport {
        let profiles: [Profile] = try id.map { [try store.get($0)] } ?? store.list()
        await manager.refresh()
        var helper = await helperInspector.report()
        if helper.error == nil, let e = manager.helperError { helper.error = e }
        return StatusReport(helper: helper, profiles: profiles.map { status($0) })
    }

    public func helperReport() async -> HelperReport {
        await helperInspector.report()
    }

    public func versionReport() -> VersionReport {
        VersionReport(
            version: appInfo.version, build: appInfo.build, appPath: appInfo.appPath,
            helperProtocolVersion: PT.helperProtocolVersion)
    }

    // MARK: connect / disconnect

    /// Connects `id` and returns when it is connected or failed. With `timeout`, gives up after that many
    /// seconds (`AutomationErrorCode.timeout`). On a timeout or when the calling task is cancelled, a
    /// session this call started is stopped; one it follows (started by the app or another process) is
    /// left alone. Which of the two it is, the manager decides when the attempt begins
    /// (`ConnectionManager.ConnectRole`), not the caller beforehand. `joining`: the caller saw an attempt
    /// under way and only wants to wait for it; throws `ConnectionManager.NothingToFollow` when it has
    /// ended meanwhile, so the caller can run its own checks before starting one. The caller asks for
    /// the confirmation first (`vault.unlock`), so the time a prompt stays open does not count.
    /// `role` is passed on to `ConnectionManager.connect` (the CLI's Ctrl-C handler uses it). A failure the
    /// manager typed (`ConnectionManager.failures`) comes as a `ConnectFailedError` around the error.
    public func connect(
        _ id: String, given: [CredentialField: String] = [:], force: Bool = false,
        timeout: TimeInterval?, joining: Bool,
        role: ((ConnectionManager.ConnectRole) -> Void)? = nil
    ) async throws {
        let manager = self.manager
        let attempt = Attempt()
        let run = { @MainActor in
            do {
                try await manager.connect(id, given: given, force: force, followOnly: joining) {
                    attempt.started = $0 == .started
                    role?($0)
                }
            } catch let error where !(error is ConnectionManager.NothingToFollow) {
                // After a rejected sign-in, the clock check (a few seconds at most), so the failure has it.
                await manager.clockCheckFinished(id)
                // Set by the attempt that threw (each attempt clears it first).
                guard let failure = manager.failures[id] else { throw error }
                throw ConnectFailedError(error, failure: Self.redacted(failure, id: id))
            }
        }
        guard let timeout else {
            do { try await run() } catch {
                if Task.isCancelled && attempt.started { _ = try? await manager.disconnect(id) }
                throw error
            }
            return
        }
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask { try await run() }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(max(0, timeout) * 1_000_000_000))
                throw DeadlineExceeded()
            }
            do {
                try await group.next()
                group.cancelAll()
            } catch {
                group.cancelAll()
                let timedOut = error is DeadlineExceeded
                if (timedOut || Task.isCancelled) && attempt.started { _ = try? await manager.disconnect(id) }
                if timedOut {
                    let name = (try? store.get(id))?.name ?? id
                    throw AutomationError(.timeout, String(localized: "\(name) did not connect within \(Int(timeout)) seconds."))
                }
                throw error
            }
        }
    }

    /// Set once the manager has started a session for this call.
    @MainActor private final class Attempt {
        var started = false
    }

    private struct DeadlineExceeded: Error {}

    /// Stops `id`; with `wait`, returns only once the helper no longer runs it (at most `timeout` s).
    /// Returns false when nothing was running.
    @discardableResult
    public func disconnect(_ id: String, wait: Bool, timeout: TimeInterval) async throws -> Bool {
        let p = try store.get(id)
        let wasActive = try await manager.disconnect(id)
        if wait { try await waitUntilDisconnected([p], timeout: timeout) }
        return wasActive
    }

    /// Stops every active profile; with `wait`, until none is running any more.
    public func disconnectAll(wait: Bool, timeout: TimeInterval) async throws {
        try await manager.disconnectAll()
        if wait { try await waitUntilDisconnected(store.list(), timeout: timeout) }
    }

    private func waitUntilDisconnected(_ profiles: [Profile], timeout: TimeInterval) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while true {
            await manager.refresh()
            let active = profiles.filter { manager.state($0.id).isActive }
            guard let first = active.first else { return }
            if Date() >= deadline {
                throw AutomationError(.timeout, String(localized: "\(first.name) did not disconnect within \(Int(timeout)) seconds."))
            }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
    }

    // MARK: logs

    /// The last `lines` lines of the profile's VPN log (OpenVPN's notes about PassTunnel's own
    /// management polls and lines that look like key material left out), each passed through
    /// `LogRedactor`. Reads the saved password and TOTP secret (plaintext items only) so that their
    /// literal values can be masked; a protected secret is not decrypted for this.
    public func logs(_ id: String, lines: Int) throws -> LogReport {
        _ = try store.get(id)
        let count = min(max(lines, 1), Self.maxLogLines)
        let url = store.logURL(id)
        let size = ((try? FileManager.default.attributesOfItem(atPath: url.path))?[.size] as? NSNumber)?.intValue ?? 0
        var text = Substring(VPNLog.read(url))
        // The tail starts mid-line: a cut "password=…" would no longer match the redactor's keywords.
        if size > VPNLog.maxReadBytes {
            text = text.firstIndex(of: "\n").map { text[text.index(after: $0)...] } ?? ""
        }
        let all = text.split(whereSeparator: \.isNewline)
            .filter { !VPNLog.isManagementChatter($0) && !LogRedactor.isKeyMaterial($0) }
        let redactor = LogRedactor(secrets: SecretKind.allCases.compactMap { Secrets.get(id, $0) })
        let tail = all.suffix(count).map { line -> String in
            let text = redactor.redact(String(line))
            return text.count > Self.maxLogLineLength ? String(text.prefix(Self.maxLogLineLength)) + "…" : text
        }
        return LogReport(id: id, lines: tail, truncated: all.count > count || size > VPNLog.maxReadBytes)
    }

    /// The last `lines` events of the profile's activity log (`ActivityLog`), each worded in the user's
    /// language with its local time, and as objects. Code digits are left out, and the text passes
    /// through `LogRedactor` like the VPN log.
    public func activity(_ id: String, lines: Int, timeZone: TimeZone = .current) throws -> LogReport {
        _ = try store.get(id)
        let count = min(max(lines, 1), Self.maxLogLines)
        let all = ActivityLog(url: store.activityURL(id)).read()
        let redactor = LogRedactor(secrets: SecretKind.allCases.compactMap { Secrets.get(id, $0) })
        let events = all.suffix(count).map { $0.withoutCodeDigits().redacted(redactor) }
        return LogReport(
            id: id, lines: events.map { $0.line(timeZone: timeZone) }, truncated: all.count > count,
            source: "activity", events: events)
    }

    // MARK: diagnose

    /// `checkClock`: also asks the time server how far the clock is off (`ConnectionManager.checkClock`);
    /// only on request, as it contacts that server. On the Mac, each VPN tool of the app is run with
    /// `--version` (`BundledTools`), which contacts nothing.
    public func diagnose(checkClock: Bool = false) async -> DiagnoseReport {
        let helper = await helperInspector.report()
        var report = DiagnoseReport(
            version: appInfo.version, build: appInfo.build, appPath: appInfo.appPath,
            inApplications: appInfo.inApplications, helper: helper,
            profiles: store.list().map(check), secretStore: await Self.secretStoreReport(),
            network: await network(), tools: await tools(appInfo))
        if checkClock {
            do { report.clock = try await manager.checkClock() } catch { report.clockError = error.localizedDescription }
        }
        return report
    }

    /// Linux: the secret store in use. Its availability check may run a tool for a few seconds, so
    /// not on the main actor. Nil on the Mac (the Keychain).
    private static func secretStoreReport() async -> SecretStoreReport? {
        #if os(Linux)
        return await Task.detached { SecretStores.report() }.value
        #else
        return nil
        #endif
    }

    /// What would stop `p` from connecting, from its files and Keychain items (whether they exist only;
    /// nothing is decrypted, nothing is returned).
    func check(_ p: Profile) -> ProfileCheck {
        var problems: [Error] = []
        switch p.type {
        case .openvpn:
            let url = store.ovpnURL(p.id)
            if !FileManager.default.fileExists(atPath: url.path) {
                problems.append(PTError.missingConfig(p.id))
            } else if let data = try? FileIO.read(url, maxSize: ProfileStore.maxOVPNSize) {
                do { _ = try OVPNSanitizer.sanitize(String(decoding: data, as: UTF8.self)) } catch let f as OVPNSanitizer.Failure {
                    problems.append(PTError.ovpnNotAllowed(f.violations.map(\.description)))
                } catch {
                    problems.append(PTError.invalidFile(ProfileStore.ovpnFile))
                }
            } else {
                problems.append(PTError.invalidFile(ProfileStore.ovpnFile))
            }
        case .forti:
            if p.host.trimmingCharacters(in: .whitespaces).isEmpty {
                problems.append(PTError.missingHost(p.id))
            } else if !FortiConfig.isValidHost(p.host) {
                problems.append(PTError.invalidField("host"))
            }
            do { try Profile.checkUsername(p.username, type: p.type) } catch { problems.append(error) }
        case .anyconnect:
            problems.append(PTError.unsupportedProfileType(p.type.rawValue))  // not connected yet
        }
        /// Whether `kind` is saved; nil, and the store's error once, when the store cannot be read.
        func saved(_ kind: SecretKind, missing: PTError) -> Bool? {
            do {
                let saved = try Secrets.exists(p.id, kind)
                if !saved { problems.append(missing) }
                return saved
            } catch {
                if !problems.contains(where: { $0 is SecretStoreUnavailable }) { problems.append(error) }
                return nil
            }
        }
        let passwordSaved = p.passwordMode == .keychain ? saved(.password, missing: .missingPassword(p.id)) : nil
        let totpSaved = p.otpMode == .totp ? saved(.totp, missing: .missingTOTPSecret(p.id)) : nil
        return ProfileCheck(
            id: p.id, name: p.name, type: p.type.rawValue, ok: problems.isEmpty,
            server: ProfileDestination.of(p, store: store).host, protected: ProfileSummary.isProtected(p),
            passwordSaved: passwordSaved, totpSaved: totpSaved, asksFor: p.needs.map(\.rawValue),
            problems: problems.map(ErrorReport.init), clock: manager.lastClock(p.id))
    }
}

/// Removes anything that looks like a credential from log lines before they leave the process. The
/// VPN tools get credentials through files, not on the command line, and do not log them or key
/// material at the verbosity the helper allows (OpenVPN `--verb` capped at 4); this is a second line
/// of defence for unusual configs and servers.
public struct LogRedactor {
    public static let mask = "<redacted>"
    private let secrets: [String]

    /// `secrets`: values that must never appear (the profile's saved password and TOTP secret).
    public init(secrets: [String]) {
        self.secrets = secrets.filter { $0.count >= 3 }.sorted { $0.count > $1.count }
    }

    private static let patterns: [(NSRegularExpression, String)] = [
        // auth-token pushed by the server (a session credential), "auth-token-user"
        (#"(?i)\b(auth-token(?:-user)?)([ ,=]+)[^\s,]+"#, "$1$2" + mask),
        // OpenVPN static/dynamic challenge responses
        (#"\b((?:SC|C)?RV1:)\S+"#, "$1" + mask),
        // "password = …", "otp: …", "token=…"
        (#"(?i)\b(pass(?:word|wd|phrase)?|secret|otp|token|response)(\s*[=:]\s*)\S+"#, "$1$2" + mask)
    ].map { (try! NSRegularExpression(pattern: $0.0), $0.1) }

    /// Hex digits, alone or in groups split by single spaces or colons: OpenVPN prints keys and
    /// packets as "0123abcd 4567ef01 …".
    private static let hexRun = try! NSRegularExpression(pattern: #"[0-9A-Fa-f]{2,}(?:[ :][0-9A-Fa-f]{2,})*"#)
    static let minHexDigits = 32

    /// openfortivpn's hint for an untrusted gateway ("--trusted-cert <sha256>", "trusted-cert = <sha256>"):
    /// the certificate's public digest, which explains the failure.
    private static let trustedCertHint = try! NSRegularExpression(pattern: #"(?:--trusted-cert\s+|\btrusted-cert\s*=\s*)[0-9A-Fa-f]{64}\b"#)

    /// A line `logs` leaves out: OpenVPN's TLS packet traces ("TLS: tls_…") and any line with a hex
    /// run of `minHexDigits` or more (data-channel keys, key sources and packet dumps from `verb` 7
    /// up, which the helper does not allow), except for openfortivpn's trusted-cert digest.
    public static func isKeyMaterial<S: StringProtocol>(_ line: S) -> Bool {
        var text = String(line)
        if text.contains("TLS: tls_") { return true }
        text = trustedCertHint.stringByReplacingMatches(in: text, range: NSRange(text.startIndex..., in: text), withTemplate: "trusted-cert")
        let range = NSRange(text.startIndex..., in: text)
        return hexRun.matches(in: text, range: range).contains { match in
            (Range(match.range, in: text).map { text[$0] } ?? "").filter(\.isHexDigit).count >= minHexDigits
        }
    }

    public func redact(_ line: String) -> String {
        var out = line
        for secret in secrets { out = out.replacingOccurrences(of: secret, with: Self.mask) }
        for (regex, template) in Self.patterns {
            out = regex.stringByReplacingMatches(in: out, range: NSRange(out.startIndex..., in: out), withTemplate: template)
        }
        return out
    }
}

extension ActivityEvent {
    /// The event with the text it carries from outside (server, user name, the server's reply) passed
    /// through `redactor`, as the VPN log's lines are.
    func redacted(_ redactor: LogRedactor) -> ActivityEvent {
        var copy = self
        switch kind {
        case let .connecting(host, port, transport):
            copy.kind = .connecting(host: redactor.redact(host), port: port, transport: transport)
        case var .sending(s):
            s.username = redactor.redact(s.username)
            copy.kind = .sending(s)
        case .rejected(let reply):
            copy.kind = .rejected(reply: reply.map(redactor.redact))
        case let .unreachable(tries, reason):
            copy.kind = .unreachable(tries: tries, reason: reason.map(redactor.redact))
        case let .failed(failure, reason, sent):
            copy.kind = .failed(kind: failure, reason: reason.map(redactor.redact), credentialsSent: sent)
        default:
            break
        }
        return copy
    }
}
