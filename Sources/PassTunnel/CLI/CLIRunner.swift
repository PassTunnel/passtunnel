import AppKit
import Combine
import Foundation
import PassTunnelCore
import PassTunnelKit
import PassTunnelShared

/// Executes parsed CLI commands against the same Core APIs the app uses. With `--json`, results are
/// the automation objects (`AutomationService`, shared with the MCP server) and failures are
/// `{"error": …}` on stdout; the exit code comes from the error (`AutomationErrorCode.exitCode`).
@MainActor
final class CLIRunner {
    typealias Exit = PassTunnelCLI.Exit

    let store = ProfileStore()
    let options: CLIOptions
    private var json = false
    private var managerStorage: ConnectionManager?
    private var automationStorage: AutomationService?
    private var bag: Set<AnyCancellable> = []
    private var signalSource: DispatchSourceSignal?

    init(options: CLIOptions = CLIOptions()) {
        self.options = options
    }

    /// Created on first use so offline commands never talk to the helper. `--no-auth-prompt` swaps in an
    /// authenticator that refuses to ask.
    var manager: ConnectionManager {
        if let managerStorage { return managerStorage }
        let authenticator: UserAuthenticator = options.noAuthPrompt
            ? PromptlessAuthenticator(SecureEnclaveAuthenticator()) : SecureEnclaveAuthenticator()
        let m = ConnectionManager(store: store, authenticator: authenticator)
        managerStorage = m
        return m
    }

    var automation: AutomationService {
        if let automationStorage { return automationStorage }
        let a = AutomationService(store: store, manager: manager)
        automationStorage = a
        return a
    }

    func run(_ command: CLICommand) async -> Int32 {
        defer { if Self.changesProfiles(command) { ProfileChangeSignal.post() } }
        json = Self.wantsJSON(command)
        do {
            return try await execute(command)
        } catch {
            return fail(error)
        }
    }

    /// Reports `error` (JSON on stdout with `--json`, else on stderr) and returns its exit code.
    func fail(_ error: Error) -> Int32 {
        if json {
            try? printJSON(ErrorEnvelope(error))
        } else if let e = error as? CLIUsageError {
            CLITerminal.fail(e.message)
            CLITerminal.err(CLIHelp.usage(for: e.command))
        } else if (error as? PTError) == .userConfirmationCancelled {
            // The user cancelled the Touch ID / password prompt: nothing happened, nothing to explain.
            CLITerminal.err(error.localizedDescription)
        } else {
            report(error)
        }
        return AutomationErrorCode.of(error).exitCode
    }

    static func wantsJSON(_ command: CLICommand) -> Bool {
        switch command {
        case let .status(_, json), let .code(_, _, json), let .list(json, _), let .show(_, json), let .toggle(_, json),
             let .set(_, _, json), let .add(_, _, json), let .importFile(_, _, json), let .export(_, _, json),
             let .remove(_, _, json), let .secret(_, _, json), let .setDefault(_, json), let .pin(_, json),
             let .unpin(_, json), let .helper(_, json), let .version(json):
            return json
        case let .connect(_, _, json, _, _), let .disconnect(_, _, json, _, _), let .log(_, _, json, _):
            return json
        default:
            return false
        }
    }

    /// Commands after which a running app should reload right away. Profile files are also seen by
    /// the app's file watcher; Keychain items (`secret`, `rm`) only through this signal.
    static func changesProfiles(_ command: CLICommand) -> Bool {
        switch command {
        case .set, .add, .importFile, .remove, .secret, .setDefault, .pin, .unpin: return true
        default: return false
        }
    }

    private func report(_ error: Error) {
        CLITerminal.fail(error.localizedDescription)
        if let tail = (error as? PTError)?.logTail, !tail.isEmpty {
            CLITerminal.err(tail.split(separator: "\n").map { "  " + $0 }.joined(separator: "\n"))
        }
    }

    private func execute(_ command: CLICommand) async throws -> Int32 {
        switch command {
        case let .status(id, json): return try await status(id, json: json)
        case let .connect(id, force, _, wait, timeout):
            return try await connect(id, force: force, timeout: wait ? timeout ?? CLICommand.defaultTimeout : nil)
        case let .disconnect(id, all, _, wait, timeout):
            return try await disconnect(id, all: all, wait: wait, timeout: timeout ?? CLICommand.defaultTimeout)
        case let .toggle(id, _): return try await toggle(id)
        case let .code(id, copy, json): return try await code(id, copy: copy, json: json)
        case let .list(json, quiet): return try list(json: json, quiet: quiet)
        case let .show(id, json): return try show(id, json: json)
        case let .set(id, assignments, _): return try await set(id, assignments)
        case let .add(name, type, _): return try add(name, type: type)
        case let .importFile(path, name, _): return try importFile(path, name: name)
        case let .export(id, output, _): return try export(id, output: output)
        case let .remove(id, yes, _): return try await remove(id, yes: yes)
        case let .secret(id, kind, _): return try await secret(id, kind: kind)
        case let .setDefault(id, _): return try setDefault(id)
        case let .pin(id, _): return try pin(id, true)
        case let .unpin(id, _): return try pin(id, false)
        case let .log(id, follow, _, lines): return try await log(id, follow: follow, lines: lines)
        case let .helper(action, _): return try await helper(action)
        case let .mcp(allowConnect):
            return await MCPServer.runStdio(service: automation, allowConnect: allowConnect)
        #if DEBUG
        case let .debug(.drop, id): return try await debugDrop(id)
        #endif
        case let .completion(shell):
            FileHandle.standardOutput.write(Data(CLICompletions.script(for: shell).utf8))
            return Exit.ok
        case let .help(name):
            CLITerminal.out(CLIHelp.usage(for: name))
            return Exit.ok
        case .version:
            let report = automation.versionReport()
            if json { try printJSON(report); return Exit.ok }
            CLITerminal.out("PassTunnel \(report.version)" + (report.build.map { " (\($0))" } ?? ""))
            return Exit.ok
        }
    }

    // MARK: profile resolution

    /// Explicit id, else the default profile, else the only profile.
    private func resolve(_ id: String?) throws -> Profile {
        if let id { return try store.get(id) }
        if let def = store.defaultID { return try store.get(def) }
        let all = store.list()
        if all.count == 1 { return all[0] }
        if all.isEmpty { throw AutomationError(.profileNotFound, String(localized: "There are no profiles yet. Add one with “passtunnel import FILE”.")) }
        throw AutomationError(.invalidArgument, String(localized: "No default profile is set. Give a profile id, or set one with “passtunnel default ID”."))
    }

    // MARK: status

    private func status(_ id: String?, json: Bool) async throws -> Int32 {
        let profiles: [Profile] = try id.map { [try store.get($0)] } ?? store.list()
        await manager.refresh()
        if let e = manager.helperError, !json {
            CLITerminal.err(CLITerminal.dim(String(localized: "Note: the helper is not available (\(e)).")))
        }
        if json {
            let statuses = profiles.map { automation.status($0) }
            try printJSON(id == nil ? AnyEncodable(statuses) : AnyEncodable(statuses[0]))
        } else if profiles.isEmpty {
            CLITerminal.out(String(localized: "No profiles. Add one with “passtunnel import FILE” or in the app."))
        } else {
            printStatusTable(profiles)
        }
        if id != nil, !manager.state(profiles[0].id).isConnected { return Exit.notConnected }
        return Exit.ok
    }

    private func printStatusTable(_ profiles: [Profile]) {
        let palette = Preferences.load().badgePalette
        let def = store.defaultID
        let idWidth = profiles.map(\.id.count).max() ?? 0
        let nameWidth = profiles.map(\.name.count).max() ?? 0
        for p in profiles {
            let tone: BadgeTone
            var text: String
            switch manager.state(p.id) {
            case .disconnected:
                tone = .disconnected
                text = String(localized: "disconnected")
            case .connecting(let phase):
                tone = .connecting
                text = phase
            case let .connected(ip, since):
                tone = .connected
                text = String(localized: "connected")
                if !ip.isEmpty { text += "  " + ip }
                if let since { text += "  " + CLIDurations.since(since) }
                if manager.statusUnavailable.contains(p.id) {
                    text += "  " + CLITerminal.dim(String(localized: "(status unavailable)"))
                }
                if let warning = manager.warnings[p.id] { text += "  " + CLITerminal.colored(warning, palette.color(.connecting)) }
            }
            if let error = manager.lastError[p.id], tone == .disconnected { text += "  " + error }
            let mark = p.id == def ? "*" : " "
            let dot = CLITerminal.colored("●", palette.color(tone))
            CLITerminal.out("\(mark) \(dot) " + p.id.padding(toLength: idWidth + 2, withPad: " ", startingAt: 0)
                + p.name.padding(toLength: nameWidth + 2, withPad: " ", startingAt: 0) + text)
        }
    }

    // MARK: connect / disconnect

    /// `timeout`: `--wait` / `--timeout`; nil waits as long as the connection steps themselves allow.
    private func connect(_ id: String?, force: Bool = false, timeout: Int? = nil) async throws -> Int32 {
        let p = try resolve(id)
        await manager.refresh()
        if manager.state(p.id).isConnected {
            if json { try printJSON(automation.status(p)) } else { CLITerminal.out(String(localized: "\(p.name) is already connected.")) }
            return Exit.ok
        }
        if manager.state(p.id).isConnecting {
            // Started elsewhere (the app, another terminal): wait for that connection instead.
            do {
                try await connectShowingProgress(p, given: [:], joining: true, timeout: timeout)
                if json { try printJSON(automation.status(p)) }
                return Exit.ok
            } catch is ConnectionManager.NothingToFollow {
                // It ended before it could be followed: connect as usual, with the checks below.
            }
        }
        do {
            // Before "Connecting …" and before asking for credentials.
            if !force { try await manager.checkCanStart(p.id) }
            try await manager.vault.unlock(p, for: .connect)
            let given = try askForNeeds(p)
            try await connectShowingProgress(p, given: given, force: force, timeout: timeout)
        } catch PTError.otherVPNActive(let other) where !json {
            CLITerminal.fail(PTError.otherVPNActive(other).localizedDescription)
            CLITerminal.err(CLITerminal.dim(String(localized: "Use --force to connect anyway.")))
            return AutomationErrorCode.otherVPNActive.exitCode
        }
        if json { try printJSON(automation.status(p)) }
        return Exit.ok
    }

    private func connectShowingProgress(_ p: Profile, given: [CredentialField: String], joining: Bool = false,
                                        force: Bool = false, timeout: Int? = nil) async throws {
        CLITerminal.err(joining ? String(localized: "Already connecting \(p.name); waiting for it…")
                                : String(localized: "Connecting \(p.name)…"))
        var progress = ConnectionManager.PhaseProgress()
        let isTTY = CLITerminal.stderrIsTTY
        manager.$states
            .compactMap { $0[p.id] }
            .sink { [weak self] state in
                guard case .connecting(let phase) = state, progress.shouldPrint(phase) else { return }
                if isTTY {
                    CLITerminal.err(CLITerminal.dim("  " + phase))
                } else if phase == ConnectionManager.Phase.waitingForCode {
                    // Without a terminal only this one: otherwise the wait (up to a code window) is silent.
                    let until = self?.manager.codeWaitUntil[p.id] ?? Date()
                    let seconds = max(1, Int(until.timeIntervalSinceNow.rounded(.up)))
                    CLITerminal.err(String(localized: "Waiting for a fresh code (\(seconds) s)…"))
                }
            }
            .store(in: &bag)
        // Ctrl-C while connecting stops the half-started connection if this process started it; a
        // session it follows (started by the app or another terminal) is left running.
        final class Started { var value = false }
        let started = Started()
        signal(SIGINT, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        source.setEventHandler { [weak self] in
            Task { @MainActor in
                if !started.value { exit(130) }
                CLITerminal.err(String(localized: "Cancelling…"))
                _ = try? await self?.manager.disconnect(p.id)
                exit(130)
            }
        }
        source.resume()
        signalSource = source
        defer {
            source.cancel()
            signal(SIGINT, SIG_DFL)
            bag.removeAll()
        }
        try await automation.connect(p.id, given: given, force: force, timeout: timeout.map(TimeInterval.init),
                                     joining: joining) { started.value = $0 == .started }
        if !json, case let .connected(ip, _) = manager.state(p.id) {
            CLITerminal.out(ip.isEmpty ? String(localized: "Connected: \(p.name)")
                                    : String(localized: "Connected: \(p.name) (\(ip))"))
            if let warning = manager.warnings[p.id] { CLITerminal.err(warning) }
        }
    }

    /// Asks on the terminal for whatever the profile needs (`Profile.needs`).
    private func askForNeeds(_ p: Profile) throws -> [CredentialField: String] {
        let needs = p.needs
        guard !needs.isEmpty else { return [:] }
        guard CLITerminal.stdinIsTTY, !options.noInput else {
            let list = needs.map(\.displayName).joined(separator: ", ")
            throw AutomationError(.inputRequired, String(localized: "This profile asks for: \(list). Run the command in a terminal."))
        }
        var given: [CredentialField: String] = [:]
        for field in needs {
            switch field {
            case .username:
                let last = p.lastUsername
                let prompt = last.isEmpty ? String(localized: "User name: ") : String(localized: "User name [\(last)]: ")
                let v = (CLITerminal.ask(prompt) ?? "").trimmingCharacters(in: .whitespaces)
                given[.username] = v.isEmpty ? last : v
            case .password:
                given[.password] = CLITerminal.askSecret(String(localized: "Password: ")) ?? ""
            case .otp:
                given[.otp] = (CLITerminal.ask(String(localized: "One-time code: ")) ?? "").trimmingCharacters(in: .whitespaces)
            }
            if given[field, default: ""].isEmpty { throw PTError.missingCredential(field) }
        }
        return given
    }

    private func disconnect(_ id: String?, all: Bool, wait: Bool, timeout: Int) async throws -> Int32 {
        if all {
            try await automation.disconnectAll(wait: wait, timeout: TimeInterval(timeout))
            if json {
                try printJSON(store.list().map { automation.status($0) })
            } else {
                CLITerminal.out(String(localized: "All profiles are disconnected."))
            }
            return Exit.ok
        }
        let p = try resolve(id)
        let wasActive = try await automation.disconnect(p.id, wait: wait, timeout: TimeInterval(timeout))
        if json {
            try printJSON(automation.status(p))
        } else if wasActive {
            CLITerminal.out(String(localized: "Disconnected: \(p.name)"))
        } else {
            CLITerminal.out(String(localized: "\(p.name) is not connected."))
        }
        return Exit.ok
    }

    private func toggle(_ id: String?) async throws -> Int32 {
        let p = try resolve(id)
        await manager.refresh()
        if manager.state(p.id).isActive {
            try await manager.disconnect(p.id)
            if !json { CLITerminal.out(String(localized: "Disconnected: \(p.name)")) }
        } else {
            try await manager.vault.unlock(p, for: .connect)
            try await connectShowingProgress(p, given: try askForNeeds(p))
        }
        if json { try printJSON(automation.status(p)) }
        return Exit.ok
    }

    // MARK: code

    private struct CodeJSON: Encodable {
        var profile: String
        var code: String
        var remaining: Int
        var period: Int
    }

    private func code(_ id: String?, copy: Bool, json: Bool) async throws -> Int32 {
        let p = try resolveTOTPProfile(id)
        guard p.otpMode == .totp else {
            throw AutomationError(.invalidArgument, String(localized: "Profile “\(p.id)” does not use a TOTP secret."))
        }
        // Encrypted ("Confirm with Touch ID"): decrypting asks for Touch ID or the Mac password.
        guard let text = try await manager.vault.secret(p, .totp, for: .code) else { throw PTError.missingTOTPSecret(p.id) }
        let secret = try TOTP.decodeSecret(text)
        let now = Date()
        let code = TOTP.code(secret: secret, params: p.totp, at: now)
        let left = TOTP.remaining(params: p.totp, at: now)
        if copy { CLIClipboard.copyConcealed(code) }
        if json {
            try printJSON(CodeJSON(profile: p.id, code: code, remaining: left, period: p.totp.period))
        } else if CLITerminal.stdoutIsTTY {
            let suffix = copy ? "  " + String(localized: "copied") : ""
            CLITerminal.out(CLITerminal.bold(Self.grouped(code)) + "  " + CLITerminal.dim(String(localized: "\(left) s left")) + suffix)
        } else if !copy {
            CLITerminal.out(code)
        }
        return Exit.ok
    }

    /// Explicit id, default profile, or the only TOTP profile.
    private func resolveTOTPProfile(_ id: String?) throws -> Profile {
        if id != nil || store.defaultID != nil { return try resolve(id) }
        let totp = store.list().filter { $0.otpMode == .totp }
        if totp.count == 1 { return totp[0] }
        return try resolve(nil)
    }

    static func grouped(_ code: String) -> String {
        guard code.count >= 6 else { return code }
        let split = code.count / 2
        return String(code.prefix(split)) + " " + String(code.suffix(code.count - split))
    }

    // MARK: list / show / set

    private func list(json: Bool, quiet: Bool) throws -> Int32 {
        let profiles = store.list()
        let def = store.defaultID
        if quiet {
            profiles.forEach { CLITerminal.out($0.id) }
        } else if json {
            try printJSON(profiles.map { ProfileSummary($0, isDefault: $0.id == def) })
        } else if profiles.isEmpty {
            CLITerminal.out(String(localized: "No profiles. Add one with “passtunnel import FILE” or in the app."))
        } else {
            let idWidth = profiles.map(\.id.count).max() ?? 0
            let nameWidth = profiles.map(\.name.count).max() ?? 0
            for p in profiles {
                var flags: [String] = [p.type == .openvpn ? "OpenVPN" : "FortiGate"]
                if !p.username.isEmpty { flags.append(p.username) }
                if p.otpMode == .totp { flags.append("TOTP") }
                if p.pinned { flags.append(String(localized: "pinned")) }
                CLITerminal.out((p.id == def ? "* " : "  ") + p.id.padding(toLength: idWidth + 2, withPad: " ", startingAt: 0)
                    + p.name.padding(toLength: nameWidth + 2, withPad: " ", startingAt: 0)
                    + CLITerminal.dim(flags.joined(separator: " · ")))
            }
        }
        return Exit.ok
    }

    private struct ShowJSON: Encodable {
        var profile: Profile
        var isDefault: Bool
        var passwordSaved: Bool
        var totpSaved: Bool
        var passwordEncrypted: Bool
        var totpEncrypted: Bool
        var configFile: String?
        var remote: String?
    }

    private func show(_ id: String, json: Bool) throws -> Int32 {
        let p = try store.get(id)
        let hasConfig = p.type == .openvpn && FileManager.default.fileExists(atPath: store.ovpnURL(id).path)
        let remotes = hasConfig ? (try? String(contentsOf: store.ovpnURL(id), encoding: .utf8)).map { OVPNAnalyzer.analyze($0).remotes } : nil
        if json {
            try printJSON(ShowJSON(profile: p, isDefault: store.defaultID == id, passwordSaved: Secrets.has(id, .password),
                                   totpSaved: Secrets.has(id, .totp), passwordEncrypted: Secrets.isProtected(id, .password),
                                   totpEncrypted: Secrets.isProtected(id, .totp),
                                   configFile: hasConfig ? store.ovpnURL(id).path : nil,
                                   remote: remotes.map { $0.first ?? "" }))
            return Exit.ok
        }
        let missing = String(localized: "not saved")
        func saved(_ kind: SecretKind) -> String {
            guard Secrets.has(id, kind) else { return missing }
            return Secrets.isProtected(id, kind) ? String(localized: "saved in Keychain, encrypted (Touch ID)")
                                                 : String(localized: "saved in Keychain")
        }
        var rows: [(String, String)] = [("id", p.id), ("type", p.type.rawValue)]
        rows += ProfileFields.keys(for: p.type).map { ($0, ProfileFields.value(p, key: $0)) }
        rows.append(("password", saved(.password)))
        if p.otpMode == .totp { rows.append(("totp_secret", saved(.totp))) }
        if p.type == .openvpn {
            rows.append(("config", hasConfig ? store.ovpnURL(id).path : missing))
            if let remotes, !remotes.isEmpty { rows.append(("remote", OVPNAnalyzer.serverDescription(remotes))) }
        }
        rows.append(("default", String(store.defaultID == id)))
        let width = rows.map(\.0.count).max() ?? 0
        for (k, v) in rows {
            CLITerminal.out(CLITerminal.dim(k.padding(toLength: width + 2, withPad: " ", startingAt: 0)) + v)
        }
        return Exit.ok
    }

    private func set(_ id: String, _ assignments: [CLICommand.Assignment]) async throws -> Int32 {
        let original = try store.get(id)
        var p = original
        for a in assignments {
            guard ProfileFields.canonicalKey(a.key) != nil else {
                throw CLIUsageError(String(localized: "Unknown key “\(a.key)”."), command: "set")
            }
            try ProfileFields.set(&p, key: a.key, value: a.value)
        }
        // Encrypts or decrypts the saved secrets for require_auth; weakening it asks for Touch ID or the
        // Mac password (the decrypt is the confirmation).
        try await manager.vault.applyProtection(from: original, to: p)
        // A prompt may have been open for a while: apply the same changes to the profile as stored now.
        _ = try store.update(id) { current in
            for a in assignments { try ProfileFields.set(&current, key: a.key, value: a.value) }
        }
        if json { return try show(id, json: true) }
        CLITerminal.out(String(localized: "Saved."))
        return Exit.ok
    }

    // MARK: add / import / export / rm

    private func add(_ name: String, type: VPNType) throws -> Int32 {
        let p = try store.create(name: name, type: type)
        if json { try printJSON(automation.summary(p)); return Exit.ok }
        CLITerminal.out(String(localized: "Created “\(p.name)” (\(p.id))."))
        switch type {
        case .openvpn:
            CLITerminal.err(CLITerminal.dim(String(localized: "Next: add the configuration in the app, or import an .ovpn file with “passtunnel import FILE”.")))
        case .forti:
            CLITerminal.err(CLITerminal.dim(String(localized: "Next: passtunnel set \(p.id) host=vpn.example.com username=alice")))
        }
        return Exit.ok
    }

    private func importFile(_ path: String, name: String?) throws -> Int32 {
        let url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
        guard FileManager.default.fileExists(atPath: url.path) else { throw PTError.fileError(url.path) }
        let p: Profile
        if Self.looksLikeShareFile(url) {
            p = try store.importShare(url, name: name)
        } else {
            p = try store.importOVPN(url, name: name)
        }
        if json { try printJSON(automation.summary(p)); return Exit.ok }
        CLITerminal.out(String(localized: "Imported “\(p.name)” as \(p.id)."))
        if p.passwordMode == .keychain && Secrets.has(p.id, .password) {
            // Only from an inline <auth-user-pass> block: a new profile starts without Keychain items.
            CLITerminal.err(CLITerminal.dim(String(localized: "The user name and password in the file were moved to the profile and the Keychain.")))
        } else if p.passwordMode == .keychain {
            CLITerminal.err(CLITerminal.dim(String(localized: "Save the password with: passtunnel secret \(p.id) password")))
        }
        if p.otpMode == .totp {
            CLITerminal.err(CLITerminal.dim(String(localized: "Save the TOTP secret with: passtunnel secret \(p.id) totp")))
        }
        return Exit.ok
    }

    static func looksLikeShareFile(_ url: URL) -> Bool {
        if url.pathExtension.lowercased() == "passtunnel" { return true }
        guard let handle = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? handle.close() }
        let head = String(decoding: (try? handle.read(upToCount: 64)) ?? Data(), as: UTF8.self)
        return head.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("{")
    }

    private func export(_ id: String, output: String?) throws -> Int32 {
        let path = output ?? "\(id).passtunnel"
        let url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
        try store.exportShare(id, to: url)
        if json { try printJSON(ExportJSON(id: id, path: url.path)); return Exit.ok }
        CLITerminal.out(String(localized: "Exported to \(url.path)"))
        return Exit.ok
    }

    private struct ExportJSON: Encodable {
        var id: String
        var path: String
    }

    private struct RemoveJSON: Encodable {
        var id: String
        var deleted: Bool
    }

    private func remove(_ id: String, yes: Bool) async throws -> Int32 {
        let p = try store.get(id)
        // Without a terminal nobody can answer: deleting needs --yes then (a script or an agent).
        if !yes && (options.noInput || !CLITerminal.stdinIsTTY) {
            throw AutomationError(.inputRequired, String(localized: "Deleting asks for a confirmation. Add --yes to delete without asking."))
        }
        if !yes {
            guard CLITerminal.confirm(String(localized: "Delete “\(p.name)” and its saved password and secret?")) else {
                throw AutomationError(.cancelled, String(localized: "Nothing was deleted."))
            }
        }
        await manager.refresh()
        if manager.state(id).isActive { _ = try? await manager.disconnect(id) }
        try store.delete(id)
        if json { try printJSON(RemoveJSON(id: id, deleted: true)); return Exit.ok }
        CLITerminal.out(String(localized: "Deleted “\(p.name)”."))
        return Exit.ok
    }

    // MARK: secrets / default / pin

    /// The result of `secret --json`: what was saved, never the value (nor, for TOTP, a code).
    private struct SecretJSON: Encodable {
        var id: String
        var secret: String
        var saved: Bool
        var encrypted: Bool
    }

    private func secret(_ id: String, kind: SecretKind) async throws -> Int32 {
        let original = try store.get(id)
        var p = original
        guard !options.noInput else {
            throw AutomationError(.inputRequired, String(localized: "The secret is read from standard input or the terminal, which --no-input does not allow."))
        }
        let value: String
        if CLITerminal.stdinIsTTY {
            let prompt = kind == .password ? String(localized: "Password for \(p.name): ")
                                           : String(localized: "TOTP secret or otpauth:// link for \(p.name): ")
            value = CLITerminal.askSecret(prompt) ?? ""
        } else {
            value = CLITerminal.readAllStdin()
        }
        guard !value.isEmpty else { throw AutomationError(.invalidArgument, String(localized: "Nothing was entered.")) }

        switch kind {
        case .password:
            p.passwordMode = .keychain
            // Encrypted with the profile's public key when require_auth protects it: no prompt.
            try await manager.vault.applyProtection(from: original, to: p)
            try manager.vault.store(p, .password, value)
            if original.passwordMode != .keychain {
                try store.save(p)
                if !json { CLITerminal.err(CLITerminal.dim(String(localized: "The password is now taken from the Keychain."))) }
            }
            if json { break }
            CLITerminal.out(String(localized: "Password saved in the Keychain."))
            if Secrets.isProtected(id, .password) {
                CLITerminal.err(CLITerminal.dim(String(localized: "It is encrypted: using it asks for Touch ID or your Mac password.")))
            }
        case .totp:
            let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
            let secret: Data
            if text.lowercased().hasPrefix("otpauth:") {
                let uri = try OTPAuthURI(text)
                secret = uri.secret
                p.totp = uri.params
            } else {
                secret = try TOTP.decodeSecret(text)
            }
            if p.otpMode != .totp { p.otpMode = .totp }
            try await manager.vault.applyProtection(from: original, to: p)
            try manager.vault.store(p, .totp, TOTP.base32Encode(secret))
            try store.save(p)
            if json { break }
            CLITerminal.out(String(localized: "TOTP secret saved in the Keychain."))
            if Secrets.isProtected(id, .totp) {
                CLITerminal.err(CLITerminal.dim(String(localized: "It is encrypted: using it asks for Touch ID or your Mac password.")))
            }
            let code = TOTP.code(secret: secret, params: p.totp)
            CLITerminal.out(String(localized: "Current code: \(Self.grouped(code)) (compare it with your authenticator app)"))
        }
        if json { try printJSON(SecretJSON(id: id, secret: kind.rawValue, saved: true, encrypted: Secrets.isProtected(id, kind))) }
        return Exit.ok
    }

    private struct DefaultJSON: Encodable {
        var `default`: String?

        enum CodingKeys: String, CodingKey { case `default` }

        func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encode(self.default, forKey: .default)   // null when none is set
        }
    }

    private func setDefault(_ id: String?) throws -> Int32 {
        guard let id else {
            guard let def = store.defaultID else {
                if json { try printJSON(DefaultJSON(default: nil)) } else { CLITerminal.err(String(localized: "No default profile is set.")) }
                return Exit.error
            }
            if json { try printJSON(DefaultJSON(default: def)) } else { CLITerminal.out(def) }
            return Exit.ok
        }
        try store.setDefault(id)
        if json { try printJSON(DefaultJSON(default: id)); return Exit.ok }
        CLITerminal.out(String(localized: "Default profile: \(id)"))
        return Exit.ok
    }

    private func pin(_ id: String, _ on: Bool) throws -> Int32 {
        var p = try store.get(id)
        p.pinned = on
        try store.save(p)
        if json { try printJSON(automation.summary(p)); return Exit.ok }
        CLITerminal.out(on ? String(localized: "Pinned “\(p.name)” to the menu bar.")
                        : String(localized: "Unpinned “\(p.name)”."))
        return Exit.ok
    }

    // MARK: log

    /// `lines`: only the last N lines first. `--json`: `AutomationService.logs` (redacted, at most
    /// `AutomationService.maxLogLines`).
    private func log(_ id: String, follow: Bool, lines: Int?) async throws -> Int32 {
        if json {
            try printJSON(automation.logs(id, lines: lines ?? AutomationService.maxLogLines))
            return Exit.ok
        }
        _ = try store.get(id)
        let url = store.logURL(id)
        var offset: UInt64 = 0
        var inode: UInt64 = 0
        func dump() {
            guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path) else { return }
            let size = (attrs[.size] as? NSNumber)?.uint64Value ?? 0
            let node = (attrs[.systemFileNumber] as? NSNumber)?.uint64Value ?? 0
            if node != inode || size < offset { offset = 0; inode = node }   // a new session recreated the log
            guard size > offset, let h = try? FileHandle(forReadingFrom: url) else { return }
            defer { try? h.close() }
            try? h.seek(toOffset: offset)
            let data = (try? h.readToEnd()) ?? Data()
            offset += UInt64(data.count)
            FileHandle.standardOutput.write(data)
        }
        if !FileManager.default.fileExists(atPath: url.path) && !follow {
            CLITerminal.err(String(localized: "There is no log for this profile yet."))
            return Exit.ok
        }
        if let lines {
            let text = VPNLog.read(url)
            let tail = text.split(separator: "\n", omittingEmptySubsequences: false).suffix(lines + (text.hasSuffix("\n") ? 1 : 0))
            FileHandle.standardOutput.write(Data(tail.joined(separator: "\n").utf8))
            let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
            offset = (attrs?[.size] as? NSNumber)?.uint64Value ?? 0
            inode = (attrs?[.systemFileNumber] as? NSNumber)?.uint64Value ?? 0
        } else {
            dump()
        }
        guard follow else { return Exit.ok }
        while true {
            try? await Task.sleep(nanoseconds: 500_000_000)
            dump()
        }
    }

    // MARK: helper

    private func helper(_ action: CLICommand.HelperAction) async throws -> Int32 {
        switch action {
        case .status:
            return await printHelperStatus()
        case .install:
            switch HelperInstaller.status {
            case .enabled:
                guard await helperIsOutdated() == true else { return await printHelperStatus() }
                return try await updateHelper()
            case .notFound:
                return await printHelperStatus()
            case .requiresApproval:
                HelperInstaller.openSystemSettingsLoginItems()
                return await printHelperStatus()
            case .notRegistered:
                break
            }
            // SMAppService refuses registrations from a process started in Terminal ("Operation not
            // permitted"), so the app does it: always, rather than trying here first.
            let replies = HandoffReplies(.install, timeout: 30)
            try handOffToApp(.install)
            CLITerminal.out(String(localized: "Opening PassTunnel to install the helper…"))
            CLITerminal.out(String(localized: "Approve it in PassTunnel, then turn on PassTunnel in System Settings → General → Login Items."))
            switch await wait(for: replies, until: { HelperInstaller.status != .notRegistered }) {
            case .done:
                return await printHelperStatus()
            case .refused:
                printRefused()
                fallthrough
            case .declined, .timedOut:
                CLITerminal.out(String(localized: "The helper is not installed yet. Finish the installation in PassTunnel → Settings → Helper."))
                return Exit.error
            }
        case .uninstall:
            guard HelperInstaller.status != .notRegistered else {
                CLITerminal.out(String(localized: "The helper is not installed."))
                return Exit.ok
            }
            let replies = HandoffReplies(.uninstall, timeout: 60)
            try handOffToApp(.uninstall)
            CLITerminal.out(String(localized: "Opening PassTunnel to remove the helper. Confirm the removal there."))
            switch await wait(for: replies, until: { HelperInstaller.status == .notRegistered }) {
            case .done:
                CLITerminal.out(String(localized: "The helper was removed."))
                return Exit.ok
            case .declined:
                CLITerminal.out(String(localized: "The removal was cancelled in PassTunnel. The helper is still installed."))
                return Exit.error
            case .refused, .timedOut:
                CLITerminal.out(String(localized: "The helper is still installed. Confirm the removal in PassTunnel → Settings → Helper."))
                return Exit.error
            }
        }
    }

    #if DEBUG
    // MARK: debug

    /// `DebugDrop`: the running app sends the command over the management connection it holds;
    /// without the app, this process sends it. Then waits for the profile to leave "connected".
    private func debugDrop(_ id: String) async throws -> Int32 {
        let p = try store.get(id)
        guard p.type == .openvpn else { throw PTError.wrongProfileType(p.id) }
        await manager.refresh()
        guard manager.state(p.id).isActive else {
            CLITerminal.out(String(localized: "\(p.name) is not connected."))
            return Exit.notConnected
        }
        if NSRunningApplication.runningApplications(withBundleIdentifier: PT.bundleID)
            .contains(where: { !$0.isTerminated && $0.processIdentifier != getpid() }) {
            DistributedNotificationCenter.default().postNotificationName(
                DebugDrop.notification, object: p.id, userInfo: nil, deliverImmediately: true)
            CLITerminal.out(String(localized: "Asked PassTunnel to drop \(p.name) as if the server ended the session…"))
        } else {
            guard try await manager.simulateDrop(p.id) else {
                CLITerminal.out(String(localized: "\(p.name) is not connected."))
                return Exit.notConnected
            }
            CLITerminal.out(String(localized: "Dropping \(p.name) as if the server ended the session…"))
        }
        let deadline = Date().addingTimeInterval(15)
        while Date() < deadline {
            try? await Task.sleep(nanoseconds: 500_000_000)
            await manager.refresh()
            if !manager.state(p.id).isConnected {
                CLITerminal.out(String(localized: "\(p.name) dropped."))
                return Exit.ok
            }
        }
        CLITerminal.out(String(localized: "\(p.name) is still connected."))
        return Exit.error
    }
    #endif

    /// The helper is enabled but from another app version or build: the app replaces it (unregister,
    /// then register from its own bundle), which stops its connections. Waits for the current helper.
    private func updateHelper() async throws -> Int32 {
        let replies = HandoffReplies(.update, timeout: 60)
        try handOffToApp(.update)
        CLITerminal.out(String(localized: "Opening PassTunnel to update the helper…"))
        CLITerminal.out(String(localized: "Active connections stop while the helper is replaced."))
        // Give the app time to unregister the old helper before asking the running one.
        try? await Task.sleep(nanoseconds: 2_000_000_000)
        let result = await wait(for: replies) {
            guard HelperInstaller.status == .enabled else { return false }
            return await self.helperIsOutdated() == false
        }
        switch result {
        case .done:
            CLITerminal.out(String(localized: "The helper was updated."))
            return await printHelperStatus()
        case .declined:
            CLITerminal.out(String(localized: "The update was cancelled in PassTunnel. The helper was not replaced."))
            return Exit.error
        case .refused:
            printRefused()
            return Exit.error
        case .timedOut:
            CLITerminal.out(String(localized: "The helper is not updated yet. Finish the update in PassTunnel → Settings → Helper."))
            _ = await printHelperStatus()
            return Exit.error
        }
    }

    private func printRefused() {
        CLITerminal.out(String(localized: "PassTunnel did not change the helper: open PassTunnel from the Applications folder, then try again."))
    }

    /// Polls `done` until it holds or the app answered the hand-off (`HelperHandoffWait`). Says so
    /// once the app asks the user to confirm, and then waits for their decision.
    private func wait(for replies: HandoffReplies, until done: () async -> Bool) async -> HelperHandoffWait.Result {
        defer { replies.stop() }
        while true {
            if replies.takeAsking() {
                CLITerminal.out(String(localized: "Waiting for your confirmation in PassTunnel…"))
            }
            if let result = replies.wait.result(done: await done()) { return result }
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
    }

    /// Whether the running helper speaks another protocol or is another build; nil when it does not answer.
    private func helperIsOutdated() async -> Bool? {
        let client = HelperClient(timeout: 5)
        defer { client.invalidate() }
        return try? await client.isOutdated()
    }

    /// Asks the app to perform `action`: a running copy gets a notification, otherwise the app is
    /// launched with the action's argument. Prefers the app bundle this CLI belongs to, whose helper
    /// is the one to register.
    private func handOffToApp(_ action: HelperHandoff) throws {
        if let running = NSRunningApplication.runningApplications(withBundleIdentifier: PT.bundleID)
            .first(where: { !$0.isTerminated && $0.processIdentifier != getpid() }) {
            DistributedNotificationCenter.default().postNotificationName(
                HelperHandoff.notification, object: action.rawValue, userInfo: nil, deliverImmediately: true)
            running.activate(options: [])
            return
        }
        let bundle = Bundle.main
        let target: [String] = bundle.bundleURL.pathExtension == "app" && bundle.bundleIdentifier == PT.bundleID
            ? [bundle.bundlePath] : ["-b", PT.bundleID]
        let open = Process()
        open.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        open.arguments = target + ["--args", action.argument]
        open.standardOutput = FileHandle.nullDevice
        open.standardError = FileHandle.nullDevice
        do { try open.run() } catch {
            throw CLIFailure(String(localized: "Could not open PassTunnel: \(error.localizedDescription)"))
        }
        open.waitUntilExit()
        guard open.terminationStatus == 0 else {
            throw CLIFailure(String(localized: "Could not open PassTunnel. Install it in the Applications folder and try again."))
        }
    }


    /// Exit 0 when the helper is enabled, answering and current, else `AutomationExit.helper`.
    private func printHelperStatus() async -> Int32 {
        let r = await automation.helperReport()
        let code = r.isUsable ? Exit.ok : AutomationExit.helper
        if json {
            try? printJSON(r)
            return code
        }
        switch r.state {
        case "enabled":
            if let v = r.protocolVersion {
                let note = r.outdated == true ? "  " + String(localized: "(out of date; “passtunnel helper install” updates it)") : ""
                CLITerminal.out(String(localized: "Helper: enabled (protocol \(v))") + note)
            } else {
                CLITerminal.out(String(localized: "Helper: enabled, but not responding"))
            }
        case "requires_approval":
            CLITerminal.out(String(localized: "Helper: needs approval in System Settings → General → Login Items"))
        case "not_installed":
            CLITerminal.out(String(localized: "Helper: not installed (run “passtunnel helper install”)"))
        default:
            CLITerminal.out(String(localized: "Helper: missing from the app bundle"))
        }
        return code
    }

    // MARK: output

    private func printJSON<T: Encodable>(_ value: T) throws {
        let data = try AutomationJSON.encoder().encode(value)
        FileHandle.standardOutput.write(data + Data("\n".utf8))
    }
}

/// Type-erased Encodable so one call can print either an array or a single object.
private struct AnyEncodable: Encodable {
    private let encodeBody: (Encoder) throws -> Void
    init<T: Encodable>(_ value: T) { encodeBody = value.encode }
    func encode(to encoder: Encoder) throws { try encodeBody(encoder) }
}

enum CLIClipboard {
    /// Copies a code like the app does (`Pasteboard.copySecret`: this Mac only, concealed, transient)
    /// and leaves a detached copy of this binary behind that clears it after `Pasteboard.secretLifetime`
    /// unless something else was copied meanwhile; the command itself returns at once.
    static func copyConcealed(_ text: String) {
        let count = Pasteboard.copySecret(text)
        scheduleClear(ifUnchangedSince: count)
    }

    /// Runs `passtunnel <PassTunnelCLI.clearClipboardArgument> COUNT` in a new session with no
    /// terminal, so closing the terminal does not end it. It inherits no descriptor (a store lock
    /// would otherwise stay held while it waits): stdin, stdout and stderr are /dev/null. Best effort.
    private static func scheduleClear(ifUnchangedSince count: Int) {
        guard let executable = Bundle.main.executablePath else { return }
        let argv = ["passtunnel", PassTunnelCLI.clearClipboardArgument, String(count)]
        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        defer { posix_spawnattr_destroy(&attr) }
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT))
        var actions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&actions)
        defer { posix_spawn_file_actions_destroy(&actions) }
        for fd in [STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO] {
            posix_spawn_file_actions_addopen(&actions, fd, "/dev/null", fd == STDIN_FILENO ? O_RDONLY : O_WRONLY, 0)
        }
        var cArgs = argv.map { strdup($0) } + [nil]
        defer { cArgs.forEach { free($0) } }
        var pid: pid_t = 0
        _ = posix_spawn(&pid, executable, &actions, &attr, &cArgs, environ)
    }

    /// The detached process: waits, then clears the pasteboard if it still holds the copied code.
    static func clearLater(ifUnchangedSince count: Int) -> Int32 {
        Thread.sleep(forTimeInterval: Pasteboard.secretLifetime)
        Pasteboard.clear(ifUnchangedSince: count)
        return PassTunnelCLI.Exit.ok
    }
}

/// A plain CLI error (exit code 1, `internal` in JSON).
struct CLIFailure: LocalizedError {
    var message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

/// The app's replies to one helper hand-off (`HelperHandoff.replyNotification`), received on the main
/// run loop the CLI keeps running. Created before the request goes out, so no reply is missed.
@MainActor
private final class HandoffReplies {
    private(set) var wait: HelperHandoffWait
    private var newlyAsking = false
    private var observer: NSObjectProtocol?

    init(_ action: HelperHandoff, timeout: TimeInterval) {
        wait = HelperHandoffWait(action: action, timeout: timeout)
        observer = DistributedNotificationCenter.default().addObserver(
            forName: HelperHandoff.replyNotification, object: nil, queue: .main) { [weak self] note in
            let object = note.object as? String
            MainActor.assumeIsolated {
                guard let self else { return }
                if self.wait.received(object) { self.newlyAsking = true }
            }
        }
    }

    /// True once after the app started asking the user.
    func takeAsking() -> Bool {
        defer { newlyAsking = false }
        return newlyAsking
    }

    func stop() {
        if let observer { DistributedNotificationCenter.default().removeObserver(observer) }
        observer = nil
    }
}
