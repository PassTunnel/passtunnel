import AppKit
import Combine
import Foundation
import PassTunnelCore
import PassTunnelShared

/// Executes parsed CLI commands against the same Core APIs the app uses.
@MainActor
final class CLIRunner {
    typealias Exit = PassTunnelCLI.Exit

    let store = ProfileStore()
    private var managerStorage: ConnectionManager?
    private var bag: Set<AnyCancellable> = []
    private var signalSource: DispatchSourceSignal?

    /// Created on first use so offline commands never talk to the helper.
    var manager: ConnectionManager {
        if let managerStorage { return managerStorage }
        let m = ConnectionManager(store: store)
        managerStorage = m
        return m
    }

    func run(_ command: CLICommand) async -> Int32 {
        defer { if Self.changesProfiles(command) { ProfileChangeSignal.post() } }
        do {
            return try await execute(command)
        } catch let e as CLIUsageError {
            CLITerminal.fail(e.message)
            CLITerminal.err(CLIHelp.usage(for: e.command))
            return Exit.usage
        } catch {
            report(error)
            return Exit.error
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
        case let .connect(id, force): return try await connect(id, force: force)
        case let .disconnect(id, all): return try await disconnect(id, all: all)
        case let .toggle(id): return try await toggle(id)
        case let .code(id, copy, json): return try code(id, copy: copy, json: json)
        case let .list(json, quiet): return try list(json: json, quiet: quiet)
        case let .show(id, json): return try show(id, json: json)
        case let .set(id, assignments): return try set(id, assignments)
        case let .add(name, type): return try add(name, type: type)
        case let .importFile(path, name): return try importFile(path, name: name)
        case let .export(id, output): return try export(id, output: output)
        case let .remove(id, yes): return try await remove(id, yes: yes)
        case let .secret(id, kind): return try secret(id, kind: kind)
        case let .setDefault(id): return try setDefault(id)
        case let .pin(id): return try pin(id, true)
        case let .unpin(id): return try pin(id, false)
        case let .log(id, follow): return try await log(id, follow: follow)
        case let .helper(action): return try await helper(action)
        case let .debug(.drop, id): return try await debugDrop(id)
        case let .completion(shell):
            FileHandle.standardOutput.write(Data(CLICompletions.script(for: shell).utf8))
            return Exit.ok
        case let .help(name):
            CLITerminal.out(CLIHelp.usage(for: name))
            return Exit.ok
        case .version:
            let info = Bundle.main.infoDictionary
            let version = info?["CFBundleShortVersionString"] as? String ?? "dev"
            let build = info?["CFBundleVersion"] as? String
            CLITerminal.out("PassTunnel \(version)" + (build.map { " (\($0))" } ?? ""))
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
        if all.isEmpty { throw CLIFailure(String(localized: "There are no profiles yet. Add one with “passtunnel import FILE”.")) }
        throw CLIFailure(String(localized: "No default profile is set. Give a profile id, or set one with “passtunnel default ID”."))
    }

    // MARK: status

    private struct StatusJSON: Encodable {
        var id: String
        var name: String
        var type: String
        var state: String
        var phase: String?
        var ip: String?
        var since: Date?
        var isDefault: Bool
        var health: String?
        var error: String?
        var warning: String?
        var statusUnavailable: Bool?
    }

    private func statusJSON(_ p: Profile) -> StatusJSON {
        let m = manager
        var s = StatusJSON(id: p.id, name: p.name, type: p.type.rawValue, state: "disconnected",
                           isDefault: store.defaultID == p.id, error: m.lastError[p.id])
        switch m.state(p.id) {
        case .disconnected: break
        case .connecting(let phase): s.state = "connecting"; s.phase = phase
        case let .connected(ip, since):
            s.state = "connected"; s.ip = ip; s.since = since; s.warning = m.warnings[p.id]
            if m.statusUnavailable.contains(p.id) { s.statusUnavailable = true }
        }
        return s
    }

    private func status(_ id: String?, json: Bool) async throws -> Int32 {
        let profiles: [Profile] = try id.map { [try store.get($0)] } ?? store.list()
        await manager.refresh()
        if let e = manager.helperError, !json {
            CLITerminal.err(CLITerminal.dim(String(localized: "Note: the helper is not available (\(e)).")))
        }
        if json {
            try printJSON(id == nil ? AnyEncodable(profiles.map(statusJSON)) : AnyEncodable(statusJSON(profiles[0])))
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

    private func connect(_ id: String?, force: Bool = false) async throws -> Int32 {
        let p = try resolve(id)
        await manager.refresh()
        if manager.state(p.id).isConnected {
            CLITerminal.out(String(localized: "\(p.name) is already connected."))
            return Exit.ok
        }
        if manager.state(p.id).isConnecting {
            // Started elsewhere (the app, another terminal): wait for that connection instead.
            try await connectShowingProgress(p, given: [:], joining: true)
            return Exit.ok
        }
        do {
            // Before "Connecting …" and before asking for credentials.
            if !force { try await manager.checkCanStart(p.id) }
            let given = try askForNeeds(p)
            try await connectShowingProgress(p, given: given, force: force)
        } catch PTError.otherVPNActive(let other) {
            CLITerminal.fail(PTError.otherVPNActive(other).localizedDescription)
            CLITerminal.err(CLITerminal.dim(String(localized: "Use --force to connect anyway.")))
            return Exit.error
        }
        return Exit.ok
    }

    private func connectShowingProgress(_ p: Profile, given: [CredentialField: String], joining: Bool = false,
                                        force: Bool = false) async throws {
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
        // Ctrl-C while connecting stops the half-started connection (only stops waiting when joining).
        signal(SIGINT, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
        source.setEventHandler { [weak self] in
            Task { @MainActor in
                if joining { exit(130) }
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
        try await manager.connect(p.id, given: given, force: force)
        if case let .connected(ip, _) = manager.state(p.id) {
            CLITerminal.out(ip.isEmpty ? String(localized: "Connected: \(p.name)")
                                    : String(localized: "Connected: \(p.name) (\(ip))"))
            if let warning = manager.warnings[p.id] { CLITerminal.err(warning) }
        }
    }

    /// Asks on the terminal for whatever the profile needs (`Profile.needs`).
    private func askForNeeds(_ p: Profile) throws -> [CredentialField: String] {
        let needs = p.needs
        guard !needs.isEmpty else { return [:] }
        guard CLITerminal.stdinIsTTY else {
            let list = needs.map(\.displayName).joined(separator: ", ")
            throw CLIFailure(String(localized: "This profile asks for: \(list). Run the command in a terminal."))
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

    private func disconnect(_ id: String?, all: Bool) async throws -> Int32 {
        if all {
            try await manager.disconnectAll()
            CLITerminal.out(String(localized: "All profiles are disconnected."))
            return Exit.ok
        }
        let p = try resolve(id)
        if try await manager.disconnect(p.id) {
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
            CLITerminal.out(String(localized: "Disconnected: \(p.name)"))
        } else {
            try await connectShowingProgress(p, given: try askForNeeds(p))
        }
        return Exit.ok
    }

    // MARK: code

    private struct CodeJSON: Encodable {
        var profile: String
        var code: String
        var remaining: Int
        var period: Int
    }

    private func code(_ id: String?, copy: Bool, json: Bool) throws -> Int32 {
        let p = try resolveTOTPProfile(id)
        guard p.otpMode == .totp else {
            throw CLIFailure(String(localized: "Profile “\(p.id)” does not use a TOTP secret."))
        }
        guard let text = Secrets.get(p.id, .totp) else { throw PTError.missingTOTPSecret(p.id) }
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

    private struct ListJSON: Encodable {
        var id: String
        var name: String
        var type: String
        var isDefault: Bool
        var pinned: Bool
        var username: String
        var passwordMode: String
        var otpMode: String
    }

    private func list(json: Bool, quiet: Bool) throws -> Int32 {
        let profiles = store.list()
        let def = store.defaultID
        if quiet {
            profiles.forEach { CLITerminal.out($0.id) }
        } else if json {
            try printJSON(profiles.map {
                ListJSON(id: $0.id, name: $0.name, type: $0.type.rawValue, isDefault: $0.id == def, pinned: $0.pinned,
                         username: $0.username, passwordMode: $0.passwordMode.rawValue, otpMode: $0.otpMode.rawValue)
            })
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
        var configFile: String?
        var remote: String?
    }

    private func show(_ id: String, json: Bool) throws -> Int32 {
        let p = try store.get(id)
        let hasConfig = p.type == .openvpn && FileManager.default.fileExists(atPath: store.ovpnURL(id).path)
        let remote = hasConfig ? (try? String(contentsOf: store.ovpnURL(id), encoding: .utf8)).map { OVPNAnalyzer.analyze($0).remote } : nil
        if json {
            try printJSON(ShowJSON(profile: p, isDefault: store.defaultID == id, passwordSaved: Secrets.has(id, .password),
                                   totpSaved: Secrets.has(id, .totp), configFile: hasConfig ? store.ovpnURL(id).path : nil,
                                   remote: remote))
            return Exit.ok
        }
        let saved = String(localized: "saved in Keychain")
        let missing = String(localized: "not saved")
        var rows: [(String, String)] = [("id", p.id), ("type", p.type.rawValue)]
        rows += ProfileFields.keys(for: p.type).map { ($0, ProfileFields.value(p, key: $0)) }
        rows.append(("password", Secrets.has(id, .password) ? saved : missing))
        if p.otpMode == .totp { rows.append(("totp_secret", Secrets.has(id, .totp) ? saved : missing)) }
        if p.type == .openvpn {
            rows.append(("config", hasConfig ? store.ovpnURL(id).path : missing))
            if let remote, !remote.isEmpty { rows.append(("remote", remote)) }
        }
        rows.append(("default", String(store.defaultID == id)))
        let width = rows.map(\.0.count).max() ?? 0
        for (k, v) in rows {
            CLITerminal.out(CLITerminal.dim(k.padding(toLength: width + 2, withPad: " ", startingAt: 0)) + v)
        }
        return Exit.ok
    }

    private func set(_ id: String, _ assignments: [CLICommand.Assignment]) throws -> Int32 {
        var p = try store.get(id)
        for a in assignments {
            guard ProfileFields.canonicalKey(a.key) != nil else {
                throw CLIUsageError(String(localized: "Unknown key “\(a.key)”."), command: "set")
            }
            try ProfileFields.set(&p, key: a.key, value: a.value)
        }
        try store.save(p)
        CLITerminal.out(String(localized: "Saved."))
        return Exit.ok
    }

    // MARK: add / import / export / rm

    private func add(_ name: String, type: VPNType) throws -> Int32 {
        let p = try store.create(name: name, type: type)
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
        CLITerminal.out(String(localized: "Imported “\(p.name)” as \(p.id)."))
        if p.passwordMode == .keychain {
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
        CLITerminal.out(String(localized: "Exported to \(url.path)"))
        return Exit.ok
    }

    private func remove(_ id: String, yes: Bool) async throws -> Int32 {
        let p = try store.get(id)
        if !yes && CLITerminal.stdinIsTTY {
            guard CLITerminal.confirm(String(localized: "Delete “\(p.name)” and its saved password and secret?")) else {
                CLITerminal.err(String(localized: "Nothing was deleted."))
                return Exit.error
            }
        }
        await manager.refresh()
        if manager.state(id).isActive { _ = try? await manager.disconnect(id) }
        try store.delete(id)
        CLITerminal.out(String(localized: "Deleted “\(p.name)”."))
        return Exit.ok
    }

    // MARK: secrets / default / pin

    private func secret(_ id: String, kind: SecretKind) throws -> Int32 {
        var p = try store.get(id)
        let value: String
        if CLITerminal.stdinIsTTY {
            let prompt = kind == .password ? String(localized: "Password for \(p.name): ")
                                           : String(localized: "TOTP secret or otpauth:// link for \(p.name): ")
            value = CLITerminal.askSecret(prompt) ?? ""
        } else {
            value = CLITerminal.readAllStdin()
        }
        guard !value.isEmpty else { throw CLIFailure(String(localized: "Nothing was entered.")) }

        switch kind {
        case .password:
            try Secrets.set(id, .password, value)
            if p.passwordMode != .keychain {
                p.passwordMode = .keychain
                try store.save(p)
                CLITerminal.err(CLITerminal.dim(String(localized: "The password is now taken from the Keychain.")))
            }
            CLITerminal.out(String(localized: "Password saved in the Keychain."))
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
            try Secrets.set(id, .totp, TOTP.base32Encode(secret))
            if p.otpMode != .totp { p.otpMode = .totp }
            try store.save(p)
            CLITerminal.out(String(localized: "TOTP secret saved in the Keychain."))
            let code = TOTP.code(secret: secret, params: p.totp)
            CLITerminal.out(String(localized: "Current code: \(Self.grouped(code)) (compare it with your authenticator app)"))
        }
        return Exit.ok
    }

    private func setDefault(_ id: String?) throws -> Int32 {
        guard let id else {
            guard let def = store.defaultID else {
                CLITerminal.err(String(localized: "No default profile is set."))
                return Exit.error
            }
            CLITerminal.out(def)
            return Exit.ok
        }
        try store.setDefault(id)
        CLITerminal.out(String(localized: "Default profile: \(id)"))
        return Exit.ok
    }

    private func pin(_ id: String, _ on: Bool) throws -> Int32 {
        var p = try store.get(id)
        p.pinned = on
        try store.save(p)
        CLITerminal.out(on ? String(localized: "Pinned “\(p.name)” to the menu bar.")
                        : String(localized: "Unpinned “\(p.name)”."))
        return Exit.ok
    }

    // MARK: log

    private func log(_ id: String, follow: Bool) async throws -> Int32 {
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
        dump()
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
            try handOffToApp(.install)
            CLITerminal.out(String(localized: "Opening PassTunnel to install the helper…"))
            CLITerminal.out(String(localized: "Approve it in PassTunnel, then turn on PassTunnel in System Settings → General → Login Items."))
            guard await waitForHelperStatus(timeout: 30, until: { $0 != .notRegistered }) else {
                CLITerminal.out(String(localized: "The helper is not installed yet. Finish the installation in PassTunnel → Settings → Helper."))
                return Exit.error
            }
            return await printHelperStatus()
        case .uninstall:
            guard HelperInstaller.status != .notRegistered else {
                CLITerminal.out(String(localized: "The helper is not installed."))
                return Exit.ok
            }
            try handOffToApp(.uninstall)
            CLITerminal.out(String(localized: "Opening PassTunnel to remove the helper. Confirm the removal there."))
            guard await waitForHelperStatus(timeout: 60, until: { $0 == .notRegistered }) else {
                CLITerminal.out(String(localized: "The helper is still installed. Confirm the removal in PassTunnel → Settings → Helper."))
                return Exit.error
            }
            CLITerminal.out(String(localized: "The helper was removed."))
            return Exit.ok
        }
    }

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

    /// The helper is enabled but from another app version or build: the app replaces it (unregister,
    /// then register from its own bundle), which stops its connections. Waits for the current helper.
    private func updateHelper() async throws -> Int32 {
        try handOffToApp(.update)
        CLITerminal.out(String(localized: "Opening PassTunnel to update the helper…"))
        CLITerminal.out(String(localized: "Active connections stop while the helper is replaced."))
        let deadline = Date().addingTimeInterval(60)
        // Give the app time to unregister the old helper before asking the running one.
        try? await Task.sleep(nanoseconds: 2_000_000_000)
        while Date() < deadline {
            if HelperInstaller.status == .enabled, await helperIsOutdated() == false {
                CLITerminal.out(String(localized: "The helper was updated."))
                return await printHelperStatus()
            }
            try? await Task.sleep(nanoseconds: 1_000_000_000)
        }
        CLITerminal.out(String(localized: "The helper is not updated yet. Finish the update in PassTunnel → Settings → Helper."))
        _ = await printHelperStatus()
        return Exit.error
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

    /// Polls the helper's registration until `condition` holds or `timeout` seconds pass.
    private func waitForHelperStatus(timeout: TimeInterval, until condition: (HelperStatus) -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition(HelperInstaller.status) {
            if Date() > deadline { return false }
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
        return true
    }

    private func printHelperStatus() async -> Int32 {
        switch HelperInstaller.status {
        case .enabled:
            if let v = try? await HelperClient.shared.version() {
                var outdated = v != PT.helperProtocolVersion
                if !outdated { outdated = (try? await HelperClient.shared.isOutdated()) == true }
                let note = outdated ? "  " + String(localized: "(out of date; “passtunnel helper install” updates it)") : ""
                CLITerminal.out(String(localized: "Helper: enabled (protocol \(v))") + note)
            } else {
                CLITerminal.out(String(localized: "Helper: enabled, but not responding"))
            }
            return Exit.ok
        case .requiresApproval:
            CLITerminal.out(String(localized: "Helper: needs approval in System Settings → General → Login Items"))
        case .notRegistered:
            CLITerminal.out(String(localized: "Helper: not installed (run “passtunnel helper install”)"))
        case .notFound:
            CLITerminal.out(String(localized: "Helper: missing from the app bundle"))
        }
        return Exit.error
    }

    // MARK: output

    private func printJSON<T: Encodable>(_ value: T) throws {
        let e = JSONCoding.encoder()
        e.dateEncodingStrategy = .iso8601
        let data = try e.encode(value)
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
    /// Copies text and marks it concealed so clipboard managers skip it.
    static func copyConcealed(_ text: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.declareTypes([.string, NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")], owner: nil)
        pb.setString(text, forType: .string)
        pb.setString("", forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
    }
}

/// A plain CLI error (exit code 1).
struct CLIFailure: LocalizedError {
    var message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}
