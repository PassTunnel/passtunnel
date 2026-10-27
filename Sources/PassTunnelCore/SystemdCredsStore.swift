import Foundation
import PassTunnelKit

#if canImport(Glibc)
import Glibc
#endif

/// Encrypted credential files in `<support dir>/secrets/` (0700; files 0600, written atomically),
/// made and read by `systemd-creds encrypt/decrypt` over standard input and output. The credential's
/// name (`--name`, the escaped account) is sealed into it, so a file renamed to another account does
/// not decrypt. Root uses the system's key (host key and TPM2); other users `--user`, which needs
/// systemd 256 or later. Linux only (docs/LINUX.md); built everywhere for its tests.
struct SystemdCredsStore: SecretStore {
    /// Where `systemd-creds` is looked for, in this order (never in PATH).
    static let toolPaths = ["/usr/bin/systemd-creds", "/bin/systemd-creds"]
    /// The first systemd whose `systemd-creds` has `--user`.
    static let minimumUserVersion = 256
    static let timeout: TimeInterval = 30
    static let maxCredentialSize = 1 << 20

    let system: SecretStoreSystem

    var directory: URL { system.paths.secretsDirectory }

    func url(_ account: String) -> URL {
        directory.appendingPathComponent(Self.credentialName(account) + ".cred")
    }

    /// The account as a credential and file name: `a-z`, `0-9`, `-` and `_` as they are, every other
    /// byte as %XX ("acme/totp" → "acme%2Ftotp"). Never empty, never starts with a dot, no slash, no
    /// colon: valid for `systemd-creds --name` and as a file name.
    static func credentialName(_ account: String) -> String {
        let plain = Set("-_0123456789abcdefghijklmnopqrstuvwxyz".utf8)
        let name = account.utf8.map { byte -> String in
            if plain.contains(byte) { return String(UnicodeScalar(byte)) }
            let hex = String(byte, radix: 16, uppercase: true)
            return "%" + (hex.count == 1 ? "0" + hex : hex)
        }.joined()
        return name.isEmpty ? "%" : name
    }

    /// The systemd version from `systemd-creds --version` ("systemd 257 (257.4-1)").
    static func parseVersion(_ output: Data) -> Int? {
        let line = String(decoding: output.prefix(256), as: UTF8.self).split(whereSeparator: \.isNewline).first ?? ""
        let words = line.split(separator: " ")
        guard words.count >= 2, words[0] == "systemd" else { return nil }
        return Int(words[1].prefix { $0.isNumber })
    }

    private var tool: String? { Self.toolPaths.first(where: system.isExecutable) }

    /// Why the store cannot be used now; nil when it can.
    func unavailability() -> SecretStoreUnavailable? {
        guard let tool else { return .systemdCredsToolMissing }
        guard !system.isRoot else { return nil }
        do {
            let version = try Self.version(of: tool, system: system)
            return version >= Self.minimumUserVersion ? nil : .systemdCredsTooOld(version)
        } catch let error as SecretStoreUnavailable {
            return error
        } catch {
            return .systemdCredsFailed(error.localizedDescription)
        }
    }

    private static let versionLock = NSLock()
    private static var versions: [String: Int] = [:]

    /// The version, asked once per process and tool.
    static func version(of tool: String, system: SecretStoreSystem) throws -> Int {
        versionLock.lock()
        let known = system.cachesProbes ? versions[tool] : nil
        versionLock.unlock()
        if let known { return known }
        let result: ToolOutput
        do {
            result = try system.runner.run(tool, ["--version"], environment: ["LANG": "C"], input: Data(), timeout: 5)
        } catch let timeout as ToolTimeout {
            throw SecretStoreUnavailable.systemdCredsTimeout(timeout.seconds)
        }
        guard result.status == 0, let version = parseVersion(result.output) else {
            throw SecretStoreUnavailable.systemdCredsFailed(result.failure)
        }
        if system.cachesProbes {
            versionLock.lock()
            versions[tool] = version
            versionLock.unlock()
        }
        return version
    }

    // MARK: SecretStore

    func read(_ account: String) throws -> Data? {
        let url = url(account)
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        let sealed: Data
        do { sealed = try FileIO.read(url, maxSize: Self.maxCredentialSize) } catch {
            throw SecretStoreUnavailable(error.localizedDescription)
        }
        var result = try run("decrypt", account, ["--newline=no"], input: sealed)
        guard result.status == 0 else {
            result.wipe()
            throw SecretStoreUnavailable.systemdCredsFailed(result.failure)
        }
        return result.output
    }

    func write(_ account: String, _ data: Data) throws {
        let result = try run("encrypt", account, [], input: data)
        guard result.status == 0, !result.output.isEmpty else { throw SecretStoreUnavailable.systemdCredsFailed(result.failure) }
        do {
            try ensureDirectory()
            try FileIO.writeAtomically(result.output, to: url(account), mode: 0o600)
        } catch let error as SecretStoreUnavailable {
            throw error
        } catch {
            throw SecretStoreUnavailable(error.localizedDescription)
        }
    }

    func remove(_ account: String) throws {
        let path = url(account).path
        guard unlink(path) == 0 || errno == ENOENT else { throw SecretStoreUnavailable(PTError.fileError(path).localizedDescription) }
    }

    /// Test cleanup: only under a `PASSTUNNEL_HOME`, never in the real support directory.
    func removeAll() {
        guard system.environment["PASSTUNNEL_HOME"]?.isEmpty == false,
            let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path)
        else { return }
        for name in names where name.hasSuffix(".cred") { unlink(directory.appendingPathComponent(name).path) }
    }

    // MARK: systemd-creds

    /// `systemd-creds VERB --name=NAME [--user] … - -`: input on standard input, result on standard output.
    private func run(_ verb: String, _ account: String, _ options: [String], input: Data) throws -> ToolOutput {
        if let problem = unavailability() { throw problem }
        guard let tool else { throw SecretStoreUnavailable.systemdCredsToolMissing }
        var arguments = [verb, "--name=" + Self.credentialName(account)] + options
        if !system.isRoot { arguments.append("--user") }
        arguments += ["-", "-"]
        var environment = ["LANG": "C"]
        for name in ["HOME", "XDG_RUNTIME_DIR"] { environment[name] = system.environment[name] }
        do {
            return try system.runner.run(tool, arguments, environment: environment, input: input, timeout: Self.timeout)
        } catch let timeout as ToolTimeout {
            throw SecretStoreUnavailable.systemdCredsTimeout(timeout.seconds)
        } catch {
            throw SecretStoreUnavailable.systemdCredsFailed(error.localizedDescription)
        }
    }

    /// The directory exists, belongs to this user and is theirs alone (0700).
    private func ensureDirectory() throws {
        let path = directory.path
        try FileIO.makeDirectory(directory)
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR, st.st_uid == geteuid() else {
            throw SecretStoreUnavailable.unsafeDirectory(path)
        }
        if st.st_mode & 0o077 != 0 && chmod(path, 0o700) != 0 { throw SecretStoreUnavailable.unsafeDirectory(path) }
    }
}
