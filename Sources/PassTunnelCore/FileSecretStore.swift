import Foundation
import PassTunnelKit

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto  // swift-crypto: the same API, outside Apple platforms
#endif
#if os(Linux)
import CryptoExtras  // swift-crypto's scrypt
#endif
#if canImport(Glibc)
import Glibc
#endif

/// scrypt's cost: N = 2^logN, block size r, parallelism p. Memory is 128 · N · r · p bytes.
struct ScryptParameters: Equatable {
    var logN: UInt8
    var r: UInt8
    var p: UInt8

    /// N = 2^17, r = 8, p = 1: 128 MiB, about half a second on a current computer (OWASP's minimum
    /// for scrypt). A new file gets these; they are kept in its header.
    static let standard = ScryptParameters(logN: 17, r: 8, p: 1)

    var memory: Int { 128 * (1 << Int(logN)) * Int(r) * Int(p) }

    /// What a file may name: at most 1 GiB, and nothing scrypt rejects outright.
    var isAcceptable: Bool {
        (1...20).contains(logN) && (1...32).contains(r) && (1...16).contains(p) && memory <= 1 << 30
    }
}

/// `secrets.enc`, version 1. A 53-byte header, then the AES-256-GCM ciphertext of the items and its tag:
///
///     "PTSF" | version 0x01 | KDF 0x01 (scrypt) | log2 N | r | p | salt (32) | nonce (12) | ciphertext | tag (16)
///
/// The whole header is the additional authenticated data, so its parameters cannot be changed
/// unnoticed. The key is scrypt(passphrase, salt) with the header's parameters; the salt stays for the
/// life of the file, the nonce is new on every write. The plaintext is a JSON object, account → value
/// (Base64).
struct SecretsFile: Equatable {
    static let magic = Data("PTSF".utf8)
    static let version: UInt8 = 1
    static let scrypt: UInt8 = 1
    static let saltSize = 32
    static let nonceSize = 12
    static let tagSize = 16
    static let headerSize = 4 + 1 + 1 + 3 + saltSize + nonceSize
    static let maxSize = 1 << 20

    var parameters: ScryptParameters
    var salt: Data
    var nonce: Data
    var ciphertext = Data()
    var tag = Data()

    var header: Data {
        var d = Self.magic
        d.append(contentsOf: [Self.version, Self.scrypt, parameters.logN, parameters.r, parameters.p])
        d.append(salt)
        d.append(nonce)
        return d
    }

    /// The header without the nonce: the same for every write with the same key.
    var keyID: Data { header.prefix(Self.headerSize - Self.nonceSize) }

    var bytes: Data { header + ciphertext + tag }

    enum ParseError: Error, Equatable { case notASecretsFile, newerVersion, unsupported }

    static func parse(_ data: Data) throws -> SecretsFile {
        let d = Data(data)  // indices from 0
        guard d.count > magic.count, d.prefix(magic.count) == magic else { throw ParseError.notASecretsFile }
        guard d[4] == version else { throw d[4] > version ? ParseError.newerVersion : ParseError.notASecretsFile }
        guard d.count >= headerSize + tagSize else { throw ParseError.notASecretsFile }
        guard d[5] == scrypt else { throw ParseError.unsupported }
        let parameters = ScryptParameters(logN: d[6], r: d[7], p: d[8])
        guard parameters.isAcceptable else { throw ParseError.unsupported }
        let saltEnd = 9 + saltSize
        return SecretsFile(
            parameters: parameters, salt: Data(d[9..<saltEnd]), nonce: Data(d[saltEnd..<headerSize]),
            ciphertext: Data(d[headerSize..<(d.count - tagSize)]), tag: Data(d[(d.count - tagSize)...]))
    }
}

/// One file, `<support dir>/secrets.enc` (0600, written atomically under a lock), encrypted with a
/// key derived from a passphrase (`SecretsFile`). The passphrase comes from the file named by
/// `PASSTUNNEL_PASSPHRASE_FILE` (a regular file of this user that no one else can read), or is asked
/// on the terminal (the CLI only; a new file asks twice); without either it fails at once. The key is
/// kept for the rest of the process, so a command asks once; the passphrase and decrypted items are
/// overwritten after use, as far as Swift allows. Linux only (docs/LINUX.md); built everywhere for its
/// tests, which bring their own key derivation (scrypt is in swift-crypto's extras, built for Linux).
struct FileSecretStore: SecretStore {
    typealias DeriveKey = (_ passphrase: Data, _ salt: Data, _ parameters: ScryptParameters) throws -> SymmetricKey

    static let passphraseFileVariable = "PASSTUNNEL_PASSPHRASE_FILE"
    static let maxPassphraseFileSize = 4096
    static let lockTimeout: TimeInterval = 10
    static let attempts = 3

    let system: SecretStoreSystem

    var url: URL { system.paths.secretsFileURL }
    var lockURL: URL { system.paths.root.appendingPathComponent(".secrets.lock") }

    #if os(Linux)
    /// scrypt from swift-crypto (BoringSSL's), 32 bytes for AES-256.
    static let scrypt: DeriveKey = { passphrase, salt, parameters in
        try KDF.Scrypt.deriveKey(
            from: passphrase, salt: salt, outputByteCount: 32, rounds: 1 << Int(parameters.logN),
            blockSize: Int(parameters.r), parallelism: Int(parameters.p))
    }
    #endif

    /// Whether a passphrase can be had here (the file names one, or the user can be asked); the reason
    /// when not.
    func unavailability() -> SecretStoreUnavailable? {
        if let path = passphraseFile {
            do {
                var passphrase = try Self.readPassphrase(path)
                passphrase.wipe()
                return nil
            } catch let error as SecretStoreUnavailable {
                return error
            } catch {
                return SecretStoreUnavailable(error.localizedDescription)
            }
        }
        return system.interaction.askPassphrase == nil ? .noPassphrase : nil
    }

    // MARK: SecretStore

    func read(_ account: String) throws -> Data? {
        guard let file = try load() else { return nil }
        var opened = try unlock(file)
        defer { Self.wipe(&opened.items) }
        return opened.items[account].map { Data($0) }
    }

    func write(_ account: String, _ data: Data) throws {
        for _ in 0..<2 {
            let before = try load()
            let (key, base) =
                try before.map { file -> (SymmetricKey, SecretsFile) in
                    var opened = try unlock(file)
                    Self.wipe(&opened.items)
                    return (opened.key, file)
                } ?? newKey()
            let done = try withLock { () -> Bool in
                let current = try load()
                guard current?.keyID == before?.keyID else { return false }  // replaced meanwhile: start over
                var items = try current.map { try decrypt($0, key) } ?? [:]
                defer { Self.wipe(&items) }
                items[account]?.wipe()
                items[account] = Data(data)
                try save(items, like: current ?? base, key: key)
                return true
            }
            if done { return }
        }
        throw SecretStoreUnavailable.secretsFileBusy
    }

    func remove(_ account: String) throws {
        guard let before = try load() else { return }
        var opened = try unlock(before)
        let present = opened.items[account] != nil
        Self.wipe(&opened.items)
        guard present else { return }
        try withLock {
            guard let current = try load() else { return }
            guard current.keyID == before.keyID else { throw SecretStoreUnavailable.secretsFileBusy }
            var items = try decrypt(current, opened.key)
            defer { Self.wipe(&items) }
            guard items[account] != nil else { return }
            items[account]?.wipe()
            items[account] = nil
            try save(items, like: current, key: opened.key)
        }
    }

    /// Test cleanup: only under a `PASSTUNNEL_HOME`, never in the real support directory.
    func removeAll() {
        guard system.environment["PASSTUNNEL_HOME"]?.isEmpty == false else { return }
        unlink(url.path)
    }

    // MARK: file

    private func load() throws -> SecretsFile? {
        let data: Data
        do {
            guard FileManager.default.fileExists(atPath: url.path) else { return nil }
            data = try FileIO.read(url, maxSize: SecretsFile.maxSize)
        } catch {
            throw SecretStoreUnavailable(error.localizedDescription)
        }
        do {
            return try SecretsFile.parse(data)
        } catch SecretsFile.ParseError.newerVersion {
            throw SecretStoreUnavailable.newerSecretsFile(url.path)
        } catch {
            throw SecretStoreUnavailable.notASecretsFile(url.path)
        }
    }

    private func save(_ items: [String: Data], like base: SecretsFile, key: SymmetricKey) throws {
        var plain = try JSONEncoder.sorted.encode(items)
        defer { plain.wipe() }
        var file = SecretsFile(parameters: base.parameters, salt: base.salt, nonce: Self.randomBytes(SecretsFile.nonceSize))
        let sealed = try AES.GCM.seal(plain, using: key, nonce: AES.GCM.Nonce(data: file.nonce), authenticating: file.header)
        file.ciphertext = sealed.ciphertext
        file.tag = sealed.tag
        do {
            try FileIO.writeAtomically(file.bytes, to: url, mode: 0o600)
        } catch {
            throw SecretStoreUnavailable(error.localizedDescription)
        }
    }

    /// The items; nil when the key does not open the file (wrong passphrase, or a changed file).
    private func decryptIfPossible(_ file: SecretsFile, _ key: SymmetricKey) throws -> [String: Data]? {
        guard let box = try? AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: file.nonce), ciphertext: file.ciphertext, tag: file.tag),
            var plain = try? AES.GCM.open(box, using: key, authenticating: file.header)
        else { return nil }
        defer { plain.wipe() }
        guard let items = try? JSONDecoder().decode([String: Data].self, from: plain) else {
            throw SecretStoreUnavailable.notASecretsFile(url.path)
        }
        return items
    }

    private func decrypt(_ file: SecretsFile, _ key: SymmetricKey) throws -> [String: Data] {
        guard let items = try decryptIfPossible(file, key) else { throw SecretStoreUnavailable.secretsFileUnreadable }
        return items
    }

    /// The items and the key: the key this process already has for the file, or one from the
    /// passphrase (asked again after a wrong one, up to `attempts` times on a terminal).
    private func unlock(_ file: SecretsFile) throws -> (items: [String: Data], key: SymmetricKey) {
        if let key = Self.keys.key(file.keyID) { return (try decrypt(file, key), key) }
        if Self.keys.failed(file.keyID) { throw SecretStoreUnavailable.secretsFileUnreadable }
        let attempts = passphraseFile == nil ? Self.attempts : 1
        for attempt in 0..<attempts {
            var passphrase = try self.passphrase(retry: attempt > 0)
            defer { passphrase.wipe() }
            let key = try derive(passphrase, file.salt, file.parameters)
            if let items = try decryptIfPossible(file, key) {
                Self.keys.remember(key, for: file.keyID)
                return (items, key)
            }
        }
        Self.keys.rememberFailure(file.keyID)
        throw SecretStoreUnavailable.secretsFileUnreadable
    }

    /// A key for a new file, from a new passphrase, with a new salt and `system.scryptParameters`.
    private func newKey() throws -> (SymmetricKey, SecretsFile) {
        var passphrase = try newPassphrase()
        defer { passphrase.wipe() }
        let base = SecretsFile(
            parameters: system.scryptParameters, salt: Self.randomBytes(SecretsFile.saltSize),
            nonce: Data(count: SecretsFile.nonceSize))
        let key = try derive(passphrase, base.salt, base.parameters)
        Self.keys.remember(key, for: base.keyID)
        return (key, base)
    }

    private func derive(_ passphrase: Data, _ salt: Data, _ parameters: ScryptParameters) throws -> SymmetricKey {
        guard let deriveKey = system.deriveKey else { throw SecretStoreUnavailable.fileStoreUnsupported }
        do {
            return try deriveKey(passphrase, salt, parameters)
        } catch {
            throw SecretStoreUnavailable.notASecretsFile(url.path)
        }
    }

    /// Serializes changes across processes (`flock`); gives up after `lockTimeout` rather than hang.
    private func withLock<T>(_ body: () throws -> T) throws -> T {
        let path = lockURL.path
        do { try FileIO.makeDirectory(lockURL.deletingLastPathComponent()) } catch {
            throw SecretStoreUnavailable(error.localizedDescription)
        }
        let fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw SecretStoreUnavailable(PTError.fileError(path).localizedDescription) }
        defer { close(fd) }
        let deadline = Date().addingTimeInterval(Self.lockTimeout)
        while flock(fd, LOCK_EX | LOCK_NB) != 0 {
            guard errno == EAGAIN || errno == EINTR, Date() < deadline else { throw SecretStoreUnavailable.secretsFileBusy }
            usleep(50_000)
        }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }

    // MARK: passphrase

    private var passphraseFile: String? {
        system.environment[Self.passphraseFileVariable].flatMap { $0.isEmpty ? nil : $0 }
    }

    private func passphrase(retry: Bool) throws -> Data {
        if let path = passphraseFile { return try Self.readPassphrase(path) }
        guard let ask = system.interaction.askPassphrase else { throw SecretStoreUnavailable.noPassphrase }
        let prompt =
            retry
            ? String(localized: "Wrong passphrase. Passphrase for the PassTunnel secrets file: ")
            : String(localized: "Passphrase for the PassTunnel secrets file: ")
        guard let value = ask(prompt), !value.isEmpty else { throw SecretStoreUnavailable.noPassphraseEntered }
        return value
    }

    /// The first write: from the passphrase file, or asked twice.
    private func newPassphrase() throws -> Data {
        if let path = passphraseFile { return try Self.readPassphrase(path) }
        guard let ask = system.interaction.askPassphrase else { throw SecretStoreUnavailable.noPassphrase }
        for _ in 0..<Self.attempts {
            guard var first = ask(String(localized: "New passphrase for the PassTunnel secrets file (\(url.path)): ")),
                !first.isEmpty
            else { throw SecretStoreUnavailable.noPassphraseEntered }
            var second = ask(String(localized: "Repeat the passphrase: ")) ?? Data()
            defer { second.wipe() }
            if first == second { return first }
            first.wipe()
        }
        throw SecretStoreUnavailable.passphrasesDiffer
    }

    /// The contents of `path` without its final line breaks. It must be a regular file of this user
    /// that neither the group nor others can access.
    static func readPassphrase(_ path: String) throws -> Data {
        let fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw SecretStoreUnavailable.passphraseFile(path) }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == geteuid(), st.st_mode & 0o077 == 0,
            st.st_size <= off_t(maxPassphraseFileSize)
        else {
            throw SecretStoreUnavailable.passphraseFile(path)
        }
        var buffer = [UInt8](repeating: 0, count: maxPassphraseFileSize + 1)
        defer { _ = buffer.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        var count = 0
        while count < buffer.count {
            let n = buffer.withUnsafeMutableBytes { raw in
                #if canImport(Darwin)
                Darwin.read(fd, raw.baseAddress! + count, raw.count - count)
                #else
                Glibc.read(fd, raw.baseAddress! + count, raw.count - count)
                #endif
            }
            if n < 0 && errno == EINTR { continue }
            guard n >= 0 else { throw SecretStoreUnavailable.passphraseFile(path) }
            if n == 0 { break }
            count += n
        }
        guard count <= maxPassphraseFileSize else { throw SecretStoreUnavailable.passphraseFile(path) }
        while count > 0 && (buffer[count - 1] == 0x0A || buffer[count - 1] == 0x0D) { count -= 1 }
        guard count > 0 else { throw SecretStoreUnavailable.noPassphraseEntered }
        return Data(buffer[0..<count])
    }

    // MARK: helpers

    static func randomBytes(_ count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }

    static func wipe(_ items: inout [String: Data]) {
        for account in Array(items.keys) { items[account]?.wipe() }
        items.removeAll()
    }

    /// Keys this process has opened files with, and files it failed to open, by `SecretsFile.keyID`.
    static let keys = KeyCache()

    final class KeyCache {
        private let lock = NSLock()
        private var keys: [Data: SymmetricKey] = [:]
        private var failures: Set<Data> = []

        func key(_ id: Data) -> SymmetricKey? { locked { keys[id] } }
        func failed(_ id: Data) -> Bool { locked { failures.contains(id) } }
        func remember(_ key: SymmetricKey, for id: Data) {
            locked {
                keys[id] = key; failures.remove(id)
            }
        }
        func rememberFailure(_ id: Data) { locked { _ = failures.insert(id) } }
        /// Tests: as in a new process.
        func forget() {
            locked {
                keys.removeAll(); failures.removeAll()
            }
        }

        private func locked<T>(_ body: () -> T) -> T {
            lock.lock()
            defer { lock.unlock() }
            return body()
        }
    }
}

private extension JSONEncoder {
    static var sorted: JSONEncoder {
        let e = JSONEncoder()
        e.outputFormatting = [.sortedKeys]
        return e
    }
}
