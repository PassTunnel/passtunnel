import Foundation
#if canImport(Glibc)
import Glibc
#endif

/// The single JSON style used for every file: snake_case keys, pretty printed, sorted keys.
public enum JSONCoding {
    public static func encoder() -> JSONEncoder {
        let e = JSONEncoder()
        e.keyEncodingStrategy = .convertToSnakeCase
        e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        e.dataEncodingStrategy = .base64
        return e
    }

    public static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.keyDecodingStrategy = .convertFromSnakeCase
        d.dataDecodingStrategy = .base64
        return d
    }

    public static func encode<T: Encodable>(_ value: T, userInfo: [CodingUserInfoKey: Any] = [:]) throws -> Data {
        let e = encoder()
        e.userInfo = userInfo
        do { return try e.encode(value) } catch { throw PTError.invalidFile(String(describing: T.self)) }
    }

    public static func decode<T: Decodable>(_ type: T.Type, from data: Data, name: String = "") throws -> T {
        do { return try decoder().decode(type, from: data) } catch { throw PTError.invalidFile(name) }
    }

    /// Encodes and writes atomically (temp file + rename) with the given permissions.
    public static func write<T: Encodable>(_ value: T, to url: URL, mode: mode_t = 0o644,
                                           userInfo: [CodingUserInfoKey: Any] = [:]) throws {
        var data = try encode(value, userInfo: userInfo)
        data.append(0x0A)
        try FileIO.writeAtomically(data, to: url, mode: mode)
    }

    public static func read<T: Decodable>(_ type: T.Type, from url: URL) throws -> T {
        let data = try FileIO.read(url)
        return try decode(type, from: data, name: url.lastPathComponent)
    }
}

/// Small file helpers that map failures to PTError.
package enum FileIO {
    package static let maxReadSize = 8 * 1024 * 1024

    package static func read(_ url: URL, maxSize: Int = maxReadSize) throws -> Data {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        if let size = attrs?[.size] as? NSNumber, size.intValue > maxSize {
            throw PTError.fileTooLarge(url.lastPathComponent)
        }
        do { return try Data(contentsOf: url) } catch { throw PTError.fileError(url.path) }
    }

    /// Reads a text file as UTF-8, falling back to Latin-1.
    package static func readText(_ url: URL, maxSize: Int = maxReadSize) throws -> String {
        let data = try read(url, maxSize: maxSize)
        if let s = String(data: data, encoding: .utf8) { return s }
        if let s = String(data: data, encoding: .isoLatin1) { return s }
        throw PTError.invalidFile(url.lastPathComponent)
    }

    package static func makeDirectory(_ url: URL, mode: Int = 0o700) throws {
        do {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: mode])
        } catch {
            throw PTError.fileError(url.path)
        }
    }

    /// Writes `data` to a temp file in the same directory, sets `mode`, then renames over `url`.
    package static func writeAtomically(_ data: Data, to url: URL, mode: mode_t) throws {
        let dir = url.deletingLastPathComponent()
        try makeDirectory(dir)
        let tmp = dir.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        let fd = open(tmp.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode)
        guard fd >= 0 else { throw PTError.fileError(url.path) }
        var ok = fchmod(fd, mode) == 0
        if ok {
            ok = data.withUnsafeBytes { buf -> Bool in
                var offset = 0
                while offset < buf.count {
                    #if canImport(Darwin)
                    let n = Darwin.write(fd, buf.baseAddress! + offset, buf.count - offset)
                    #else
                    let n = Glibc.write(fd, buf.baseAddress! + offset, buf.count - offset)
                    #endif
                    if n < 0 { if errno == EINTR { continue }; return false }
                    offset += n
                }
                return true
            }
        }
        if ok { ok = fsync(fd) == 0 }
        close(fd)
        if ok { ok = rename(tmp.path, url.path) == 0 }
        if !ok {
            unlink(tmp.path)
            throw PTError.fileError(url.path)
        }
    }
}
