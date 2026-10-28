// macOS only: the helper's own executable (proc_pidinfo, code signatures).
#if os(macOS)
import Foundation

/// The privileged helper's own executable, opened once at launch: its build ID (`HelperBuild`) and the
/// source of openconnect's hook (`ToolStager.stageHook`).
///
/// The executable sits in the app bundle, which the user who installed it can change. Between the kernel
/// starting the helper and the helper opening that path, the user could put something else there: a FIFO
/// (an open or read that never returns would hang the root helper before it serves anything) or a link to a
/// file only root can read (whose SHA-256 the helper would then report). So the path is opened without
/// following a link and without blocking, must be a regular file with one link and a bounded size, and,
/// what settles it, must be the very file the kernel mapped as this process's executable: the device and
/// inode of the descriptor are compared with those of the vnode backing the executable's own Mach-O
/// header in memory (`PROC_PIDREGIONPATHINFO`). The mapping cannot be changed by renaming or replacing the
/// path, so whatever the path names after a swap fails the comparison. The digest is then read from the
/// descriptor, bounded.
///
/// When any step fails there is no verified image: the helper still runs the other tools, under a build ID
/// taken from its own running code (`fallbackBuildID`), and refuses only openconnect (no hook source).
public struct HelperImage {
    /// The verified descriptor (kept open for the helper's lifetime).
    public let descriptor: Int32
    /// Hex SHA-256 of the file: the helper's build ID.
    public let digest: String

    /// Larger files are refused (the helper is a few megabytes).
    public static let maxBytes: off_t = 256 << 20

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case open(Int32)
        case notARegularFile
        case multipleLinks
        case tooLarge
        /// The kernel does not say which file backs the image.
        case unknownImage
        /// The path names another file than the one running.
        case notTheRunningImage
        case unreadable

        public var description: String {
            switch self {
            case .open(let e): return "cannot open it: \(String(cString: strerror(e)))"
            case .notARegularFile: return "it is not a regular file"
            case .multipleLinks: return "it is hard-linked"
            case .tooLarge: return "it is too large"
            case .unknownImage: return "the running image's file is unknown"
            case .notTheRunningImage: return "it is not the file that is running"
            case .unreadable: return "it cannot be read"
            }
        }
    }

    /// Opens `path` and checks that it is the file mapped at `imageAddress` (the Mach-O header of the image,
    /// `#dsohandle` of the executable's own code) in this process.
    public static func open(_ path: String, imageAddress: UnsafeRawPointer) throws -> HelperImage {
        let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw Failure.open(errno) }
        do {
            var st = stat()
            guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { throw Failure.notARegularFile }
            guard st.st_nlink == 1 else { throw Failure.multipleLinks }
            guard st.st_size <= maxBytes else { throw Failure.tooLarge }
            guard let image = mappedFile(at: imageAddress) else { throw Failure.unknownImage }
            guard image.device == UInt32(bitPattern: st.st_dev), image.inode == st.st_ino else { throw Failure.notTheRunningImage }
            guard let digest = HelperBuild.digest(ofDescriptor: fd, maxBytes: Int(maxBytes)) else { throw Failure.unreadable }
            return HelperImage(descriptor: fd, digest: digest)
        } catch {
            close(fd)
            throw error
        }
    }

    /// Device and inode of the file backing the memory region that contains `address` in this process.
    static func mappedFile(at address: UnsafeRawPointer) -> (device: UInt32, inode: UInt64)? {
        var info = proc_regionwithpathinfo()
        let size = Int32(MemoryLayout<proc_regionwithpathinfo>.size)
        let addr = UInt64(UInt(bitPattern: address))
        guard proc_pidinfo(getpid(), PROC_PIDREGIONPATHINFO, addr, &info, size) == size else { return nil }
        // The call reports the region containing the address, or the next one: it must contain it.
        let start = info.prp_prinfo.pri_address, length = info.prp_prinfo.pri_size
        guard start <= addr, addr - start < length else { return nil }
        let vst = info.prp_vip.vip_vi.vi_stat
        guard vst.vst_ino != 0 else { return nil }
        return (vst.vst_dev, vst.vst_ino)
    }

    /// A build ID for a helper without a verified image: the hex cdhash the kernel recorded for this
    /// process's code when it started it (`csops` `CS_OPS_CDHASH`; no file is read, so nothing in the
    /// bundle can affect it), 40 digits, which `ToolStager` accepts and no file digest (64) equals. The app
    /// then sees another build than the one it ships and offers to replace the helper. Nil for code
    /// without a signature.
    public static func fallbackBuildID() -> String? {
        var hash = [UInt8](repeating: 0, count: 20)
        guard hash.withUnsafeMutableBytes({ csops(getpid(), csOpsCDHash, $0.baseAddress, $0.count) }) == 0,
            hash.contains(where: { $0 != 0 })
        else { return nil }
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    /// `CS_OPS_CDHASH` (`<sys/codesign.h>`).
    static let csOpsCDHash: UInt32 = 5
}
#endif

#if os(macOS)
/// The kernel's code-signing query (libsystem_kernel; `<sys/codesign.h>` is not in the SDK's module map).
@_silgen_name("csops")
private func csops(_ pid: pid_t, _ ops: UInt32, _ userAddress: UnsafeMutableRawPointer?, _ userSize: Int) -> Int32
#endif
