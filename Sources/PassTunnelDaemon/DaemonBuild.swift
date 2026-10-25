/// The build number of passtunneld: `hello`'s `build_number` and every reply's `helper_build`
/// (docs/LINUX.md). The daemon links nothing of PassTunnelCore, so it has its own copy of what
/// `BuildVersion` holds for `passtunnel`.
///
/// `scripts/build-linux.sh` writes `DaemonBuild+Generated.swift` next to this file (never committed),
/// with the same number it gives `passtunnel`:
///
///     #if PASSTUNNEL_BUILD_VERSION
///     extension DaemonBuild {
///         static let generatedNumber: Int? = 214
///     }
///     #endif
///
/// and compiles with `-Xswiftc -DPASSTUNNEL_BUILD_VERSION`. Without the define (`swift build`,
/// `swift test`) the build is a development build without a number.
public enum DaemonBuild {
    public static let number: Int? = generatedNumber
}

#if !PASSTUNNEL_BUILD_VERSION
extension DaemonBuild {
    static let generatedNumber: Int? = nil
}
#endif
