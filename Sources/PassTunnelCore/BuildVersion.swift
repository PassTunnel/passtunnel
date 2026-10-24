/// The version and build number of a build without an Info.plist: `AppInfo.current` on Linux.
///
/// A release build writes `BuildVersion+Generated.swift` next to this file (never committed, like
/// `PinnedTools+Generated.swift`):
///
///     #if PASSTUNNEL_BUILD_VERSION
///     extension BuildVersion {
///         static let generatedVersion = "1.2.0"
///         static let generatedBuild: String? = "214"
///     }
///     #endif
///
/// and compiles with `-Xswiftc -DPASSTUNNEL_BUILD_VERSION`. Without the define (`swift build`,
/// `swift test`) the build is a development build: `development`, no build number.
public enum BuildVersion {
    public static let version: String = generatedVersion
    public static let build: String? = generatedBuild

    /// The version of a development build.
    public static let development = "0.0.0-dev"
}

#if !PASSTUNNEL_BUILD_VERSION
extension BuildVersion {
    static let generatedVersion = development
    static let generatedBuild: String? = nil
}
#endif
