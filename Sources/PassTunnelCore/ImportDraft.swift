import Foundation
import PassTunnelKit

/// An .ovpn file read for the review before it becomes a profile (`ProfileStore.analyzeOVPN`): what it
/// holds and what an import would store. Nothing is written until `ProfileStore.commit`.
public struct ImportDraft: Equatable {
    /// The file that was read.
    public let source: URL
    /// The name to suggest for the profile: the file's name without its extension.
    public let suggestedName: String
    public let report: OVPNImportReport

    public init(source: URL, report: OVPNImportReport) {
        self.source = source
        self.suggestedName = source.deletingPathExtension().lastPathComponent
        self.report = report
    }

    public var fileName: String { source.lastPathComponent }
    /// Lines left out of the stored configuration.
    public var skipped: [OVPNSkipRules.Skipped] { report.skipped }
    /// Lines that refuse the file: `commit` throws while there are any.
    public var blocking: [OVPNSkipRules.Blocking] { report.blocking }

    /// Everything the new profile needs, in the order to ask for it: its name, then the sign-in
    /// (`OVPNImportReport.needs`).
    public var needs: [OVPNImportReport.Field] { [.name] + report.needs }

    /// `needs` that are still empty with these entries.
    public func missing(name: String, username: String?, password: String?, codeSecret: Bool) -> [OVPNImportReport.Field] {
        let noName = name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        return (noName ? [.name] : []) + report.missing(username: username, password: password, codeSecret: codeSecret)
    }

    /// `needs` the file does not fill in (the suggested name counts as a name).
    public var missing: [OVPNImportReport.Field] {
        missing(name: suggestedName, username: report.username, password: report.password, codeSecret: false)
    }
}
