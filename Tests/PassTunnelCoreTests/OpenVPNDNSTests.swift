import XCTest

@testable import PassTunnelShared

/// The system configuration as `OpenVPNDNS` sees it, in memory: the dynamic store's keys, the network
/// preferences and the interfaces. Every write is recorded; writes can be made to fail or not to hold.
final class FakeDNSSystem: OpenVPNDNSSystem {
    /// `Setup:/Network/Service/<id>/DNS`.
    var services: [String: DNSEntity] = [:]
    /// The services of the network preferences and their `DNS` entity (nil: the service has none).
    var preferences: [String: DNSEntity?] = [:]
    var backups: [String: DNSEntity] = [:]
    var tunnels: [String: DNSEntity] = [:]
    var interfaces: Set<String> = []
    var names: [String: String] = [:]
    var primary: String?
    var resolver: [String]?
    var storeReadable = true
    var preferencesReadable = true
    /// Writes refused before one is taken.
    var refusedWrites = 0
    /// Writes taken that do not hold (something puts the old value back).
    var lostWrites = 0
    private(set) var writes: [String] = []

    func serviceDNS() -> [String: DNSEntity]? { storeReadable ? services : nil }

    func preferencesDNS(service: String) -> OpenVPNDNS.Preferences {
        guard preferencesReadable else { return .unreadable }
        guard let entry = preferences[service] else { return .none }
        return entry.map(OpenVPNDNS.Preferences.entity) ?? .none
    }

    func setServiceDNS(service: String, _ entity: DNSEntity?) -> Bool {
        writes.append("set \(service) " + (entity.map(Self.describe) ?? "removed"))
        if refusedWrites > 0 {
            refusedWrites -= 1
            return false
        }
        if lostWrites > 0 {
            lostWrites -= 1
            return true
        }
        services[service] = entity
        return true
    }

    func scriptBackups() -> [String: DNSEntity]? { storeReadable ? backups : nil }

    func removeScriptBackup(dev: String) -> Bool {
        writes.append("remove backup \(dev)")
        backups[dev] = nil
        return true
    }

    func tunnelDNS() -> [String: DNSEntity]? { storeReadable ? tunnels : nil }

    func removeTunnelDNS(dev: String) -> Bool {
        writes.append("remove tunnel \(dev)")
        tunnels[dev] = nil
        return true
    }

    func interfaceExists(_ name: String) -> Bool { interfaces.contains(name) }

    func serviceName(_ service: String) -> String? { names[service] }

    func primaryService() -> String? { primary }

    func globalDNSServers() -> [String]? { resolver }

    static func describe(_ e: DNSEntity) -> String {
        e.keys.sorted().map { key -> String in
            switch e[key]! {
            case .integer(let n): return "\(key)=\(n)"
            case let v: return "\(key)=" + (v.strings?.joined(separator: ",") ?? "?")
            }
        }.joined(separator: " ")
    }
}

final class OpenVPNDNSTests: XCTestCase {
    static let wifi = "8E3F0A1C-0000-4000-8000-00000000A001"
    static let ethernet = "8E3F0A1C-0000-4000-8000-00000000A002"

    /// A full-tunnel session: the VPN's servers and a search domain, no resolve domains.
    static let session = OpenVPNDNSSession(dev: "utun7", servers: ["10.8.0.1", "10.8.0.2"], searchDomains: ["corp.example.com"])
    /// Its dns-up succeeded with Wi-Fi primary.
    static let record = OpenVPNDNSRecord(session: session, status: 0, service: wifi)

    var system: FakeDNSSystem!

    override func setUp() {
        system = FakeDNSSystem()
        system.names = [Self.wifi: "Wi-Fi", Self.ethernet: "Ethernet"]
        system.preferences = [Self.wifi: [:], Self.ethernet: nil]
    }

    static func strings(_ list: [String]) -> PlistValue { .array(list.map(PlistValue.string)) }

    func settle(_ record: OpenVPNDNSRecord = record, live: [OpenVPNDNSRecord] = []) -> OpenVPNDNS.Settlement {
        OpenVPNDNS.settle(record, live: live, system: system)
    }

    // MARK: The session's record

    func testSessionFromRecordedVariables() throws {
        let record = """
            dev=utun7
            dns_search_domain_1=corp.example.com
            dns_search_domain_2=corp.example.com
            dns_search_domain_3=lab.example.com
            dns_server_1_address_1=192.0.2.53
            dns_server_1_transport=DoT
            dns_server_2_address_1=192.0.2.54
            dns_server_2_port_1=5353
            dns_server_3_address_1=10.8.0.1
            dns_server_3_address_2=2001:db8::53
            dns_server_3_address_3=10.8.0.1
            dns_server_3_port_2=53
            dns_server_3_dnssec=no
            dns_server_3_resolve_domain_1=corp.example.com

            """
        let variables = try XCTUnwrap(HelperCore.dnsVariables(record: record))
        let session = try XCTUnwrap(OpenVPNDNSSession(variables: variables))
        XCTAssertEqual(
            session,
            OpenVPNDNSSession(
                dev: "utun7", servers: ["10.8.0.1", "2001:db8::53", "10.8.0.1"], searchDomains: ["corp.example.com", "lab.example.com"],
                matchDomains: ["corp.example.com"]),
            "the first server the script can use (no DoT, only port 53) with every address as it is, the search domains once each")
        XCTAssertTrue(session.isSplit)

        let none = try XCTUnwrap(
            OpenVPNDNSSession(variables: ["dev": "utun7", "dns_server_1_address_1": "192.0.2.53", "dns_server_1_dnssec": "yes"]))
        XCTAssertEqual(none.servers, [], "no server the script can use: it sets nothing")
        XCTAssertEqual(settle(OpenVPNDNSRecord(session: none, status: 0, service: Self.wifi)), OpenVPNDNS.Settlement(.done))
        XCTAssertNil(OpenVPNDNSSession(variables: ["dev": "utun7/x", "dns_server_1_address_1": "10.8.0.1"]), "no key is built from that")
    }

    /// No server the script can use: `find_compat_profile`'s `exit 1` ends only the `$(…)` it runs in, and the script
    /// writes its override without any server, with the search domains and `SearchOrder` 5000, and exits 0. That is
    /// recognised, given back and reported like any other.
    func testNoUsableServerStillWritesAnOverride() throws {
        let session = try XCTUnwrap(
            OpenVPNDNSSession(variables: [
                "dev": "utun7", "dns_server_1_address_1": "192.0.2.53", "dns_server_1_transport": "DoT",
                "dns_server_1_resolve_domain_1": "corp.example.com", "dns_search_domain_1": "corp.example.com"
            ]))
        XCTAssertEqual(session, OpenVPNDNSSession(dev: "utun7", servers: [], searchDomains: ["corp.example.com"]), "no resolve domains: full branch")
        XCTAssertEqual(
            session.overrideEntity,
            ["ServerAddresses": .array([]), "SearchDomains": Self.strings(["corp.example.com"]), "SearchOrder": .integer(5000)])

        system.services[Self.wifi] = session.overrideEntity
        system.primary = Self.wifi
        let left = try XCTUnwrap(OpenVPNDNS.leftBehind(system: system)?.first)
        XCTAssertEqual(left.servers, [])
        XCTAssertEqual(left.searchDomains, ["corp.example.com"])
        XCTAssertEqual(left.settings, ["corp.example.com"])
        XCTAssertTrue(left.inEffect)

        let s = settle(OpenVPNDNSRecord(session: session, status: 0, service: Self.wifi))
        XCTAssertEqual(s.restored, [OpenVPNDNS.Restored(serviceID: Self.wifi, service: "Wi-Fi", settings: ["corp.example.com"])])
        XCTAssertNil(system.services[Self.wifi])

        // Without search domains either: the note says so.
        let bare = OpenVPNDNSSession(dev: "utun7", servers: [])
        system.services[Self.wifi] = ["ServerAddresses": .array([]), "SearchDomains": .array([]), "SearchOrder": .integer(5000)]
        XCTAssertEqual(settle(OpenVPNDNSRecord(session: bare, status: 0, service: Self.wifi)).restored.map(\.settings), [[]])
        let note = OpenVPNDNS.Note(.restored, service: "Wi-Fi", settings: [])
        XCTAssertEqual(note.line, "PassTunnel helper: restored the DNS of “Wi-Fi”, which still used the VPN's (none)")
        XCTAssertEqual(OpenVPNDNS.Note(line: note.line), note)
    }

    /// What the script leaves at a normal end on a service without DNS of its own: `scutil` starts with an empty
    /// dictionary, so the backup is `{}` and the dns-down writes `{}` back. That is no DNS, as the preferences hold:
    /// nothing to do.
    func testAnEmptyDictionaryIsNoDNS() {
        system.services[Self.wifi] = [:]
        XCTAssertEqual(settle(), OpenVPNDNS.Settlement(.done))
        XCTAssertEqual(system.writes, [])
    }

    /// The script's own repeat test: an unquoted `=~`, so a `.` matches any character, a space too.
    func testDomainListsAsTheScriptBuildsThem() {
        XCTAssertEqual(OpenVPNDNSSession.scriptList(["a.example", "a.example", "b.example"]), ["a.example", "b.example"])
        XCTAssertEqual(OpenVPNDNSSession.scriptList(["axb", "a.b"]), ["axb"], "a.b matches axb")
        XCTAssertEqual(OpenVPNDNSSession.scriptList(["a", "b", "a.b"]), ["a", "b"], "a.b matches “a b” in the list so far")
        XCTAssertEqual(OpenVPNDNSSession.scriptList(["a.b", "axb"]), ["a.b", "axb"], "axb is no pattern for a.b")
        XCTAssertEqual(OpenVPNDNSSession.scriptList(["corp.example", "example"]), ["corp.example", "example"], "whole words only")
        XCTAssertEqual(OpenVPNDNSSession.scriptList(["b-c", "a_b:c"]), ["b-c", "a_b:c"])
    }

    // MARK: Full branch

    /// The issue's case: the network went away, the script's dns-down found no primary service and left the
    /// VPN's DNS on Wi-Fi, whose preferences hold no DNS: the key goes.
    func testNetworkAwayLeavesNothingBehind() {
        system.services[Self.wifi] = Self.session.overrideEntity
        XCTAssertEqual(
            settle(),
            OpenVPNDNS.Settlement(.done, restored: [OpenVPNDNS.Restored(serviceID: Self.wifi, service: "Wi-Fi", settings: ["10.8.0.1", "10.8.0.2"])]))
        XCTAssertNil(system.services[Self.wifi])
        XCTAssertEqual(system.writes, ["set \(Self.wifi) removed"])
        XCTAssertEqual(settle(), OpenVPNDNS.Settlement(.done), "nothing left")
    }

    /// A service whose preferences hold manual servers gets them back, as the preferences hold them.
    func testManualServersComeBack() {
        let manual: DNSEntity = ["ServerAddresses": Self.strings(["192.0.2.1"]), "SearchDomains": Self.strings(["home.example"])]
        system.preferences[Self.wifi] = manual
        system.services[Self.wifi] = Self.session.overrideEntity
        XCTAssertEqual(settle().restored.map(\.serviceID), [Self.wifi])
        XCTAssertEqual(system.services[Self.wifi], manual)
    }

    /// An empty or inactive entity in the preferences is none: configd publishes no key for it.
    func testWhatThePreferencesHoldIsWhatConfigdPublishes() {
        XCTAssertNil(OpenVPNDNS.normalized([:] as DNSEntity))
        XCTAssertNil(OpenVPNDNS.normalized(["__INACTIVE__": .bool(true), "ServerAddresses": Self.strings(["192.0.2.1"])]))
        XCTAssertEqual(
            OpenVPNDNS.normalized(["ServerAddresses": Self.strings(["192.0.2.1"]), "Sub": .dictionary(["a": .integer(1)])]),
            ["ServerAddresses": Self.strings(["192.0.2.1"])])
        system.preferences[Self.wifi] = ["__INACTIVE__": .bool(true)]
        system.services[Self.wifi] = Self.session.overrideEntity
        _ = settle()
        XCTAssertNil(system.services[Self.wifi])
    }

    /// Only the service the dns-up changed: the same override on another service (another OpenVPN on the Mac with
    /// the same server, another profile) is not this session's and is left.
    func testOnlyTheServiceTheSessionChanged() {
        system.services = [Self.wifi: Self.session.overrideEntity, Self.ethernet: Self.session.overrideEntity]
        XCTAssertEqual(settle().restored.map(\.serviceID), [Self.wifi])
        XCTAssertEqual(system.services[Self.ethernet], Self.session.overrideEntity)
        XCTAssertEqual(system.writes, ["set \(Self.wifi) removed"])
    }

    /// The service is not known (the primary service changed around the dns-up), or the dns-up did not succeed or
    /// left no result: nothing is changed, nothing scanned.
    func testNoEvidenceNoChange() {
        system.services = [Self.wifi: Self.session.overrideEntity, Self.ethernet: Self.session.overrideEntity]
        for record in [
            OpenVPNDNSRecord(session: Self.session, status: 0, service: nil),
            OpenVPNDNSRecord(session: Self.session, status: 1, service: Self.wifi),
            OpenVPNDNSRecord(session: Self.session)
        ] {
            let s = settle(record)
            XCTAssertEqual(s.outcome, .done)
            XCTAssertEqual(s.restored, [])
            XCTAssertEqual(s.reports.count, 1, "\(record)")
        }
        XCTAssertEqual(system.writes, [])
    }

    /// The primary service changed during the session: the script's dns-down looked at Ethernet and left Wi-Fi as
    /// it was. Only Wi-Fi changes.
    func testAnotherPrimaryServiceIsNotTouched() {
        system.preferences[Self.ethernet] = ["ServerAddresses": Self.strings(["192.0.2.1"])]
        system.services = [Self.wifi: Self.session.overrideEntity, Self.ethernet: ["ServerAddresses": Self.strings(["192.0.2.1"])]]
        system.primary = Self.ethernet
        XCTAssertEqual(settle().restored.map(\.service), ["Wi-Fi"])
        XCTAssertEqual(system.services[Self.ethernet], ["ServerAddresses": Self.strings(["192.0.2.1"])])
        XCTAssertEqual(system.writes, ["set \(Self.wifi) removed"])
    }

    /// Changed by someone else since the session set it (other servers, one more key, another search order, the
    /// search domains taken away): left.
    func testASettingSomeoneElseChangedIsLeft() {
        var changed = Self.session.overrideEntity
        changed["ServerAddresses"] = Self.strings(["10.8.0.1"])
        var more = Self.session.overrideEntity
        more["DomainName"] = .string("corp.example.com")
        var order = Self.session.overrideEntity
        order["SearchOrder"] = .integer(1)
        var domains = Self.session.overrideEntity
        domains["SearchDomains"] = Self.strings(["home.example"])
        for entity in [changed, more, order, domains, ["ServerAddresses": Self.strings(["10.8.0.1", "10.8.0.2"])]] {
            system.services[Self.wifi] = entity
            XCTAssertEqual(settle(), OpenVPNDNS.Settlement(.done))
            XCTAssertEqual(system.services[Self.wifi], entity)
        }
        XCTAssertEqual(system.writes, [])
    }

    /// A split session ran over the full one: its dns-up put its search domains and the Mac's in front of the full
    /// session's, its dns-down took only its own out again. Still the full session's override.
    func testAnOverrideWhoseSearchDomainsASplitSessionExtended() {
        var extended = Self.session.overrideEntity
        extended["SearchDomains"] = Self.strings(["lab.example.com", "corp.example.com", "home.example"])
        system.services[Self.wifi] = extended
        XCTAssertEqual(settle().restored.map(\.serviceID), [Self.wifi])
        extended["SearchDomains"] = Self.strings(["corp.example.com", "home.example"])
        system.services[Self.wifi] = extended
        XCTAssertEqual(settle().restored.map(\.serviceID), [Self.wifi])
        XCTAssertNil(system.services[Self.wifi])
    }

    /// The preferences hold exactly what the script set (someone configured those servers): nothing to do.
    func testPreferencesThatHoldTheSameAreLeft() {
        system.preferences[Self.wifi] = Self.session.overrideEntity
        system.services[Self.wifi] = Self.session.overrideEntity
        XCTAssertEqual(settle(), OpenVPNDNS.Settlement(.done))
        XCTAssertEqual(system.writes, [])
    }

    /// The script writes an empty search domain list when the server sent none.
    func testOverrideWithoutSearchDomains() {
        let record = OpenVPNDNSRecord(session: OpenVPNDNSSession(dev: "utun7", servers: ["10.8.0.1"]), status: 0, service: Self.wifi)
        system.services[Self.wifi] = ["ServerAddresses": Self.strings(["10.8.0.1"]), "SearchDomains": .array([]), "SearchOrder": .integer(5000)]
        XCTAssertEqual(settle(record).restored.count, 1)
        system.services[Self.wifi] = ["ServerAddresses": Self.strings(["10.8.0.1"]), "SearchOrder": .integer(5000)]
        XCTAssertEqual(settle(record).restored.count, 1)
    }

    /// A running session that changed the same service the same way holds it (it may be that one's, which its own
    /// end settles). One that did not succeed, or set other DNS, or changed another service, does not.
    func testAnotherLiveSessionHoldsTheSameDNS() {
        system.services[Self.wifi] = Self.session.overrideEntity
        system.interfaces = ["utun8"]
        let same = OpenVPNDNSSession(dev: "utun8", servers: Self.session.servers, searchDomains: Self.session.searchDomains)
        XCTAssertEqual(settle(live: [OpenVPNDNSRecord(session: same, status: 0, service: Self.wifi)]).restored, [])
        XCTAssertEqual(system.writes, [])

        for live in [
            OpenVPNDNSRecord(session: same, status: 1, service: Self.wifi),
            OpenVPNDNSRecord(session: same, status: 0, service: Self.ethernet),
            OpenVPNDNSRecord(session: OpenVPNDNSSession(dev: "utun8", servers: ["10.9.0.1"]), status: 0, service: Self.wifi)
        ] {
            system.services[Self.wifi] = Self.session.overrideEntity
            XCTAssertEqual(settle(live: [live]).restored.map(\.serviceID), [Self.wifi], "\(live)")
        }
    }

    /// The session's DNS was backed up by another running session of the script (its dns-up came while the VPN's DNS
    /// was still on the primary service): it comes back when that one ends, so the record stays (`parked`). A backup
    /// whose tunnel is gone and no running session has is reported, not waited for.
    func testParkedOnlyInTheBackupOfARunningSession() {
        system.interfaces = ["utun8"]
        system.backups["utun8"] = Self.session.overrideEntity
        system.services[Self.wifi] = ["ServerAddresses": Self.strings(["10.9.0.1"]), "SearchDomains": .array([]), "SearchOrder": .integer(5000)]
        XCTAssertEqual(settle().outcome, .parked)
        system.interfaces = []
        let other = OpenVPNDNSRecord(session: OpenVPNDNSSession(dev: "utun8", servers: ["10.9.0.1"]), status: 0, service: Self.wifi)
        XCTAssertEqual(settle(live: [other]).outcome, .parked, "its job runs")
        let stale = settle()
        XCTAssertEqual(stale.outcome, .done)
        XCTAssertEqual(stale.reports, ["the backup of utun8, whose tunnel is gone, holds this session's DNS: left as it is"])
        XCTAssertEqual(system.writes, [])
        // That session ended; its script put the backup back.
        system.backups = [:]
        system.services[Self.wifi] = Self.session.overrideEntity
        XCTAssertEqual(settle().restored.map(\.serviceID), [Self.wifi])
    }

    /// The session's own backup outlived it (its dns-down never got that far): once its tunnel is gone it goes, as
    /// it would make every later dns-up of the script fail. A tunnel of that name that is no running session of
    /// PassTunnel's (the number taken again) keeps it, and the record waits; a running session of that name owns it.
    func testOwnStaleBackupIsRemovedOnceTheTunnelIsGone() {
        system.backups["utun7"] = [:]
        system.interfaces = ["utun7"]
        let waiting = settle()
        XCTAssertEqual(waiting.outcome, .parked)
        XCTAssertEqual(waiting.reports, ["a tunnel named utun7 is there again: its backup is left until it is gone"])
        let owner = OpenVPNDNSRecord(session: OpenVPNDNSSession(dev: "utun7", servers: ["10.9.0.1"]), status: 0, service: Self.wifi)
        XCTAssertEqual(settle(live: [owner]), OpenVPNDNS.Settlement(.done))
        XCTAssertEqual(system.writes, [])
        system.interfaces = []
        XCTAssertEqual(settle(), OpenVPNDNS.Settlement(.done))
        XCTAssertEqual(system.writes, ["remove backup utun7"])
    }

    /// A repair that fails is reported with what is left, and the next try does it.
    func testAFailedRepairIsTriedAgain() {
        system.services[Self.wifi] = Self.session.overrideEntity
        let wifi = OpenVPNDNS.Restored(serviceID: Self.wifi, service: "Wi-Fi", settings: Self.session.servers)

        system.refusedWrites = 1
        XCTAssertEqual(settle(), OpenVPNDNS.Settlement(.failed("the system configuration did not take the change"), left: [wifi]))
        system.lostWrites = 1
        XCTAssertEqual(settle(), OpenVPNDNS.Settlement(.failed("the change did not hold"), left: [wifi]))
        system.preferencesReadable = false
        XCTAssertEqual(settle(), OpenVPNDNS.Settlement(.failed("the network preferences cannot be read"), left: [wifi]))
        system.preferencesReadable = true
        system.storeReadable = false
        XCTAssertEqual(settle(), OpenVPNDNS.Settlement(.failed("the system configuration cannot be read")))
        XCTAssertEqual(system.services[Self.wifi], Self.session.overrideEntity, "still there")

        system.storeReadable = true
        XCTAssertEqual(settle(), OpenVPNDNS.Settlement(.done, restored: [wifi]))
        XCTAssertNil(system.services[Self.wifi])
    }

    // MARK: Split branch

    static let split = OpenVPNDNSRecord(
        session: OpenVPNDNSSession(dev: "utun7", servers: ["10.8.0.1"], searchDomains: ["corp.example.com"], matchDomains: ["corp.example.com"]),
        status: 0, service: wifi)
    static let splitKey: DNSEntity = [
        "ServerAddresses": strings(["10.8.0.1"]), "SupplementalMatchDomains": strings(["corp.example.com"]),
        "SupplementalMatchDomainsNoSearch": .integer(1)
    ]

    /// Its own `State:` key goes once the tunnel is gone; the search domains it put on the service it changed go
    /// while the rest of that service's DNS is what the preferences hold. Another service is not looked at.
    func testSplitDNSAndItsSearchDomains() {
        system.tunnels["utun7"] = Self.splitKey
        system.preferences[Self.ethernet] = ["ServerAddresses": Self.strings(["192.0.2.1"])]
        system.services = [
            Self.wifi: ["SearchDomains": Self.strings(["corp.example.com", "home.example"])],
            Self.ethernet: ["ServerAddresses": Self.strings(["192.0.2.1"]), "SearchDomains": Self.strings(["corp.example.com"])]
        ]
        let s = settle(Self.split)
        XCTAssertEqual(s.restored, [OpenVPNDNS.Restored(serviceID: Self.wifi, service: "Wi-Fi", settings: ["corp.example.com"])])
        XCTAssertNil(system.services[Self.wifi])
        XCTAssertEqual(system.services[Self.ethernet]?["SearchDomains"], Self.strings(["corp.example.com"]), "not the session's service")
        XCTAssertNil(system.tunnels["utun7"])
    }

    func testSplitDNSThatOthersHoldOrChangedIsLeft() {
        // A tunnel of that name is there again (no running session of PassTunnel's): its key stays, the record waits.
        system.tunnels["utun7"] = Self.splitKey
        system.interfaces = ["utun7"]
        // Someone changed the servers too.
        system.services = [Self.wifi: ["ServerAddresses": Self.strings(["192.0.2.9"]), "SearchDomains": Self.strings(["corp.example.com"])]]
        XCTAssertEqual(settle(Self.split).outcome, .parked)
        // A running split session has its search domains there.
        system.services = [Self.wifi: ["SearchDomains": Self.strings(["corp.example.com", "lab.example.com"])]]
        let other = OpenVPNDNSRecord(
            session: OpenVPNDNSSession(dev: "utun8", servers: ["10.9.0.1"], searchDomains: ["lab.example.com"], matchDomains: ["lab.example.com"]),
            status: 0, service: Self.wifi)
        XCTAssertEqual(settle(Self.split, live: [other]).restored, [])
        XCTAssertEqual(system.writes, [])
        XCTAssertEqual(system.tunnels["utun7"], Self.splitKey)
    }

    // MARK: Left behind

    /// The script's DNS with no session of the script running and no record: reported, never changed; in effect
    /// only on the primary service or while the default resolver has those servers.
    func testLeftBehindIsOnlyReported() {
        system.services = [
            Self.wifi: [
                "ServerAddresses": Self.strings(["10.8.0.1"]), "SearchDomains": Self.strings(["corp.example.com"]), "SearchOrder": .integer(5000)
            ],
            Self.ethernet: ["ServerAddresses": Self.strings(["192.0.2.1"])]
        ]
        system.preferences[Self.ethernet] = ["ServerAddresses": Self.strings(["192.0.2.1"])]
        system.primary = Self.ethernet
        XCTAssertEqual(
            OpenVPNDNS.leftBehind(system: system),
            [
                OpenVPNDNS.LeftBehind(
                    serviceID: Self.wifi, service: "Wi-Fi", servers: ["10.8.0.1"], searchDomains: ["corp.example.com"], inEffect: false)
            ])
        system.resolver = ["10.8.0.1"]
        XCTAssertEqual(OpenVPNDNS.leftBehind(system: system)?.first?.inEffect, true)
        system.resolver = nil
        system.primary = Self.wifi
        XCTAssertEqual(OpenVPNDNS.leftBehind(system: system)?.first?.inEffect, true)
        XCTAssertEqual(system.writes, [])

        // A session of the script is redirecting DNS now (its tunnel is there): that is its DNS.
        system.backups["utun3"] = [:]
        system.interfaces = ["utun3"]
        XCTAssertEqual(OpenVPNDNS.leftBehind(system: system), [])
        // A backup whose tunnel is gone holds up nothing.
        system.interfaces = []
        XCTAssertEqual(OpenVPNDNS.leftBehind(system: system)?.count, 1)
        // What the preferences hold is no leftover.
        system.preferences[Self.wifi] = system.services[Self.wifi]!
        XCTAssertEqual(OpenVPNDNS.leftBehind(system: system), [])
        system.storeReadable = false
        XCTAssertNil(OpenVPNDNS.leftBehind(system: system))
    }

    func testScriptOverrideShape() {
        XCTAssertTrue(OpenVPNDNS.isScriptOverride(["ServerAddresses": Self.strings(["10.8.0.1"]), "SearchOrder": .integer(5000)]))
        XCTAssertTrue(Self.session.overrideEntity.keys.count == 3 && OpenVPNDNS.isScriptOverride(Self.session.overrideEntity))
        XCTAssertFalse(OpenVPNDNS.isScriptOverride(["ServerAddresses": Self.strings(["10.8.0.1"])]))
        XCTAssertTrue(OpenVPNDNS.isScriptOverride(["ServerAddresses": .array([]), "SearchOrder": .integer(5000)]), "no usable server")
        XCTAssertFalse(OpenVPNDNS.isScriptOverride(["SearchOrder": .integer(5000)]))
        XCTAssertFalse(
            OpenVPNDNS.isScriptOverride(["ServerAddresses": Self.strings(["10.8.0.1"]), "SearchOrder": .integer(5000), "DomainName": .string("x")]))
        XCTAssertFalse(OpenVPNDNS.isScriptOverride(["ServerAddresses": Self.strings(["10.8.0.1"]), "SearchOrder": .integer(1)]))
    }

    func testNamesAndKeys() {
        XCTAssertTrue(OpenVPNDNS.isDeviceName("utun12"))
        for bad in ["", "utun/1", "utun 1", "utun.1", String(repeating: "a", count: 16)] { XCTAssertFalse(OpenVPNDNS.isDeviceName(bad), bad) }
        XCTAssertTrue(OpenVPNDNS.isServiceID(Self.wifi))
        for bad in ["", "a/b", "a b", "..", "*", String(repeating: "a", count: 65)] { XCTAssertFalse(OpenVPNDNS.isServiceID(bad), bad) }
        system.services["a/b"] = Self.session.overrideEntity
        XCTAssertEqual(settle(OpenVPNDNSRecord(session: Self.session, status: 0, service: "a/b")).restored, [], "never a key of that")
        XCTAssertEqual(OpenVPNDNS.name(of: Self.ethernet, system: system), "Ethernet")
        system.names[Self.ethernet] = "My “Office”\nLAN"
        XCTAssertEqual(OpenVPNDNS.name(of: Self.ethernet, system: system), "My  Office  LAN")
        system.names[Self.ethernet] = nil
        XCTAssertEqual(OpenVPNDNS.name(of: Self.ethernet, system: system), Self.ethernet)
    }

    // MARK: The Mac

    #if os(macOS)
    /// Reads only: the dynamic store and the network preferences of the Mac the tests run on, never written.
    func testMacSystemReadsTheStoreAndThePreferences() throws {
        let mac = MacOpenVPNDNSSystem(name: "PassTunnel tests")
        let services = try XCTUnwrap(mac.serviceDNS())
        XCTAssertNotNil(mac.scriptBackups())
        XCTAssertNotNil(mac.tunnelDNS())
        for (id, _) in services {
            XCTAssertTrue(OpenVPNDNS.isServiceID(id))
            XCTAssertNotEqual(mac.preferencesDNS(service: id), .unreadable, id)
        }
        XCTAssertEqual(mac.preferencesDNS(service: "00000000-0000-4000-8000-000000000000"), .none)
        XCTAssertEqual(mac.preferencesDNS(service: "a/b"), .unreadable, "never a path of another key")
        XCTAssertTrue(mac.interfaceExists("lo0"))
        XCTAssertFalse(mac.interfaceExists("utun999"))
        if let primary = mac.primaryService() { XCTAssertTrue(OpenVPNDNS.isServiceID(primary)) }
        _ = mac.globalDNSServers()
        XCTAssertNotNil(OpenVPNDNS.leftBehind(system: mac))

        let entity: DNSEntity = [
            "ServerAddresses": Self.strings(["10.8.0.1"]), "SearchOrder": .integer(5000), "Weight": .real(0.5), "On": .bool(true),
            "Sub": .dictionary(["Data": .data(Data([1, 2])), "When": .date(Date(timeIntervalSince1970: 1))])
        ]
        XCTAssertEqual(MacOpenVPNDNSSystem.entity(MacOpenVPNDNSSystem.propertyList(.dictionary(entity))), entity)
    }
    #endif

    // MARK: Log lines

    func testNotesRoundTrip() {
        let notes = [
            OpenVPNDNS.Note(.restored, service: "Wi-Fi", settings: ["10.8.0.1", "2001:db8::53"]),
            OpenVPNDNS.Note(.notRestored, service: "USB 10/100 LAN", settings: ["10.8.0.1"], reason: "the change did not hold"),
            OpenVPNDNS.Note(.notRestored, service: "Wi-Fi", settings: ["corp.example.com"]),
            OpenVPNDNS.Note(.leftBehind, service: "Wi-Fi, 2", settings: ["10.8.0.1"])
        ]
        for note in notes {
            XCTAssertTrue(note.line.hasPrefix("PassTunnel helper: "), "never read as a failed start")
            XCTAssertFalse(note.line.contains("\n"))
            XCTAssertEqual(OpenVPNDNS.Note(line: note.line), note, note.line)
        }
        XCTAssertEqual(
            notes[0].line, "PassTunnel helper: restored the DNS of “Wi-Fi”, which still used the VPN's 10.8.0.1, 2001:db8::53")
        for other in [
            "PassTunnel: restored the DNS of “Wi-Fi”, which still used the VPN's 10.8.0.1",
            "PassTunnel helper: restored the DNS of “”, which still used the VPN's 10.8.0.1",
            "PassTunnel helper: restored the DNS of “Wi-Fi”, which still used the VPN's ",
            "PassTunnel helper: the DNS of “Wi-Fi” still uses 10.8.0.1"
        ] {
            XCTAssertNil(OpenVPNDNS.Note(line: other), other)
        }
        XCTAssertEqual(OpenVPNDNS.Note(.restored, service: "x", settings: ["10.8.0.1", "a b", "$(id)"]).settings, ["10.8.0.1"])
    }

    /// Only the helper's lines before the tool's first line and after its last one: a line the tool printed (a
    /// server's words can be in it) never counts.
    func testHelperNotesOnlyAroundTheToolsOutput() {
        let start = OpenVPNDNS.Note(.leftBehind, service: "Ethernet", settings: ["10.9.0.1"])
        let forged = OpenVPNDNS.Note(.restored, service: "Wi-Fi", settings: ["10.7.0.1"])
        let end = OpenVPNDNS.Note(.restored, service: "Wi-Fi", settings: ["10.8.0.1"])
        let log =
            [
                start.line, "2026-11-22 11:00:00 OpenVPN 2.7.9 aarch64-apple-darwin", forged.line,
                "2026-11-22 11:12:01 SIGTERM[soft,exit-with-notification] received, process exiting", "", end.line
            ].joined(separator: "\n") + "\n"
        XCTAssertEqual(OpenVPNDNS.Note.helperNotes(in: log), [start, end])
        XCTAssertEqual(OpenVPNDNS.Note.helperNotes(in: start.line + "\n" + end.line + "\n"), [start, end], "no tool output at all")
        XCTAssertEqual(OpenVPNDNS.Note.helperNotes(in: ""), [])
    }
}
