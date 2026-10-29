import Foundation
import FuzzSupport
import PassTunnelShared

// Fuzzes openconnect's hook, the part that runs as root on the server's values: the environment check
// (`OpenConnectNetwork`), the plan built from it (`OpenConnectPlan`), the session's record
// (`OpenConnectRecord`) and the report lines (`VPNHook`).
//
// Input: one byte of flags, then the environment as `NAME=VALUE` entries separated by NUL (as `environ`
// holds them). Flags: bit 0 Linux, bit 1 set_routes, bit 2 set_dns, bits 3–4 the default gateways (none,
// IPv4, both, one on the tunnel's own interface), bit 5 the rest is a record instead of an environment,
// bit 6 local networks are attached.
//
// Properties: nothing crashes or hangs; a refusal's description and failure line are one line of printable
// ASCII; an accepted network written back as variables parses to the same network, and every value in it
// passes its rule again; every change of a plan parses back from its text and never routes the default
// route; a blocked family has both reject routes and no other route but the server's; no route the server
// asked for goes into the tunnel inside a local network; a route that would capture the server comes after
// its host route; the record of a set-up reads back the same, reverts in reverse order and compacts (also
// with a change pending after the status); the report line is one line and parses back; a record that
// parses prints back byte for byte and compacts to the same state.
@_cdecl("LLVMFuzzerTestOneInput")
func LLVMFuzzerTestOneInput(_ data: UnsafePointer<UInt8>?, _ size: Int) -> CInt {
    let bytes = [UInt8](fuzzData(data, size))
    guard let flags = bytes.first else { return 0 }
    let rest = Array(bytes.dropFirst())
    if flags & 0x20 != 0 {
        checkRecord(rest)
        return 0
    }
    let platform: OpenConnectNetwork.Platform = flags & 1 != 0 ? .linux : .macOS
    let policy = OpenConnectPolicy(uid: 501, profileID: "acme", setRoutes: flags & 2 != 0, setDNS: flags & 4 != 0)
    let v4 = OpenConnectPlan.Gateway(address: IPAddress("198.51.100.1"), interface: "en0")
    let v6 = OpenConnectPlan.Gateway(address: IPAddress("fe80::1"), interface: "en0")
    var underlay: OpenConnectPlan.Underlay
    switch flags >> 3 & 3 {
    case 0: underlay = .init()
    case 1: underlay = .init(ipv4: v4)
    case 2: underlay = .init(ipv4: v4, ipv6: v6)
    default: underlay = .init(ipv4: OpenConnectPlan.Gateway(address: nil, interface: platform == .macOS ? "utun5" : "tun0"))
    }
    if flags & 0x40 != 0 {
        underlay.attached = [
            ("192.168.1.0/24", "en0"), ("10.11.0.0/16", "en0"), ("2001:db8:1::/48", "en0"), ("fe80::/64", "en0"),
            ("10.0.0.0/8", platform == .macOS ? "utun5" : "tun0")
        ].map { OpenConnectPlan.Attached(IPNetwork($0.0)!, interface: $0.1) }
    }

    let entries = rest.split(separator: 0, omittingEmptySubsequences: true).map(Array.init)
    let event: OpenConnectNetwork.Event
    do {
        event = try OpenConnectNetwork.parse(.init(entries: entries), platform: platform)
    } catch {
        checkLine(VPNHook.failureLine(String(describing: error)))
        precondition(String(describing: error).utf8.allSatisfy { $0 >= 0x20 && $0 < 0x7F }, "a refusal that is not printable")
        return 0
    }
    guard let network = event.network else { return 0 }
    checkNetwork(network, event: event, platform: platform)

    let plan: OpenConnectPlan
    do {
        plan = try OpenConnectPlan.connect(network, policy: policy, underlay: underlay)
    } catch {
        checkLine(VPNHook.failureLine(String(describing: error)))
        return 0
    }
    checkPlan(plan, network: network, underlay: underlay)
    var record = OpenConnectRecord(interface: network.interface)!
    for change in plan.changes {
        let text = change.text
        precondition(OpenConnectPlan.Change(text: text) == change, "a change does not parse back")
        precondition(text.utf8.allSatisfy { $0 >= 0x20 && $0 < 0x7F }, "a change that is not one line")
        if case .route(let route) = change {
            precondition(route.network.prefixLength > 0, "a plan that routes the default route")
            if case .interface(let name) = route.via { precondition(name == network.interface) }
            if case .reject = route.via { precondition(plan.blocked.contains(route.network.family)) }
            precondition(policy.setRoutes, "a route without set_routes")
        }
        if case .dns = change { precondition(policy.setDNS, "DNS without set_dns") }
        try! record.append(.begin(change))
        try! record.append(.owned(change))
    }
    try! record.append(.status(.up))
    precondition(record.toRevert(sparing: []) == plan.changes.reversed(), "a revert that is not newest first")
    precondition(record.toRevert(sparing: [record]).isEmpty, "a revert of what another session holds")
    var spareAll = record
    precondition((try? spareAll.beginRevert(sparing: [record]))?.isEmpty == true && spareAll.pending == nil)
    var undoAll = record
    for change in try! undoAll.beginRevert(sparing: []) { try! undoAll.append(.reverted(change)) }
    precondition(undoAll.toRevert(sparing: []).isEmpty, "a revert that left something of the session's")
    if let text = try? record.text() {
        precondition(OpenConnectRecord.parse(text) == record, "the record does not read back")
    }
    checkCompaction(record)
    // A change begun after the status, killed before its outcome.
    var killed = record
    let extra = OpenConnectPlan.Change.address(interface: network.interface, IPAddress("192.0.2.1")!)
    if !plan.changes.contains(extra) {
        try! killed.append(.begin(extra))
        checkCompaction(killed)
        precondition(killed.toRevert(sparing: []).first == extra)
        var spared = killed
        precondition((try? spared.beginRevert(sparing: [record])) == [extra] && spared.pending == extra)
        try! spared.append(.reverted(extra))
        checkCompaction(spared)
    }
    precondition(OpenConnectPlan.matches(network, policy: policy, underlay: underlay, record: record), "a set-up that does not match itself")
    let refresh = OpenConnectPlan.refresh(network, policy: policy, underlay: underlay, record: record)
    precondition(refresh.remove.isEmpty && refresh.add.isEmpty, "a refresh that changes nothing changed something")

    let report = VPNHook.Report(plan)
    checkLine(report.line)
    precondition(VPNHook.Report.parse(report.line[...]) == report, "the report line does not parse back")
    return 0
}

/// One line of printable ASCII and its line break.
func checkLine(_ line: String) {
    let utf8 = Array(line.utf8)
    precondition(utf8.last == 0x0A && utf8.dropLast().allSatisfy { $0 >= 0x20 && $0 < 0x7F }, "a report that is not one line")
    precondition(line.hasPrefix(VPNHook.linePrefix))
}

/// What the plan promises about blocks, local networks and the VPN server.
func checkPlan(_ plan: OpenConnectPlan, network n: OpenConnectNetwork, underlay: OpenConnectPlan.Underlay) {
    let routes = plan.changes.compactMap { change -> OpenConnectPlan.Route? in
        if case .route(let r) = change { return r }
        return nil
    }
    for family in plan.blocked {
        let mine = routes.filter { $0.network.family == family }
        for half in IPNetwork.halves(family) {
            precondition(mine.contains(OpenConnectPlan.Route(half, via: .reject)), "a blocked family without its reject route")
        }
        precondition(
            mine.allSatisfy { $0.via == .reject || $0.network == IPNetwork.host(n.gateway) }, "a hole in a blocked family")
        precondition(plan.dns.map { !$0.servers.contains { $0.family == family } } ?? true, "a DNS server of a blocked family")
    }
    let local = underlay.attached.filter { $0.interface != n.interface && !IPNetwork("fe80::/10")!.contains($0.network) }
    for route in routes {
        guard case .interface = route.via, route.network.prefixLength > 1 else { continue }
        precondition(!local.contains { $0.network.contains(route.network) }, "a route into the tunnel inside a local network")
    }
    let capturing = routes.firstIndex { route in
        if case .gateway = route.via { return false }
        return route.network.contains(n.gateway)
    }
    if let capturing, !n.gateway.isLoopback {
        let host = routes.firstIndex { $0.network == IPNetwork.host(n.gateway) }
        precondition(host != nil && host! < capturing, "a route captures the VPN server before its host route")
    }
}

func checkCompaction(_ record: OpenConnectRecord) {
    guard let compact = try? record.compacted() else { preconditionFailure("a valid record does not compact") }
    precondition(OpenConnectRecord.parse(try! compact.text()) == compact, "a compacted record does not read back")
    precondition(
        compact.toRevert(sparing: []) == record.toRevert(sparing: []) && compact.applied == record.applied
            && compact.status == record.status && compact.pending == record.pending)
}

func checkNetwork(_ n: OpenConnectNetwork, event: OpenConnectNetwork.Event, platform: OpenConnectNetwork.Platform) {
    precondition(OpenConnectNetwork.isTunnelInterface(n.interface, platform: platform))
    precondition(OpenConnectNetwork.mtuRange.contains(n.mtu))
    precondition(n.ipv4 != nil || n.ipv6 != nil)
    let ipv6 = [n.gateway, n.ipv6?.address].compactMap { $0 } + n.dnsServers
    precondition(!ipv6.contains { $0.isIPv4Embedded }, "an IPv4 address written as IPv6")
    precondition(!(n.ipv6Includes + n.ipv6Excludes).contains { $0.isIPv4Embedded }, "an IPv4 network written as IPv6")
    precondition(n.ipv6 == nil || n.mtu >= OpenConnectNetwork.minIPv6MTU)
    for address in [n.gateway] + [n.ipv4?.address, n.ipv6?.address].compactMap({ $0 }) + n.dnsServers {
        precondition(IPAddress(address.description) == address, "an address that does not validate again")
    }
    for domain in n.defaultDomains + n.splitDNSDomains {
        precondition(DomainName.normalize(domain) == domain, "a domain that does not validate again")
    }
    precondition(n.dnsServers.count <= OpenConnectNetwork.maxDNSServers)
    precondition(n.defaultDomains.count <= OpenConnectNetwork.maxDomains && n.splitDNSDomains.count <= OpenConnectNetwork.maxDomains)
    for list in [n.ipv4Includes, n.ipv4Excludes, n.ipv6Includes, n.ipv6Excludes] {
        precondition(list.count <= OpenConnectNetwork.maxSplitRoutes)
        for net in list { precondition(IPNetwork(net.description) == net, "a network that does not validate again") }
    }
    let again = try? OpenConnectNetwork.parse(.init(n.environment(reason: event.reason)), platform: platform)
    precondition(again == event, "the network written back does not parse to itself")
}

func checkRecord(_ bytes: [UInt8]) {
    let text = String(decoding: bytes, as: UTF8.self)
    guard let record = OpenConnectRecord.parse(text) else { return }
    precondition(Array((try! record.text()).utf8) == bytes, "a record that does not print back byte for byte")
    checkCompaction(record)
}

runFuzzer(LLVMFuzzerTestOneInput)
