// macOS only, like HelperInstaller (SMAppService).
#if os(macOS)
import ServiceManagement
import XCTest
@testable import PassTunnelCore

final class HelperInstallerTests: XCTestCase {
    /// Scripted SMAppService stand-in: `registerResults` are used in order (then success), and the
    /// status stays `.enabled` for `enabledPollsAfterUnregister` reads after an unregister.
    final class FakeRegistrar: HelperRegistrar, @unchecked Sendable {
        private let lock = NSLock()
        var registerResults: [Error?] = []
        var unregisterError: Error?
        var enabledPollsAfterUnregister = 0
        private(set) var registerCalls = 0
        private(set) var unregisterCalls = 0
        private(set) var events: [String] = []
        private var current: HelperStatus = .enabled

        var status: HelperStatus {
            lock.withLock {
                if current == .notRegistered, enabledPollsAfterUnregister > 0 {
                    enabledPollsAfterUnregister -= 1
                    return .enabled
                }
                return current
            }
        }

        func register() throws {
            try lock.withLock {
                registerCalls += 1
                events.append("register")
                if !registerResults.isEmpty, let error = registerResults.removeFirst() { throw error }
                current = .enabled
            }
        }

        func unregister() async throws {
            try lock.withLock {
                unregisterCalls += 1
                events.append("unregister")
                if let unregisterError { throw unregisterError }
                current = .notRegistered
            }
        }
    }

    final class SleepRecorder: @unchecked Sendable {
        private let lock = NSLock()
        private var _delays: [TimeInterval] = []
        var delays: [TimeInterval] { lock.withLock { _delays } }
        var sleeper: HelperInstaller.Sleeper {
            { [self] seconds in lock.withLock { _delays.append(seconds) } }
        }
    }

    static let eperm = NSError(
        domain: "SMAppServiceErrorDomain", code: Int(EPERM),
        userInfo: [NSLocalizedDescriptionKey: "Operation not permitted"])
    static let posixEPERM = NSError(domain: NSPOSIXErrorDomain, code: Int(EPERM))
    static let denied = NSError(domain: "SMAppServiceErrorDomain", code: kSMErrorLaunchDeniedByUser)
    static let already = NSError(domain: "SMAppServiceErrorDomain", code: kSMErrorAlreadyRegistered)
    static let notFound = NSError(domain: "SMAppServiceErrorDomain", code: kSMErrorJobNotFound)
    static let other = NSError(domain: "SMAppServiceErrorDomain", code: kSMErrorInvalidSignature)

    func testClassifiesServiceManagementAndPOSIXErrors() {
        XCTAssertEqual(HelperInstaller.classify(Self.eperm), .notPermitted)
        XCTAssertEqual(HelperInstaller.classify(Self.posixEPERM), .notPermitted)
        XCTAssertEqual(HelperInstaller.classify(Self.denied), .deniedByUser)
        XCTAssertEqual(HelperInstaller.classify(Self.already), .alreadyRegistered)
        XCTAssertEqual(HelperInstaller.classify(Self.notFound), .jobNotFound)
        XCTAssertEqual(HelperInstaller.classify(Self.other), .other)
        // POSIX 11 / 12 are EDEADLK / ENOMEM, not the ServiceManagement codes.
        XCTAssertEqual(HelperInstaller.classify(NSError(domain: NSPOSIXErrorDomain, code: 12)), .other)
        let wrapped = NSError(
            domain: "SMAppServiceErrorDomain", code: kSMErrorInternalFailure,
            userInfo: [NSUnderlyingErrorKey: Self.posixEPERM])
        XCTAssertEqual(HelperInstaller.classify(wrapped), .notPermitted)
    }

    func testRegisterRetriesWhileNotPermitted() async throws {
        let r = FakeRegistrar()
        r.registerResults = [Self.eperm, Self.posixEPERM]
        let sleep = SleepRecorder()
        try await HelperInstaller.register(using: r, sleep: sleep.sleeper)
        XCTAssertEqual(r.registerCalls, 3)
        XCTAssertEqual(sleep.delays, [0.5, 1])
        XCTAssertEqual(r.status, .enabled)
    }

    func testRegisterGivesUpAfterTheLastRetry() async {
        let r = FakeRegistrar()
        r.registerResults = Array(repeating: Self.eperm, count: 10)
        let sleep = SleepRecorder()
        do {
            try await HelperInstaller.register(using: r, sleep: sleep.sleeper)
            XCTFail("registered")
        } catch {
            XCTAssertEqual(error as? HelperInstallError, .notPermitted("Operation not permitted"))
            XCTAssertFalse(error.localizedDescription.isEmpty)
        }
        XCTAssertEqual(r.registerCalls, HelperInstaller.retryDelays.count + 1)
        XCTAssertEqual(sleep.delays, HelperInstaller.retryDelays)
        XCTAssertLessThanOrEqual(HelperInstaller.retryDelays.reduce(0, +) + HelperInstaller.unregisterWait, 8)
    }

    func testDeniedByUserIsNotRetried() async {
        let r = FakeRegistrar()
        r.registerResults = [Self.denied]
        let sleep = SleepRecorder()
        do {
            try await HelperInstaller.register(using: r, sleep: sleep.sleeper)
            XCTFail("registered")
        } catch {
            XCTAssertEqual(error as? HelperInstallError, .deniedByUser)
        }
        XCTAssertEqual(r.registerCalls, 1)
        XCTAssertEqual(sleep.delays, [])
    }

    func testOtherErrorsAreThrownAsTheyAre() async {
        let r = FakeRegistrar()
        r.registerResults = [Self.other]
        do {
            try await HelperInstaller.register(using: r, sleep: SleepRecorder().sleeper)
            XCTFail("registered")
        } catch {
            XCTAssertEqual((error as NSError).code, kSMErrorInvalidSignature)
        }
        XCTAssertEqual(r.registerCalls, 1)
    }

    func testAlreadyRegisteredCountsAsSuccess() async throws {
        let r = FakeRegistrar()
        r.registerResults = [Self.already]
        try await HelperInstaller.register(using: r, sleep: SleepRecorder().sleeper)
        XCTAssertEqual(r.registerCalls, 1)
    }

    func testUpdateWaitsForTheOldHelperThenRetriesTheRegistration() async throws {
        let r = FakeRegistrar()
        r.enabledPollsAfterUnregister = 3
        r.registerResults = [Self.eperm, Self.eperm]
        let sleep = SleepRecorder()
        try await HelperInstaller.update(using: r, sleep: sleep.sleeper)
        XCTAssertEqual(r.events, ["unregister", "register", "register", "register"])
        // Three status polls while launchd still lists the old job, then the register back-off.
        XCTAssertEqual(sleep.delays, [0.25, 0.25, 0.25, 0.5, 1])
        XCTAssertEqual(r.status, .enabled)
    }

    func testUpdateStopsWaitingForTheOldHelperAfterAWhile() async throws {
        let r = FakeRegistrar()
        r.enabledPollsAfterUnregister = 1000
        let sleep = SleepRecorder()
        try await HelperInstaller.update(using: r, unregisterWait: 1, sleep: sleep.sleeper)
        XCTAssertEqual(sleep.delays, [0.25, 0.25, 0.25, 0.25])
        XCTAssertEqual(r.registerCalls, 1)
    }

    func testUpdateRegistersWhenNothingWasRegistered() async throws {
        let r = FakeRegistrar()
        r.unregisterError = Self.notFound
        try await HelperInstaller.update(using: r, sleep: SleepRecorder().sleeper)
        XCTAssertEqual(r.events, ["unregister", "register"])
    }

    func testUpdateReportsAFailedUnregister() async {
        let r = FakeRegistrar()
        r.unregisterError = Self.other
        do {
            try await HelperInstaller.update(using: r, sleep: SleepRecorder().sleeper)
            XCTFail("updated")
        } catch {
            XCTAssertEqual((error as NSError).code, kSMErrorInvalidSignature)
        }
        XCTAssertEqual(r.registerCalls, 0)
    }

    func testUpdateFailsClearlyWhenRegistrationNeverWorks() async {
        let r = FakeRegistrar()
        r.registerResults = Array(repeating: Self.eperm, count: 10)
        do {
            try await HelperInstaller.update(using: r, sleep: SleepRecorder().sleeper)
            XCTFail("updated")
        } catch {
            guard case .notPermitted = error as? HelperInstallError else { return XCTFail("\(error)") }
        }
    }
}
#endif
