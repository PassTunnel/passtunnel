import Foundation
import PassTunnelShared
import XCTest

@testable import PassTunnelCore

final class HelperAutoInstallTests: XCTestCase {
    private typealias Trigger = HelperAutoInstall.Trigger
    private let triggers: [Trigger] = [.firstRun, .switchedOn, .connect, .refresh]
    private let statuses: [HelperStatus] = [.notRegistered, .notFound, .enabled, .requiresApproval]

    private func situation(
        enabled: Bool = true, removed: Bool = false, status: HelperStatus = .notRegistered, notAnswering: Bool = false,
        relation: HelperBuild.Relation? = nil, sessions: Int = 0, busy: Bool = false, inApplications: Bool = true,
        bundled: Bool = true
    ) -> HelperAutoInstall.Situation {
        .init(
            enabled: enabled, removedByUser: removed, status: status, notAnswering: notAnswering, relation: relation,
            activeSessions: sessions, busy: busy, inApplicationsFolder: inApplications, bundled: bundled)
    }

    /// Every situation the switch can meet: off by default, and while off nothing happens on its own.
    func testOffByDefaultAndNothingAutomaticWhileOff() {
        XCTAssertFalse(Preferences().autoInstallHelper)
        var policy = HelperAutoInstall()
        let relations: [HelperBuild.Relation?] = [nil, .current, .older, .newer, .different]
        for status in statuses {
            for notAnswering in [false, true] {
                for relation in relations {
                    for sessions in [0, 1] {
                        for trigger in triggers {
                            let s = situation(
                                enabled: Preferences().autoInstallHelper, status: status, notAnswering: notAnswering,
                                relation: relation, sessions: sessions)
                            XCTAssertEqual(policy.next(s, trigger: trigger), .none, "\(status) \(notAnswering) \(sessions) \(trigger)")
                        }
                    }
                }
            }
        }
        XCTAssertFalse(policy.registerAttempted)
        XCTAssertFalse(policy.repairAttempted)
    }

    func testMissingHelperIsRegisteredOnceWhenSomeoneIsThere() {
        for trigger in [Trigger.firstRun, .switchedOn, .connect] {
            for status in [HelperStatus.notRegistered, .notFound] {
                var policy = HelperAutoInstall()
                XCTAssertEqual(policy.next(situation(status: status), trigger: trigger), .register, "\(trigger) \(status)")
                XCTAssertTrue(policy.registerAttempted)
                // Failed (still missing): left to the button, whatever asks next.
                for again in triggers {
                    XCTAssertEqual(policy.next(situation(status: status), trigger: again), .none)
                }
            }
        }
    }

    func testRefreshNeverRegisters() {
        var policy = HelperAutoInstall()
        XCTAssertEqual(policy.next(situation(status: .notRegistered), trigger: .refresh), .none)
        XCTAssertEqual(policy.next(situation(status: .notFound), trigger: .refresh), .none)
        XCTAssertFalse(policy.registerAttempted)
        XCTAssertEqual(policy.next(situation(), trigger: .connect), .register)
    }

    /// Registering points the root helper at this copy: only a bundled copy in /Applications.
    func testOnlyABundledCopyInApplicationsActs() {
        for (inApplications, bundled) in [(false, true), (true, false), (false, false)] {
            var policy = HelperAutoInstall()
            for trigger in triggers {
                for status in statuses {
                    let s = situation(
                        status: status, notAnswering: true, inApplications: inApplications, bundled: bundled)
                    XCTAssertEqual(policy.next(s, trigger: trigger), .none)
                }
            }
        }
    }

    func testRemovedByTheUserIsNotInstalledOrRepaired() {
        var policy = HelperAutoInstall()
        for trigger in triggers {
            XCTAssertEqual(policy.next(situation(removed: true), trigger: trigger), .none)
            XCTAssertEqual(policy.next(situation(removed: true, status: .notFound), trigger: trigger), .none)
            XCTAssertEqual(policy.next(situation(removed: true, status: .enabled, notAnswering: true), trigger: trigger), .none)
        }
        XCTAssertFalse(policy.registerAttempted)
        // Installed by hand again (the flag cleared): the automatic install works again.
        XCTAssertEqual(policy.next(situation(), trigger: .connect), .register)
    }

    /// Waiting for the approval, never approved or switched off in Login Items: never registered again.
    func testApprovalIsNeverTouched() {
        var policy = HelperAutoInstall()
        for trigger in triggers {
            XCTAssertEqual(policy.next(situation(status: .requiresApproval), trigger: trigger), .none)
            XCTAssertEqual(policy.next(situation(status: .requiresApproval, notAnswering: true), trigger: trigger), .none)
        }
        XCTAssertFalse(policy.registerAttempted)
        XCTAssertFalse(policy.repairAttempted)
    }

    func testNotAnsweringHelperIsRepairedOnceWithoutSessions() {
        var policy = HelperAutoInstall()
        XCTAssertEqual(policy.next(situation(status: .enabled, notAnswering: true, sessions: 1), trigger: .refresh), .none)
        XCTAssertEqual(policy.next(situation(status: .enabled, notAnswering: true, sessions: 3), trigger: .connect), .none)
        XCTAssertFalse(policy.repairAttempted)
        // The last session ended.
        XCTAssertEqual(policy.next(situation(status: .enabled, notAnswering: true), trigger: .refresh), .repair)
        XCTAssertTrue(policy.repairAttempted)
        for trigger in triggers {
            XCTAssertEqual(policy.next(situation(status: .enabled, notAnswering: true), trigger: trigger), .none)
        }
    }

    /// A helper last seen as newer (a downgrade) or not comparable is never replaced without asking, even when it
    /// stopped answering; one never seen, this copy's build or an older one is.
    func testRepairOnlyWhenTheLastAnswerAllowsIt() {
        let cases: [(HelperBuild.Relation?, HelperAutoInstall.Action)] = [
            (nil, .repair), (.current, .repair), (.older, .repair), (.newer, .none), (.different, .none)
        ]
        for (relation, expected) in cases {
            var policy = HelperAutoInstall()
            XCTAssertEqual(policy.mayStillRepair(relation: relation), expected == .repair, "\(String(describing: relation))")
            for trigger in triggers {
                let s = situation(status: .enabled, notAnswering: true, relation: relation)
                let action = policy.next(s, trigger: trigger)
                XCTAssertEqual(action, trigger == triggers.first ? expected : .none, "\(String(describing: relation)) \(trigger)")
            }
            XCTAssertEqual(policy.repairAttempted, expected == .repair)
            XCTAssertFalse(policy.mayStillRepair(relation: relation), "attempted, or not allowed")
        }
    }

    func testAnsweringHelperIsLeftAlone() {
        var policy = HelperAutoInstall()
        for trigger in triggers {
            XCTAssertEqual(policy.next(situation(status: .enabled), trigger: trigger), .none)
        }
        XCTAssertFalse(policy.repairAttempted)
    }

    func testNothingWhileBusy() {
        var policy = HelperAutoInstall()
        XCTAssertEqual(policy.next(situation(busy: true), trigger: .connect), .none)
        XCTAssertEqual(policy.next(situation(status: .enabled, notAnswering: true, busy: true), trigger: .refresh), .none)
        XCTAssertFalse(policy.registerAttempted)
        XCTAssertFalse(policy.repairAttempted)
        XCTAssertEqual(policy.next(situation(), trigger: .connect), .register)
    }

    func testRegisterAndRepairAreSeparateAttempts() {
        var policy = HelperAutoInstall()
        XCTAssertEqual(policy.next(situation(), trigger: .firstRun), .register)
        XCTAssertEqual(policy.next(situation(status: .enabled, notAnswering: true), trigger: .refresh), .repair)
    }

    func testLoginItemsOpenOnceAndOnlyAfterTheUserActed() {
        var policy = HelperAutoInstall()
        XCTAssertFalse(policy.opensLoginItems(userActed: false))
        XCTAssertFalse(policy.openedLoginItems)
        XCTAssertTrue(policy.opensLoginItems(userActed: true))
        XCTAssertFalse(policy.opensLoginItems(userActed: true))
        XCTAssertFalse(policy.opensLoginItems(userActed: false))
    }

    // MARK: HelperAnswerWatch

    func testOneTimeoutIsNotEnough() {
        let t0 = Date(timeIntervalSince1970: 1_000)
        var watch = HelperAnswerWatch()
        watch.failed(HelperClientError.timeout(15), at: t0)
        XCTAssertFalse(watch.notAnswering)
        watch.failed(HelperClientError.timeout(15), at: t0.addingTimeInterval(15))
        XCTAssertFalse(watch.notAnswering)
        // Three in a row over 30 s: not answering.
        watch.failed(HelperClientError.timeout(15), at: t0.addingTimeInterval(30))
        XCTAssertTrue(watch.notAnswering)
    }

    func testQuickFailuresNeedTheMinimumSpan() {
        let t0 = Date(timeIntervalSince1970: 1_000)
        var watch = HelperAnswerWatch()
        for i in 0..<10 {
            watch.failed(HelperClientError.unavailable("refused"), at: t0.addingTimeInterval(Double(i)))
        }
        XCTAssertEqual(watch.failures, 10)
        XCTAssertFalse(watch.notAnswering, "10 failures within 9 s")
        watch.failed(HelperClientError.unavailable("refused"), at: t0.addingTimeInterval(HelperAnswerWatch.minimumSpan))
        XCTAssertTrue(watch.notAnswering)
    }

    func testAnyAnswerStartsOver() {
        let t0 = Date(timeIntervalSince1970: 1_000)
        var watch = HelperAnswerWatch()
        watch.failed(HelperClientError.timeout(15), at: t0)
        watch.failed(HelperClientError.timeout(15), at: t0.addingTimeInterval(20))
        watch.answered()
        watch.failed(HelperClientError.timeout(15), at: t0.addingTimeInterval(40))
        XCTAssertEqual(watch.failures, 1)
        XCTAssertFalse(watch.notAnswering)
        // An invalid reply or a mismatch came from a running helper.
        for error in [HelperClientError.badResponse, .buildMismatch, .versionMismatch(helper: 1, app: 2)] {
            watch.failed(HelperClientError.timeout(15), at: t0)
            watch.failed(error, at: t0.addingTimeInterval(60))
            XCTAssertEqual(watch.failures, 0, "\(error)")
        }
    }

    func testAsksLessOftenOnceDecided() {
        let t0 = Date(timeIntervalSince1970: 1_000)
        var watch = HelperAnswerWatch()
        XCTAssertTrue(watch.shouldAsk(at: t0))
        watch.failed(HelperClientError.timeout(15), at: t0)
        watch.failed(HelperClientError.timeout(15), at: t0.addingTimeInterval(15))
        XCTAssertTrue(watch.shouldAsk(at: t0.addingTimeInterval(16)), "not decided yet: every refresh")
        watch.failed(HelperClientError.timeout(15), at: t0.addingTimeInterval(30))
        XCTAssertTrue(watch.notAnswering)
        XCTAssertFalse(watch.shouldAsk(at: t0.addingTimeInterval(35)))
        XCTAssertFalse(watch.shouldAsk(at: t0.addingTimeInterval(30 + HelperAnswerWatch.retryInterval - 1)))
        XCTAssertTrue(watch.shouldAsk(at: t0.addingTimeInterval(30 + HelperAnswerWatch.retryInterval)))
        watch.failed(HelperClientError.unavailable("refused"), at: t0.addingTimeInterval(100))
        XCTAssertFalse(watch.shouldAsk(at: t0.addingTimeInterval(101)), "the interval starts again")
        watch.answered()
        XCTAssertTrue(watch.shouldAsk(at: t0.addingTimeInterval(101)))
    }

    func testStatusErrorsAndOtherErrorsDoNotCount() {
        let t0 = Date(timeIntervalSince1970: 1_000)
        var watch = HelperAnswerWatch()
        watch.failed(HelperClientError.timeout(15), at: t0)
        watch.failed(HelperClientError.requiresApproval, at: t0.addingTimeInterval(1))
        XCTAssertEqual(watch.failures, 0)
        watch.failed(HelperClientError.timeout(15), at: t0)
        watch.failed(CancellationError(), at: t0.addingTimeInterval(1))
        XCTAssertEqual(watch.failures, 1, "not a helper error: ignored")
        watch.reset()
        XCTAssertEqual(watch, HelperAnswerWatch())
    }

    // MARK: HelperPendingConnect

    func testPendingConnectStartsWhenReady() {
        let t0 = Date(timeIntervalSince1970: 1_000)
        var pending = HelperPendingConnect()
        XCTAssertEqual(pending.next(ready: true, now: t0), .none, "nothing waits")
        pending.start("work", now: t0)
        XCTAssertTrue(pending.isWaiting)
        XCTAssertEqual(pending.next(ready: false, now: t0.addingTimeInterval(60)), .none)
        XCTAssertEqual(pending.next(ready: true, now: t0.addingTimeInterval(120)), .connect("work"))
        XCTAssertFalse(pending.isWaiting)
        XCTAssertEqual(pending.next(ready: true, now: t0.addingTimeInterval(121)), .none, "once")
    }

    func testPendingConnectExpires() {
        let t0 = Date(timeIntervalSince1970: 1_000)
        var pending = HelperPendingConnect()
        pending.start("work", now: t0)
        XCTAssertEqual(pending.next(ready: false, now: t0.addingTimeInterval(HelperPendingConnect.timeout - 1)), .none)
        XCTAssertEqual(pending.next(ready: false, now: t0.addingTimeInterval(HelperPendingConnect.timeout)), .expired("work"))
        XCTAssertFalse(pending.isWaiting)
        XCTAssertEqual(pending.next(ready: true, now: t0.addingTimeInterval(HelperPendingConnect.timeout + 1)), .none)
        XCTAssertEqual(HelperPendingConnect.timeout, 300)
    }

    /// An expired connect says what it still waited for.
    func testWhatAPendingConnectWaitsFor() {
        typealias P = HelperPendingConnect
        XCTAssertEqual(P.waitingFor(status: .notRegistered, outdated: false), .install)
        XCTAssertEqual(P.waitingFor(status: .notFound, outdated: false), .install)
        XCTAssertEqual(P.waitingFor(status: .requiresApproval, outdated: false), .approval)
        XCTAssertEqual(P.waitingFor(status: .enabled, outdated: true), .update)
        XCTAssertEqual(P.waitingFor(status: .enabled, outdated: false), .answer)
    }

    func testPendingConnectCancelAndReplace() {
        let t0 = Date(timeIntervalSince1970: 1_000)
        var pending = HelperPendingConnect()
        XCTAssertNil(pending.cancel())
        pending.start("work", now: t0)
        XCTAssertFalse(pending.cancel(profile: "lab"))
        XCTAssertTrue(pending.isWaiting)
        XCTAssertTrue(pending.cancel(profile: "work"))
        XCTAssertEqual(pending.next(ready: true, now: t0), .none)

        // Another profile's Connect replaces it, with a fresh deadline.
        pending.start("work", now: t0)
        pending.start("lab", now: t0.addingTimeInterval(200))
        XCTAssertEqual(pending.profileID, "lab")
        XCTAssertEqual(pending.next(ready: false, now: t0.addingTimeInterval(HelperPendingConnect.timeout)), .none)
        XCTAssertEqual(pending.cancel(), "lab")
        XCTAssertFalse(pending.isWaiting)
    }
}
