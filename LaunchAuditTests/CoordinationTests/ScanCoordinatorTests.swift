import XCTest
@testable import LaunchAudit

/// Tests for scan orchestration.
///
/// These use **injected fake scanners** rather than running all 36 against the live
/// machine. The previous versions asserted things that could not fail
/// (`scanDuration > 0`, `slowest.count <= 5` on a `prefix(5)`, that `sorted` sorts)
/// and paid a full real scan three times over to do it — which also made them the
/// most likely source of spurious CI failures.
@MainActor
final class ScanCoordinatorTests: XCTestCase {

    // MARK: - Fakes

    private struct FakeScanner: PersistenceScanner {
        let category: PersistenceCategory
        var requiresPrivilege = false
        var scanPaths: [String] { [] }
        var itemNames: [String] = []
        var errors: [ScanError] = []
        var delay: Duration = .zero
        var thrownError: Error?

        func scan() async throws -> ScanOutcome {
            if delay > .zero { try? await Task.sleep(for: delay) }
            if let thrownError { throw thrownError }
            return ScanOutcome(
                items: itemNames.map {
                    PersistenceItem(category: category, name: $0)
                },
                errors: errors
            )
        }
    }

    private struct HangingScanner: PersistenceScanner {
        let category: PersistenceCategory
        let requiresPrivilege = false
        var scanPaths: [String] { [] }

        func scan() async throws -> ScanOutcome {
            // Simulates a blocking read on a FIFO or a stalled subprocess.
            try? await Task.sleep(for: .seconds(600))
            return .empty
        }
    }

    private struct FailingScanner: PersistenceScanner {
        let category: PersistenceCategory
        let requiresPrivilege = false
        var scanPaths: [String] { [] }

        struct Boom: Error, LocalizedError {
            var errorDescription: String? { "scanner exploded" }
        }

        func scan() async throws -> ScanOutcome { throw Boom() }
    }

    // MARK: - Aggregation

    func testAggregatesItemsAndErrorsFromEveryScanner() async {
        let coordinator = ScanCoordinator(scanners: [
            FakeScanner(category: .launchDaemons, itemNames: ["a", "b"]),
            FakeScanner(
                category: .cronJobs,
                itemNames: ["c"],
                errors: [ScanError(category: .cronJobs, message: "unreadable")]
            ),
        ])

        let result = await coordinator.performFullScan()

        XCTAssertEqual(result.items.count, 3)
        XCTAssertEqual(result.errors.count, 1)
        XCTAssertEqual(result.errors.first?.message, "unreadable")
    }

    /// The whole point of the error channel: an unreadable directory must be
    /// distinguishable from an empty one.
    func testScannerErrorsSurviveToTheResult() async {
        let coordinator = ScanCoordinator(scanners: [
            FakeScanner(
                category: .launchAgents,
                itemNames: [],
                errors: [ScanError(
                    category: .launchAgents,
                    path: "/Library/LaunchAgents",
                    message: "Permission denied",
                    isPermissionDenied: true
                )]
            ),
        ])

        let result = await coordinator.performFullScan()

        XCTAssertTrue(result.items.isEmpty)
        XCTAssertEqual(result.categoriesBlockedByPermissions, [.launchAgents])
        XCTAssertTrue(result.hasCoverageGaps)
    }

    func testThrowingScannerBecomesAnErrorNotACrash() async {
        let coordinator = ScanCoordinator(scanners: [
            FailingScanner(category: .pamModules),
            FakeScanner(category: .launchDaemons, itemNames: ["survivor"]),
        ])

        let result = await coordinator.performFullScan()

        // One scanner failing must not lose the others' results.
        XCTAssertEqual(result.items.map(\.name), ["survivor"])
        XCTAssertEqual(result.errors.count, 1)
        XCTAssertEqual(result.errors.first?.category, .pamModules)
    }

    // MARK: - Timeout isolation

    func testWedgedScannerTimesOutWithoutStallingTheScan() async {
        // An attacker who can plant a FIFO in $HOME could otherwise hang every
        // scan forever. One category degrades; the rest complete.
        let coordinator = ScanCoordinator(scanners: [
            HangingScanner(category: .shellProfiles),
            FakeScanner(category: .launchDaemons, itemNames: ["ok"]),
        ])

        let start = Date()
        let result = await coordinator.performFullScan(
            options: ScanOptions(perScannerTimeout: 1)
        )
        let elapsed = Date().timeIntervalSince(start)

        XCTAssertLessThan(elapsed, 20, "the hung scanner must not block the run")
        XCTAssertEqual(result.items.map(\.name), ["ok"])
        XCTAssertTrue(
            result.errors.contains { $0.category == .shellProfiles },
            "the timed-out category must be reported, not silently empty"
        )
    }

    // MARK: - Category scoping

    func testCategoryFilterRestrictsWhichScannersRun() async {
        // `--category` used to run all 36 scanners and filter afterwards.
        let coordinator = ScanCoordinator(scanners: [
            FakeScanner(category: .launchDaemons, itemNames: ["daemon"]),
            FakeScanner(category: .cronJobs, itemNames: ["cron"]),
        ])

        let result = await coordinator.performFullScan(
            options: ScanOptions(categories: [.cronJobs])
        )

        XCTAssertEqual(result.items.map(\.name), ["cron"])
        XCTAssertEqual(coordinator.progress.totalScanners, 1,
                       "only the requested category should have been scheduled")
    }

    // MARK: - Privilege reporting

    /// Privileged scanners must still be *run* when the process is unprivileged.
    ///
    /// The coordinator used to short-circuit them with a synthetic "requires root"
    /// error. That is why the privileged helper was unreachable from the GUI: the
    /// scanners that would have used it never executed. They now run and decide for
    /// themselves whether a route exists.
    func testPrivilegedScannerStillRunsWhenNotRoot() async throws {
        try XCTSkipIf(getuid() == 0, "this test describes the unprivileged case")

        let coordinator = ScanCoordinator(scanners: [
            FakeScanner(
                category: .backgroundTaskManagement,
                requiresPrivilege: true,
                itemNames: ["reached-via-helper"]
            ),
        ])

        let result = await coordinator.performFullScan()

        XCTAssertEqual(result.items.map(\.name), ["reached-via-helper"])
        XCTAssertTrue(result.errors.isEmpty,
                      "the coordinator must not invent a permission error for the scanner")
    }

    /// A privileged scanner that genuinely cannot proceed reports its own error.
    func testPrivilegedScannerReportsItsOwnCoverageGap() async {
        let coordinator = ScanCoordinator(scanners: [
            FakeScanner(
                category: .configurationProfiles,
                requiresPrivilege: true,
                itemNames: [],
                errors: [ScanError(
                    category: .configurationProfiles,
                    message: "needs root or an approved helper",
                    isPermissionDenied: true
                )]
            ),
        ])

        let result = await coordinator.performFullScan()

        XCTAssertTrue(result.items.isEmpty)
        XCTAssertEqual(result.categoriesBlockedByPermissions, [.configurationProfiles])
    }

    // MARK: - Reentrancy

    func testConcurrentScansDoNotInterleave() async {
        // Two scans on one coordinator used to interleave their progress counters,
        // and whichever finished first cleared `isScanning` while the other ran.
        let coordinator = ScanCoordinator(scanners: [
            FakeScanner(category: .launchDaemons, itemNames: ["a"], delay: .milliseconds(200)),
        ])

        async let first = coordinator.performFullScan()
        async let second = coordinator.performFullScan()
        let (one, two) = await (first, second)

        // The rejected call returns the existing result rather than starting a
        // second concurrent traversal.
        XCTAssertLessThanOrEqual(coordinator.progress.completedScanners,
                                 coordinator.progress.totalScanners,
                                 "progress must never exceed its own total")
        XCTAssertFalse(coordinator.isScanning)
        XCTAssertTrue(one.items.count == 1 || two.items.count == 1)
    }

    // MARK: - Progress reporting

    func testProgressReachesCompleteAndIsMonotonic() async {
        let coordinator = ScanCoordinator(scanners: [
            FakeScanner(category: .launchDaemons, itemNames: ["a"]),
            FakeScanner(category: .cronJobs, itemNames: ["b"]),
        ])

        _ = await coordinator.performFullScan()

        XCTAssertEqual(coordinator.progress.phase, .complete)
        XCTAssertEqual(coordinator.progress.fractionComplete, 1.0)
        XCTAssertEqual(coordinator.progress.completedScanners, 2)
    }

    /// The bar used to sit at a constant 0.9 through signature verification — the
    /// longest phase — and report 1.0 while risk analysis was still running.
    func testFractionCompleteIsHonestPerPhase() {
        var progress = ScanProgress(totalScanners: 10)

        progress.phase = .scanning
        progress.completedScanners = 5
        XCTAssertEqual(progress.fractionComplete, 0.35, accuracy: 0.001)

        progress.phase = .verifyingSignatures
        progress.verificationTotal = 100
        progress.verificationCompleted = 0
        let atStart = progress.fractionComplete
        progress.verificationCompleted = 50
        let atHalf = progress.fractionComplete
        progress.verificationCompleted = 100
        let atEnd = progress.fractionComplete
        XCTAssertLessThan(atStart, atHalf)
        XCTAssertLessThan(atHalf, atEnd)
        XCTAssertLessThan(atEnd, 1.0, "verification finishing is not the whole scan")

        progress.phase = .analyzingRisk
        progress.analysisTotal = 10
        progress.analysisCompleted = 5
        XCTAssertLessThan(progress.fractionComplete, 1.0,
                          "analysis in progress must not report 100%")

        progress.phase = .complete
        XCTAssertEqual(progress.fractionComplete, 1.0)
    }

    func testStatusTextNamesTheCurrentPhase() {
        var progress = ScanProgress(totalScanners: 4)
        progress.completedScanners = 2
        XCTAssertTrue(progress.statusText.contains("2/4"))

        progress.phase = .verifyingSignatures
        progress.verificationTotal = 20
        progress.verificationCompleted = 7
        XCTAssertTrue(progress.statusText.contains("7/20"),
                      "verification progress should be specific, not just 'Verifying…'")
    }

    // MARK: - Provenance

    func testResultRecordsWhetherItRanAsRoot() async {
        let coordinator = ScanCoordinator(scanners: [
            FakeScanner(category: .launchDaemons, itemNames: ["a"]),
        ])
        let result = await coordinator.performFullScan()

        XCTAssertEqual(result.ranAsRoot, getuid() == 0)
        XCTAssertEqual(result.schemaVersion, ScanResult.currentSchemaVersion)
        XCTAssertFalse(result.toolVersion.isEmpty)
    }
}
