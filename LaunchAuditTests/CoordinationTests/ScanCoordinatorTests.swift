import XCTest
@testable import LaunchAudit

@MainActor
final class ScanCoordinatorTests: XCTestCase {

    func testFullScanCompletesAndPopulatesTimings() async {
        let coordinator = ScanCoordinator()
        let result = await coordinator.performFullScan()

        // Smoke test: scan completed and produced a result, and per-scanner
        // timings were captured for at least some scanners.
        XCTAssertGreaterThan(result.scanDuration, 0)
        XCTAssertFalse(coordinator.progress.scannerTimings.isEmpty,
            "Per-scanner timings should be populated after Phase 1")
    }

    func testFullScanMeetsPerformanceBudget() async {
        // Performance regression budget. Pre-optimization scans hit 30s+
        // because of pipe deadlocks and per-PID shell-outs. Post-optimization,
        // a healthy system should finish well within 30 seconds.
        let coordinator = ScanCoordinator()
        let start = Date()
        _ = await coordinator.performFullScan()
        let elapsed = Date().timeIntervalSince(start)
        // Print slowest scanners on failure so the next iteration knows where to look.
        if elapsed >= 30 {
            print("== Slowest scanners ==")
            for (cat, dur) in coordinator.progress.slowestScanners(limit: 10) {
                print(String(format: "  %@ — %.3fs", cat.displayName as NSString, dur))
            }
        }
        XCTAssertLessThan(elapsed, 30.0,
            "Full scan should complete in under 30s on healthy systems")
    }

    func testSlowestScannersHelperReturnsSortedDescending() async {
        let coordinator = ScanCoordinator()
        _ = await coordinator.performFullScan()
        let slowest = coordinator.progress.slowestScanners(limit: 5)
        XCTAssertLessThanOrEqual(slowest.count, 5)
        // Confirm descending order
        for i in 1..<slowest.count {
            XCTAssertGreaterThanOrEqual(slowest[i - 1].1, slowest[i].1)
        }
    }
}
