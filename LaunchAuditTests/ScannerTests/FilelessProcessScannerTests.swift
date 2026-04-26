import XCTest
@testable import LaunchAudit

final class FilelessProcessScannerTests: XCTestCase {

    func testScannerCategory() {
        let scanner = FilelessProcessScanner()
        XCTAssertEqual(scanner.category, .filelessProcesses)
    }

    func testScannerRequiresPrivilege() {
        let scanner = FilelessProcessScanner()
        XCTAssertTrue(scanner.requiresPrivilege)
    }

    func testScanCompletesQuickly() async throws {
        // Regression: previous implementation spawned lsof + ps PER candidate.
        // On a system with even one fileless process, that was multiple seconds.
        // The new implementation must complete in well under a second.
        let scanner = FilelessProcessScanner()
        let start = Date()
        _ = try await scanner.scan()
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertLessThan(elapsed, 2.0,
            "FilelessProcessScanner should complete in under 2s on any healthy system")
    }

    func testScanReturnsArrayWithoutCrashing() async throws {
        let scanner = FilelessProcessScanner()
        let items = try await scanner.scan()
        // Most systems have zero fileless processes; just confirm we got a
        // valid (possibly empty) array and the items are well-formed.
        for item in items {
            XCTAssertEqual(item.category, .filelessProcesses)
            XCTAssertFalse(item.name.isEmpty)
            XCTAssertTrue(item.name.contains("PID"),
                "Fileless process names should include the PID")
        }
    }
}
