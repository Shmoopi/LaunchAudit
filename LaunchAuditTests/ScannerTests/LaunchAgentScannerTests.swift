import XCTest
@testable import LaunchAudit

final class LaunchAgentScannerTests: XCTestCase {

    func testScannerCategory() {
        let scanner = LaunchAgentScanner()
        XCTAssertEqual(scanner.category, .launchAgents)
    }

    func testScannerPaths() {
        let scanner = LaunchAgentScanner()
        XCTAssertFalse(scanner.scanPaths.isEmpty)
        XCTAssert(scanner.scanPaths.contains("/Library/LaunchAgents"))
    }

    func testScanReturnsItems() async throws {
        let scanner = LaunchAgentScanner()
        let items = try await scanner.scan()
        // There should be at least some launch agents on any macOS system
        XCTAssertFalse(items.isEmpty, "Expected to find at least one launch agent")

        for item in items {
            XCTAssertEqual(item.category, .launchAgents)
            XCTAssertFalse(item.name.isEmpty)
        }
    }
}
