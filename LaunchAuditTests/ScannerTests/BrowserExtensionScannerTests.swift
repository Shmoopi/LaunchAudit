import XCTest
@testable import LaunchAudit

final class BrowserExtensionScannerTests: XCTestCase {

    func testScannerCategory() {
        let scanner = BrowserExtensionScanner()
        XCTAssertEqual(scanner.category, .browserExtensions)
    }

    func testScannerDoesNotRequirePrivilege() {
        let scanner = BrowserExtensionScanner()
        XCTAssertFalse(scanner.requiresPrivilege)
    }

    func testScanCompletesWithoutThrowing() async throws {
        let scanner = BrowserExtensionScanner()
        let items = try await scanner.scan()
        for item in items {
            XCTAssertEqual(item.category, .browserExtensions)
            XCTAssertFalse(item.name.isEmpty)
            XCTAssert(item.name.contains(":"),
                "Browser extension names should be prefixed with the browser name")
        }
    }

    func testScanIsBoundedInTime() async throws {
        // Even with all major browsers installed and many extensions, the
        // parallelized scan should complete in well under 5 seconds.
        let scanner = BrowserExtensionScanner()
        let start = Date()
        _ = try await scanner.scan()
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertLessThan(elapsed, 5.0,
            "BrowserExtensionScanner should complete in under 5s")
    }
}
