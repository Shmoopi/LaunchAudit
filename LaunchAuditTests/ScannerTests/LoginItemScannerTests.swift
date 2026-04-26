import XCTest
@testable import LaunchAudit

final class LoginItemScannerTests: XCTestCase {

    func testScannerCategory() {
        let scanner = LoginItemScanner()
        XCTAssertEqual(scanner.category, .loginItems)
    }

    func testScannerDoesNotRequirePrivilege() {
        let scanner = LoginItemScanner()
        XCTAssertFalse(scanner.requiresPrivilege)
    }

    func testScanCompletesQuickly() async throws {
        // The osascript path can take 1-3 seconds; the SMAppService path
        // is essentially instant (<100ms). Either way the scanner should
        // complete in well under 5 seconds on any healthy system.
        let scanner = LoginItemScanner()
        let start = Date()
        _ = try await scanner.scan()
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertLessThan(elapsed, 5.0,
            "LoginItemScanner should complete in under 5s")
    }

    func testScanReturnsValidItems() async throws {
        let scanner = LoginItemScanner()
        let items = try await scanner.scan()
        for item in items {
            XCTAssertEqual(item.category, .loginItems)
            XCTAssertFalse(item.name.isEmpty)
            // Most login items run at .login; some LaunchAgents-derived
            // entries may report .onDemand. Either is valid.
            XCTAssertTrue(item.runContext == .login || item.runContext == .onDemand)
        }
    }
}
