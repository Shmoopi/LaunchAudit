import XCTest
@testable import LaunchAudit

final class ProfileScannerTests: XCTestCase {

    func testScannerCategory() {
        let scanner = ProfileScanner()
        XCTAssertEqual(scanner.category, .configurationProfiles)
    }

    func testScannerRequiresPrivilege() {
        let scanner = ProfileScanner()
        XCTAssertTrue(scanner.requiresPrivilege)
    }

    func testScanCompletesWithoutThrowing() async throws {
        let scanner = ProfileScanner()
        // Without root, the `profiles` command may emit nothing — that's
        // a valid empty result, not a failure.
        let items = try await scanner.scan()
        for item in items {
            XCTAssertEqual(item.category, .configurationProfiles)
            XCTAssertFalse(item.name.isEmpty)
        }
    }

    func testScanCompletesPromptly() async throws {
        // Single invocation should never exceed 5s — the profiles command
        // typically returns in <500ms even on managed devices.
        let scanner = ProfileScanner()
        let start = Date()
        _ = try await scanner.scan()
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertLessThan(elapsed, 5.0)
    }
}
